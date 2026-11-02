// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package dns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"go.ate.dev/substrate/internal/atunnel/dns/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

// Exchange sends one DNS query and returns its answer. The egress gateway's
// DoH endpoint implements it: the query is decided against the actor's
// EgressPolicy there, and the answer carries the query's transaction ID, so
// the relay hands it to the actor unchanged.
type Exchange func(ctx context.Context, query []byte) ([]byte, error)

// queryTimeout bounds one exchange, covering the gateway's policy decision
// and its own resolver round trip.
const queryTimeout = 7 * time.Second

// maxDatagramSize that we accept on the actor-facing UDP socket.
const maxDatagramSize = 4 * 1024

type serverConfig struct {
	// exchange answers every well-formed query. Nil refuses everything,
	// failing closed.
	exchange Exchange
}

type netConn struct {
	udp         net.PacketConn
	tcpListener net.Listener
}

// Server is one sandbox's running DNS relay, returned by [Relay.Serve]. It
// answers the actor's plain UDP/53 and TCP/53 queries by exchanging them
// over the supplied Exchange, keeping every other detail of resolution
// outside the worker.
type Server struct {
	n        *netConn
	limiter  *limiter
	dns      *dnsHandler
	exchange Exchange

	stopServing context.CancelFunc
	closeOnce   sync.Once
	closeErr    error
	serving     sync.WaitGroup
}

// newServer starts serving goroutines on sockets the caller has bound.
func newServer(ctx context.Context, config *serverConfig, netC *netConn) (*Server, error) {
	// Detached from the activation RPC's context but cancelable so teardown
	// drops queries still in flight and releases the actor's sockets.
	serveCtx, stopServing := context.WithCancel(context.WithoutCancel(ctx))

	s := &Server{
		stopServing: stopServing,
		n:           netC,
		limiter:     newLimiter(),
		dns:         newDNSHandler(),
		exchange:    config.exchange,
	}

	s.serving.Add(2)
	go func() {
		defer s.serving.Done()
		if err := s.serveUDP(serveCtx); err != nil {
			slog.WarnContext(ctx, "Actor DNS socket stopped", slog.Any("err", err))
		}
	}()
	go func() {
		defer s.serving.Done()
		if err := s.serveTCP(serveCtx); err != nil {
			slog.WarnContext(ctx, "Actor DNS listener stopped", slog.Any("err", err))
		}
	}()

	return s, nil
}

// serveUDP answers the actor's UDP queries. Each datagram is one query;
// answers are written back to the asking address with the query's own
// transaction ID.
func (s *Server) serveUDP(ctx context.Context) error {
	for {
		buf := make([]byte, maxDatagramSize)
		n, addr, err := s.n.udp.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("DNS socket read: %w", err)
		}
		raw := buf[:n]
		dec := s.dns.onRequest(raw)
		switch dec.verdict {
		case verdictDrop:
			continue
		case verdictReply:
			_, _ = s.n.udp.WriteTo(dec.reply, addr)
		case verdictForward:
			if !s.limiter.inFlight.tryAcquire() {
				slog.Debug("dns relay dropped query; too many in flight")
				continue
			}
			go func() {
				defer s.limiter.inFlight.release()
				msg := s.exchangeQuery(ctx, dec)
				if msg != nil {
					_, _ = s.n.udp.WriteTo(msg, addr)
				}
			}()
		}
	}
}

// serveTCP answers the actor's TCP queries: length-prefixed frames per
// RFC 1035 section 4.2.2, one exchange per frame, answered in order.
func (s *Server) serveTCP(ctx context.Context) error {
	for {
		conn, err := s.n.tcpListener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("DNS listener accept: %w", err)
		}
		if !s.limiter.connections.tryAcquire() {
			slog.Debug("dns relay refused a TCP connection; too many open")
			_ = conn.Close()
			continue
		}
		go func() {
			defer s.limiter.connections.release()
			s.serveTCPConn(ctx, conn)
		}()
	}
}

func (s *Server) serveTCPConn(ctx context.Context, conn net.Conn) {
	defer func() {
		_ = conn.Close()
		// The client half-closing its write side is normal for pipelined
		// queries; closing here drains nothing further, since frames are
		// answered one at a time.
	}()
	for {
		raw, err := protocol.ReadTCPFrame(conn)
		if err != nil {
			return
		}
		dec := s.dns.onRequest(raw)
		switch dec.verdict {
		case verdictDrop:
			return
		case verdictReply:
			if err := protocol.WriteTCPFrame(conn, dec.reply); err != nil {
				return
			}
		case verdictForward:
			msg := s.exchangeQuery(ctx, dec)
			if msg == nil {
				return
			}
			if err := protocol.WriteTCPFrame(conn, msg); err != nil {
				return
			}
		}
	}
}

// exchangeQuery runs one exchange with a bounded lifetime and returns the
// answer, or a synthesized SERVFAIL when the exchange fails. A nil decision
// reply is never returned: the actor asked something well-formed and must
// get a well-formed answer.
func (s *Server) exchangeQuery(ctx context.Context, dec decision) []byte {
	if s.exchange == nil {
		return protocol.ErrorPacket(dec.hdr, dnsmessage.RCodeServerFailure, &dec.q)
	}
	ctx, cancel := context.WithTimeout(ctx, queryTimeout)
	defer cancel()
	answer, err := s.exchange(ctx, dec.query)
	if err != nil || len(answer) == 0 {
		return protocol.ErrorPacket(dec.hdr, dnsmessage.RCodeServerFailure, &dec.q)
	}
	return answer
}

// Stop cancels in-flight queries and connections, closes the sockets, and
// waits for the serving goroutines to exit or ctx to expire.
func (s *Server) Stop(ctx context.Context) error {
	s.closeOnce.Do(func() {
		// Cancel first: closing the sockets alone leaves the queries already
		// being resolved holding the relay.
		s.stopServing()
		for _, c := range []io.Closer{s.n.udp, s.n.tcpListener} {
			if c == nil {
				continue
			}
			if err := c.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.closeErr = errors.Join(s.closeErr, err)
			}
		}
	})
	stopped := make(chan struct{})
	go func() {
		s.serving.Wait()
		close(stopped)
	}()
	select {
	case <-stopped:
		return s.closeErr
	case <-ctx.Done():
		return errors.Join(s.closeErr, fmt.Errorf("while waiting for the DNS server to stop: %w", ctx.Err()))
	}
}
