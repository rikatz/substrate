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

package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"go.ate.dev/substrate/internal/atunnel/dns/protocol"
	"go.ate.dev/substrate/internal/doh"
	"go.ate.dev/substrate/internal/resources"
)

const (
	// upstreamTimeout bounds one resolver exchange.
	upstreamTimeout = 5 * time.Second
	// resolverDialTimeout bounds opening one resolver socket.
	resolverDialTimeout = time.Second
)

// DoHServer is the egress gateway's DNS endpoint. atunnel's per-actor DNS
// relay sends it every actor query as DoH (RFC 8484) over the actor's own
// mTLS connection, selected by the ate-doh ALPN on the egress listener. It
// decides each query against the actor's EgressPolicy and resolves allowed
// names from the gateway pod's own resolvers: the worker's resolvers and the
// raw-DNS path to them are gone, which is the point of the endpoint.
type DoHServer struct {
	handler   *Handler
	resolvers []*net.UDPAddr
}

// NewDoHServer builds the server on h. It reads the gateway pod's
// /etc/resolv.conf once: those resolvers are trusted, and reachable in ways
// an actor's never were.
func (h *Handler) NewDoHServer() (*DoHServer, error) {
	resolvers, err := podResolvers("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}
	return &DoHServer{handler: h, resolvers: resolvers}, nil
}

// ServeHTTP answers one DoH request. The actor is the mTLS peer the egress
// listener verified, carried on the x-forwarded-client-cert header Envoy
// sanitizes, which is the same identity the CONNECT leg authenticates.
//
// A policy denial is an HTTP 200 carrying NXDOMAIN, not an HTTP error: the
// actor's resolver must see an answer it can hand to the application, and a
// denied name is indistinguishable from a nonexistent one by design.
func (s *DoHServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method != http.MethodPost || r.URL.Path != doh.Path {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), doh.ContentType) {
		http.Error(w, "content-type must be "+doh.ContentType, http.StatusUnsupportedMediaType)
		return
	}
	query, err := io.ReadAll(io.LimitReader(r.Body, doh.MaxQueryBytes+1))
	if err != nil || len(query) == 0 || len(query) > doh.MaxQueryBytes {
		http.Error(w, "unreadable query", http.StatusBadRequest)
		return
	}

	actorRef, err := s.authenticate(r)
	if err != nil {
		// The peer failed authentication: no detail about why.
		slog.WarnContext(ctx, "doh denied: actor rejected", slog.Any("err", err))
		http.Error(w, "egress denied", http.StatusForbidden)
		return
	}
	hdr, q, ok := parseQuery(query)
	if !ok {
		// The actor is fine; the query is not. Answer FORMERR as DNS, so
		// the actor's resolver sees a well-formed failure.
		s.reply(w, protocol.ErrorPacket(dnsmessage.Header{}, dnsmessage.RCodeFormatError, nil))
		return
	}

	policy, err := s.handler.policies.get(ctx, actorRef)
	if err != nil || policy.RuleCount() == 0 {
		// No policy, or one that can allow nothing: the same posture as a
		// denied name, and it fails closed on a control-plane error too.
		// NXDOMAIN rather than 503 keeps the actor's resolver from retrying
		// a path that will not open up.
		slog.DebugContext(ctx, "doh denied: no usable egress policy", slog.Any("actor", actorRef), slog.Any("err", err))
		s.reply(w, protocol.NXDomainPacket(hdr, q))
		return
	}

	if !policy.AllowsHostname(q.Name.String()) {
		// The queried name is not logged, matching the relay's refusal
		// behavior: a denial looks like an ordinary resolution failure.
		slog.DebugContext(ctx, "doh denied: no rule allows the name", slog.Any("actor", actorRef))
		s.reply(w, protocol.NXDomainPacket(hdr, q))
		return
	}

	answer, err := s.exchange(ctx, query)
	if err != nil {
		slog.DebugContext(ctx, "doh: upstream resolution failed", slog.Any("actor", actorRef), slog.Any("err", err))
		s.reply(w, protocol.ErrorPacket(hdr, dnsmessage.RCodeServerFailure, &q))
		return
	}
	s.reply(w, answer)
}

func (s *DoHServer) reply(w http.ResponseWriter, msg []byte) {
	w.Header().Set("Content-Type", doh.ContentType)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(msg)
}

// authenticate verifies the request's peer certificate and its actor against
// the control plane: the same checks the CONNECT leg makes.
func (s *DoHServer) authenticate(r *http.Request) (resources.ActorRef, error) {
	header := r.Header.Get(forwardedClientCertHeader)
	if header == "" {
		return resources.ActorRef{}, fmt.Errorf("request carries no %s header", forwardedClientCertHeader)
	}
	chain, err := parseXFCCChain(header)
	if err != nil {
		return resources.ActorRef{}, err
	}
	roots, err := s.handler.loadActorIdentityRoots()
	if err != nil {
		return resources.ActorRef{}, fmt.Errorf("actor-identity CA failed to load: %w", err)
	}
	ref, err := verifyActorCertificate(chain, roots)
	if err != nil {
		return resources.ActorRef{}, err
	}
	if err := s.handler.validateActor(r.Context(), ref, doh.Host); err != nil {
		return resources.ActorRef{}, err
	}
	return ref, nil
}

// parseQuery applies the same request validation the worker-side relay
// does: one well-formed standard query, no zone transfers. It returns the
// header and question a reply is built from.
func parseQuery(raw []byte) (dnsmessage.Header, dnsmessage.Question, bool) {
	if !protocol.RequestSanityCheck(raw) {
		return dnsmessage.Header{}, dnsmessage.Question{}, false
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil || hdr.OpCode != 0 || hdr.Response {
		return dnsmessage.Header{}, dnsmessage.Question{}, false
	}
	if protocol.QDCount(raw) != 1 {
		return dnsmessage.Header{}, dnsmessage.Question{}, false
	}
	q, err := p.Question()
	if err != nil || q.Type == dnsmessage.TypeAXFR || q.Type == protocol.TypeIXFR {
		return dnsmessage.Header{}, dnsmessage.Question{}, false
	}
	return hdr, q, true
}

// exchange forwards the query verbatim to the gateway pod's resolvers over
// UDP and returns the answer. The answer's transaction ID must match the
// query's, so atunnel hands it to the actor unchanged.
func (s *DoHServer) exchange(ctx context.Context, query []byte) ([]byte, error) {
	buf := make([]byte, doh.MaxQueryBytes)
	var lastErr error
	for _, resolver := range s.resolvers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		answer, err := udpExchange(resolver, query, buf)
		if err == nil {
			return answer, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no resolver configured")
	}
	return nil, lastErr
}

// udpExchange sends query to resolver and reads one answer on a connected
// socket, so only that resolver can answer.
func udpExchange(resolver *net.UDPAddr, query, buf []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", resolver.String(), resolverDialTimeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(upstreamTimeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	answer := buf[:n]
	if !protocol.ResponseSanityCheck(answer) || protocol.TxnID(answer) != protocol.TxnID(query) {
		return nil, fmt.Errorf("resolver answer failed validation")
	}
	return answer, nil
}

// podResolvers reads the nameservers out of a resolv.conf.
func podResolvers(path string) ([]*net.UDPAddr, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var resolvers []*net.UDPAddr
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "nameserver" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(fields[1], "53"))
		if err != nil {
			continue
		}
		resolvers = append(resolvers, addr)
	}
	if len(resolvers) == 0 {
		return nil, fmt.Errorf("%s names no resolver", path)
	}
	return resolvers, nil
}
