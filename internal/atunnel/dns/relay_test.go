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
	"net"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// serveLoopback binds the relay's sockets on loopback and serves them with
// the exchange, returning the server and its UDP and TCP addresses.
func serveLoopback(t *testing.T, relay *Relay, exchange Exchange) (*Server, net.Addr, net.Addr) {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp, err := net.Listen("tcp", udp.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	netC := &netConn{udp: udp, tcpListener: tcp}
	srv, err := relay.serveOn(context.Background(), netC, exchange)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Stop(ctx)
	})
	return srv, udp.LocalAddr(), tcp.Addr()
}

func serveRelayUDP(t *testing.T, relay *Relay, exchange Exchange) net.Conn {
	t.Helper()
	_, udpAddr, _ := serveLoopback(t, relay, exchange)
	client, err := net.Dial("udp", udpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func readWithin(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	buf := make([]byte, maxDatagramSize)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("reading an answer: %v", err)
	}
	return buf[:n]
}

// The relay hands the exchange's answer to the actor unchanged, keeping the
// query's own transaction ID.
func TestRelayAnswersFromTheExchange(t *testing.T) {
	var gotQuery []byte
	exchange := func(_ context.Context, query []byte) ([]byte, error) {
		gotQuery = append([]byte(nil), query...)
		return dnsAnswer(query, 0), nil
	}
	client := serveRelayUDP(t, NewRelay(), exchange)

	query := dnsQuery(0xabcd)
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	answer := readWithin(t, client)
	if diff := cmp.Diff(dnsAnswer(query, 0), answer); diff != "" {
		t.Errorf("answer mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(query, gotQuery); diff != "" {
		t.Errorf("query mismatch (-want +got):\n%s", diff)
	}
}

// A failing exchange must still answer: SERVFAIL, with the query's ID.
func TestRelayAnswersServerFailureWhenTheExchangeFails(t *testing.T) {
	client := serveRelayUDP(t, NewRelay(), func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("gateway unreachable")
	})

	query := dnsQuery(0x2468)
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	want := dnsAnswer(query, byte(2)) // SERVFAIL
	want[3] |= 0x80                   // the synthesized header says RA
	if diff := cmp.Diff(want, readWithin(t, client)); diff != "" {
		t.Errorf("answer mismatch (-want +got):\n%s", diff)
	}
}

// A nil exchange fails closed the same way.
func TestRelayFailsClosedWithoutAnExchange(t *testing.T) {
	client := serveRelayUDP(t, NewRelay(), nil)

	query := dnsQuery(0x1357)
	if _, err := client.Write(query); err != nil {
		t.Fatal(err)
	}
	want := dnsAnswer(query, byte(2)) // SERVFAIL
	want[3] |= 0x80                   // the synthesized header says RA
	if diff := cmp.Diff(want, readWithin(t, client)); diff != "" {
		t.Errorf("answer mismatch (-want +got):\n%s", diff)
	}
}

// A malformed query is answered FORMERR, not forwarded.
func TestRelayAnswersFormErrorForMalformedQueries(t *testing.T) {
	called := false
	client := serveRelayUDP(t, NewRelay(), func(context.Context, []byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	// QDCOUNT 2: structurally a packet, but not one query.
	if _, err := client.Write([]byte{0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	answer := readWithin(t, client)
	if len(answer) < 4 || answer[0] != 0x12 || answer[1] != 0x34 || answer[3]&0x0f != 1 {
		t.Errorf("answer is not FORMERR carrying the query's ID: % x", answer)
	}
	if called {
		t.Error("the exchange saw a malformed query")
	}
}

// TCP queries are answered with length-prefixed frames.
func TestRelayAnswersTCP(t *testing.T) {
	_, _, tcpAddr := serveLoopback(t, NewRelay(), func(_ context.Context, query []byte) ([]byte, error) {
		return dnsAnswer(query, 0), nil
	})
	conn, err := net.Dial("tcp", tcpAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	query := dnsQuery(0x4321)
	if err := writeTCPFrameTest(conn, query); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, maxDatagramSize)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	// Strip the 2-byte length prefix the frame carries.
	if diff := cmp.Diff(dnsAnswer(query, 0), buf[2:n]); diff != "" {
		t.Errorf("answer mismatch (-want +got):\n%s", diff)
	}
}

func writeTCPFrameTest(conn net.Conn, msg []byte) error {
	frame := make([]byte, 2+len(msg))
	frame[0] = byte(len(msg) >> 8)
	frame[1] = byte(len(msg))
	copy(frame[2:], msg)
	_, err := conn.Write(frame)
	return err
}

func dnsQuery(id uint16) []byte {
	msg := []byte{byte(id >> 8), byte(id), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}
	for _, label := range []string{"example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	return append(msg, 0, 0, 1, 0, 1) // root label, QTYPE A, QCLASS IN
}

// dnsAnswer echoes a query back as a response carrying rcode.
func dnsAnswer(query []byte, rcode byte) []byte {
	resp := make([]byte, len(query))
	copy(resp, query)
	resp[2] |= 0x80 // QR: this is a response
	resp[3] = resp[3]&0xf0 | rcode
	return resp
}
