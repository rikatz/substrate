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
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/dns/dnsmessage"

	"go.ate.dev/substrate/internal/doh"
)

// newFakeResolver answers one query at a time on UDP, echoing it back as a
// response with rcode 0.
func newFakeResolver(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		buf := make([]byte, doh.MaxQueryBytes)
		for {
			n, from, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			resp := make([]byte, n)
			copy(resp, buf[:n])
			resp[2] |= 0x80
			_, _ = conn.WriteTo(resp, from)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// dohRequest builds a POST carrying query, with the peer certificate Envoy
// would sanitize into x-forwarded-client-cert.
func dohRequest(xfcc string, query []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://"+doh.Host+doh.Path, bytes.NewReader(query))
	req.Header.Set("Content-Type", doh.ContentType)
	if xfcc != "" {
		req.Header.Set(forwardedClientCertHeader, xfcc)
	}
	return req
}

func dohQuery(id uint16, name string) []byte {
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{
			Name:  dnsmessage.MustNewName(name),
			Type:  dnsmessage.TypeA,
			Class: dnsmessage.ClassINET,
		}},
	}
	raw, err := msg.Pack()
	if err != nil {
		panic(err)
	}
	return raw
}

// rcodeOf parses the DNS response a ServeHTTP call wrote.
func rcodeOf(t *testing.T, rec *httptest.ResponseRecorder) dnsmessage.RCode {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("HTTP status = %d, want 200", rec.Code)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(rec.Body.Bytes())
	if err != nil {
		t.Fatalf("answer does not parse: %v", err)
	}
	return hdr.RCode
}

// An allowed name is resolved and answered verbatim; a name no rule lists is
// answered NXDOMAIN; a request without a peer certificate is refused.
func TestDoHServerDecisions(t *testing.T) {
	ca := newTestCA(t, "actor-identity-ca")
	leaf := ca.issueActorCert(t, "spiffe://substrate-actor.local/worker-for-actor/foo/bar", actorCertOptions{})
	resolver := newFakeResolver(t)

	h := New(&egressMockClient{
		actor:  runningActor(),
		policy: httpPolicy("example.com"),
	}, ca.loadRoots, 0, nil)
	s := &DoHServer{handler: h, resolvers: []*net.UDPAddr{resolver}}

	t.Run("allowed name resolves", func(t *testing.T) {
		query := dohQuery(0x1234, "example.com.")
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, dohRequest(xfccHeader(leaf), query))
		if rcodeOf(t, rec) != dnsmessage.RCodeSuccess {
			t.Errorf("rcode = %v, want success", rcodeOf(t, rec))
		}
		var p dnsmessage.Parser
		hdr, _ := p.Start(rec.Body.Bytes())
		if hdr.ID != 0x1234 {
			t.Errorf("answer ID = %#x, want the query's", hdr.ID)
		}
	})

	t.Run("denied name is NXDOMAIN", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, dohRequest(xfccHeader(leaf), dohQuery(0x5678, "blocked.example.org.")))
		if rcode := rcodeOf(t, rec); rcode != dnsmessage.RCodeNameError {
			t.Errorf("rcode = %v, want NXDOMAIN", rcode)
		}
	})

	t.Run("no peer certificate is refused", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, dohRequest("", dohQuery(0x9abc, "example.com.")))
		if rec.Code != http.StatusForbidden {
			t.Errorf("HTTP status = %d, want 403", rec.Code)
		}
	})

	t.Run("malformed query is FORMERR", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, dohRequest(xfccHeader(leaf), []byte{0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0}))
		if rcode := rcodeOf(t, rec); rcode != dnsmessage.RCodeFormatError {
			t.Errorf("rcode = %v, want FORMERR", rcode)
		}
	})
}

// A dead resolver fails closed as SERVFAIL, not as an HTTP error.
func TestDoHServerFailsClosedOnDeadResolver(t *testing.T) {
	ca := newTestCA(t, "actor-identity-ca")
	leaf := ca.issueActorCert(t, "spiffe://substrate-actor.local/worker-for-actor/foo/bar", actorCertOptions{})
	h := New(&egressMockClient{actor: runningActor(), policy: httpPolicy("*")}, ca.loadRoots, 0, nil)
	// A resolver address with nothing listening.
	dead, err := net.ResolveUDPAddr("udp", "127.0.0.1:1")
	if err != nil {
		t.Fatal(err)
	}
	s := &DoHServer{handler: h, resolvers: []*net.UDPAddr{dead}}

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, dohRequest(xfccHeader(leaf), dohQuery(0xbeef, "example.com.")))
	if rcode := rcodeOf(t, rec); rcode != dnsmessage.RCodeServerFailure {
		t.Errorf("rcode = %v, want SERVFAIL", rcode)
	}
}
