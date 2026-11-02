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
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// The handler validates structure only: every well-formed standard query is
// forwarded to the exchange, malformed ones are answered or dropped, and no
// policy lives here anymore.
func TestDNSHandlerOnRequest(t *testing.T) {
	h := newDNSHandler()

	// Short packets and responses are dropped.
	if dec := h.onRequest([]byte{1, 2, 3, 4}); dec.verdict != verdictDrop {
		t.Errorf("short packet verdict = %v, want verdictDrop", dec.verdict)
	}
	if dec := h.onRequest(dnsAnswer(dnsQuery(0x1234), 0)); dec.verdict != verdictDrop {
		t.Errorf("response packet verdict = %v, want verdictDrop", dec.verdict)
	}

	qExample := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}

	tests := []struct {
		name      string
		raw       []byte
		wantRCode dnsmessage.RCode
	}{
		{
			name: "QDCOUNT == 0 -> FORMERR",
			raw: buildTestMessage(t, dnsmessage.Header{
				ID:               0x1001,
				RecursionDesired: true,
			}, nil),
			wantRCode: dnsmessage.RCodeFormatError,
		},
		{
			name: "non-query opcode -> NOTIMP",
			raw: buildTestMessage(t, dnsmessage.Header{
				ID:       0x1003,
				OpCode:   1,
				Response: false,
			}, &qExample),
			wantRCode: dnsmessage.RCodeNotImplemented,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dec := h.onRequest(tc.raw)
			if dec.verdict != verdictReply {
				t.Fatalf("verdict = %v, want verdictReply", dec.verdict)
			}
			var p dnsmessage.Parser
			hdr, err := p.Start(dec.reply)
			if err != nil {
				t.Fatalf("reply does not parse: %v", err)
			}
			if hdr.RCode != tc.wantRCode {
				t.Errorf("RCode = %v, want %v", hdr.RCode, tc.wantRCode)
			}
			if hdr.Response != true {
				t.Errorf("reply is not a response")
			}
		})
	}
}

// A well-formed query is forwarded, with its header and question parsed for
// the caller's error answers.
func TestDNSHandlerForwardsWellFormedQueries(t *testing.T) {
	h := newDNSHandler()
	raw := dnsQuery(0x5678)
	dec := h.onRequest(raw)
	if dec.verdict != verdictForward {
		t.Fatalf("verdict = %v, want verdictForward", dec.verdict)
	}
	if dec.hdr.ID != 0x5678 {
		t.Errorf("header ID = %#x, want 0x5678", dec.hdr.ID)
	}
	if dec.q.Name.String() != "example.com." || dec.q.Type != dnsmessage.TypeA {
		t.Errorf("question = %+v, want example.com. A", dec.q)
	}
}

// Zone transfers are refused even though they are well-formed queries.
func TestDNSHandlerRefusesZoneTransfers(t *testing.T) {
	h := newDNSHandler()
	transfer := dnsmessage.Question{
		Name:  dnsmessage.MustNewName("example.com."),
		Type:  dnsmessage.TypeAXFR,
		Class: dnsmessage.ClassINET,
	}
	dec := h.onRequest(buildTestMessage(t, dnsmessage.Header{ID: 0x6789}, &transfer))
	if dec.verdict != verdictReply {
		t.Fatalf("verdict = %v, want verdictReply", dec.verdict)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(dec.reply)
	if err != nil {
		t.Fatalf("reply does not parse: %v", err)
	}
	if hdr.RCode != dnsmessage.RCodeNotImplemented {
		t.Errorf("RCode = %v, want NOTIMP", hdr.RCode)
	}
}

func buildTestMessage(t *testing.T, hdr dnsmessage.Header, q *dnsmessage.Question) []byte {
	t.Helper()
	msg := dnsmessage.Message{Header: hdr}
	if q != nil {
		msg.Questions = []dnsmessage.Question{*q}
	}
	raw, err := msg.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
