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
	"go.ate.dev/substrate/internal/atunnel/dns/protocol"
	"golang.org/x/net/dns/dnsmessage"
)

// verdict describes what to do with a request the protocol handler inspected.
type verdict int

const (
	// verdictDrop the DNS packet.
	verdictDrop verdict = iota
	// verdictReply immediately with the synthesized response in the decision.
	verdictReply
	// verdictForward the query to the exchange.
	verdictForward
)

// decision is the outcome of inspecting one actor query.
type decision struct {
	verdict verdict
	// reply is the response to write for verdictReply.
	reply []byte
	// query is the raw request, for verdictForward.
	query []byte
	// hdr and q are the parsed header and question, which an error answer
	// is built from.
	hdr dnsmessage.Header
	q   dnsmessage.Question
}

// dnsHandler inspects DNS requests and returns transport-agnostic decisions.
// It validates structure only: policy is decided where the query is
// answered, at the egress gateway.
type dnsHandler struct{}

func newDNSHandler() *dnsHandler { return &dnsHandler{} }

// onRequest checks packet structure, returning verdictDrop, verdictReply
// (with a synthesized error response), or verdictForward along with the
// parsed header and canonicalized question.
func (h *dnsHandler) onRequest(raw []byte) decision {
	if !protocol.RequestSanityCheck(raw) {
		return decision{verdict: verdictDrop}
	}

	var p dnsmessage.Parser
	hdr, err := p.Start(raw)
	if err != nil {
		return decision{verdict: verdictReply, reply: protocol.ErrorPacket(hdr, dnsmessage.RCodeFormatError, nil)}
	}

	qdCount := protocol.QDCount(raw)

	// OpCode must be QUERY (== 0).
	if hdr.OpCode != 0 {
		var qPtr *dnsmessage.Question
		if qdCount == 1 {
			if q, qErr := p.Question(); qErr == nil {
				qPtr = &q
			}
		}
		return decision{verdict: verdictReply, reply: protocol.ErrorPacket(hdr, dnsmessage.RCodeNotImplemented, qPtr)}
	}

	// Must have one query.
	if qdCount != 1 {
		return decision{verdict: verdictReply, reply: protocol.ErrorPacket(hdr, dnsmessage.RCodeFormatError, nil)}
	}

	q, err := p.Question()
	if err != nil {
		return decision{verdict: verdictReply, reply: protocol.ErrorPacket(hdr, dnsmessage.RCodeFormatError, nil)}
	}

	// Question type must be supported.
	if q.Type == dnsmessage.TypeAXFR || q.Type == protocol.TypeIXFR {
		return decision{verdict: verdictReply, reply: protocol.ErrorPacket(hdr, dnsmessage.RCodeNotImplemented, &q)}
	}

	return decision{verdict: verdictForward, query: raw, hdr: hdr, q: canonicalizeQuestion(q)}
}

// canonicalizeQuestion normalizes the contents of the Question.
func canonicalizeQuestion(q dnsmessage.Question) dnsmessage.Question {
	for i := range int(q.Name.Length) {
		c := q.Name.Data[i]
		if 'A' <= c && c <= 'Z' {
			q.Name.Data[i] = c + ('a' - 'A')
		}
	}
	clear(q.Name.Data[q.Name.Length:])
	return q
}
