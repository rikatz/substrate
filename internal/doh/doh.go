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

// Package doh holds the constants of the DoH endpoint the egress gateway
// serves and atunnel's DNS relay calls. Both sides import them, so the
// ALPN token, host, and path can never drift apart.
package doh

const (
	// ALPN selects the egress listener's DoH filter chain. atunnel's DoH
	// client offers it alongside "h2"; every other egress connection offers
	// only "h2" and "http/1.1", so only DoH lands on that chain.
	ALPN = "ate-doh"

	// Host is the authority of every DoH request. It is a routing token,
	// never resolved: atunnel sends it, Envoy's route matches it, and nothing
	// dials it. The .invalid TLD keeps it out of any real namespace.
	Host = "doh.egress.ate.invalid"

	// Path is the DoH endpoint's request path, RFC 8484 style.
	Path = "/dns-query"

	// ContentType is the DoH request and response body type, RFC 8484.
	ContentType = "application/dns-message"

	// ListenAddress is where the atenet-egress pod serves DoH on loopback,
	// behind Envoy's egress_doh cluster. Loopback, like the ext_proc server,
	// so nothing outside the pod can reach it: Envoy fronts it with the
	// actor-identity mTLS the egress listener already enforces.
	ListenAddress = "127.0.0.1:7053"

	// MaxQueryBytes bounds one DoH request body. The actor-facing UDP path
	// accepts 4 KiB datagrams; the TCP path can carry more, so the bound is
	// the DNS-over-TCP ceiling.
	MaxQueryBytes = 65535
)
