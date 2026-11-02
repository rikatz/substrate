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
)

// Relay creates the per-actor DNS servers. It holds no upstreams and no
// policy: every well-formed query an actor sends is exchanged with the
// egress gateway as DoH, where it is decided against that actor's
// EgressPolicy and resolved. The worker never resolves a name itself.
type Relay struct{}

// dnsPort is the relay port on the sandbox's gateway.
const dnsPort = 53

// NewRelay returns the relay a worker shares across its actors.
func NewRelay() *Relay { return &Relay{} }

// serveOn serves DNS on netC's sockets, which the caller has already bound.
func (r *Relay) serveOn(ctx context.Context, netC *netConn, exchange Exchange) (*Server, error) {
	return newServer(ctx, &serverConfig{exchange: exchange}, netC)
}
