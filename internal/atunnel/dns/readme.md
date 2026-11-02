# Actor DNS

Actor DNS answers the actor's queries from inside its own sandbox, deciding
and resolving nothing on the worker.

## Code structure

### Relay

- `Relay`: one per ateworker, creating the per-actor `Server`s. It holds no
  upstreams and no policy.
- `Relay.Serve()`: binds UDP and TCP sockets on port 53 in the sandbox's
  gateway netns and returns the per-actor `Server`.

### Server

`Server` is the per-actor state: the bound sockets, the per-actor concurrency
limits (`maxInFlight` UDP queries and `maxConnections` TCP connections), and
the `Exchange` every well-formed query is sent through.

- UDP handling: a read loop on the actor-facing socket. Each datagram is one
  query: malformed ones are dropped or answered with a synthesized error,
  well-formed ones go to the exchange in a goroutine bounded by the
  in-flight limit, and the answer is written back with the query's own
  transaction ID.
- TCP handling: an accept loop, one connection at a time per connection up
  to the connection limit. Frames are length-prefixed per RFC 1035
  section 4.2.2 and answered in order.
- `Server.Stop()`: cancels in-flight work, closes the sockets, and waits
  for the serving goroutines.

### DNS protocol layer

`dnshandler.go` validates request structure: one well-formed standard query,
no zone transfers, and the same FORMERR/NOTIMP synthesis for malformed
packets. It decides nothing else: policy lives where the query is answered.

`protocol/` holds the wire helpers: sanity checks, transaction IDs, the
NXDOMAIN packet with its TTL-0 root SOA (RFC 2308 section 5, so a denial is
not cached), and TCP framing.

### The exchange

The exchange is the egress gateway's DoH endpoint
(`cmd/atenet/internal/router/egress/doh.go`), reached over the actor's own
mTLS connection with the `ate-doh` ALPN. The gateway authenticates the actor
from the certificate, checks the query's name against the actor's
`EgressPolicy`, resolves allowed names from the gateway pod's resolvers, and
answers with the response or a synthesized NXDOMAIN. The worker never
resolves a name and never holds the policy, which is the design: the only
component that can resolve on the actor's behalf is the same one every other
egress policy already lives in.
