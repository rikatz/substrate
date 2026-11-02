---
title: "Actor DNS over DoH"
linkTitle: "Actor DNS over DoH"
weight: 20
description: >
  Route actor DNS queries to the egress gateway as DNS-over-HTTPS, so the PEP
  decides and resolves every query. Implementation plan for #2313.
status: planned
status_note: >
  Not implemented. This plan is the Envoy-dataplane v1; see "Scope decisions".
---

# Actor DNS over DoH

## Problem

Actor DNS is the one actor-originated traffic that bypasses the egress gateway
(#2313, #2075). Today the sandbox DNS relay in `internal/atunnel/dns` forwards
every policy-allowed query, as raw DNS, to the worker pod's resolvers. Three
consequences:

1. The queries leave through a path no PEP sees, so a third-party PEP cannot
   inspect, rate-limit, or take over DNS decisions.
2. The query content is an exfiltration channel. An actor with a rule for
   `*.example.com` can encode data in subdomains, and the relay forwards it
   verbatim.
3. The worker pod's resolvers are the cluster's, so cluster-internal names are
   discoverable whenever a rule matches one.

The short-term fix (hostname allowlist in the relay, #2524 and #2774) closed
the open relay but kept the decision in atunnel and the resolution path through
the worker's resolvers.

## Design

The relay becomes a converter. It keeps answering plain UDP/53 and TCP/53 on
the sandbox gateway, but its upstream is no longer a resolver: it wraps each
query in an RFC 8484 `application/dns-message` body and sends it as one HTTPS
request through the existing egress path (`internal/atunnel/egress.Client`).
The egress gateway serves a DoH endpoint, decides the query against the actor's
`EgressPolicy`, resolves allowed names itself, and returns the answer or a
synthesized NXDOMAIN.

```
 actor          atunnel (worker, sandbox gateway netns)    atenet-egress (PEP)
 untrusted      trusted, policy-blind                      trusted, decides and resolves
 -------        ----------------------------------          --------------------------
 curl           UDP/53 in                                  mTLS CONNECT terminates
                wrap in RFC 8484 body                      parse DoH
                send via egress.Client                     check EgressPolicy
                (no resolver, no policy)                   denied: synthesize NXDOMAIN
                                                           allowed: resolve via the
                                                           gateway pod's own resolver
                UDP/53 out                                 unwrap answer, return
```

Why this shape:

- The actor never speaks DoH. glibc and musl do plain UDP/53 against
  `/etc/resolv.conf`, and the relay already terminates that inside the
  ateworker process. The only new protocol speaker is trusted code, so
  arbitrary actor images keep working unchanged.
- The DoH request rides the same mTLS CONNECT tunnel as every other egress
  connection: actor-specific client certificate, gateway-side actor check
  against ateapi, no new trust boundary, no new authentication.
- Transport correlation replaces socket bookkeeping. Each HTTP request carries
  its own query and response, so the transaction-ID rewriting, the
  `pendingRequests` map, and the upstream failover machinery in the relay are
  deleted rather than ported.
- Both DNS and data enter the PEP through the same door, which is the property
  #2313 asks for: one policy engine, one replaceable PEP, for everything.

## Scope decisions

- **Envoy dataplane only.** The egress-policy dynamic module
  (`cmd/dataplane/envoy/dynamic-modules/egress-policy`) gains a `doh` verdict
  that routes the gateway's own DoH traffic to a local cluster on loopback,
  served by an in-process HTTP handler in the `atenet-egress` pod. The module
  routes only; it does not evaluate egress policy for DoH, and the policy
  store, hashing, and lifetime logic are untouched. `ext_proc` is not involved
  in DNS. agentgateway gets no DoH support in v1; an agentgateway install
  without the route fails DNS closed. The install gates the new path on the
  dataplane selection.
- **Cleartext HTTP inside the tunnel.** atunnel sends the DoH request as plain
  HTTP inside the outer mTLS CONNECT, so the module matches it by Host through
  the http inspector that already runs. No second TLS layer, no sdsmint leaf
  per query. An actor reaching the DoH endpoint is by design: it is their DNS
  interface, and every query is policy-checked at the handler.
- **Real answers.** The gateway returns real addresses. Synthetic addresses
  (#2313 question 3, fake-IP mapping) are a follow-up with their own contract
  questions around `cidr` rules and mapping lifetime across suspend and resume.
- **Denial semantics unchanged.** Denied and nonexistent names are both
  NXDOMAIN with a TTL-0 root SOA, as today (#2774). #2313 question 4 stays
  open and is not changed by this plan.
- **No defense-in-depth check in atunnel.** Policy lives only at the gateway.
  Keeping the check in atunnel would split policy in two places again, which is
  the problem this plan removes.

## Implementation plan

### PR 1: DoH endpoint at the egress gateway

No caller yet; deployable behind the dataplane selection.

- `cmd/dataplane/envoy/dynamic-modules/egress-policy/src/listener_filter.rs`:
  a `doh` verdict constant and one match arm. Before the existing SNI and
  transport classification, a request whose Host (cleartext, via the http
  inspector) is the gateway's DoH endpoint emits `doh`. Routing only; the
  policy store filter, the hashing, and the policy lifetime logic are
  untouched.
- `manifests/ate-install/atenet-egress.yaml`: one matcher entry for `doh`, one
  filter chain, one static loopback cluster pointing at the handler. The chain
  name must be pinned to the Go constants in
  `cmd/atenet/internal/router/extproc/dispatch.go`, with a row in
  `egresspolicymanifest_test.go`: a chain renamed on one side only fails
  closed at runtime.
- `cmd/atenet/internal/router/egress`: new handler serving DoH on a loopback
  listener. Parse the RFC 8484 body, decide the query against the actor's
  `EgressPolicy` (reuse `policycache.go` and `internal/egresspolicy` hostname
  matching; actor identity from the filter state or forwarded client
  certificate the existing legs use), resolve allowed names with the gateway
  pod's own resolver, return the answer or synthesize NXDOMAIN with a TTL-0
  root SOA.
- Rate limit per actor and per query-name length, to blunt the
  subdomain-encoding channel on allowed names. Log denials without the
  queried name, as the relay does today.
- Check the `ate-system` NetworkPolicies admit the pod-internal loopback
  connection.

### PR 2: atunnel relay swap

- `internal/atunnel/dns/relay.go`: replace the upstream resolvers (worker pod
  `resolv.conf`) with a DoH client over `internal/atunnel/egress.Client`.
  Answer the actor's original UDP/53 or TCP/53 query from the DoH response.
  On tunnel failure, answer SERVFAIL, fail closed.
- Delete `internal/atunnel/dns/pendingreq.go` and the upstream halves of
  `udphandler.go` and `tcphandler.go`: transaction-ID rewriting, response
  matching against a shared socket, and upstream failover all exist only
  because a raw socket multiplexed queries. Actor-facing validation
  (QDCOUNT, non-query opcodes, AXFR and IXFR rejection) stays.
- Delete `internal/atunnel/egresspolicy.go` and
  `SandboxNetworkConfig.DNSPolicy` in `internal/ateworker/actornet`, and the
  DNS-only use of the `GetActorEgressPolicy` call to atelet. Confirm the RPC
  has no other caller before removing it from `ateletpb`.
- `internal/atunnel/dns/resolvconf.go` goes with the upstream; the actor-facing
  `resolv.conf` rewrite in `internal/ateworker/actornet` stays.

### PR 3: e2e coverage and contract update

- Extend the existing e2e suites (`internal/e2e/suites/networking`,
  `egressauthz`) rather than adding new ones: allowed name resolves, denied
  name gets NXDOMAIN, no-policy actor resolves nothing, policy change applies
  within the 5-second window, tunnel-down fails closed. Both runtimes, gVisor
  and microVM, Envoy dataplane.
- Rewrite the DNS sections of `docs/guides/network-egress.md` and
  `docs/guides/egress-traffic.md` to describe the new path and what a PEP must
  implement.
- Metrics: a denied-query counter at the gateway, registered in
  `docs/metrics/registry/` with `hack/verify/metrics.sh` run.

### Before PR 1

A human contributor posts the direction and the two deferred decisions (real
answers, unchanged denial semantics) to #2313 and gets maintainer agreement.
Agents must not comment on issues or PRs. The issue is `kind/design` with no
technical discussion yet.

## Testing

- Unit: the DoH handler decides policy and resolves; the relay converts both
  ways and fails closed. The existing `internal/atunnel/dns` tests shrink with
  the deleted machinery.
- e2e as in PR 3. No fixed sleeps: the policy-change test waits on the
  observable effect of the refresh window.
- Measure DoH round-trip latency through the tunnel against the activation
  budget before merging PR 2, since every first connection to a new name now
  pays it.

## Risks and open questions

- The Rust module and the manifest are pinned together by
  `egresspolicymanifest_test.go`; the `doh` chain must land on both sides of
  that pin in the same PR. The module itself is a small change, but its build
  and test loop (Cargo workspace under `cmd/dataplane`) is separate from the
  Go tree and must run in CI.
- The module classifies by peeking at client-first bytes. The DoH Host match
  must sit before the policy verdict, and a request that claims the DoH Host
  but is not a well-formed DoH request must fail closed at the handler, not
  fall through to the cleartext chain.
- DoH adds a TLS round trip and an HTTP exchange per uncached name. Bounded by
  the same h2 connection pooling every other egress connection uses, but
  unmeasured.
- Answer caching at the gateway would help latency but risks serving answers
  past a policy change. v1 resolves every allowed query; revisit with
  measurements.
- The `x-forwarded-client-cert` handling the DoH handler needs is the same one
  the HTTP path uses, including its open TODO(identity) audit.
