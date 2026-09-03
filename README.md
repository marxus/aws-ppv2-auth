# ppv2-auth

An Envoy dynamic module that turns AWS PROXY protocol v2 identity into an
**IPv6 address**, so ordinary `clientCIDRs` rules can express PrivateLink tenant
identity at both L4 and L7.

Three filters ship in one `.so`, chosen by `filter_name`. Each name is a position
in a chain and takes exactly one config shape:

    ppv2_auth   parse the header, synthesize, enforce      ula + allow
    ppv2        parse the header, synthesize, label only   ula
    auth        read that label, scope by SNI, enforce     scopes

    tcp  -> [ppv2_auth, ...]
    udp  -> [ppv2_auth, ...]
    tls  -> [ppv2, tls_inspector, auth, ...]

TLS is the special case. `auth` needs the SNI, which exists only after
`tls_inspector` runs, and `tls_inspector` cannot find a ClientHello until the PROXY
header is drained — so `ppv2` splits off to the front. Everywhere else `auth` does
the whole job itself.

## The idea

Every policy engine here matches addresses — Envoy RBAC, `CiliumNetworkPolicy` —
and none can match a `vpce-id`. So synthesize one:

An **onboarded** tenant — one the `sites` table names — gets a real Tailscale
4via6 address, so the same value reads as identity here and as a route there:

```text
fd7a:115c:a1e0:b1a : 0000 : 0007 : 0a00:011c
└──── via /64 ────┘  zero   site   client IPv4
```

Verified bit-identical to `tailscale debug via 7 10.0.1.28/32`. The site sits in
group 6 and the IPv4 in the low 32 bits, which is RFC 6052 embedding for the
`<via>:0:<site>::/96` that CoreDNS's `dns64` plugin already declares — so the
encoding is the standard one rather than a private invention.

Anyone else lands in the fallback ULA, derived rather than looked up, so the data
plane holds no knowledge of a stranger:

```text
fd00:dead:beef : 0001 : 7b53:e75b : 0a00:011c
└── /48 ULA ──┘  └kind┘  └ hash ─┘  client IPv4
                    1 = sha256(vpce-id), an un-onboarded tenant
                    4 = no vpce-id, so the hash half is zero
```

Reproduce a hash with
`printf %s vpce-0123456789abcdef0 | sha256sum | cut -c1-8`.

| header says | result |
|---|---|
| resolves to a site, by `vpce-id` | `via` + site + the tenant's own IPv4 |
| resolves to a site, by source prefix | `via` + site, low 32 bits **zero** |
| a `vpce-id` no site claims | kind 1, `sha256(id)` + client IPv4 |
| no `vpce-id`, IPv4 client | kind 4, 4via6 |
| no `vpce-id`, IPv6 client | **passed through unchanged** |

A v6 client already *is* an address, so encoding could only lose information.
The invariant: everything inside one of the two configured prefixes was
synthesized here, everything outside them is a real client address.

**Why a source prefix carries no machine.** Through PrivateLink the header holds
the tenant's own address — measured, the NLB reports the consumer-side 5-tuple —
so it is theirs and worth carrying. Over the internet their NAT already rewrote
it, so the address is not in their space at all; zero reads honestly as "this
tenant, machine unknown" and still sits inside the tenant's own `/96`. The real
source is in the access log either way.

**Trust is split within one address, and that is worth knowing before writing a
rule.** The site or hash half comes from an AWS-assigned id the sender cannot
choose. The low 32 bits are whatever their machine put in its own packets. So a
`/96` rule naming a tenant is a boundary; a `/128` naming one of their machines
is a convenience, and not something to lean on against that tenant.

Two coarse rules still fall out of the kind group — `…:1::/64` is any
un-onboarded tenant, `…:4::/64` is any IPv4 client — and an IPv4 `/N` maps onto
`/(96+N)`.

The address is a label, not a route. Nothing is ever sent from it, so there is no
spoofing concern and nothing for a CNI's source-IP verification to reject.

## What it buys

Deny by default at the very first thing traffic reaches after the NLB, before a
filter chain is even selected — and identity scoped per hostname, which nothing at
L4 could express before. `clientCIDRs` is the *only* principal a `TCPRoute`
supports, and CEL is rejected outright.

The label is still written with `set_remote_address` before any RBAC filter runs, so
a `SecurityPolicy` can match the same identity downstream if you want defence in
depth:

```yaml
principal:
  clientCIDRs:
    - fd00:dead:beef:1:7b53:e75b:a00:11c/128   # one tenant, one machine
    - fd00:dead:beef:4::12c7:0/112               # 18.199.0.0/16
```

## Install

See [`deploy/`](deploy). The image is mounted, not copied — `volumes[].image` is
a native OCI volume source (Kubernetes ≥1.33), so no initContainer and no
ConfigMap:

```yaml
pod:
  volumes:
    - name: ppv2-auth
      image: { reference: ghcr.io/marxus/aws-ppv2-auth:0.5.0 }
container:
  volumeMounts: [{ name: ppv2-auth, mountPath: /modules, readOnly: true }]
  env: [{ name: LD_LIBRARY_PATH, value: /modules }]
```

`FROM scratch` with exactly one file, so nothing in it ever executes. It is a
manifest list, so the kubelet resolves the architecture.

## Configuration

A `google.protobuf.Struct`, which Envoy serializes to JSON before handing it to
the module (`MessageUtil::knownAnyToBytes`, `utility.h:460`). Structured rather
than a string blob so separate CRs can contribute scopes — see below.

```yaml
filter_config:
  "@type": type.googleapis.com/google.protobuf.Struct
  value:
    scopes:
      - sni:
          - l7.mgmt.test
          - "*.pass.mgmt.test"     # quote it: YAML reads a leading * as an alias
        allow:
          - fd00:dead:beef:1:7b53:e75b:a00:11c/128
```

A scope may name **several hostnames** sharing one list — the shape Envoy's
`ServerNameMatcher` uses, where one `domains` list maps to one action.

Each filter takes one config shape, and anything else fails the listener:

| filter | config | meaning |
|---|---|---|
| `ppv2_auth` | `ula` + `allow` | the whole job in one — plain TCP, and UDP |
| `ppv2` | `ula` only | synthesize and label; it never denies, so it takes no rules |
| `auth` | `scopes` | read the label a `ppv2` filter left — the TLS chain |

`via` and `sites` are optional and belong wherever `ula` does: they describe how a
header is encoded, and only a filter that parses the header does that. On `auth`
they are rejected, because there they would read as applied and do nothing.

```yaml
    ula: fd00:dead:beef::/48
    via: fd7a:115c:a1e0:b1a::/64        # tailscale's 4via6 range, a /64 not a /48
    sites:
      - id: 1
        members: [vpce-028ff61de1d1fea8c, 3.126.239.93/32]
      - id: 2
        members: [203.0.113.0/24, 198.51.100.7/32]
```

A list of objects rather than a map keyed by id, and that is the generator's
constraint rather than a preference: CEL can build a list from a comprehension
but not a map, so a ConfigMap of `id -> text` can be reshaped into this shape and
not into the other. Ids must be unique — a list can repeat one where a map could
not, and then which members apply would depend on order.

A site member is a `vpce-id` or a source prefix, told apart by trying to read it
as an address. IPv4 is lifted to `::ffff:a.b.c.d/(96+N)` so one matcher covers
both families, and a bare address means a single host. A `vpce-id` outranks a
prefix: AWS assigned it and the sender cannot choose it.

Site ids are 1..=65535 — the field is 16 bits, and 0 renders as the bare `via`
prefix, so it is refused. Overlapping prefixes across sites are **not** detected
here; keep them disjoint where the table is generated, or which site wins depends
on iteration order.

Without `via` there is no site space and everything falls to `ula`, which is what
this module did before v0.6.0.

The split exists only because TLS forces it: `auth` needs the SNI, which exists
only after `tls_inspector`, and `tls_inspector` cannot find a ClientHello until
the PROXY header is drained. Everywhere else `ppv2_auth` does both halves.

Because the name fixes the shape, a filter in the wrong place fails its listener
rather than half-working — `ppv2_auth` with `scopes` is rejected (it runs before
`tls_inspector`, so there is no SNI), and `auth` with a `ula` is too.

An `auth` filter with no `allow` at all is valid and denies everything — an empty
allowlist is deny-all, the same as an empty security group. There is no
`require_ppv2` knob: this module is the first thing after the NLB, so traffic
without a header reached the listener directly and is refused, always. Unknown
fields fail the config, so a typo cannot silently disable enforcement.

### Contributing scopes from separate CRs

`scopes` is an array, so another `EnvoyPatchPolicy` can append to it:

```yaml
operation:
  op: add
  path: /listener_filters/2/typed_config/filter_config/value/scopes/-
  value:
    sni: [tenant-a.mgmt.test]
    allow: [fd00:dead:beef:1:7b53:e75b:a00:11c/128]
```

Several policies may target one Gateway — verified on EG v1.9.1 — and they apply
in policy-**name** order, which is also how filter order is fixed.

Two things this depends on:

- **The base must ship `scopes: []`** even when empty, or `/scopes/-` has nothing
  to append to. Empty means SNI mode with nothing claimed, which denies
  everything — the right state for a gateway with no tenants onboarded.
- **The path index is positional.** `/listener_filters/2` assumes
  `[ppv2, tls_inspector, auth]`; a policy inserting at index 0 shifts it.

**Merging, not chaining.** Every scope lands in one `auth` filter, so precedence
holds across CRs: an exact name in a tenant's CR still beats a `*.` wildcard in
the base. Chaining separate `auth` filters cannot do this — whichever filter ran
first would claim the name and judge it against the wrong list, because
exact-beats-wildcard is a property of the whole scope set.

### SNI matching

Envoy's `ServerNameMatcher` (`source/extensions/common/matcher/domain_matcher.h`):

- **exact wins** over any wildcard, whatever the config order
- **wildcards are tried longest-suffix-first** — `a.mgmt.test` probes
  `*.mgmt.test` before `*.test`
- **`*.foo.com` does not match `foo.com`** — the wildcard needs a label in front
- **`*.foo.com` does match `a.b.foo.com`** — a label-boundary suffix match, not
  the single-label rule TLS certificates use
- **ASCII case-insensitive on both sides.** Envoy folds only the SNI, so a pattern
  written `L7.Mgmt.Test` never matches there; we fold the config too.

Only a whole leading `*.` is a wildcard. `foo.*` and `*bla.com` are kept as
literal strings rather than rejected, so they never match a real SNI — erring
toward deny rather than failing the config.

## Observability

The parsed header is published as dynamic metadata, so an access log can show
who called beside what was judged:

```yaml
    text: "src=%DOWNSTREAM_REMOTE_ADDRESS% tenant=%DYNAMIC_METADATA(ppv2_auth:vpce_id)% from=%DYNAMIC_METADATA(ppv2_auth:src)%"
```

`vpce_id` is the TLV the load balancer wrote and `src` is the source the header
gave. Neither is client-settable — the NLB writes the header and the client's own
bytes begin after it — which is what separates them from an `x-vpce-id` REQUEST
header, a claim that was once logged here and was a bypass. Both are set before
the deny branch, so a refused connection is attributable too.

`src` matters most where the identity cannot carry it: a site matched by NAT
prefix zeroes the low 32 bits, and `%DOWNSTREAM_DIRECT_REMOTE_ADDRESS%` is the
load balancer rather than the client, so without this field the caller's own
address appears nowhere.

**UDP has neither.** The dynamic-modules UDP ABI exposes no metadata or filter
state, so there the counters remain the only signal.


A refused TCP connection is closed with no bytes sent (the client sees a reset),
and Envoy emits a **listener-level access log** entry for it — EG configures those
by default. Because the filter labels before judging, a deny entry shows the
synthesized identity that was judged; the address class tells you what it was
(`<ula>:1:…` tenant, `<ula>:4:…` IPv4 client, outside the /48 a real IPv6 client).

`%DOWNSTREAM_TRANSPORT_FAILURE_REASON%` in that entry says why:

| reason | meaning |
|---|---|
| `denied_by_allowlist` | parsed and judged; no rule covers the identity |
| `not_proxy_protocol` | no PPv2 header — reached the listener directly |
| `no_identity_label` | `auth` ran without a `ppv2` filter ahead of it |
| `set_remote_address_failed` | internal: Envoy rejected the relabel |

Each filter also defines three counters, prefixed with its filter_name because
all filters share one `metrics_namespace` (default `dynamicmodulescustom`):
`<filter_name>_allowed`, `<filter_name>_denied`, `<filter_name>_not_ppv2` —
Prometheus renders e.g. `envoy_dynamicmodulescustom_auth_denied_total`. On UDP
the counters are the **only** signal —
a denied datagram produces no session, no log, and no failure reason, and is
otherwise indistinguishable from packet loss.

## Why the two filters differ

The UDP ABI has 21 callbacks but none can attach an identity to a session, and
`udp_proxy` has no RBAC filter — so nothing downstream can read one. Enforcement
happens in the filter or nowhere. That same gap is why UDP cannot split into
`[ppv2, auth]`: there is no filter state and no `set_remote_address`, so a UDP
`ppv2` filter would have nowhere to put what it derived.

The gap is one missing extension point upstream: a UDP *session* filter can write
filter state and `tunneling_config` reads `%FILTER_STATE(key)%`, but there is no
dynamic-modules session filter. If one lands, the UDP filter becomes a labeller
like the TCP one.

## AWS-specific on purpose

The parser accepts `0x21` with family IPv4 or IPv6 and rejects everything else:
LOCAL, `AF_UNSPEC`, `AF_UNIX`, version 1. Narrowing fixed a real spec violation —
on a LOCAL header the receiver must *discard* the address block, and a general
parser that ignores the command nibble adopts whatever it claims.

AWS's good behaviour is not the threat model, so bounds are checked on every
read, a TLV claiming a length past the end stops the walk, and a header declaring
more than 256 bytes is rejected rather than buffered.

## Security

**A missing `tls_inspector` denies everything.** On a TLS chain `auth` reads the SNI
from the socket, and without that filter it is always empty, so no scope matches.
Fail-closed, but check the chain order first if a listener refuses everything.

**The module must be the only PPv2 speaker on its listeners.** Anything that can
reach one directly can claim any address and have it adopted — the same class of
issue as trusting `X-Forwarded-For` behind an L4 load balancer. Restrict the
listener ports to the load balancer.

The vpce-id does not survive endpoint recreation. A replaced endpoint gets a new
id and is then denied with no symptom but a 403 that looks like a routing
problem. That cuts both ways: it is also a real safety property.

## Upgrading Envoy

The SDK is pinned to an exact Envoy tag in `Cargo.toml` and must match the binary
it loads into. **A mismatch does not fail the load** — Envoy only warns
(`source/extensions/dynamic_modules/dynamic_modules.cc`). A hook added or removed
fails loudly at symbol resolution, but a changed struct layout behind unchanged
names would load and misbehave quietly.

Bump the pin in the same commit as the Envoy image, then check:

```sh
kubectl -n envoy-gateway-system logs <envoy-pod> -c envoy | grep -i 'abi version'
```

Silent on a match, prints on a mismatch. Note this couples to the Envoy **image
tag**, not the Envoy Gateway version — a chart bump can move Envoy underneath the
module.

## Building

```sh
cargo test
cargo run --release --example bench
docker build -t ppv2-auth .
```

A host build on macOS needs the `dynamic_lookup` flag already in
`.cargo/config.toml`: the module references `envoy_dynamic_module_callback_*`
symbols that only exist inside Envoy, and macOS does not permit undefined symbols
in a `.so` while Linux does.

Cross-compiling needs `cargo-zigbuild` rather than plain `cargo --target`:
`bindgen` needs the target sysroot, and rustc passes `--fix-cortex-a53-843419`
for aarch64, which `zig cc` rejects.

## License

Apache-2.0
