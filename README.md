# ppv2-auth

An Envoy dynamic module that turns AWS PROXY protocol v2 identity into an
**IPv6 address**, so ordinary `clientCIDRs` rules can express PrivateLink tenant
identity at both L4 and L7.

Three filters ship in one `.so`, chosen by `filter_name`. Each name is a position
in a chain and takes exactly one config shape:

    ppv2_auth   parse the header, synthesize, enforce      ula + sites + groups + allow
    ppv2        parse the header, synthesize, label only   ula + sites
    auth        read that label, scope by SNI, enforce     scopes (+ ula/sites/groups, to encode)

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

**One ULA holds all three cases**, told apart by the kind in group 4:

```text
fd0b:1003:5ec0 : 0b1a : 0000 : 0007 : 0a00:011c   KIND_SITE, an onboarded tenant
fd0b:1003:5ec0 : 0001 : 7b53:e75b   : 0a00:011c   KIND_VPCE, a tenant no site claims
fd0b:1003:5ec0 : 0004 : 0000:0000   : 0a00:011c   KIND_ADDR, no vpce-id at all
└── /48 ULA ──┘  └kind┘  └ body ───┘  client IPv4
```

`0xb1a` spells "via" the way Tailscale's own 4via6 range does, and the site sits
in group 6 where Tailscale keeps it — so a site address has the same *shape* as a
4via6 address without being one. That is deliberate: 4via6 translation is keyed
to Tailscale's prefix inside the client, verified by `tailscale debug via`
answering identically with `--socket=/nonexistent`, i.e. from a compile-time
constant and not from anything the coordination server said. **An address here is
an identity and never a route.** Routes stay Tailscale's; identity is ours.

Reproduce a kind-1 hash with
`printf %s vpce-0123456789abcdef0 | sha256sum | cut -c1-8`.

| header says | result |
|---|---|
| resolves to a site, by `vpce-id` | `b1a` + site + the tenant's own IPv4 |
| resolves to a site, by source prefix | `b1a` + site, low 32 bits **zero** |
| resolves to a **contested** source | `b1a` + site **0** — see quarantine below |
| a `vpce-id` no site claims | kind 1, `sha256(id)` + client IPv4 |
| no `vpce-id`, IPv4 client | kind 4, the address alone |
| no `vpce-id`, IPv6 client | **passed through unchanged** |

A v6 client already *is* an address, so encoding could only lose information. The
invariant: everything inside the `/48` was synthesized here, everything outside
it is a real client address.

**Why a source prefix carries no machine.** Through PrivateLink the header holds
the tenant's own address — measured, the NLB reports the consumer-side 5-tuple —
so it is theirs and worth carrying. Over the internet their NAT already rewrote
it, so the address is not in their space at all; zero reads honestly as "this
tenant, machine unknown" and still sits inside the tenant's own `/96`. The real
source is in the access log either way.

**Trust is split within one address.** The site or hash half comes from an
AWS-assigned id the sender cannot choose. The low 32 bits are whatever their
machine put in its own packets. So a `/96` rule naming a tenant is a boundary; a
`/128` naming one of their machines is a convenience, and not something to lean
on against that tenant.

Coarse rules fall out of the kind group — `…:b1a::/64` is any onboarded tenant,
`…:1::/64` any un-onboarded one, `…:4::/64` any plain IPv4 client — and an IPv4
`/N` maps onto `/(96+N)`.

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
      image: { reference: ghcr.io/marxus/aws-ppv2-auth:0.13.0 }
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

Each filter takes one shape, and anything else fails the listener:

| filter | config | meaning |
|---|---|---|
| `ppv2_auth` | `ula` `sites` `groups` `allow` | the whole job in one — plain TCP, and UDP |
| `ppv2` | `ula` `sites` | synthesize and label; it never denies, so it takes no rules |
| `auth` | `scopes` + `ula` `sites` `groups` | read the label a `ppv2` filter left — the TLS chain |

`ula` and `sites` describe how a header is encoded, so the header-parsing filters
need them per connection. `auth` never parses a header, but its rule entries must
**encode the way the wire does**, so it carries the same table for that alone.

### The source grammar

Every entry in `allow`, `scopes[].allow`, and every group member is one grammar,
and encoding is **total over strings** — the packet side hashes header bytes
verbatim, so the config side never second-guesses:

| entry | encodes to |
|---|---|
| `@group` | expand through `groups` — nested `@refs` walk, revisits skip (cycles just terminate) |
| `!N` | declared site N's whole space, `<ula>:b1a:0:<N>::/96` |
| `!0` | the quarantine space, `<ula>:b1a::/96` — always resolvable, system-owned |
| `!*` | every **declared** site's space — the union, current by construction |
| site-owned source | that site's `/96` — a label a site lists, or a range wholly inside its prefixes |
| `ipv6` / `ipv6_cidr` | itself (`/128` for a bare address) |
| `ipv4` / `ipv4_cidr` | kind-4 lift, `/(96+N)` |
| anything else | kind-1 label hash of the verbatim string, `/96` |

"Anything else" includes bad widths (`10.0.0.1/99`), bad octets (`10.999.2.0`),
unknown `@ghost`, undeclared `!5` — one fallback rule, deny-safe, and a group or
site that appears later re-renders the config and the ref resolves for real. The
only refusal is a source that needs encoding with no `ula` to encode into.

```yaml
    ula: fd0b:1003:5ec0::/48
    sites:
      "1": [vpce-028ff61de1d1fea8c, 3.126.239.93]
      "2": [203.0.113.0/24]
    groups:
      tenant-a: [vpce-028ff61de1d1fea8c]    # site 1 owns it -> encodes as !1
      home:     [81.199.237.15, 2a02:ba0:10a8:3427::/64]
      trusted:  ["@tenant-a", "@home", "!2"]
    allow: ["@trusted"]
```

`sites` and `groups` are maps — CEL's `transformMapEntry` folds a CR collection
into exactly this shape, so a Kubernetes controller can generate both (see the
registry section). Site keys must parse to 1..=65535; id 0 is the system's.
Groups may sit unreferenced — that is the appendable base state, same as
`scopes: []` — and their literals are validated eagerly so a bad member cannot
hide until some later tenant references the group.

A site *source* is a `vpce-id` or a source prefix, told apart by trying to read
it as an address; `@strings` are not followed there — sources are classifier
inputs, and an `@` pattern is bytes no header will ever carry. IPv4 lifts to
`::ffff:a.b.c.d/(96+N)` so one matcher covers both families. A `vpce-id` outranks
a prefix: AWS assigned it and the sender cannot choose it.

### Contested sources: site 0 is quarantine

Site matching is two flat indices built once at load — a `vpce -> id` map and a
disjoint segment map over every site's ranges (overlaps split at boundaries), one
hash lookup + one binary search per connection whatever the site count. Building
the segments is where contests surface, and **a contest resolves to site 0**
rather than to a winner: a label two sites list, or the overlap of two sites'
ranges, is nobody's privilege and everybody's visibility. Load prints one warning
per contest naming the claimants.

The quarantine space is `<ula>:b1a::/96`. Nothing admits it unless a rule says
`!0` — the conventional group for that is `unknown-site: ["!0"]` — so contested
traffic keeps flowing wherever examination is welcome and nowhere privileged.
`encode_member` answers range ownership from the same segments, so a member
spanning two owners honestly encodes as **neither** (it falls to the plain lift):
no single encoding could match what the wire stamps.

Contests are detectable misconfiguration; the *undetectable* version — a site
claiming a range that simply belongs to someone who never declared it — can only
be prevented where sources are allocated. Guard the registry at provisioning
(duplicate-label and overlap checks belong there), and treat NAT-CIDR identity as
weaker than PrivateLink identity when writing privileged rules.

An empty or absent `sites` sends every header to kind 1 or 4. An empty `allow`
denies everything — the same as an empty security group. There is no
`require_ppv2` knob: this module is the first thing after the NLB, so traffic
without a header reached the listener directly and is refused, always. Unknown
fields fail the config, so a typo cannot silently disable enforcement.

Because the name fixes the shape, a filter in the wrong place fails its listener
rather than half-working — `ppv2_auth` with `scopes` is rejected (it runs before
`tls_inspector`, so there is no SNI).

### The registry on Kubernetes

The intended authoring surface is three CRDs and zero controllers of ours:

| kind | what | controller |
|---|---|---|
| `IdentitySite` | `spec.id` + `spec.sources` — the wire identity | none: a plain CRD, pure data |
| `IdentityGroup` | `spec.members` — composition, `@refs`/`!refs`/sources | none: a plain CRD, pure data |
| `PPv2Auth` / `PPv2AuthRule` | base filter chain per port / tenant allow+scopes | [kro](https://kro.run) graphs |

The kro base graph `externalRef`s every `IdentitySite` and `IdentityGroup` in the
namespace and folds them into `sites`/`groups` with
`transformMapEntry(i, s, {string(s.spec.id): ...})` — raw, unresolved, no CEL
identity math. All resolution is this module, one Rust codepath for config load
and packet time, so the two can never drift. A group or site change re-renders
the patch policy, Envoy Gateway pushes new xDS, the module re-parses: seconds,
end to end, with no per-CR reconcile fan-out.

One rule keeps it sane: **one owner mints `IdentitySite` CRs** (the tenant
provisioning layer), because two stacks writing sites is how duplicate ids
happen — kro's fold fails loudly on a duplicate key and freezes the policy at
last-good, but the fix is ownership, not error handling.

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

**Contested sources are quarantined, not adjudicated.** The data plane can only
be deterministic about ownership, never right — see the site-0 section. Verify
source claims where they are provisioned.

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
