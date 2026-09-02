# aws-ppv2-identity

An Envoy dynamic module that turns AWS PROXY protocol v2 identity into an
**IPv6 address**, so ordinary `clientCIDRs` rules can express PrivateLink tenant
identity at both L4 and L7.

Two filters ship in one `.so`, chosen by `filter_name`:

    ppv2   parse the PROXY header, synthesize, label the socket, drain
    auth   establish identity, scope it by SNI, allow or close

    tcp  -> [auth, ...]
    udp  -> [auth, ...]
    tls  -> [ppv2, tls_inspector, auth, ...]

TLS is the special case. `auth` needs the SNI, which exists only after
`tls_inspector` runs, and `tls_inspector` cannot find a ClientHello until the PROXY
header is drained — so `ppv2` splits off to the front. Everywhere else `auth` does
the whole job itself.

## The idea

Every policy engine here matches addresses — Envoy RBAC, `CiliumNetworkPolicy` —
and none can match a `vpce-id`. So synthesize one:

```text
fd00:dead:beef : 0001 : 7b53:e75b:6e3d:cfdb
└── /48 ULA ──┘  └kind┘  └── 64-bit body ──┘
                    1 = sha256(vpce-id) truncated
                    4 = 4via6, client IPv4 in the low 32 bits
```

Derived, not mapped, so the data plane holds no tenant knowledge — adding a
tenant is one policy rule. Reproduce any value with
`printf %s vpce-0123456789abcdef0 | sha256sum | cut -c1-16`.

| header says | result |
|---|---|
| a `vpce-id` is present | kind 1, `sha256(id)` |
| no `vpce-id`, IPv4 client | kind 4, 4via6 |
| no `vpce-id`, IPv6 client | **passed through unchanged** |

A v6 client already *is* an address, so encoding could only lose information.
The invariant: everything inside the ULA `/48` was synthesized here, everything
outside it is a real client address.

Two coarse rules fall out of the kind nibble — `…:1::/64` is any tenant,
`…:4::/64` is any IPv4 client — and an IPv4 `/N` maps onto `/(96+N)`.

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
    - fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128   # one tenant
    - fd00:dead:beef:4::12c7:0/112               # 18.199.0.0/16
```

## Install

See [`deploy/`](deploy). The image is mounted, not copied — `volumes[].image` is
a native OCI volume source (Kubernetes ≥1.33), so no initContainer and no
ConfigMap:

```yaml
pod:
  volumes:
    - name: aws-ppv2-identity
      image: { reference: ghcr.io/marxus/aws-ppv2-identity:0.4.0 }
container:
  volumeMounts: [{ name: aws-ppv2-identity, mountPath: /modules, readOnly: true }]
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
          - fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128
```

A scope may name **several hostnames** sharing one list — the shape Envoy's
`ServerNameMatcher` uses, where one `domains` list maps to one action.

Each filter takes one config shape, and anything else fails the listener:

| filter | config | meaning |
|---|---|---|
| `ppv2` | `ula` only | synthesize and label; it never denies, so it takes no rules |
| `auth` | `ula` + `allow` | parse the header here — plain TCP, and UDP |
| `auth` | `scopes` | read the label a `ppv2` filter left — the TLS chain |

**`ula` and `scopes` are mutually exclusive, and the reason is positional rather
than about transport**: `ula` means this filter runs *before* `tls_inspector`, so
no SNI exists yet; `scopes` means it runs *after*, so the socket is already
labelled. Both at once is the contradiction "first and not first". That is why
`auth` never needs to know whether it is on TCP or UDP.

An `auth` filter with no `allow` at all is valid and denies everything — an empty
allowlist is deny-all, the same as an empty security group. `require_ppv2: false`
with a non-empty allowlist is rejected, because unparsed headers yield no address
to match and would walk straight past it. Unknown fields fail the config, so a
typo cannot silently disable enforcement.

### Contributing scopes from separate CRs

`scopes` is an array, so another `EnvoyPatchPolicy` can append to it:

```yaml
operation:
  op: add
  path: /listener_filters/2/typed_config/filter_config/value/scopes/-
  value:
    sni: [tenant-a.mgmt.test]
    allow: [fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128]
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
docker build -t aws-ppv2-identity .
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
