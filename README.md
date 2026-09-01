# aws-ppv2-identity

An Envoy dynamic module that turns AWS PROXY protocol v2 identity into an
**IPv6 address**, so ordinary `clientCIDRs` rules can express PrivateLink tenant
identity at both L4 and L7.

One shared object, two filters, one identity scheme:

    envoy.filters.listener.dynamic_modules       TCP  -> set_remote_address
    envoy.filters.udp_listener.dynamic_modules   UDP  -> enforce in-filter

## The idea

Stop trying to carry tenant identity as a string. Every policy engine already
matches on addresses — Envoy network RBAC on a `TCPRoute`, HTTP RBAC on an
`HTTPRoute`, `CiliumNetworkPolicy` — and none of them can match a `vpce-id`. So
synthesize one:

```text
fd2a:5c1b:7e90 : 0001 : e3b1:45a8:c041:e80a
└── /48 ULA ──┘  └kind┘  └── 64-bit body ──┘
    yours, once     1 = sha256(vpce-id) truncated
                    4 = 4via6, client IPv4 in the low 32 bits
```

**Derived, not mapped**, so the data plane holds no tenant knowledge: adding a
tenant is one policy rule and no module config. Reproduce any value with

```sh
printf %s vpce-028ff61de1d1fea8c | sha256sum | cut -c1-16   # e3b145a8c041e80a
```

Three ordered cases, and only the first two synthesize anything:

| header says | result |
|---|---|
| a `vpce-id` is present | kind 1, `sha256(id)` — an identity that is not an address |
| no `vpce-id`, IPv4 client | kind 4, 4via6 — lifted so one rule list covers both |
| no `vpce-id`, IPv6 client | **passed through unchanged** |

A v6 client already *is* an address, so encoding could only lose information.
The useful invariant: everything inside the ULA `/48` was synthesized here, and
everything outside it is a real client address.

Two coarse rules fall out of the kind nibble for free — `…:1::/64` is "any
PrivateLink tenant", `…:4::/64` is "any IPv4 internet client" — and an IPv4 `/N`
maps mechanically onto `/(96+N)`, so `18.199.0.0/16` becomes `…:4::12c7:0/112`.

**The address is a label, not a route.** Nothing is ever sent from it, so there
is no spoofing concern, no return path, and nothing for a CNI's source-IP
verification to reject. It only has to survive as a declared value.

## What it buys

Identical rules at both layers, because the rewrite happens before any RBAC
filter runs:

```yaml
# L4 — SecurityPolicy on a TCPRoute      # L7 — on an HTTPRoute
principal:                               principal:
  clientCIDRs:                             clientCIDRs:
    - fd2a:5c1b:7e90:1:e3b1:…/128            - fd2a:5c1b:7e90:1:e3b1:…/128
    - fd2a:5c1b:7e90:4::12c7:0/112           - fd2a:5c1b:7e90:4::12c7:0/112
```

No header injection, no CEL, no `EnvoyPatchPolicy` for identity itself. That
matters because `clientCIDRs` is the *only* principal a `TCPRoute` supports — CEL
is rejected outright — so L4 previously had no tenant identity at all.

Failure modes still differ: an L4 denial drops the connection, L7 returns `403`.

## Install

See [`deploy/`](deploy). The image is **mounted**, not copied — `volumes[].image`
is a native OCI volume source (Kubernetes ≥1.33), so there is no initContainer
and no ConfigMap:

```yaml
pod:
  volumes:
    - name: aws-ppv2-identity
      image: { reference: ghcr.io/marxus/aws-ppv2-identity:v0.1.2 }
container:
  volumeMounts: [{ name: aws-ppv2-identity, mountPath: /modules, readOnly: true }]
  env: [{ name: LD_LIBRARY_PATH, value: /modules }]
```

The image is `FROM scratch` and holds exactly one file, so nothing in it ever
executes. It is a manifest list, so the kubelet resolves the architecture — no
arch in your YAML.

Releases also carry the bare `.so` per architecture for anyone who prefers
`dynamicModules`' `source.remote` (`url` + `sha256`).

## Configuration

A `google.protobuf.StringValue` in `filter_config`, which the proto passes
through unwrapped. Line-oriented, because at 10,000 entries a `kubectl diff` of
one-per-line is readable and a comma soup is not:

```text
ula   fd2a:5c1b:7e90::/48
allow fd2a:5c1b:7e90:1:e3b1:45a8:c041:e80a/128
allow 2a05:d014:10da:7800::/56
# require_ppv2 false   -- let unlabelled traffic through instead of dropping
```

Generate your own `ula` once, per RFC 4193: `fd` plus 40 random bits. Unknown
keys are an error rather than ignored, so a typo fails the config instead of
silently disabling enforcement.

**`allow` is consulted only by the UDP filter**, and it is **allowlist-only, like
a security group**: an address is permitted iff some `allow` line covers it, so an
empty list denies everything. That is why there is no `enforce` flag — one derived
from "is the list non-empty" would make the single safe state mean allow-any.

On the TCP path, leave `allow` unset: `set_remote_address` makes the synthesized
address the connection's own and a `SecurityPolicy` does the matching.

One interaction to keep in mind: `require_ppv2 false` returns `Continue` *before*
the allowlist is consulted, because an unparsed header yields no address to match.
On UDP that makes it an allowlist bypass for headerless traffic.

## Why the two filters differ

| | TCP listener filter | UDP listener filter |
|---|---|---|
| `set_remote_address` | **yes** | no |
| what it does with the parsed header | rewrites the connection source | matches an in-filter allowlist |
| where policy lives | `SecurityPolicy` CRD | `filter_config` string |

The UDP ABI has 21 callbacks — `get_peer_address`, `send_datagram`, a full stats
surface — but none of them can attach an identity to a session, so nothing
downstream can read one. `udp_proxy` has no RBAC filter either. Enforcement
happens in the filter or nowhere.

The gap is one missing extension point upstream: a UDP **session** filter *can*
write filter state and `tunneling_config` reads `%FILTER_STATE(key)%`, but there
is no dynamic-modules session filter. If `envoy.filters.udp.session.dynamic_modules`
ever lands, the UDP filter becomes a labeller like the TCP one and policy moves to
a CRD. That is an `envoyproxy/envoy` change.

## AWS-specific on purpose

The parser accepts `0x21` (version 2 + PROXY) with family IPv4 or IPv6 and
rejects everything else outright: LOCAL, `AF_UNSPEC`, `AF_UNIX`, version 1. The
`0xEA` TLV is an AWS extension rather than part of the base spec, so pretending
to be a general parser while depending on it was the worst of both.

Narrowing also fixed a real spec violation: on a LOCAL header the spec requires
the receiver *discard* the address block and keep the real endpoints, and a
general parser that ignores the command nibble will instead adopt whatever
address the block claims. Rejecting the command means the block is never reached.

What is deliberately kept, because AWS's good behaviour is not the threat model —
anything that can reach the listener directly sends what it likes: bounds are
checked on every read, and a TLV claiming a length past the end of the buffer
stops the walk instead of indexing out of range.

There is no "streaming" mode in PPv2, and the spec forbids the idea: *"The
receiver must not start to parse an address before the whole address block is
received."* So the TCP filter reads incrementally and parses only once complete,
never the other way round.

## Security

**The module must be the only PPv2 speaker on its listeners.** Anything that can
reach a listener directly can send a header claiming any address, and that address
will be adopted — the same class of issue as trusting `X-Forwarded-For` behind an
L4 load balancer. Restrict the listener ports to the load balancer, e.g. with a
`NetworkPolicy`, and do not enable `allow_requests_without_proxy_protocol` on a
listener reachable from elsewhere.

The vpce-id does not survive endpoint recreation. A replaced endpoint gets a new
id and is then denied with no symptom other than a 403 that looks like a routing
problem. That cuts both ways: it is also a real safety property.

## Upgrading Envoy

The SDK is pinned to an exact Envoy tag in `Cargo.toml`, and it must match the
Envoy binary it is loaded into. **A mismatch does not fail the load** — Envoy only
warns (`source/extensions/dynamic_modules/dynamic_modules.cc`):

```cpp
// We log a warning if the ABI version does not match exactly.
...
return dynamic_module;   // loads either way
```

A hook added or removed upstream fails loudly at symbol resolution, but a changed
struct layout behind unchanged symbol names would load and misbehave quietly. So:
bump the pin in the same commit as the Envoy image, and check

```sh
kubectl -n envoy-gateway-system logs <envoy-pod> -c envoy | grep -i 'abi version'
```

which is silent on a match (the success line is `info`) and prints on a mismatch.

Note this couples to the **Envoy image tag**, not to the Envoy Gateway version —
an Envoy Gateway chart bump can move Envoy underneath the module.

## Building

```sh
cargo test                 # 24 pure-logic tests, natively
cargo run --release --example bench
docker build -t aws-ppv2-identity .
```

A host build on macOS needs the `dynamic_lookup` flag already in
`.cargo/config.toml`: the module references `envoy_dynamic_module_callback_*`
symbols that only exist inside Envoy, and Linux `.so` files permit undefined
symbols while macOS does not.

Cross-compiling needs `cargo-zigbuild`, not plain `cargo --target`. Two things
break otherwise: `bindgen` needs the target sysroot, and rustc passes
`--fix-cortex-a53-843419` for aarch64, which `zig cc` rejects. Upstream's own
examples use `zig cc` for the same reason.

## License

Apache-2.0
