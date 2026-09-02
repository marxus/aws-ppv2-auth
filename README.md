# aws-ppv2-identity

An Envoy dynamic module that turns AWS PROXY protocol v2 identity into an
**IPv6 address**, so ordinary `clientCIDRs` rules can express PrivateLink tenant
identity at both L4 and L7.

    envoy.filters.listener.dynamic_modules       TCP  -> set_remote_address
    envoy.filters.udp_listener.dynamic_modules   UDP  -> enforce in-filter

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

The rewrite happens before any RBAC filter, so the same rules work at both
layers:

```yaml
principal:
  clientCIDRs:
    - fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128   # one tenant
    - fd00:dead:beef:4::12c7:0/112               # 18.199.0.0/16
```

No header injection, no CEL. `clientCIDRs` is the *only* principal a `TCPRoute`
supports — CEL is rejected outright — so L4 had no tenant identity before this.
An L4 denial drops the connection; L7 returns 403.

## Install

See [`deploy/`](deploy). The image is mounted, not copied — `volumes[].image` is
a native OCI volume source (Kubernetes ≥1.33), so no initContainer and no
ConfigMap:

```yaml
pod:
  volumes:
    - name: aws-ppv2-identity
      image: { reference: ghcr.io/marxus/aws-ppv2-identity:v0.1.2 }
container:
  volumeMounts: [{ name: aws-ppv2-identity, mountPath: /modules, readOnly: true }]
  env: [{ name: LD_LIBRARY_PATH, value: /modules }]
```

`FROM scratch` with exactly one file, so nothing in it ever executes. It is a
manifest list, so the kubelet resolves the architecture.

## Configuration

A `google.protobuf.StringValue` in `filter_config`, line-oriented so a
`kubectl diff` of 10,000 entries stays readable:

```text
ula   fd00:dead:beef::/48
allow fd00:dead:beef:1:7b53:e75b:6e3d:cfdb/128
allow 2001:db8:10da:7800::/56
```

Generate your own `ula` once per RFC 4193: `fd` plus 40 random bits, nothing set
below the /48. Unknown keys are an error, and `require_ppv2` takes only `true` or
`false` — a typo fails the config rather than silently disabling enforcement.

`allow` is **UDP-only** and **allowlist-only, like a security group**: permitted
iff some line covers it, so an empty list denies everything. There is no
`enforce` flag because deriving one from "is the list non-empty" would make the
single safe state mean allow-any.

Two combinations are rejected outright rather than documented as footguns:

- `allow` on a **TCP** config — the TCP filter has no enforcement point, so the
  rule would read as applied and do nothing. Use a `SecurityPolicy`.
- `require_ppv2 false` with a non-empty `allow` — unparsed headers yield no
  address to match, so they would walk straight past the allowlist.

## Why the two filters differ

The UDP ABI has 21 callbacks but none can attach an identity to a session, and
`udp_proxy` has no RBAC filter — so nothing downstream can read one. Enforcement
happens in the filter or nowhere.

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
