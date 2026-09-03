# An image whose only purpose is to BE a volume.
#
# Kubernetes mounts an OCI image read-only via volumes[].image (beta since 1.33),
# so nothing here ever executes: no entrypoint, no shell, no libc. FROM scratch
# with one file is the whole image, which keeps it a few hundred KB and gives it
# no attack surface of its own.
#
# Build multi-arch and the kubelet resolves the right architecture from the
# manifest list by itself -- the main advantage over publishing a .so to a
# release and pointing dynamicModules' source.remote at a URL, which pins one
# architecture into the YAML.
# 0.19.8 shipped a Rust older than 1.85, where the SDK's set_factory_once macro
# fails on the then-unstable ptr::fn_addr_eq. Keep this pin current.
FROM --platform=$BUILDPLATFORM ghcr.io/rust-cross/cargo-zigbuild:0.23.3 AS build
# No clang install. bindgen needs libclang to parse Envoy's abi.h, and the image
# already ships libclang-19 -- the `clang` binary was never the dependency.
WORKDIR /build

# Fetch dependencies first so the layer caches independently of source edits.
# This clones envoyproxy/envoy (~800MB) so it is worth not repeating.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo "" > src/lib.rs && cargo fetch --locked && rm -rf src

# .cargo/config.toml is NOT copied: it only sets rustflags for the two
# apple-darwin targets, so it configures nothing in a Linux build.
COPY src ./src
ARG TARGETARCH
RUN case "$TARGETARCH" in \
      arm64) TRIPLE=aarch64-unknown-linux-gnu ;; \
      amd64) TRIPLE=x86_64-unknown-linux-gnu  ;; \
      *) echo "unsupported TARGETARCH=$TARGETARCH" >&2; exit 1 ;; \
    esac && \
    cargo zigbuild --release --locked --target "$TRIPLE" && \
    # Envoy loads lib<name>.so and Envoy Gateway's module name may not contain
    # an underscore, which is what Rust emits. Rename once, here.
    cp "target/$TRIPLE/release/libppv2_auth.so" /libppv2-auth.so

FROM scratch
COPY --from=build /libppv2-auth.so /libppv2-auth.so
