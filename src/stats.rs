//! Counter ids, resolved once at listener build.
//!
//! Names are prefixed with the filter_name: all filters on a listener share one
//! `metrics_namespace` (default `dynamicmodulescustom`), so unprefixed names from
//! `ppv2` and `auth` on the same TLS listener would merge into one stat.
//! Prometheus renders these as `envoy_<namespace>_<filter_name>_<name>_total`.

use envoy_proxy_dynamic_modules_rust_sdk::EnvoyCounterId;

/// None means registration failed or was skipped -- never a reason to fail a listener.
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub allowed: Option<EnvoyCounterId>,
    pub denied: Option<EnvoyCounterId>,
    pub not_ppv2: Option<EnvoyCounterId>,
}

impl Counters {
    /// Generic over a define closure so TCP and UDP configs share one registrar.
    pub fn register(
        filter_name: &str,
        mut define: impl FnMut(&str) -> Option<EnvoyCounterId>,
    ) -> Counters {
        let mut named = |stat: &str| define(&format!("{filter_name}_{stat}"));
        Counters {
            allowed: named("allowed"),
            denied: named("denied"),
            not_ppv2: named("not_ppv2"),
        }
    }
}
