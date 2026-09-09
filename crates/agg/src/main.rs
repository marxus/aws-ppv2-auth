//! identity-agg: watch IdentityGroup CRs cluster-wide, hold the raw membership graph in memory, expose it for inspection. Zero k8s writes; zero side effects. This is Step 1 of the "no reconciler" design -- the code here is what will move into the envoy filter as its config resolver in Step 2.

use anyhow::Result;
use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use futures::TryStreamExt;
use kube::{
    api::Api,
    runtime::{watcher, WatchStreamExt},
    Client, CustomResource, ResourceExt,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};
use tokio::{net::TcpListener, signal};
use tracing::{info, warn};

mod graph;
use graph::{Graph, Key, Member};

// Matches the CRD kro currently manages (group/version/kind/spec-shape). We use `serde_json::Value` for status because the CRD carries `status.cidrs` from the RGD era -- kube-rs deserialization would reject an unknown shape without this. We never read it.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "gateway.envoyproxy.io",
    version = "v1alpha1",
    kind = "IdentityGroup",
    plural = "identitygroups",
    namespaced,
    status = "serde_json::Value"
)]
pub struct IdentityGroupSpec {
    #[serde(default)]
    pub members: Vec<String>,
}

type SharedGraph = Arc<RwLock<Graph>>;

#[tokio::main]
async fn main() -> Result<()> {
    // rustls 0.23 needs a crypto provider chosen before any TLS handshake; kube-rs's rustls-tls feature doesn't pick one.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls ring provider");

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "identity_agg=info,warn".into()),
        )
        .init();

    let graph: SharedGraph = Arc::new(RwLock::new(Graph::default()));

    let client = Client::try_default().await?;
    let api: Api<IdentityGroup> = Api::all(client);

    let http_addr: SocketAddr = std::env::var("ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".into())
        .parse()?;
    let http = tokio::spawn(serve_http(graph.clone(), http_addr));

    let watch = tokio::spawn(run_watcher(api, graph.clone()));

    // Ctrl-C exits cleanly (useful for cargo-run local dev). Either task returning also exits.
    tokio::select! {
        _ = signal::ctrl_c() => info!("ctrl-c, shutting down"),
        r = http  => warn!(?r, "http server exited"),
        r = watch => warn!(?r, "watcher exited"),
    }
    Ok(())
}

async fn run_watcher(api: Api<IdentityGroup>, graph: SharedGraph) -> Result<()> {
    let stream = watcher(api, watcher::Config::default().any_semantic()).default_backoff();
    tokio::pin!(stream);

    while let Some(ev) = stream.try_next().await? {
        match ev {
            watcher::Event::Apply(o) | watcher::Event::InitApply(o) => apply(&graph, &o),
            watcher::Event::Delete(o) => delete(&graph, &o),
            watcher::Event::Init => {
                info!("watcher: initial sync starting");
                // Wipe on relist: watcher::Config::any_semantic guarantees an Init boundary before InitApply's replay, so the graph rebuilds cleanly.
                graph.write().unwrap().reset();
            }
            watcher::Event::InitDone => {
                let n = graph.read().unwrap().len();
                info!("watcher: initial sync done, {n} groups");
            }
        }
    }
    Ok(())
}

fn key(o: &IdentityGroup) -> Key {
    (o.namespace().unwrap_or_default(), o.name_any())
}

fn apply(graph: &SharedGraph, o: &IdentityGroup) {
    let k = key(o);
    let members = o.spec.members.clone();
    let mut g = graph.write().unwrap();
    match g.upsert(k.clone(), members) {
        Ok(()) => tracing::debug!(ns=%k.0, name=%k.1, "upsert"),
        Err(e) => warn!(ns=%k.0, name=%k.1, ?e, "reject"),
    }
}

fn delete(graph: &SharedGraph, o: &IdentityGroup) {
    let k = key(o);
    graph.write().unwrap().remove(&k);
    tracing::debug!(ns=%k.0, name=%k.1, "delete");
}

// --- HTTP debug surface -----------------------------------------------------

async fn serve_http(graph: SharedGraph, addr: SocketAddr) -> Result<()> {
    let app = Router::new()
        .route("/", get(|| async { "identity-agg\n\nGET /graph\nGET /resolve?ns=<ns>&refs=@a,@b,literal\n" }))
        .route("/graph", get(handle_graph))
        .route("/resolve", get(handle_resolve))
        .with_state(graph);
    info!(%addr, "http listening");
    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_graph(State(g): State<SharedGraph>) -> Json<BTreeMap<String, Vec<Member>>> {
    Json(g.read().unwrap().dump())
}

#[derive(Deserialize)]
struct ResolveQ {
    ns: String,
    refs: String,
}

#[derive(Serialize)]
struct ResolveResp {
    ns: String,
    entry: Vec<String>,
    resolved: Vec<String>,
}

async fn handle_resolve(State(g): State<SharedGraph>, Query(q): Query<ResolveQ>) -> Json<ResolveResp> {
    let entry: Vec<Member> = q.refs.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    let mut resolved: Vec<String> = g.read().unwrap().resolve(&q.ns, &entry).into_iter().collect();
    resolved.sort();
    Json(ResolveResp { ns: q.ns, entry, resolved })
}

