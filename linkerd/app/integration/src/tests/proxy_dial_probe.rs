//! Version-portable probe: does the inbound proxy dial the APPLICATION for
//! client connections that complete TCP but never send any bytes?
//!
//! Deliberately uses no tonic APIs, so the same file runs against proxy trees
//! that pin different tonic versions (main pins tonic 0.14, release/v2.323.0
//! pins tonic 0.13). The "application" is a bare TCP listener that counts
//! accepts, which is all these measurements need.

use crate::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Scaled-down stand-in for the production 3500-connection pool.
const SILENT: usize = 500;

/// A bare TCP listener standing in for the application; counts accepts and
/// holds every accepted socket open.
async fn accept_counter() -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((sock, _)) => {
                    c.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(async move {
                        let _hold = sock;
                        futures::future::pending::<()>().await;
                    });
                }
                Err(_) => break,
            }
        }
    });
    (addr, count)
}

async fn open_silent(target: SocketAddr, n: usize) -> Vec<tokio::net::TcpStream> {
    let mut held = Vec::with_capacity(n);
    for _ in 0..n {
        match tokio::net::TcpStream::connect(target).await {
            Ok(s) => held.push(s),
            Err(e) => {
                tracing::warn!(?e, "silent connect failed");
                break;
            }
        }
    }
    held
}

/// Opaque port: expected to relay eagerly, so silent connections should reach
/// the application.
#[tokio::test]
async fn probe_opaque_port() {
    let _trace = trace_init();

    let (app, accepts) = accept_counter().await;
    let proxy = proxy::new()
        .inbound_ip(app)
        .disable_inbound_ports_protocol_detection(vec![app.port()])
        .run()
        .await;

    let held = open_silent(proxy.inbound, SILENT).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    let n = accepts.load(Ordering::SeqCst);
    println!("PROBE-RESULT opaque: opened={} reached_app={}", held.len(), n);
}

/// HTTP-aware port, idled well past BOTH detection stages (the TLS stage from
/// the env var, then the policy's own 10s HTTP `Detect` timeout).
#[tokio::test]
async fn probe_http_aware_past_detect_timeout() {
    let _trace = trace_init();

    let (app, accepts) = accept_counter().await;

    let policy = controller::policy()
        .with_inbound_default(policy::all_unauthenticated())
        .run()
        .await;

    let mut env = TestEnv::default();
    // Shorten the TLS-detection stage; the policy's HTTP Detect stage is 10s.
    env.put(
        "LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT",
        "1s".to_owned(),
    );

    let proxy = proxy::new()
        .inbound_ip(app)
        .policy(policy)
        .run_with_test_env(env)
        .await;

    let held = open_silent(proxy.inbound, SILENT).await;

    // Outlive both detection stages (1s TLS + 10s HTTP).
    tokio::time::sleep(Duration::from_secs(16)).await;

    let n = accepts.load(Ordering::SeqCst);
    println!(
        "PROBE-RESULT http_aware: opened={} reached_app={}",
        held.len(),
        n
    );
}

// ---------------------------------------------------------------------------
// OUTBOUND leg. This is where the client's own pool actually lands first.
//
// Outbound differs from inbound in two ways worth noting:
//   * there is NO TLS-detection stage (nothing in outbound/src/ references
//     `tls::server`), so there is exactly ONE detection window, bounded by
//     `LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT` (default 10s);
//   * there is no `LINKERD2_PROXY_OUTBOUND_PORTS_DISABLE_PROTOCOL_DETECTION`
//     env var -- only the inbound one exists (`env.rs:192`). Outbound opacity
//     comes from policy (`outbound::Protocol::Opaque`).
// ---------------------------------------------------------------------------

const OUTBOUND_HOST: &str = "probe.test.svc.cluster.local";

/// HTTP-aware outbound proxy in front of `app`, with a short detect timeout.
async fn outbound_proxy(app: SocketAddr, detect: Duration) -> proxy::Listening {
    let dstctl = controller::new();
    let polctl = controller::policy();

    let name = format!("{OUTBOUND_HOST}:{}", app.port());
    let _policy_tx = polctl.outbound_tx_default(app, name.clone());
    let _profile_tx = dstctl.profile_tx_default(app, OUTBOUND_HOST);
    let dst_tx = dstctl.destination_tx(name);
    dst_tx.send_addr(app);

    let mut env = TestEnv::default();
    env.put(
        "LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT",
        format!("{}ms", detect.as_millis()),
    );

    let proxy = proxy::new()
        .controller(dstctl.run().await)
        .policy(polctl.run().await)
        .outbound_ip(app)
        .run_with_test_env(env)
        .await;

    // Senders must outlive the proxy or the discovery streams close.
    std::mem::forget((_policy_tx, _profile_tx, dst_tx));
    proxy
}

/// Silent connections into the OUTBOUND proxy, idled past its single detection
/// window. Does the outbound proxy dial through to the destination?
#[tokio::test]
async fn probe_outbound_past_detect_timeout() {
    let _trace = trace_init();

    let (app, accepts) = accept_counter().await;
    let proxy = outbound_proxy(app, Duration::from_secs(1)).await;

    let held = open_silent(proxy.outbound, SILENT).await;

    // Single 1s detection window; wait well past it.
    tokio::time::sleep(Duration::from_secs(8)).await;

    let n = accepts.load(Ordering::SeqCst);
    println!(
        "PROBE-RESULT outbound: opened={} reached_dst={}",
        held.len(),
        n
    );
}

// ---------------------------------------------------------------------------
// The full two-sidecar mesh: client -> outbound sidecar -> inbound sidecar -> app.
//
// This is the production topology. The outbound sidecar dials through for
// preface-less connections (see above) and, because the destination advertises
// a mesh identity, does so over mTLS with linkerd's transport header. The
// question is whether the inbound sidecar then hands those connections to the
// application -- which would reproduce the hang with NO opaque port configured
// anywhere.
// ---------------------------------------------------------------------------

const MESH_IDENTITY: &str = "default.default.serviceaccount.identity.linkerd.cluster.local";

#[tokio::test]
async fn probe_two_sidecar_mesh() {
    let _trace = trace_init();

    let (app, accepts) = accept_counter().await;

    // --- server-side sidecar: HTTP-aware inbound in front of the app
    let in_policy = controller::policy()
        .with_inbound_default(policy::all_unauthenticated())
        .run()
        .await;
    let mut in_env = TestEnv::default();
    in_env.put("LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT", "1s".to_owned());
    let p_in = proxy::new()
        .inbound_ip(app)
        .policy(in_policy)
        .run_with_test_env(in_env)
        .await;

    // --- client-side sidecar: outbound aimed at the server's inbound, with the
    //     destination advertising the mesh identity so mTLS is used.
    let dstctl = controller::new();
    let polctl = controller::policy();
    let name = format!("{OUTBOUND_HOST}:{}", p_in.inbound.port());
    let policy_tx = polctl.outbound_tx_default(p_in.inbound, name.clone());
    let profile_tx = dstctl.profile_tx_default(p_in.inbound, OUTBOUND_HOST);
    let dst_tx = dstctl.destination_tx(name);
    dst_tx.send(controller::destination_add(p_in.inbound).identity(MESH_IDENTITY));

    let mut out_env = TestEnv::default();
    out_env.put("LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT", "1s".to_owned());
    let p_out = proxy::new()
        .controller(dstctl.run().await)
        .policy(polctl.run().await)
        .outbound_ip(p_in.inbound)
        .run_with_test_env(out_env)
        .await;
    std::mem::forget((policy_tx, profile_tx, dst_tx));

    // Client connections that complete TCP and send nothing -- exactly what
    // tonic's balance_channel leaves behind for abandoned pool members.
    let held = open_silent(p_out.outbound, SILENT).await;

    // Outlive every detection window in the chain.
    tokio::time::sleep(Duration::from_secs(16)).await;

    let n = accepts.load(Ordering::SeqCst);
    println!(
        "PROBE-RESULT mesh: opened={} reached_app={}",
        held.len(),
        n
    );
}
