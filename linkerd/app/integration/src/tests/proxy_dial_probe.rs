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
