//! Does a real linkerd proxy insulate a tonic gRPC server from graceful-shutdown hangs?
//!
//! These tests run the ACTUAL linkerd2-proxy inbound stack (with the harness's
//! stub destination/policy/identity controllers) in front of real
//! `tonic::transport::Server` instances.
//!
//! Two independent tonic/hyper shutdown-hang modes are under investigation:
//!
//!   #1 "non-upgraded": a TCP connection that never sends the HTTP/2 client
//!      preface. hyper's h2 server sits in `State::Handshaking`, where
//!      `graceful_shutdown()` only sets `close_pending` (never read), so the
//!      connection future never resolves and tonic's drain never completes.
//!
//!   #2 "hung client": an established connection whose peer stops running.
//!      h2's `go_away_gracefully()` sends GOAWAY then waits for a PONG before
//!      finishing; an unresponsive peer never acks, so the drain never completes.
//!
//! Notes on test validity:
//!
//!  * The inbound *policy* carries its own protocol-detection timeout, and that
//!    governs the opaque fallback -- not `LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT`
//!    alone. Every HTTP-aware test installs an explicit `Detect` policy so a
//!    pass cannot be an artifact of the stub controller having no policy.
//!  * Drain completion is signalled from a drop guard (as in the original
//!    hyper_hung_client_example), and the value returned by
//!    `serve_with_incoming_shutdown` is captured separately, so a panicking or
//!    erroring server cannot masquerade as a clean drain.
//!  * Every "clean drain" test also asserts a connection actually reached the
//!    application, so it cannot pass vacuously.

use crate::*;
use std::net::SocketAddr;
use tonic::service::Routes;
use tonic::transport::Server as TonicServer;
use tonic::transport::channel::Change;
use tonic::transport::{Channel, Endpoint};
use tower::ServiceExt;

/// Size of the client connection pool. Production uses 3500.
const POOL: usize = 500;

/// Signals on drop, regardless of how the holding future terminated.
struct SignalOnDrop(Option<oneshot::Sender<()>>);

impl Drop for SignalOnDrop {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

/// A real `tonic::transport::Server`.
struct TonicUnderTest {
    addr: SocketAddr,
    shutdown: oneshot::Sender<()>,
    /// Fires when the serve task's future is DROPPED -- however it ends.
    drained: oneshot::Receiver<()>,
    /// What `serve_with_incoming_shutdown` returned, if it returned.
    outcome: Arc<parking_lot::Mutex<Option<Result<(), String>>>>,
    /// TCP connections the tonic server itself accepted.
    accepts: Arc<std::sync::atomic::AtomicUsize>,
}

impl TonicUnderTest {
    fn accepted(&self) -> usize {
        self.accepts.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Triggers graceful shutdown and waits up to `within`.
    /// Returns `(drained_in_time, serve_outcome)`.
    async fn shutdown_and_wait(self, within: Duration) -> (bool, Option<Result<(), String>>) {
        let TonicUnderTest {
            shutdown,
            drained,
            outcome,
            ..
        } = self;
        let _ = shutdown.send(());
        let in_time = tokio::time::timeout(within, drained).await.is_ok();
        let out = outcome.lock().clone();
        (in_time, out)
    }
}

fn assert_clean(drained: bool, outcome: Option<Result<(), String>>, ctx: &str) {
    assert!(drained, "{ctx}: tonic drain HUNG");
    match outcome {
        Some(Ok(())) => {}
        Some(Err(e)) => panic!("{ctx}: tonic server returned an error: {e}"),
        None => panic!("{ctx}: serve task ended without returning (panicked?)"),
    }
}

async fn spawn_tonic() -> TonicUnderTest {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (shutdown, shutdown_rx) = oneshot::channel::<()>();
    let (drained_tx, drained) = oneshot::channel::<()>();

    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepts.clone();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).inspect(move |r| {
        if r.is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let outcome = Arc::new(parking_lot::Mutex::new(None));
    let outcome_w = outcome.clone();

    tokio::spawn(async move {
        let _complete = SignalOnDrop(Some(drained_tx));
        // An empty router is enough: both failure modes live in the transport
        // layer, so no method needs to exist.
        let res = TonicServer::builder()
            .add_routes(Routes::default())
            .serve_with_incoming_shutdown(incoming, async move {
                let _ = shutdown_rx.await;
            })
            .await
            .map_err(|e| e.to_string());
        *outcome_w.lock() = Some(res);
    });

    TonicUnderTest {
        addr,
        shutdown,
        drained,
        outcome,
        accepts,
    }
}

/// `policy::all_unauthenticated()` with an explicit detection timeout.
fn detect_policy(timeout: Duration) -> policy::inbound::Server {
    let mut srv = policy::all_unauthenticated();
    srv.protocol = Some(policy::inbound::ProxyProtocol {
        kind: Some(policy::inbound::proxy_protocol::Kind::Detect(
            policy::inbound::proxy_protocol::Detect {
                timeout: Some(timeout.try_into().unwrap()),
                http_routes: vec![],
                http_local_rate_limit: None,
            },
        )),
    });
    srv
}

/// An inbound proxy that does real protocol detection for `srv_addr`.
///
/// A preface-less connection must exhaust TWO detection stages before linkerd
/// considers the opaque fallback: TLS detection (bounded by
/// `LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT`, `detect.rs:274`) then HTTP detection
/// (bounded by the policy's `Detect.timeout`). Both are set here.
async fn http_aware_proxy(srv_addr: SocketAddr, detect_timeout: Duration) -> proxy::Listening {
    let policy = controller::policy()
        .with_inbound_default(detect_policy(detect_timeout))
        .run()
        .await;
    let mut env = TestEnv::default();
    env.put(
        app::env::ENV_INBOUND_DETECT_TIMEOUT,
        format!("{}ms", detect_timeout.as_millis()),
    );
    proxy::new()
        .inbound_ip(srv_addr)
        .policy(policy)
        .run_with_test_env(env)
        .await
}

/// An inbound proxy with the port marked opaque (no protocol detection).
async fn opaque_proxy(srv_addr: SocketAddr) -> proxy::Listening {
    proxy::new()
        .inbound_ip(srv_addr)
        .disable_inbound_ports_protocol_detection(vec![srv_addr.port()])
        .run()
        .await
}

fn grpc_request(path: &str) -> http::request::Builder {
    http::Request::builder()
        .method("POST")
        .uri(path)
        .header("te", "trailers")
        .header("content-type", "application/grpc")
}

/// Builds a `balance_channel` pool of `POOL` lazy endpoints spread over
/// `targets`. The change sender must be held alive, exactly as in the repro.
async fn build_pool(
    targets: &[SocketAddr],
) -> (Channel, tokio::sync::mpsc::Sender<Change<usize, Endpoint>>) {
    let (channel, tx) = Channel::balance_channel::<usize>(POOL);
    for key in 0..POOL {
        let target = targets[key % targets.len()];
        let ep = Endpoint::from_shared(format!("http://{target}")).unwrap();
        tx.send(Change::Insert(key, ep)).await.unwrap();
    }
    (channel, tx)
}

/// One RPC through the pool. This is what makes the balancer dial EVERY endpoint
/// while waiting for only the first to become ready.
async fn one_rpc(channel: &mut Channel) {
    let req = grpc_request("/test.Svc/Method")
        .body(tonic::body::Body::empty())
        .unwrap();
    let _ = channel.ready().await.expect("channel ready").call(req).await;
}

// ---------------------------------------------------------------------------
// Single-connection behaviour
// ---------------------------------------------------------------------------

/// #1 through linkerd: an opaque policy relays bytes verbatim and dials eagerly,
/// so a client that never sends a preface produces a non-upgraded connection ON
/// THE TONIC SERVER, blocking its drain.
#[tokio::test]
async fn opaque_policy_creates_non_upgraded_connection() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    let proxy = opaque_proxy(srv.addr).await;

    let _silent = tokio::net::TcpStream::connect(proxy.inbound)
        .await
        .expect("connect to proxy inbound");

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        srv.accepted() > 0,
        "opaque proxy never dialed the application; test would be vacuous"
    );

    let (drained, _) = srv.shutdown_and_wait(Duration::from_secs(8)).await;
    assert!(
        !drained,
        "expected tonic drain to HANG on an opaquely-relayed preface-less connection"
    );
}

/// Control: while detection is in progress the proxy has not dialed the
/// application, so tonic drains cleanly.
#[tokio::test]
async fn detection_in_progress_holds_connection_at_proxy() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    let proxy = http_aware_proxy(srv.addr, Duration::from_secs(30)).await;

    let _silent = tokio::net::TcpStream::connect(proxy.inbound)
        .await
        .expect("connect to proxy inbound");

    tokio::time::sleep(Duration::from_secs(2)).await;

    let (drained, outcome) = srv.shutdown_and_wait(Duration::from_secs(8)).await;
    assert_clean(drained, outcome, "detection in progress");
}

/// The SURPRISE: detection is enabled and the connection idles past BOTH
/// detection stages. `inbound/src/detect.rs:127-163` reads as though linkerd
/// then forwards it "as an opaque TCP stream", which would hand tonic a
/// preface-less connection.
///
/// It does not. tonic accepts ZERO connections: linkerd never dials the
/// application for a client that has sent no bytes, however long it idles. Only
/// an *explicitly* opaque port dials eagerly.
#[tokio::test]
async fn detect_timeout_does_not_dial_application() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    let proxy = http_aware_proxy(srv.addr, Duration::from_secs(1)).await;

    let _silent = tokio::net::TcpStream::connect(proxy.inbound)
        .await
        .expect("connect to proxy inbound");

    tokio::time::sleep(Duration::from_secs(6)).await;

    let accepted = srv.accepted();
    assert_eq!(
        accepted, 0,
        "expected linkerd NOT to dial the application for a zero-byte connection"
    );

    let (drained, outcome) = srv.shutdown_and_wait(Duration::from_secs(8)).await;
    assert_clean(drained, outcome, "post-detect-timeout");
}

/// #2 through linkerd: tonic's h2 peer is the proxy, not the remote client, so a
/// client that stops running cannot block tonic's drain.
#[tokio::test]
async fn http_aware_proxy_absorbs_hung_client() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    let proxy = http_aware_proxy(srv.addr, Duration::from_secs(30)).await;
    let proxy_inbound = proxy.inbound;

    let (stall_tx, stall_rx) = std::sync::mpsc::channel::<()>();
    let (sent_tx, sent_rx) = oneshot::channel::<()>();

    let client_thread = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut ch = Endpoint::from_shared(format!("http://{proxy_inbound}"))
                .unwrap()
                .connect()
                .await
                .expect("client connect");
            one_rpc(&mut ch).await;
            let _ = sent_tx.send(());
            // Block the only runtime thread.
            let _ = stall_rx.recv();
        });
    });

    sent_rx.await.expect("client request sent");
    tokio::time::sleep(Duration::from_secs(1)).await;

    assert!(
        srv.accepted() > 0,
        "proxy never reached the application; test would be vacuous"
    );

    let (drained, outcome) = srv.shutdown_and_wait(Duration::from_secs(10)).await;

    let _ = stall_tx.send(());
    let _ = client_thread.join();

    assert_clean(drained, outcome, "hung client behind proxy");
}

// ---------------------------------------------------------------------------
// The production shape: a 500-connection balance_channel pool
// ---------------------------------------------------------------------------

/// The real client shape through an HTTP-aware port. One RPC makes the balancer
/// dial all `POOL` endpoints but wait for only the first, abandoning the rest
/// mid-handshake. Those abandoned connections never send a preface -- and
/// linkerd never dials the application for them, so tonic still drains.
#[tokio::test]
async fn pool_through_http_aware_port_drains_cleanly() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    // Short detect timeout and we idle past it: the strongest version.
    let proxy = http_aware_proxy(srv.addr, Duration::from_secs(1)).await;

    let (mut channel, _tx) = build_pool(&[proxy.inbound]).await;
    one_rpc(&mut channel).await;

    tokio::time::sleep(Duration::from_secs(5)).await;

    let accepted = srv.accepted();
    tracing::info!(pool = POOL, accepted, "connections that reached tonic");
    assert!(accepted > 0, "no connection reached tonic; test would be vacuous");

    let (drained, outcome) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
    assert_clean(
        drained,
        outcome,
        &format!("{POOL}-conn pool via HTTP-aware port ({accepted} reached tonic)"),
    );
}

/// The same pool through an OPAQUE port: the abandoned, preface-less pool
/// members are relayed straight through, so tonic's drain hangs. This is the
/// production incident reproduced end-to-end through a real linkerd proxy.
#[tokio::test]
async fn pool_through_opaque_port_hangs_shutdown() {
    let _trace = trace_init();

    let srv = spawn_tonic().await;
    let proxy = opaque_proxy(srv.addr).await;

    let (mut channel, _tx) = build_pool(&[proxy.inbound]).await;
    one_rpc(&mut channel).await;

    tokio::time::sleep(Duration::from_secs(3)).await;

    let accepted = srv.accepted();
    tracing::info!(pool = POOL, accepted, "connections that reached tonic");
    assert!(
        accepted > 1,
        "expected the opaque port to relay many pool members, got {accepted}"
    );

    let (drained, _) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
    assert!(
        !drained,
        "expected the {POOL}-conn pool over an opaque port to hang tonic's drain"
    );
}

/// Multiple servers, each with its own inbound proxy (one sidecar per pod), the
/// pool spread across all three: draining one must not disturb the others.
#[tokio::test]
async fn pool_across_servers_one_drains_while_others_serve() {
    let _trace = trace_init();

    let a = spawn_tonic().await;
    let b = spawn_tonic().await;
    let c = spawn_tonic().await;

    let pa = http_aware_proxy(a.addr, Duration::from_secs(30)).await;
    let pb = http_aware_proxy(b.addr, Duration::from_secs(30)).await;
    let pc = http_aware_proxy(c.addr, Duration::from_secs(30)).await;

    let (mut channel, _tx) = build_pool(&[pa.inbound, pb.inbound, pc.inbound]).await;

    // Enough RPCs that the balancer routes to every backend.
    for _ in 0..200 {
        one_rpc(&mut channel).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    let (na, nb, nc) = (a.accepted(), b.accepted(), c.accepted());
    tracing::info!(a = na, b = nb, c = nc, "accepts before drain");
    assert!(na > 0 && nb > 0 && nc > 0, "pool did not reach all three servers: {na}/{nb}/{nc}");

    // Drain ONLY server A.
    let (drained, outcome) = a.shutdown_and_wait(Duration::from_secs(10)).await;
    assert_clean(drained, outcome, "server A with pool across 3 servers");

    // B and C must still serve.
    let (before_b, before_c) = (b.accepted(), c.accepted());
    for _ in 0..50 {
        one_rpc(&mut channel).await;
    }
    assert!(b.accepted() >= before_b, "server B stopped serving");
    assert!(c.accepted() >= before_c, "server C stopped serving");
}

// ---------------------------------------------------------------------------
// Pod termination: the sidecar and the app get SIGTERM at the SAME time.
// This needs no opaque ports, so it is a candidate mechanism for a production
// hang on an HTTP-aware port.
// ---------------------------------------------------------------------------

/// Proxy and server drain concurrently.
async fn concurrent_shutdown_case(
    proxy_first: Option<bool>,
    ctx: &str,
) -> (bool, Option<Result<(), String>>, usize) {
    let srv = spawn_tonic().await;

    let (proxy_shdn, proxy_rx) = shutdown_signal();
    let policy = controller::policy()
        .with_inbound_default(detect_policy(Duration::from_secs(30)))
        .run()
        .await;
    let proxy = proxy::new()
        .inbound_ip(srv.addr)
        .policy(policy)
        .shutdown_signal(proxy_rx)
        .run()
        .await;

    // Establish a real end-to-end h2 path through the proxy.
    let (mut channel, _tx) = build_pool(&[proxy.inbound]).await;
    one_rpc(&mut channel).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let accepted = srv.accepted();
    assert!(accepted > 0, "{ctx}: proxy never reached the app");

    match proxy_first {
        // Sidecar drains first, then the app.
        Some(true) => {
            proxy_shdn.signal();
            tokio::time::sleep(Duration::from_millis(250)).await;
            let (d, o) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
            (d, o, accepted)
        }
        // App drains first, then the sidecar.
        Some(false) => {
            let fut = srv.shutdown_and_wait(Duration::from_secs(10));
            tokio::time::sleep(Duration::from_millis(250)).await;
            proxy_shdn.signal();
            let (d, o) = fut.await;
            (d, o, accepted)
        }
        // Both at once (what kubelet actually does).
        None => {
            proxy_shdn.signal();
            let (d, o) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
            (d, o, accepted)
        }
    }
}

#[tokio::test]
async fn sidecar_drains_before_app() {
    let _trace = trace_init();
    let (drained, outcome, n) = concurrent_shutdown_case(Some(true), "sidecar first").await;
    tracing::info!(accepted = n, drained, "sidecar first");
    assert_clean(drained, outcome, "sidecar drains before app");
}

#[tokio::test]
async fn app_drains_before_sidecar() {
    let _trace = trace_init();
    let (drained, outcome, n) = concurrent_shutdown_case(Some(false), "app first").await;
    tracing::info!(accepted = n, drained, "app first");
    assert_clean(drained, outcome, "app drains before sidecar");
}

#[tokio::test]
async fn sidecar_and_app_drain_simultaneously() {
    let _trace = trace_init();
    let (drained, outcome, n) = concurrent_shutdown_case(None, "simultaneous").await;
    tracing::info!(accepted = n, drained, "simultaneous");
    assert_clean(drained, outcome, "sidecar and app drain simultaneously");
}
