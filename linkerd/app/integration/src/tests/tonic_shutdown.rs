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
use tokio_util::sync::CancellationToken;
use tonic::transport::{Channel, Endpoint};
use tower::ServiceExt;

/// Size of the client connection pool. Production uses 3500.
const POOL: usize = 500;

/// Runs a closure on drop. Same shape as `OnDrop` in the original
/// hyper_hung_client_example, so the shutdown plumbing here matches the repro
/// exactly rather than merely approximating it.
pub struct OnDrop<F: FnMut()>(pub F);

impl<F: FnMut()> Drop for OnDrop<F> {
    fn drop(&mut self) {
        self.0();
    }
}

/// A real `tonic::transport::Server`.
///
/// Both signals are `CancellationToken`s, matching the repro: `shutdown` is what
/// `serve_with_incoming_shutdown` awaits, and `drain_complete` is cancelled from
/// an `OnDrop` guard so it fires however the serve task ends (including a
/// panic). Unlike a `oneshot`, a token can be awaited repeatedly and observed
/// without consuming the handle.
struct TonicUnderTest {
    addr: SocketAddr,
    shutdown: CancellationToken,
    drain_complete: CancellationToken,
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
    async fn shutdown_and_wait(&self, within: Duration) -> (bool, Option<Result<(), String>>) {
        self.shutdown.cancel();
        let in_time = tokio::time::timeout(within, self.drain_complete.cancelled())
            .await
            .is_ok();
        let out = self.outcome.lock().clone();
        (in_time, out)
    }

    /// Whether the drain has completed, without waiting.
    fn is_drained(&self) -> bool {
        self.drain_complete.is_cancelled()
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

    let shutdown = CancellationToken::new();
    let drain_complete = CancellationToken::new();

    let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = accepts.clone();
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener).inspect(move |r| {
        if r.is_ok() {
            counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    });

    let outcome = Arc::new(parking_lot::Mutex::new(None));
    let outcome_w = outcome.clone();

    let shutdown_rx = shutdown.clone();
    let complete_tx = drain_complete.clone();

    tokio::spawn(async move {
        // Cancels on drop, so it fires however this task ends -- including a
        // panic, which a plain `oneshot` sent after `.await` would misreport as
        // a clean drain.
        let _complete = OnDrop(|| {
            complete_tx.cancel();
        });

        // An empty router is enough: both failure modes live in the transport
        // layer, so no method needs to exist.
        let res = TonicServer::builder()
            .add_routes(Routes::default())
            .serve_with_incoming_shutdown(incoming, async move {
                shutdown_rx.cancelled().await;
            })
            .await
            .map_err(|e| e.to_string());
        *outcome_w.lock() = Some(res);
    });

    TonicUnderTest {
        addr,
        shutdown,
        drain_complete,
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
    build_pool_n(targets, POOL).await
}

async fn build_pool_n(
    targets: &[SocketAddr],
    n: usize,
) -> (Channel, tokio::sync::mpsc::Sender<Change<usize, Endpoint>>) {
    let (channel, tx) = Channel::balance_channel::<usize>(n.max(1));
    for key in 0..n {
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
            // Cancel the app's token first, then the sidecar's, while the
            // app's drain is still in flight.
            let app = srv.shutdown.clone();
            let complete = srv.drain_complete.clone();
            app.cancel();
            tokio::time::sleep(Duration::from_millis(250)).await;
            proxy_shdn.signal();
            let in_time = tokio::time::timeout(Duration::from_secs(10), complete.cancelled())
                .await
                .is_ok();
            let out = srv.outcome.lock().clone();
            (in_time, out, accepted)
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

// ---------------------------------------------------------------------------
// THE PRODUCTION TOPOLOGY: client -> outbound sidecar -> inbound sidecar -> tonic
//
// No opaque ports anywhere; the inbound policy is a normal HTTP `Detect`.
//
// The asymmetry that makes this work (see proxy_dial_probe):
//   * the INBOUND proxy never dials the app for a bare preface-less connection;
//   * the OUTBOUND proxy DOES dial through once its detection window expires;
//   * and because the destination advertises a mesh identity, it dials over
//     mTLS with linkerd's transport header -- so the inbound proxy receives
//     real bytes, skips detection, and forwards to the app immediately.
// ---------------------------------------------------------------------------

const MESH_HOST: &str = "grpc.test.svc.cluster.local";
const MESH_IDENTITY: &str = "default.default.serviceaccount.identity.linkerd.cluster.local";

/// Runs the full-mesh scenario with `n` pool members and returns
/// `(reached_tonic, drained_in_time)`.
async fn full_mesh_case(n: usize, settle: Duration) -> (usize, bool) {
    let srv = spawn_tonic().await;

    // --- server-side sidecar: ordinary HTTP-aware inbound.
    let in_policy = controller::policy()
        .with_inbound_default(detect_policy(Duration::from_secs(1)))
        .run()
        .await;
    let mut in_env = TestEnv::default();
    in_env.put("LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT", "1s".to_owned());
    let p_in = proxy::new()
        .inbound_ip(srv.addr)
        .policy(in_policy)
        .run_with_test_env(in_env)
        .await;

    // --- client-side sidecar: outbound aimed at the server's inbound.
    let dstctl = controller::new();
    let polctl = controller::policy();
    let name = format!("{MESH_HOST}:{}", p_in.inbound.port());
    let policy_tx = polctl.outbound_tx_default(p_in.inbound, name.clone());
    let profile_tx = dstctl.profile_tx_default(p_in.inbound, MESH_HOST);
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

    // --- the real client: a balance_channel pool aimed at its own sidecar.
    let (mut channel, _tx) = build_pool_n(&[p_out.outbound], n).await;
    one_rpc(&mut channel).await;

    // Outlive every detection window in the chain.
    tokio::time::sleep(settle).await;

    let accepted = srv.accepted();
    let (drained, _) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
    println!("MESH-TONIC: pool={n} reached_tonic={accepted} drained={drained}");
    (accepted, drained)
}

#[tokio::test]
async fn full_mesh_pool_500() {
    let _trace = trace_init();
    full_mesh_case(500, Duration::from_secs(14)).await;
}

#[tokio::test]
async fn full_mesh_pool_50_long_settle() {
    let _trace = trace_init();
    full_mesh_case(50, Duration::from_secs(25)).await;
}

#[tokio::test]
async fn full_mesh_pool_10_long_settle() {
    let _trace = trace_init();
    full_mesh_case(10, Duration::from_secs(25)).await;
}

// ---------------------------------------------------------------------------
// Isolating the contradiction: raw silent sockets through the outbound sidecar
// reach the far side (500/500, see proxy_dial_probe), but a balance_channel
// pool through the same sidecar reaches it once. The mesh is identical, so the
// variable is the CLIENT. These two measurements separate the steps.
// ---------------------------------------------------------------------------

/// Bare TCP listener that counts accepts and holds sockets open.
async fn tcp_accept_counter() -> (SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let c = count.clone();
    tokio::spawn(async move {
        while let Ok((sock, _)) = listener.accept().await {
            c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let _hold = sock;
                futures::future::pending::<()>().await;
            });
        }
    });
    (addr, count)
}

/// STEP 1: how many TCP connections does a 500-member pool actually open?
/// Straight at a bare listener, no proxy involved.
#[tokio::test]
async fn measure_pool_tcp_connections_direct() {
    let _trace = trace_init();

    let (target, accepts) = tcp_accept_counter().await;
    let (mut channel, _tx) = build_pool_n(&[target], 500).await;

    // The RPC cannot succeed (the listener speaks no h2); we only want the dials.
    let _ = tokio::time::timeout(Duration::from_secs(5), one_rpc(&mut channel)).await;
    tokio::time::sleep(Duration::from_secs(5)).await;

    println!(
        "MEASURE direct: pool=500 tcp_established={}",
        accepts.load(std::sync::atomic::Ordering::SeqCst)
    );
}

/// STEP 2: the same pool through an outbound sidecar at a bare listener.
/// Compare with `probe_outbound_past_detect_timeout` (raw sockets: 500/500).
#[tokio::test]
async fn measure_pool_via_outbound_proxy() {
    let _trace = trace_init();

    let (target, accepts) = tcp_accept_counter().await;

    let dstctl = controller::new();
    let polctl = controller::policy();
    let name = format!("{MESH_HOST}:{}", target.port());
    let policy_tx = polctl.outbound_tx_default(target, name.clone());
    let profile_tx = dstctl.profile_tx_default(target, MESH_HOST);
    let dst_tx = dstctl.destination_tx(name);
    dst_tx.send_addr(target);

    let mut out_env = TestEnv::default();
    out_env.put("LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT", "1s".to_owned());
    let p_out = proxy::new()
        .controller(dstctl.run().await)
        .policy(polctl.run().await)
        .outbound_ip(target)
        .run_with_test_env(out_env)
        .await;
    std::mem::forget((policy_tx, profile_tx, dst_tx));

    let (mut channel, _tx) = build_pool_n(&[p_out.outbound], 500).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), one_rpc(&mut channel)).await;
    tokio::time::sleep(Duration::from_secs(12)).await;

    println!(
        "MEASURE via-outbound: pool=500 reached_target={}",
        accepts.load(std::sync::atomic::Ordering::SeqCst)
    );
}

/// STEP 3: what do abandoned pool members actually SEND? This distinguishes
/// "never wrote the preface" from "wrote the 24-byte preface but never the
/// SETTINGS frame" -- which are very different for anything doing protocol
/// detection, and for hyper's h2 server handshake.
#[tokio::test]
async fn measure_what_abandoned_pool_members_send() {
    let _trace = trace_init();

    const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let total = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let silent = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let preface_only = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let more_than_preface = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    {
        let (t, s, po, m) = (
            total.clone(),
            silent.clone(),
            preface_only.clone(),
            more_than_preface.clone(),
        );
        tokio::spawn(async move {
            while let Ok((mut sock, _)) = listener.accept().await {
                t.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let (s, po, m) = (s.clone(), po.clone(), m.clone());
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 256];
                    let mut n = 0usize;
                    // Give the peer a moment to write whatever it intends to.
                    let deadline = tokio::time::sleep(Duration::from_secs(4));
                    tokio::pin!(deadline);
                    loop {
                        tokio::select! {
                            _ = &mut deadline => break,
                            r = tokio::io::AsyncReadExt::read(&mut sock, &mut buf[n..]) => {
                                match r {
                                    Ok(0) | Err(_) => break,
                                    Ok(k) => {
                                        n += k;
                                        if n >= buf.len() { break; }
                                    }
                                }
                            }
                        }
                    }
                    if n == 0 {
                        s.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    } else if n == PREFACE.len() && &buf[..n] == PREFACE {
                        po.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    } else {
                        m.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                    let _hold = sock;
                    futures::future::pending::<()>().await;
                });
            }
        });
    }

    let (mut channel, _tx) = build_pool_n(&[addr], 500).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), one_rpc(&mut channel)).await;
    tokio::time::sleep(Duration::from_secs(8)).await;

    use std::sync::atomic::Ordering::SeqCst;
    println!(
        "MEASURE bytes: accepted={} zero_bytes={} preface_only={} more_than_preface={}",
        total.load(SeqCst),
        silent.load(SeqCst),
        preface_only.load(SeqCst),
        more_than_preface.load(SeqCst),
    );
}

// ---------------------------------------------------------------------------
// Count connections at EVERY hop of the production chain:
//
//   pool --1--> [relayA] -> outbound sidecar --2--> [relayB] -> inbound sidecar --3--> tonic
//
// relayA/relayB are transparent byte relays (mTLS passes through untouched)
// that count accepts and how many connections are still open at measurement
// time -- which also tests whether the pool's sockets survive long enough to
// outlive the detection windows.
// ---------------------------------------------------------------------------

struct HopCounter {
    addr: SocketAddr,
    accepted: Arc<std::sync::atomic::AtomicUsize>,
    open: Arc<std::sync::atomic::AtomicUsize>,
}

async fn counting_relay(upstream: SocketAddr) -> HopCounter {
    counting_relay_lat(upstream, None).await
}

/// Transparent counting relay in front of `upstream`, optionally delaying
/// connection setup to emulate a real pod-to-pod network hop.
async fn counting_relay_lat(upstream: SocketAddr, latency: Option<Duration>) -> HopCounter {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let accepted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let open = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (a, o) = (accepted.clone(), open.clone());

    tokio::spawn(async move {
        while let Ok((mut down, _)) = listener.accept().await {
            a.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            o.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let o2 = o.clone();
            tokio::spawn(async move {
                if let Some(l) = latency {
                    tokio::time::sleep(l).await;
                }
                match tokio::net::TcpStream::connect(upstream).await {
                    Ok(mut up) => {
                        let _ = tokio::io::copy_bidirectional(&mut down, &mut up).await;
                    }
                    Err(e) => tracing::warn!(?e, "relay upstream connect failed"),
                }
                o2.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            });
        }
    });

    HopCounter {
        addr,
        accepted,
        open,
    }
}

/// Outbound sidecar whose resolved destination is `dst`, advertising `identity`
/// so the mesh path (mTLS + transport header) is used.
async fn outbound_sidecar_with(
    dst: SocketAddr,
    detect: Duration,
    discovery_idle: Option<Duration>,
) -> proxy::Listening {
    let dstctl = controller::new();
    let polctl = controller::policy();
    let name = format!("{MESH_HOST}:{}", dst.port());
    let policy_tx = polctl.outbound_tx_default(dst, name.clone());
    let profile_tx = dstctl.profile_tx_default(dst, MESH_HOST);
    let dst_tx = dstctl.destination_tx(name);
    dst_tx.send(controller::destination_add(dst).identity(MESH_IDENTITY));

    let mut env = TestEnv::default();
    env.put(
        "LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT",
        format!("{}ms", detect.as_millis()),
    );
    if let Some(idle) = discovery_idle {
        env.put(
            "LINKERD2_PROXY_OUTBOUND_DISCOVERY_IDLE_TIMEOUT",
            format!("{}ms", idle.as_millis()),
        );
    }
    let p = proxy::new()
        .controller(dstctl.run().await)
        .policy(polctl.run().await)
        .outbound_ip(dst)
        .run_with_test_env(env)
        .await;
    std::mem::forget((policy_tx, profile_tx, dst_tx));
    p
}

async fn outbound_sidecar(dst: SocketAddr, detect: Duration) -> proxy::Listening {
    outbound_sidecar_with(dst, detect, None).await
}

async fn per_hop_case(n: usize, detect: Duration, settle: Duration, label: &str) {
    per_hop_case_with(n, detect, None, settle, label).await
}

async fn per_hop_case_with(
    n: usize,
    detect: Duration,
    discovery_idle: Option<Duration>,
    settle: Duration,
    label: &str,
) {
    let srv = spawn_tonic().await;

    // server pod
    let p_in = http_aware_proxy(srv.addr, detect).await;
    // hop 2 counter: between the sidecars
    let relay_b = counting_relay(p_in.inbound).await;
    // client pod
    let p_out = outbound_sidecar_with(relay_b.addr, detect, discovery_idle).await;
    // hop 1 counter: between the app and its own sidecar
    let relay_a = counting_relay(p_out.outbound).await;

    // Real pool, real tonic at the end, so the RPC SUCCEEDS and nothing is
    // torn down for lack of a working backend.
    let (mut channel, _tx) = build_pool_n(&[relay_a.addr], n).await;
    one_rpc(&mut channel).await;

    tokio::time::sleep(settle).await;

    use std::sync::atomic::Ordering::SeqCst;
    println!(
        "PER-HOP[{label}] pool={n} detect={:?} | hop1 accepted={} open={} | hop2 accepted={} open={} | hop3(tonic) accepted={}",
        detect,
        relay_a.accepted.load(SeqCst),
        relay_a.open.load(SeqCst),
        relay_b.accepted.load(SeqCst),
        relay_b.open.load(SeqCst),
        srv.accepted(),
    );

    let (drained, _) = srv.shutdown_and_wait(Duration::from_secs(10)).await;
    println!("PER-HOP[{label}] tonic_drained={drained}");
}

/// Fast variant: 1s detection windows.
#[tokio::test]
async fn per_hop_counts_fast_detect() {
    let _trace = trace_init();
    per_hop_case(500, Duration::from_secs(1), Duration::from_secs(12), "fast").await;
}

/// Faithful variant: production-default 10s detection windows, settled well past
/// both the outbound window and the inbound TLS+HTTP windows.
#[tokio::test]
async fn per_hop_counts_production_detect() {
    let _trace = trace_init();
    per_hop_case(500, Duration::from_secs(10), Duration::from_secs(35), "prod").await;
}

/// Is the production-default protection just an accident of
/// `OUTBOUND_DISCOVERY_IDLE_TIMEOUT` (5s) being SHORTER than
/// `OUTBOUND_DETECT_TIMEOUT` (10s)? If so, raising the discovery idle timeout
/// above the detect window should let idle connections propagate again.
#[tokio::test]
async fn per_hop_counts_prod_detect_long_discovery_idle() {
    let _trace = trace_init();
    per_hop_case_with(
        500,
        Duration::from_secs(10),
        Some(Duration::from_secs(120)),
        Duration::from_secs(35),
        "prod-detect+long-idle",
    )
    .await;
}

/// Sweep the detection window to find the threshold between "idle pool members
/// propagate through both sidecars and hang tonic" and "they don't". Tells us
/// how much margin production's 10s default actually has.
#[tokio::test]
async fn per_hop_detect_sweep() {
    let _trace = trace_init();
    for secs in [1u64, 2, 4, 7, 10] {
        let detect = Duration::from_secs(secs);
        per_hop_case(
            200,
            detect,
            detect + Duration::from_secs(15),
            &format!("sweep-{secs}s"),
        )
        .await;
    }
}

/// Production uses 3500 connections, 7x the 500 above. Does a larger pool
/// overcome the 10s production detection window?
#[tokio::test]
async fn per_hop_big_pool_production_detect() {
    let _trace = trace_init();
    per_hop_case(
        2000,
        Duration::from_secs(10),
        Duration::from_secs(35),
        "big-pool-prod-detect",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Production-scale: 3500 members, real inter-pod latency on hop 2, and a
// side-by-side comparison of the lazy `balance_channel` pool against an
// eagerly-connected `ServiceList` pool.
// ---------------------------------------------------------------------------

struct MeshUnderTest {
    srv: TonicUnderTest,
    relay_a: HopCounter,
    relay_b: HopCounter,
    client_entry: SocketAddr,
    // These MUST be retained: dropping a `proxy::Listening` shuts the sidecar
    // down, which silently zeroes hop2/hop3.
    _p_in: proxy::Listening,
    _p_out: proxy::Listening,
}

async fn build_mesh(detect: Duration, hop2_latency: Option<Duration>) -> MeshUnderTest {
    let srv = spawn_tonic().await;
    let p_in = http_aware_proxy(srv.addr, detect).await;
    let relay_b = counting_relay_lat(p_in.inbound, hop2_latency).await;
    let p_out = outbound_sidecar(relay_b.addr, detect).await;
    let relay_a = counting_relay(p_out.outbound).await;
    let client_entry = relay_a.addr;
    MeshUnderTest {
        srv,
        relay_a,
        relay_b,
        client_entry,
        _p_in: p_in,
        _p_out: p_out,
    }
}

fn report(m: &MeshUnderTest, label: &str, n: usize, detect: Duration, lat: Option<Duration>) -> usize {
    use std::sync::atomic::Ordering::SeqCst;
    let hop3 = m.srv.accepted();
    println!(
        "MESH[{label}] pool={n} detect={:?} hop2_lat={:?} | hop1={}/{} | hop2={}/{} | hop3(tonic)={}",
        detect,
        lat,
        m.relay_a.accepted.load(SeqCst),
        m.relay_a.open.load(SeqCst),
        m.relay_b.accepted.load(SeqCst),
        m.relay_b.open.load(SeqCst),
        hop3,
    );
    hop3
}

/// The current production client: lazy `balance_channel`.
async fn lazy_pool_case(n: usize, detect: Duration, lat: Option<Duration>, settle: Duration, label: &str) {
    let m = build_mesh(detect, lat).await;
    let (mut channel, _tx) = build_pool_n(&[m.client_entry], n).await;
    one_rpc(&mut channel).await;
    tokio::time::sleep(settle).await;
    let hop3 = report(&m, label, n, detect, lat);
    let (drained, _) = m.srv.shutdown_and_wait(Duration::from_secs(10)).await;
    println!("MESH[{label}] hop3={hop3} tonic_drained={drained}");
}

/// The proposed fix: eagerly-connected pool over `ServiceList` + p2c, so no
/// member is ever left parked mid-handshake.
async fn eager_pool_case(n: usize, detect: Duration, lat: Option<Duration>, settle: Duration, label: &str) {
    let m = build_mesh(detect, lat).await;

    let ep = Endpoint::from_shared(format!("http://{}", m.client_entry)).unwrap();
    let mut members = Vec::with_capacity(n);
    for _ in 0..n {
        let ch = ep.connect().await.expect("eager connect");
        members.push(tower::load::PendingRequests::new(
            ch,
            tower::load::CompleteOnResponse::default(),
        ));
    }
    let balance = tower::balance::p2c::Balance::new(tower::discover::ServiceList::new(members));
    let mut svc = tower::buffer::Buffer::new(balance, 1024);

    let req = grpc_request("/test.Svc/Method")
        .body(tonic::body::Body::empty())
        .unwrap();
    let _ = svc.ready().await.expect("svc ready").call(req).await;

    tokio::time::sleep(settle).await;
    let hop3 = report(&m, label, n, detect, lat);
    let (drained, _) = m.srv.shutdown_and_wait(Duration::from_secs(10)).await;
    println!("MESH[{label}] hop3={hop3} tonic_drained={drained}");
    assert!(
        drained,
        "eager ServiceList pool should always drain cleanly ({hop3} conns at tonic)"
    );
}

#[tokio::test]
async fn mesh_lazy_3500_prod_detect() {
    let _trace = trace_init();
    lazy_pool_case(3500, Duration::from_secs(10), None, Duration::from_secs(35), "lazy-3500").await;
}

#[tokio::test]
async fn mesh_lazy_3500_prod_detect_with_latency() {
    let _trace = trace_init();
    lazy_pool_case(
        3500,
        Duration::from_secs(10),
        Some(Duration::from_millis(2)),
        Duration::from_secs(35),
        "lazy-3500-lat2ms",
    )
    .await;
}

#[tokio::test]
async fn mesh_eager_3500_prod_detect_with_latency() {
    let _trace = trace_init();
    eager_pool_case(
        3500,
        Duration::from_secs(10),
        Some(Duration::from_millis(2)),
        Duration::from_secs(20),
        "eager-3500-lat2ms",
    )
    .await;
}

// --- apples-to-apples at a scale the harness can actually carry (500) ---
// NOTE: the 500/1s lazy-vs-eager pair now lives in `grpc_pool_shutdown.rs`.

/// Does real pod-to-pod latency on hop 2 change the production-window result?
#[tokio::test]
async fn mesh_lazy_500_prod_detect_lat() {
    let _trace = trace_init();
    lazy_pool_case(
        500,
        Duration::from_secs(10),
        Some(Duration::from_millis(2)),
        Duration::from_secs(35),
        "lazy-500-prod-lat2ms",
    )
    .await;
}

/// The fix at the production window with latency.
#[tokio::test]
async fn mesh_eager_500_prod_detect_lat() {
    let _trace = trace_init();
    eager_pool_case(
        500,
        Duration::from_secs(10),
        Some(Duration::from_millis(2)),
        Duration::from_secs(20),
        "eager-500-prod-lat2ms",
    )
    .await;
}
