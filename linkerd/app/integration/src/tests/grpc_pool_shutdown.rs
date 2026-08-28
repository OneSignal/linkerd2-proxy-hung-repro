//! A tonic gRPC server can hang forever in graceful shutdown, and the cause is
//! the *client's* connection pool. Both tests below run the real linkerd
//! inbound and outbound stacks, in the production topology, with **no opaque
//! ports** and an ordinary HTTP-detecting inbound policy.
//!
//! # The issue
//!
//! `Channel::balance_channel` builds a pool of *lazy* endpoints. The first RPC
//! makes the balancer dial every one of them, but it returns as soon as the
//! first becomes ready, leaving the rest parked mid-connect. Those parked
//! members complete their TCP handshake and then send nothing at all -- no
//! HTTP/2 client preface.
//!
//! Given enough time, the client's outbound sidecar gives up on protocol
//! detection and forwards them through to the server, where hyper's HTTP/2
//! server parks in `State::Handshaking` waiting for a preface that never comes.
//! `graceful_shutdown()` on a handshaking connection only sets an internal
//! `close_pending` flag, which is never read, so the connection future never
//! resolves -- and tonic's `serve_with_incoming_shutdown` waits for every
//! connection task before returning. One such connection hangs the drain
//! permanently.
//!
//! # The resolution
//!
//! Build the pool eagerly: connect each member with `Endpoint::connect()` (which
//! drives the HTTP/2 handshake to completion) and balance over a fixed
//! `ServiceList`. No member is ever parked mid-handshake, so there is nothing to
//! leak and nothing to hang the server.
//!
//! # Reading the output
//!
//! Each run prints the connection count at all three hops. The telling column is
//! how many client connections are still open: a hang has always coincided with
//! exactly one pool member's socket having closed.

use crate::*;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio_util::sync::CancellationToken;
use tonic::service::Routes;
use tonic::transport::channel::Change;
use tonic::transport::{Channel, Endpoint, Server as TonicServer};
use tower::ServiceExt;
use tower::balance::p2c::Balance;
use tower::buffer::Buffer;
use tower::discover::ServiceList;
use tower::load::{CompleteOnResponse, PendingRequests};

/// Connections in the client's pool. Production uses 3500.
const POOL_SIZE: usize = 500;

/// Protocol-detection window for both sidecars. Production defaults to 10s;
/// this is shortened so the forwarding path is exercised quickly.
const DETECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Time allowed after the first RPC for the sidecars to finish detecting and
/// forwarding the idle pool members.
const SETTLE: Duration = Duration::from_secs(6);

/// How long a graceful shutdown may take before we call it hung.
const DRAIN_DEADLINE: Duration = Duration::from_secs(5);

/// The lazy pool fails intermittently (roughly 6 runs in 10), so a single
/// attempt is not enough to demonstrate the issue.
const ATTEMPTS: usize = 6;

const MESH_HOST: &str = "grpc.test.svc.cluster.local";
const MESH_IDENTITY: &str = "default.default.serviceaccount.identity.linkerd.cluster.local";

const GRPC_METHOD: &str = "/test.Svc/Method";

type GrpcRequest = http::Request<tonic::body::Body>;
type GrpcResponse = http::Response<tonic::body::Body>;
type BoxedGrpcService = tower::util::BoxService<GrpcRequest, GrpcResponse, Error>;

// =========================================================================
// The server under test
// =========================================================================

/// Runs a closure on drop, however the holding future terminated.
struct RunOnDrop<F: FnMut()>(F);

impl<F: FnMut()> Drop for RunOnDrop<F> {
    fn drop(&mut self) {
        (self.0)();
    }
}

/// A real `tonic::transport::Server`.
struct GrpcServer {
    address: SocketAddr,
    shutdown: CancellationToken,
    /// Cancelled from a drop guard, so it fires however the serve task ended --
    /// including a panic, which a signal sent after `.await` would miss.
    drain_complete: CancellationToken,
    serve_result: Arc<parking_lot::Mutex<Option<Result<(), String>>>>,
    connections_accepted: Arc<AtomicUsize>,
}

impl GrpcServer {
    async fn spawn() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();

        let shutdown = CancellationToken::new();
        let drain_complete = CancellationToken::new();
        let serve_result = Arc::new(parking_lot::Mutex::new(None));
        let connections_accepted = Arc::new(AtomicUsize::new(0));

        let counter = connections_accepted.clone();
        let incoming =
            tokio_stream::wrappers::TcpListenerStream::new(listener).inspect(move |accepted| {
                if accepted.is_ok() {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
            });

        let shutdown_signal = shutdown.clone();
        let drained_signal = drain_complete.clone();
        let result_slot = serve_result.clone();

        tokio::spawn(async move {
            let _signal_on_exit = RunOnDrop(move || drained_signal.cancel());

            // An empty router suffices: the hang is in the transport layer, so
            // no gRPC method needs to exist.
            let result = TonicServer::builder()
                .add_routes(Routes::default())
                .serve_with_incoming_shutdown(incoming, async move {
                    shutdown_signal.cancelled().await;
                })
                .await
                .map_err(|error| error.to_string());

            *result_slot.lock() = Some(result);
        });

        Self {
            address,
            shutdown,
            drain_complete,
            serve_result,
            connections_accepted,
        }
    }

    fn connections_accepted(&self) -> usize {
        self.connections_accepted.load(Ordering::SeqCst)
    }

    /// Triggers graceful shutdown and reports whether the drain finished within
    /// [`DRAIN_DEADLINE`]. Panics if the server itself failed, so a crash can
    /// never be mistaken for a clean drain.
    async fn shutdown_and_wait(&self) -> bool {
        self.shutdown.cancel();

        let drained = tokio::time::timeout(DRAIN_DEADLINE, self.drain_complete.cancelled())
            .await
            .is_ok();

        if drained {
            match &*self.serve_result.lock() {
                Some(Ok(())) => {}
                Some(Err(error)) => panic!("tonic server returned an error: {error}"),
                None => panic!("tonic serve task ended without returning"),
            }
        }

        drained
    }
}

// =========================================================================
// Hop instrumentation
// =========================================================================

/// A transparent TCP relay that counts connections. It only copies bytes, so
/// mTLS between the sidecars passes through untouched.
struct HopCounter {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    still_open: Arc<AtomicUsize>,
}

impl HopCounter {
    async fn in_front_of(upstream: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let still_open = Arc::new(AtomicUsize::new(0));

        let accepted_counter = accepted.clone();
        let open_counter = still_open.clone();

        tokio::spawn(async move {
            while let Ok((mut downstream, _)) = listener.accept().await {
                accepted_counter.fetch_add(1, Ordering::SeqCst);
                open_counter.fetch_add(1, Ordering::SeqCst);

                let open_counter = open_counter.clone();
                tokio::spawn(async move {
                    match tokio::net::TcpStream::connect(upstream).await {
                        Ok(mut upstream) => {
                            let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream)
                                .await;
                        }
                        Err(error) => tracing::warn!(?error, "relay could not reach upstream"),
                    }
                    open_counter.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });

        Self {
            address,
            accepted,
            still_open,
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn still_open(&self) -> usize {
        self.still_open.load(Ordering::SeqCst)
    }
}

// =========================================================================
// The mesh: client sidecar + server sidecar
// =========================================================================

/// An ordinary HTTP-aware inbound policy: protocol detection enabled, nothing
/// marked opaque.
fn http_detect_policy() -> policy::inbound::Server {
    let mut server = policy::all_unauthenticated();
    server.protocol = Some(policy::inbound::ProxyProtocol {
        kind: Some(policy::inbound::proxy_protocol::Kind::Detect(
            policy::inbound::proxy_protocol::Detect {
                timeout: Some(DETECT_TIMEOUT.try_into().unwrap()),
                http_routes: Vec::new(),
                http_local_rate_limit: None,
            },
        )),
    });
    server
}

/// The sidecar in the server's pod, forwarding to the local application.
///
/// A preface-less connection must exhaust two detection stages here: TLS
/// detection, bounded by the env var, and then HTTP detection, bounded by the
/// policy above.
async fn start_server_sidecar(application: SocketAddr) -> proxy::Listening {
    let policy = controller::policy()
        .with_inbound_default(http_detect_policy())
        .run()
        .await;

    let mut env = TestEnv::default();
    env.put(
        "LINKERD2_PROXY_INBOUND_DETECT_TIMEOUT",
        format!("{}ms", DETECT_TIMEOUT.as_millis()),
    );

    proxy::new()
        .inbound_ip(application)
        .policy(policy)
        .run_with_test_env(env)
        .await
}

/// The sidecar in the client's pod, forwarding to the server's sidecar.
///
/// The destination advertises a mesh identity so the connection is made over
/// mTLS, exactly as it would be between two meshed pods.
async fn start_client_sidecar(destination: SocketAddr) -> proxy::Listening {
    let destinations = controller::new();
    let policies = controller::policy();

    let service_name = format!("{MESH_HOST}:{}", destination.port());
    let outbound_policy = policies.outbound_tx_default(destination, service_name.clone());
    let profile = destinations.profile_tx_default(destination, MESH_HOST);
    let endpoints = destinations.destination_tx(service_name);
    endpoints.send(controller::destination_add(destination).identity(MESH_IDENTITY));

    let mut env = TestEnv::default();
    env.put(
        "LINKERD2_PROXY_OUTBOUND_DETECT_TIMEOUT",
        format!("{}ms", DETECT_TIMEOUT.as_millis()),
    );

    let sidecar = proxy::new()
        .controller(destinations.run().await)
        .policy(policies.run().await)
        .outbound_ip(destination)
        .run_with_test_env(env)
        .await;

    // These senders must outlive the sidecar or its discovery streams close.
    std::mem::forget((outbound_policy, profile, endpoints));

    sidecar
}

/// The production topology:
///
/// ```text
/// client --hop1--> client sidecar --hop2--> server sidecar --hop3--> tonic
/// ```
struct Mesh {
    server: GrpcServer,
    hop1: HopCounter,
    hop2: HopCounter,
    /// Where the client's pool connects, standing in for the address that
    /// iptables would redirect to the client's own sidecar.
    client_entrypoint: SocketAddr,
    // Retained: dropping a `Listening` shuts its sidecar down.
    _client_sidecar: proxy::Listening,
    _server_sidecar: proxy::Listening,
}

impl Mesh {
    async fn start() -> Self {
        let server = GrpcServer::spawn().await;
        let server_sidecar = start_server_sidecar(server.address).await;
        let hop2 = HopCounter::in_front_of(server_sidecar.inbound).await;
        let client_sidecar = start_client_sidecar(hop2.address).await;
        let hop1 = HopCounter::in_front_of(client_sidecar.outbound).await;
        let client_entrypoint = hop1.address;

        Self {
            server,
            hop1,
            hop2,
            client_entrypoint,
            _client_sidecar: client_sidecar,
            _server_sidecar: server_sidecar,
        }
    }
}

// =========================================================================
// The two client pools
// =========================================================================

/// A client pool ready to issue requests.
struct ClientPool {
    service: BoxedGrpcService,
    /// The lazy pool's discovery channel. It must stay open, or the balancer
    /// drops the endpoints it was told about.
    _changes: Option<tokio::sync::mpsc::Sender<Change<usize, Endpoint>>>,
}

impl ClientPool {
    /// THE ISSUE. `balance_channel` registers lazy endpoints; nothing connects
    /// until the first request forces the balancer to dial them all.
    async fn lazy(entrypoint: SocketAddr) -> Self {
        let (channel, changes) = Channel::balance_channel::<usize>(POOL_SIZE);
        for key in 0..POOL_SIZE {
            let endpoint = Endpoint::from_shared(format!("http://{entrypoint}")).unwrap();
            changes.send(Change::Insert(key, endpoint)).await.unwrap();
        }

        Self {
            service: tower::util::BoxService::new(channel.map_err(Error::from)),
            _changes: Some(changes),
        }
    }

    /// THE RESOLUTION. Every member is connected up front, so its HTTP/2
    /// handshake is complete before it joins the pool and none can be left
    /// parked. `PendingRequests` also gives the balancer a real load signal,
    /// which tonic's own pooled connections do not.
    async fn eager(entrypoint: SocketAddr) -> Self {
        let endpoint = Endpoint::from_shared(format!("http://{entrypoint}")).unwrap();

        let mut members = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            let connected = endpoint.connect().await.expect("eager connect");
            members.push(PendingRequests::new(
                connected,
                CompleteOnResponse::default(),
            ));
        }

        let balancer = Balance::new(ServiceList::new(members));
        let buffered = Buffer::new(balancer, POOL_SIZE);

        Self {
            service: tower::util::BoxService::new(buffered.map_err(Error::from)),
            _changes: None,
        }
    }

    /// Issues one request. For the lazy pool this is what makes the balancer
    /// dial every endpoint while waiting for only the first to become ready.
    async fn send_one_request(&mut self) {
        let request = http::Request::builder()
            .method("POST")
            .uri(GRPC_METHOD)
            .header("te", "trailers")
            .header("content-type", "application/grpc")
            .body(tonic::body::Body::empty())
            .unwrap();

        let ready = self.service.ready().await.expect("pool ready");
        let _ = ready.call(request).await;
    }
}

// =========================================================================
// Running one attempt
// =========================================================================

#[derive(Debug)]
enum PoolStyle {
    Lazy,
    Eager,
}

struct Outcome {
    drained: bool,
    client_connections_open: usize,
    reached_server_sidecar: usize,
    reached_tonic: usize,
}

async fn run_attempt(style: PoolStyle) -> Outcome {
    let mesh = Mesh::start().await;

    let mut pool = match style {
        PoolStyle::Lazy => ClientPool::lazy(mesh.client_entrypoint).await,
        PoolStyle::Eager => ClientPool::eager(mesh.client_entrypoint).await,
    };
    pool.send_one_request().await;

    tokio::time::sleep(SETTLE).await;

    let outcome = Outcome {
        drained: false,
        client_connections_open: mesh.hop1.still_open(),
        reached_server_sidecar: mesh.hop2.accepted(),
        reached_tonic: mesh.server.connections_accepted(),
    };

    let drained = mesh.server.shutdown_and_wait().await;

    tracing::info!(
        ?style,
        pool = POOL_SIZE,
        hop1_accepted = mesh.hop1.accepted(),
        hop1_open = outcome.client_connections_open,
        hop2 = outcome.reached_server_sidecar,
        hop3 = outcome.reached_tonic,
        drained,
        "attempt finished"
    );

    Outcome { drained, ..outcome }
}

fn describe(attempt: usize, outcome: &Outcome) -> String {
    format!(
        "attempt {attempt}: client_open={}/{POOL_SIZE} reached_server_sidecar={} reached_tonic={} drained={}",
        outcome.client_connections_open,
        outcome.reached_server_sidecar,
        outcome.reached_tonic,
        outcome.drained,
    )
}

// =========================================================================
// The tests
// =========================================================================

/// THE ISSUE: a lazy `balance_channel` pool leaves preface-less connections
/// behind, they reach the server through both sidecars, and its graceful
/// shutdown never completes.
///
/// This is a race, so it is retried; it typically fails on the first or second
/// attempt.
#[tokio::test]
async fn lazy_pool_hangs_graceful_shutdown() {
    let _trace = trace_init();

    let mut log = Vec::new();

    for attempt in 1..=ATTEMPTS {
        let outcome = run_attempt(PoolStyle::Lazy).await;
        log.push(describe(attempt, &outcome));

        if !outcome.drained {
            for line in &log {
                println!("LAZY {line}");
            }
            assert!(
                outcome.reached_tonic > 1,
                "shutdown hung but only {} connection(s) reached tonic; \
                 the hang has some other cause",
                outcome.reached_tonic
            );
            return;
        }
    }

    for line in &log {
        println!("LAZY {line}");
    }
    panic!("lazy pool drained cleanly in all {ATTEMPTS} attempts; the race did not reproduce");
}

/// THE RESOLUTION: an eagerly-connected pool over `ServiceList` never leaves a
/// member parked, so the server always drains. Run the same number of times as
/// the test above, for a like-for-like comparison.
#[tokio::test]
async fn eager_pool_always_drains_cleanly() {
    let _trace = trace_init();

    for attempt in 1..=ATTEMPTS {
        let outcome = run_attempt(PoolStyle::Eager).await;
        println!("EAGER {}", describe(attempt, &outcome));

        assert!(
            outcome.drained,
            "eager pool failed to drain on attempt {attempt}: {} connection(s) reached tonic",
            outcome.reached_tonic
        );
        assert_eq!(
            outcome.client_connections_open, POOL_SIZE,
            "every eagerly-connected member should still be open on attempt {attempt}"
        );
    }
}
