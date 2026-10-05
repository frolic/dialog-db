//! A measurement, not a check: how a client that follows N cells fares
//! over the service's socket. Native only, ignored by default. Run with
//!
//! ```sh
//! SCALE=1,100,1000,10000 DELAY_MS=0,20 cargo test -p dialog-remote-ucan \
//!   --features helpers --test socket_scale -- --ignored --nocapture
//! ```
//!
//! A proxy between client and socket delays every chunk by `DELAY_MS`
//! each way and counts the bytes. Each line it prints is one run.
#![cfg(all(feature = "helpers", not(target_arch = "wasm32")))]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dialog_capability::access::{Authorization as _, TimeRange};
use dialog_capability::{Ability, Capability, Effect, ForkInvocation, Provider, Subject};
use dialog_credentials::{Ed25519Signer, Signer};
use dialog_effects::memory::prelude::CellScope;
use dialog_effects::memory::{Editions, Publish, Watch};
use dialog_remote_ucan::helpers::UcanServer;
use dialog_remote_ucan::{UcanAddress, UcanAuthorization, UcanSite};
use dialog_ucan::Scope;
use dialog_varsig::Principal as _;
use futures_util::future::join_all;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};

/// A head as till writes it: a revision and the names of up to 64 nodes.
const HEAD_BYTES: usize = 1_500;

fn now_s() -> u64 {
    dialog_common::time::now()
        .duration_since(dialog_common::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or_default()
}

async fn issued<Fx>(signer: &Ed25519Signer, capability: &Capability<Fx>) -> UcanAuthorization
where
    Fx: Effect + Clone,
    Capability<Fx>: Ability,
{
    let at = now_s();
    let minting = dialog_ucan::UcanAuthorization {
        chain: None,
        signer: Signer::from(signer.clone()),
        scope: Scope::invoke(capability),
        duration: TimeRange {
            not_before: Some(at),
            expiration: Some(at + 600),
        },
        meta: None,
    };
    UcanAuthorization::from(minting.invoke().await.expect("the invocation mints"))
}

/// Bytes the proxy carried each way.
#[derive(Default)]
struct Counted {
    up: AtomicU64,
    down: AtomicU64,
    connections: AtomicU64,
}

/// A TCP proxy to `upstream` that holds every chunk for `delay` before
/// passing it on, in order, and counts the bytes.
async fn proxy(upstream: SocketAddr, delay: Duration, counted: Arc<Counted>) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            counted.connections.fetch_add(1, Ordering::Relaxed);
            let counted = counted.clone();
            tokio::spawn(async move {
                let Ok(server) = TcpStream::connect(upstream).await else {
                    return;
                };
                let (client_read, client_write) = client.into_split();
                let (server_read, server_write) = server.into_split();
                let up = counted.clone();
                tokio::spawn(pipe(client_read, server_write, delay, move |n| {
                    up.up.fetch_add(n, Ordering::Relaxed);
                }));
                tokio::spawn(pipe(server_read, client_write, delay, move |n| {
                    counted.down.fetch_add(n, Ordering::Relaxed);
                }));
            });
        }
    });
    address
}

async fn pipe(
    mut from: tokio::net::tcp::OwnedReadHalf,
    mut to: tokio::net::tcp::OwnedWriteHalf,
    delay: Duration,
    count: impl Fn(u64) + Send + 'static,
) {
    let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<(Instant, Vec<u8>)>();
    tokio::spawn(async move {
        while let Some((due, chunk)) = receiver.recv().await {
            tokio::time::sleep_until(due.into()).await;
            if to.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    let mut buffer = vec![0u8; 64 * 1024];
    while let Ok(read) = from.read(&mut buffer).await {
        if read == 0 {
            break;
        }
        count(read as u64);
        if sender
            .send((Instant::now() + delay, buffer[..read].to_vec()))
            .is_err()
        {
            break;
        }
    }
}

fn list(name: &str, default: &str) -> Vec<u64> {
    std::env::var(name)
        .unwrap_or_else(|_| default.into())
        .split(',')
        .filter_map(|item| item.trim().parse().ok())
        .collect()
}

fn socket_addr(url: &str) -> SocketAddr {
    url.trim_start_matches("ws://")
        .trim_end_matches('/')
        .parse()
        .unwrap()
}

/// Publish `HEAD_BYTES` to every cell over HTTP, 64 at a time.
async fn fill(server: &UcanServer, cells: &[(Ed25519Signer, CellScope)]) {
    let address = UcanAddress::new(&server.endpoint);
    for part in cells.chunks(64) {
        join_all(part.iter().map(|(signer, cell)| {
            let address = address.clone();
            async move {
                let publish = cell.publish(vec![7u8; HEAD_BYTES], None);
                let authorization = issued(signer, &publish).await;
                Provider::<ForkInvocation<UcanSite, Publish>>::execute(
                    &UcanSite::default(),
                    ForkInvocation::new(publish, address, authorization),
                )
                .await
                .expect("the cell fills");
            }
        }))
        .await;
    }
}

/// Watch every cell over one site, as a device would, and report the
/// cold start and one wake-up.
async fn run(label: &str, cells: Vec<(Ed25519Signer, CellScope)>, delay: Duration) {
    let count = cells.len();
    let server = UcanServer::start(1 << 20).await.unwrap();
    fill(&server, &cells).await;

    let counted = Arc::new(Counted::default());
    let proxied = proxy(socket_addr(&server.socket), delay, counted.clone()).await;
    let address = UcanAddress::new(&server.endpoint).with_socket(format!("ws://{proxied}/"));

    let minting = Instant::now();
    let mut watches = Vec::with_capacity(count);
    for (signer, cell) in &cells {
        let watch = cell.watch();
        let authorization = issued(signer, &watch).await;
        watches.push((watch, authorization));
    }
    let minted = minting.elapsed();

    let site = UcanSite::default();
    let started = Instant::now();
    let mut editions: Vec<Editions> = Vec::with_capacity(count);
    for (watch, authorization) in watches {
        editions.push(
            Provider::<ForkInvocation<UcanSite, Watch>>::execute(
                &site,
                ForkInvocation::new(watch, address.clone(), authorization),
            )
            .await
            .expect("the watch begins"),
        );
    }
    let sent = started.elapsed();
    let states = join_all(editions.iter_mut().map(|editions| editions.next())).await;
    let cold = started.elapsed();
    let held = states
        .iter()
        .filter(|state| matches!(state, Ok(Some(Some(_)))))
        .count();
    let refused = states.iter().filter(|state| state.is_err()).count();
    let (up, down) = (
        counted.up.load(Ordering::Relaxed),
        counted.down.load(Ordering::Relaxed),
    );

    // One wake-up: another device publishes the first cell over HTTP.
    let (signer, cell) = &cells[0];
    let version = match &states[0] {
        Ok(Some(Some(edition))) => Some(edition.version.clone()),
        _ => None,
    };
    let publish = cell.publish(vec![9u8; HEAD_BYTES], version);
    let authorization = issued(signer, &publish).await;
    let (up_before, down_before) = (
        counted.up.load(Ordering::Relaxed),
        counted.down.load(Ordering::Relaxed),
    );
    let waking = Instant::now();
    Provider::<ForkInvocation<UcanSite, Publish>>::execute(
        &UcanSite::default(),
        ForkInvocation::new(publish, UcanAddress::new(&server.endpoint), authorization),
    )
    .await
    .expect("the publish lands");
    let woke = editions[0].next().await;
    let wake = waking.elapsed();
    let woke_with_content =
        matches!(woke, Ok(Some(Some(ref edition))) if edition.content.len() == HEAD_BYTES);

    println!(
        "{label} n={count} delay_ms={} sockets={} mint_ms={} send_ms={} cold_ms={} held={held} refused={refused} \
         up_bytes={up} down_bytes={down} up_per_watch={} down_per_watch={} \
         wake_ms={} wake_down_bytes={} wake_up_bytes={} wake_carries_head={woke_with_content}",
        delay.as_millis(),
        counted.connections.load(Ordering::Relaxed),
        minted.as_millis(),
        sent.as_millis(),
        cold.as_millis(),
        up / count as u64,
        down / count as u64,
        wake.as_millis(),
        counted.down.load(Ordering::Relaxed) - down_before,
        counted.up.load(Ordering::Relaxed) - up_before,
    );
    drop(editions);
}

/// N cells of one subject: one space, so one socket.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement; run it by name"]
async fn one_space_n_cells() {
    for delay in list("DELAY_MS", "0,20") {
        for count in list("SCALE", "1,100,1000") {
            let signer = Ed25519Signer::generate().await.unwrap();
            let subject = Subject::from(signer.did());
            let cells = (0..count)
                .map(|index| {
                    (
                        signer.clone(),
                        CellScope::new(subject.clone(), "local", format!("head-{index}")),
                    )
                })
                .collect();
            run("one_space", cells, Duration::from_millis(delay)).await;
        }
    }
}

/// N subjects with one cell each, as N circles are: a socket per space.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "a measurement; run it by name"]
async fn n_spaces_one_cell_each() {
    for delay in list("DELAY_MS", "0,20") {
        for count in list("SPACES", "1,100,1000") {
            let mut cells = Vec::new();
            for _ in 0..count {
                let signer = Ed25519Signer::generate().await.unwrap();
                let subject = Subject::from(signer.did());
                cells.push((signer, CellScope::new(subject, "local", "main")));
            }
            run("n_spaces", cells, Duration::from_millis(delay)).await;
        }
    }
}
