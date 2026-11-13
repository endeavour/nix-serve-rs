//! Async Nix binary cache.
//!
//! The Perl nix-serve pins one Starman worker for an entire NAR download.
//! Starman defaults to five workers and writes the response with a blocking
//! `syswrite`, so five slow clients stop the process from calling `accept`.
//! This server accepts on the async runtime, streams each NAR on its own
//! task, and arms `TCP_USER_TIMEOUT` so a client that stops acknowledging
//! data cannot hold a download slot until the kernel retransmit timeout.

mod db;
mod nar;
mod nix32;
mod sign;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{OriginalUri, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use clap::Parser;
use http_body::Frame;
use http_body_util::StreamBody;
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Semaphore};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;
use tracing::{info, warn};

use crate::db::{basename, PathInfo, StoreDb};
use crate::sign::SecretKey;

#[derive(Parser, Debug)]
#[command(name = "nix-serve-rs", about = "Async Nix binary cache server")]
struct Args {
    /// TCP port to bind. Ignored when --listen is set.
    #[arg(long, default_value_t = 5000)]
    port: u16,

    /// Listen address, for example [::]:9500 or 0.0.0.0:9500.
    #[arg(long)]
    listen: Option<String>,

    /// Priority advertised in /nix-cache-info. Lower is preferred.
    #[arg(long, default_value_t = 30)]
    priority: i64,

    /// Nix store directory.
    #[arg(long, env = "NIX_STORE_DIR", default_value = "/nix/store")]
    store_dir: PathBuf,

    /// Nix SQLite database.
    #[arg(long, default_value = "/nix/var/nix/db/db.sqlite")]
    db: PathBuf,

    /// Secret key used to sign narinfo records. Same file nix-serve reads.
    #[arg(long, env = "NIX_SECRET_KEY_FILE")]
    secret_key_file: Option<PathBuf>,

    /// Drop a connection whose sent data stays unacknowledged this long.
    #[arg(long, default_value_t = 60)]
    write_timeout_secs: u64,

    /// Maximum NAR streams in flight. narinfo lookups are not limited by this.
    #[arg(long, default_value_t = 64)]
    nar_concurrency: usize,
}

#[derive(Clone)]
struct AppState {
    db: Arc<StoreDb>,
    secret: Option<SecretKey>,
    priority: i64,
    nar_slots: Arc<Semaphore>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let args = Args::parse();
    let secret = match &args.secret_key_file {
        Some(path) => {
            let text = std::fs::read_to_string(path).unwrap_or_else(|err| {
                panic!("reading secret key {}: {err}", path.display());
            });
            let key = SecretKey::parse(&text).unwrap_or_else(|err| panic!("{err}"));
            info!(key = %key.name, "loaded binary cache signing key");
            Some(key)
        }
        None => {
            warn!("NIX_SECRET_KEY_FILE is unset; narinfo responses will be unsigned");
            None
        }
    };
    let state = AppState {
        db: Arc::new(StoreDb::new(args.db, args.store_dir)),
        secret,
        priority: args.priority,
        nar_slots: Arc::new(Semaphore::new(args.nar_concurrency.max(1))),
    };
    let app = Router::new()
        .route("/nix-cache-info", get(cache_info))
        .fallback(get(dispatch))
        .with_state(state);

    let listener = bind_listener(args.listen.as_deref(), args.port).expect("bind listen socket");
    let local = listener.local_addr().expect("local addr");
    info!(%local, "nix-serve-rs listening");

    let write_timeout = Duration::from_secs(args.write_timeout_secs);
    let inflight = Arc::new(AtomicUsize::new(0));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => {
                info!("shutting down");
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(%err, "accept failed");
                        continue;
                    }
                };
                if let Err(err) = configure_stream(&stream, write_timeout) {
                    warn!(%peer, %err, "failed to configure accepted socket");
                }
                let service = TowerToHyperService::new(app.clone());
                let inflight = inflight.clone();
                inflight.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    if let Err(err) = hyper::server::conn::http1::Builder::new()
                        .keep_alive(true)
                        .serve_connection(io, service)
                        .await
                    {
                        tracing::debug!(%peer, %err, "connection ended");
                    }
                    inflight.fetch_sub(1, Ordering::Relaxed);
                });
            }
        }
    }

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while inflight.load(Ordering::Relaxed) > 0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn shutdown_signal() {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = terminate.recv() => {}
    }
}

fn bind_listener(listen: Option<&str>, port: u16) -> std::io::Result<TcpListener> {
    if let Some(listen) = listen {
        let addr: SocketAddr = listen
            .parse()
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        return bind_addr(addr);
    }
    match bind_addr(SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], port))) {
        Ok(listener) => Ok(listener),
        Err(ipv6_err) => {
            warn!(%ipv6_err, "IPv6 dual-stack bind failed, falling back to IPv4");
            bind_addr(SocketAddr::from(([0, 0, 0, 0], port)))
        }
    }
}

fn bind_addr(addr: SocketAddr) -> std::io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    if addr.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

fn configure_stream(stream: &TcpStream, write_timeout: Duration) -> std::io::Result<()> {
    let socket = socket2::SockRef::from(stream);
    socket.set_nodelay(true)?;
    // Unacknowledged data older than this aborts the connection. Unlike
    // SO_SNDTIMEO, this applies to non-blocking sockets, so a client that
    // stops reading cannot pin a NAR task for the TCP retransmit timeout.
    socket.set_tcp_user_timeout(Some(write_timeout))?;
    socket.set_keepalive(true)?;
    Ok(())
}

async fn cache_info(State(state): State<AppState>) -> impl IntoResponse {
    text(
        StatusCode::OK,
        "text/plain",
        format!(
            "StoreDir: {}\nWantMassQuery: 1\nPriority: {}\n",
            state.db.store_dir(),
            state.priority
        ),
    )
}

async fn dispatch(State(state): State<AppState>, OriginalUri(uri): OriginalUri) -> Response {
    let path = uri.path();
    if let Some(hash) = path.strip_prefix('/').and_then(|rest| rest.strip_suffix(".narinfo")) {
        if !hash.contains('/') {
            return narinfo(state, hash).await;
        }
    }
    if let Some(name) = path.strip_prefix("/nar/") {
        if !name.contains('/') {
            return nar(state, name).await;
        }
    }
    if let Some(name) = path.strip_prefix("/log/") {
        if !name.contains('/') {
            return log(state, name).await;
        }
    }
    text(StatusCode::NOT_FOUND, "text/plain", "File not found.\n")
}

async fn narinfo(state: AppState, hash: &str) -> Response {
    let Some(info) = (match state.db.lookup_hash_part(&hash) {
        Ok(info) => info,
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", format!("{err}\n")),
    }) else {
        return text(StatusCode::NOT_FOUND, "text/plain", "No such path.\n");
    };
    match render_narinfo(&state, &info) {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/x-nix-narinfo"),
                (header::CONTENT_LENGTH, &body.len().to_string()),
            ],
            body,
        )
            .into_response(),
        Err(err) => text(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", format!("{err}\n")),
    }
}

fn render_narinfo(state: &AppState, info: &PathInfo) -> Result<String, String> {
    let mut body = format!(
        "StorePath: {}\nURL: nar/{}-{}.nar\nCompression: none\nNarHash: sha256:{}\nNarSize: {}\n",
        info.path, info.hash_part, info.nar_hash_nix32, info.nar_hash_nix32, info.nar_size
    );
    if !info.references.is_empty() {
        body.push_str("References:");
        for reference in &info.references {
            body.push(' ');
            body.push_str(basename(reference));
        }
        body.push('\n');
    }
    if let Some(deriver) = &info.deriver {
        body.push_str("Deriver: ");
        body.push_str(basename(deriver));
        body.push('\n');
    }
    if let Some(secret) = &state.secret {
        let fingerprint = sign::fingerprint(
            &info.path,
            &info.nar_hash_nix32,
            info.nar_size,
            &info.references,
        );
        body.push_str("Sig: ");
        body.push_str(&secret.sign(&fingerprint));
        body.push('\n');
    } else {
        for signature in &info.sigs {
            body.push_str("Sig: ");
            body.push_str(signature);
            body.push('\n');
        }
    }
    Ok(body)
}

async fn nar(state: AppState, name: &str) -> Response {
    let Some((hash_part, expected)) = parse_nar_name(&name) else {
        return text(StatusCode::NOT_FOUND, "text/plain", "File not found.\n");
    };
    let info = match state.db.lookup_hash_part(hash_part) {
        Ok(Some(info)) => info,
        Ok(None) => return text(StatusCode::NOT_FOUND, "text/plain", "No such path.\n"),
        Err(err) => return text(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", format!("{err}\n")),
    };
    if let Some(expected) = expected {
        if expected != info.nar_hash_nix32 {
            return text(
                StatusCode::NOT_FOUND,
                "text/plain",
                "Incorrect NAR hash. Maybe the path has been recreated.\n",
            );
        }
    }
    let Ok(permit) = state.nar_slots.clone().try_acquire_owned() else {
        return text(
            StatusCode::SERVICE_UNAVAILABLE,
            "text/plain",
            "Too many NAR downloads in progress.\n",
        );
    };
    let path = PathBuf::from(&info.path);
    if !path.starts_with(state.db.store_dir()) {
        return text(StatusCode::NOT_FOUND, "text/plain", "No such path.\n");
    }
    let nar_size = info.nar_size;
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let _permit = permit;
        let mut writer = ChunkWriter { tx, buf: Vec::with_capacity(64 * 1024) };
        match nar::write_nar(&path, &mut writer).await {
            Ok(written) if written == nar_size => {
                if let Err(err) = writer.finish().await {
                    warn!(path = %path.display(), %err, "client went away during NAR");
                }
            }
            Ok(written) => {
                warn!(
                    path = %path.display(),
                    written,
                    expected = nar_size,
                    "NAR size did not match the database; aborting the response"
                );
                let _ = writer
                    .fail(std::io::Error::other("NAR size mismatch"))
                    .await;
            }
            Err(err) => {
                warn!(path = %path.display(), %err, "NAR dump failed");
                let _ = writer.fail(err).await;
            }
        }
    });
    let stream = ReceiverStream::new(rx).map(|item| item.map(Frame::data));
    let mut response = Response::new(Body::new(StreamBody::new(stream)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        header::HeaderValue::from_str(&nar_size.to_string()).expect("content length"),
    );
    response
}

fn parse_nar_name(name: &str) -> Option<(&str, Option<&str>)> {
    let stem = name.strip_suffix(".nar")?;
    if let Some((hash_part, nar_hash)) = stem.split_once('-') {
        if nix32::is_hash_part(hash_part) && nix32::is_nar_hash(nar_hash) {
            return Some((hash_part, Some(nar_hash)));
        }
        return None;
    }
    if nix32::is_hash_part(stem) {
        return Some((stem, None));
    }
    None
}

async fn log(state: AppState, name: &str) -> Response {
    if name.contains('/') || name.contains('\0') || !name.contains('-') {
        return text(StatusCode::NOT_FOUND, "text/plain", "File not found.\n");
    }
    let store_path = format!("{}/{name}", state.db.store_dir());
    let mut child = match tokio::process::Command::new("nix")
        .args(["log", "--", &store_path])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
    {
        Ok(child) => child,
        Err(err) => {
            return text(
                StatusCode::INTERNAL_SERVER_ERROR,
                "text/plain",
                format!("failed to run nix log: {err}\n"),
            );
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        return text(StatusCode::INTERNAL_SERVER_ERROR, "text/plain", "missing log pipe\n");
    };
    let (tx, rx) = mpsc::channel(8);
    tokio::spawn(async move {
        let mut writer = ChunkWriter { tx, buf: Vec::with_capacity(8 * 1024) };
        let mut buf = vec![0u8; 8 * 1024];
        let copy = async {
            loop {
                let read = tokio::io::AsyncReadExt::read(&mut stdout, &mut buf).await?;
                if read == 0 {
                    break;
                }
                crate::nar::NarWrite::write_all(&mut writer, &buf[..read]).await?;
            }
            Ok::<(), std::io::Error>(())
        }
        .await;
        let status = child.wait().await;
        match (copy, status) {
            (Ok(()), Ok(status)) if status.success() => {
                let _ = writer.finish().await;
            }
            _ => {
                let _ = writer
                    .fail(std::io::Error::other("build log unavailable"))
                    .await;
            }
        }
    });
    let stream = ReceiverStream::new(rx).map(|item| item.map(Frame::data));
    let mut response = Response::new(Body::new(StreamBody::new(stream)));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("text/plain"),
    );
    response
}

fn text(status: StatusCode, content_type: &'static str, body: impl Into<String>) -> Response {
    let body = body.into();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static(content_type),
    );
    response
}

struct ChunkWriter {
    tx: mpsc::Sender<Result<Bytes, std::io::Error>>,
    buf: Vec<u8>,
}

impl crate::nar::NarWrite for ChunkWriter {
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.buf.extend_from_slice(data);
        while self.buf.len() >= 64 * 1024 {
            let chunk = Bytes::copy_from_slice(&self.buf[..64 * 1024]);
            self.buf.drain(..64 * 1024);
            self.tx.send(Ok(chunk)).await.map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone")
            })?;
        }
        Ok(())
    }
}

impl ChunkWriter {
    async fn finish(mut self) -> std::io::Result<()> {
        self.flush_all().await
    }

    async fn fail(self, err: std::io::Error) -> std::io::Result<()> {
        self.tx
            .send(Err(err))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone"))
    }

    async fn flush_all(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx
            .send(Ok(chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "client gone"))
    }
}
