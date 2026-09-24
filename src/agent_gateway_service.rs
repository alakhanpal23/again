//! Opt-in local gateway daemon with an OS-authenticated Unix transport.
//!
//! The daemon is an optimization boundary, not a new reuse authority. Every
//! MCP connection still constructs the normal repository-aware gateway and
//! earns reuse through the existing store proofs. The transport accepts only
//! the current effective uid, binds a canonical-workspace digest and random
//! bounded-lifetime session nonce in a fixed handshake, and publishes a random
//! socket name through an owner-private locator. No caller-provided bearer
//! token is accepted and possession of stale session material is insufficient.

use std::collections::BTreeMap;
use std::fs::{self, DirBuilder, File, FileType, Metadata, OpenOptions, Permissions};
use std::io::{self, BufReader, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent_gateway_runtime::ExperimentalMcpGatewayV1;
use crate::mcp_gateway::{
    AuthenticatedStdioRecipientV1, AuthorizationScopeId, MCP_PROTOCOL_VERSION,
};
use crate::store::Store;

const HANDSHAKE_MAGIC_V1: &[u8; 8] = b"AGNGW001";
const RESPONSE_MAGIC_V1: &[u8; 8] = b"AGNR0001";
const ENDPOINT_MAGIC_V1: &[u8; 8] = b"AGNEP001";
const COMPATIBILITY_DIGEST_BYTES_V1: usize = 32;
const SESSION_NONCE_BYTES_V1: usize = 16;
const SOCKET_NAME_BYTES_V1: usize = 32;
const ENDPOINT_BYTES_V1: usize = 8 + SESSION_NONCE_BYTES_V1 + SOCKET_NAME_BYTES_V1;
const HANDSHAKE_BYTES_V1: usize =
    8 + 1 + 32 + SESSION_NONCE_BYTES_V1 + COMPATIBILITY_DIGEST_BYTES_V1;
const MAX_CONTROL_PAYLOAD_BYTES_V1: usize = 4 * 1024;
const MAX_DAEMON_BINARY_BYTES_V1: u64 = 256 * 1024 * 1024;
const MAX_ACTIVE_CONNECTIONS_V1: usize = 128;
const HANDSHAKE_TIMEOUT_V1: Duration = Duration::from_secs(5);
const MCP_IDLE_READ_TIMEOUT_V1: Duration = Duration::from_secs(60);
const MCP_WRITE_TIMEOUT_V1: Duration = Duration::from_secs(10);
const MAX_SESSION_LIFETIME_V1: Duration = Duration::from_secs(8 * 60 * 60);
const SHUTDOWN_TIMEOUT_V1: Duration = Duration::from_secs(10);
const ACCEPT_POLL_V1: Duration = Duration::from_millis(10);
const DAEMON_IDLE_TIMEOUT_V1: Duration = Duration::from_secs(10 * 60);
const CONNECT_RETRY_TIMEOUT_V1: Duration = Duration::from_secs(2);
const CONNECT_RETRY_MIN_DELAY_V1: Duration = Duration::from_millis(5);
const CONNECT_RETRY_MAX_DELAY_V1: Duration = Duration::from_millis(200);

static TERMINATION_REQUESTED_V1: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ConnectionModeV1 {
    Mcp = 1,
    Status = 2,
    Stop = 3,
}

impl TryFrom<u8> for ConnectionModeV1 {
    type Error = GatewayServiceError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Mcp),
            2 => Ok(Self::Status),
            3 => Ok(Self::Stop),
            _ => Err(GatewayServiceError::InvalidHandshake),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ResponseCodeV1 {
    Ready = 0,
    Invalid = 1,
    Busy = 2,
    Internal = 3,
    Incompatible = 4,
    Draining = 5,
}

#[derive(Debug, Error)]
pub enum GatewayServiceError {
    #[error("gateway daemon requires a canonical repository directory")]
    InvalidWorkspace,
    #[error("gateway daemon socket parent is not an owner-private real directory")]
    UnsafeSocketParent,
    #[error("gateway daemon socket path is too long for the host Unix socket ABI")]
    SocketPathTooLong,
    #[error(
        "gateway daemon socket already exists; verify the daemon or remove only the stale socket"
    )]
    SocketExists,
    #[error("gateway daemon peer uid does not match the current effective uid")]
    WrongPeer,
    #[error("gateway daemon handshake is malformed or bound to another workspace")]
    InvalidHandshake,
    #[error("gateway daemon is at its bounded connection capacity")]
    Busy,
    #[error(
        "gateway daemon protocol or binary is incompatible; upgrade Again and reconnect after existing sessions drain"
    )]
    Incompatible,
    #[error("gateway daemon is draining existing sessions; retry after it exits")]
    Draining,
    #[error("gateway daemon peer authentication is unsupported on this platform")]
    UnsupportedPlatform,
    #[error("gateway daemon workers did not stop before the shutdown deadline")]
    ShutdownDeadline,
    #[error("gateway daemon I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("gateway daemon initialization failed")]
    Initialization,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct GatewayDaemonStatusV1 {
    schema_version: u16,
    status: String,
    workspace_digest: String,
    active_connections: usize,
    max_active_connections: usize,
    peer_authentication: String,
    protocol_version: String,
    binary_version: String,
    idle_timeout_seconds: u64,
}

impl GatewayDaemonStatusV1 {
    #[must_use]
    pub fn workspace_digest(&self) -> &str {
        &self.workspace_digest
    }

    #[must_use]
    pub const fn active_connections(&self) -> usize {
        self.active_connections
    }
}

struct RuntimeCleanupV1 {
    endpoint: PathBuf,
    endpoint_device: u64,
    endpoint_inode: u64,
    socket: PathBuf,
    socket_identity: Option<(u64, u64)>,
}

impl Drop for RuntimeCleanupV1 {
    fn drop(&mut self) {
        if let Some((device, inode)) = self.socket_identity
            && let Ok(metadata) = fs::symlink_metadata(&self.socket)
            && metadata.file_type().is_socket()
            && metadata.dev() == device
            && metadata.ino() == inode
        {
            let _ = fs::remove_file(&self.socket);
        }
        if let Ok(metadata) = fs::symlink_metadata(&self.endpoint)
            && metadata.file_type().is_file()
            && metadata.dev() == self.endpoint_device
            && metadata.ino() == self.endpoint_inode
        {
            let _ = fs::remove_file(&self.endpoint);
        }
    }
}

struct RuntimePathsV1 {
    root: PathBuf,
    lock: PathBuf,
    startup_lock: PathBuf,
    endpoint: PathBuf,
}

#[derive(Clone, Copy)]
struct HandshakeBindingV1 {
    workspace_digest: [u8; 32],
    session_nonce: [u8; SESSION_NONCE_BYTES_V1],
    compatibility_digest: [u8; COMPATIBILITY_DIGEST_BYTES_V1],
}

struct GatewaySessionOptionsV1 {
    authorization_scope: AuthorizationScopeId,
    execute_only: bool,
}

struct ActiveConnectionGuardV1 {
    id: u64,
    active: Arc<AtomicUsize>,
    peers: Arc<Mutex<BTreeMap<u64, UnixStream>>>,
    last_activity: Arc<Mutex<Instant>>,
}

impl Drop for ActiveConnectionGuardV1 {
    fn drop(&mut self) {
        self.peers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
        self.active.fetch_sub(1, Ordering::AcqRel);
        *self
            .last_activity
            .lock()
            .unwrap_or_else(|poison| poison.into_inner()) = Instant::now();
    }
}

/// A live daemon listener. Construction validates but never chmods an existing
/// parent. After acquiring the exclusive instance lock it can reclaim only a
/// validated crash-stale socket. Drop unlinks only the exact socket inode
/// created by this instance.
pub struct GatewayDaemonV1 {
    workspace: PathBuf,
    store: Arc<Mutex<Store>>,
    workspace_digest: [u8; 32],
    compatibility_digest: [u8; COMPATIBILITY_DIGEST_BYTES_V1],
    authorization_scope: AuthorizationScopeId,
    listener: UnixListener,
    runtime_cleanup: RuntimeCleanupV1,
    session_nonce: [u8; SESSION_NONCE_BYTES_V1],
    started: Instant,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    peers: Arc<Mutex<BTreeMap<u64, UnixStream>>>,
    last_activity: Arc<Mutex<Instant>>,
    idle_timeout: Duration,
    next_connection: AtomicU64,
    execute_only: bool,
    _instance_lock: File,
}

impl std::fmt::Debug for GatewayDaemonV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GatewayDaemonV1")
            .field("active", &self.active.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl GatewayDaemonV1 {
    pub fn bind(
        workspace: &Path,
        authorization_scope: AuthorizationScopeId,
    ) -> Result<Self, GatewayServiceError> {
        Self::bind_with_options_v1(
            workspace,
            authorization_scope,
            DAEMON_IDLE_TIMEOUT_V1,
            false,
        )
    }

    pub(crate) fn bind_execute_only_v1(
        workspace: &Path,
        authorization_scope: AuthorizationScopeId,
    ) -> Result<Self, GatewayServiceError> {
        Self::bind_with_options_v1(workspace, authorization_scope, DAEMON_IDLE_TIMEOUT_V1, true)
    }

    #[cfg(test)]
    fn bind_with_idle_timeout_v1(
        workspace: &Path,
        authorization_scope: AuthorizationScopeId,
        idle_timeout: Duration,
    ) -> Result<Self, GatewayServiceError> {
        Self::bind_with_options_v1(workspace, authorization_scope, idle_timeout, false)
    }

    fn bind_with_options_v1(
        workspace: &Path,
        authorization_scope: AuthorizationScopeId,
        idle_timeout: Duration,
        execute_only: bool,
    ) -> Result<Self, GatewayServiceError> {
        ensure_supported_platform_v1()?;
        let workspace =
            fs::canonicalize(workspace).map_err(|_| GatewayServiceError::InvalidWorkspace)?;
        if !workspace.is_dir() {
            return Err(GatewayServiceError::InvalidWorkspace);
        }

        // Open and validate the durable authority once per daemon. Each MCP
        // connection retains isolated protocol state over this shared store.
        let store = Arc::new(Mutex::new(
            Store::open_for_workspace(&workspace)
                .map_err(|_| GatewayServiceError::Initialization)?,
        ));
        let paths = gateway_runtime_paths_v1(&workspace, true)?;
        let instance_lock = acquire_instance_lock_v1(&paths.lock)?;
        cleanup_stale_endpoint_v1(&paths)?;
        let (listener, socket, session_nonce, endpoint_metadata, socket_metadata) =
            publish_endpoint_v1(&paths)?;
        let runtime_cleanup = RuntimeCleanupV1 {
            endpoint: paths.endpoint,
            endpoint_device: endpoint_metadata.dev(),
            endpoint_inode: endpoint_metadata.ino(),
            socket: socket.clone(),
            socket_identity: Some((socket_metadata.dev(), socket_metadata.ino())),
        };
        listener.set_nonblocking(true)?;
        let workspace_digest = canonical_workspace_digest_v1(&workspace);

        Ok(Self {
            workspace,
            store,
            workspace_digest,
            compatibility_digest: compatibility_digest_v1()?,
            authorization_scope,
            listener,
            runtime_cleanup,
            session_nonce,
            started: Instant::now(),
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
            peers: Arc::new(Mutex::new(BTreeMap::new())),
            last_activity: Arc::new(Mutex::new(Instant::now())),
            idle_timeout,
            next_connection: AtomicU64::new(1),
            execute_only,
            _instance_lock: instance_lock,
        })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.runtime_cleanup.socket
    }

    /// Run until an authenticated same-uid stop request arrives. Active MCP
    /// streams are then shut down, causing the existing gateway cleanup paths
    /// to cancel provider work and retire connection-bound grants.
    pub fn serve(self) -> Result<(), GatewayServiceError> {
        let mut workers = Vec::new();
        let mut worker_panicked = false;
        loop {
            if TERMINATION_REQUESTED_V1.load(Ordering::Acquire) {
                self.stop.store(true, Ordering::Release);
            }
            if self.started.elapsed() >= MAX_SESSION_LIFETIME_V1 {
                self.stop.store(true, Ordering::Release);
            }
            if self.active.load(Ordering::Acquire) == 0
                && self
                    .last_activity
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .elapsed()
                    >= self.idle_timeout
            {
                self.stop.store(true, Ordering::Release);
            }
            reap_finished_workers_v1(&mut workers, &mut worker_panicked);
            if worker_panicked {
                self.stop.store(true, Ordering::Release);
            }
            if self.stop.load(Ordering::Acquire) && self.active.load(Ordering::Acquire) == 0 {
                break;
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if authenticate_peer_v1(&stream).is_err()
                        || stream.set_nonblocking(false).is_err()
                        || stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT_V1)).is_err()
                        || stream
                            .set_write_timeout(Some(HANDSHAKE_TIMEOUT_V1))
                            .is_err()
                    {
                        continue;
                    }
                    if self.active.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS_V1 {
                        let mut stream = stream;
                        let _ = write_response_v1(
                            &mut stream,
                            ResponseCodeV1::Busy,
                            &serde_json::json!({
                                "schemaVersion": 1,
                                "status": "busy",
                                "guidance": "retry with bounded backoff"
                            }),
                        );
                        continue;
                    }
                    let Ok(peer_copy) = stream.try_clone() else {
                        continue;
                    };
                    let id = self.next_connection.fetch_add(1, Ordering::Relaxed);
                    self.peers
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .insert(id, peer_copy);
                    self.active.fetch_add(1, Ordering::AcqRel);
                    *self
                        .last_activity
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner()) = Instant::now();
                    let workspace = self.workspace.clone();
                    let store = Arc::clone(&self.store);
                    let handshake = HandshakeBindingV1 {
                        workspace_digest: self.workspace_digest,
                        session_nonce: self.session_nonce,
                        compatibility_digest: self.compatibility_digest,
                    };
                    let session_options = GatewaySessionOptionsV1 {
                        authorization_scope: self.authorization_scope.clone(),
                        execute_only: self.execute_only,
                    };
                    let stop = Arc::clone(&self.stop);
                    let active = Arc::clone(&self.active);
                    let active_for_handler = Arc::clone(&self.active);
                    let peers = Arc::clone(&self.peers);
                    let last_activity = Arc::clone(&self.last_activity);
                    workers.push(thread::spawn(move || {
                        let _guard = ActiveConnectionGuardV1 {
                            id,
                            active,
                            peers,
                            last_activity,
                        };
                        let _ = handle_connection_v1(
                            stream,
                            &workspace,
                            store,
                            handshake,
                            &session_options,
                            &stop,
                            &active_for_handler,
                        );
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(ACCEPT_POLL_V1);
                }
                Err(error) => return Err(error.into()),
            }
        }

        join_workers_until_v1(
            &mut workers,
            Instant::now() + SHUTDOWN_TIMEOUT_V1,
            &mut worker_panicked,
        )?;
        if worker_panicked {
            return Err(GatewayServiceError::Initialization);
        }
        Ok(())
    }
}

/// Install a signal-safe SIGTERM handler for the daemon CLI. The handler only
/// flips an atomic flag; normal daemon code performs connection retirement and
/// endpoint cleanup outside signal context.
pub fn install_termination_handler_v1() -> Result<(), GatewayServiceError> {
    extern "C" fn request_termination(_signal: libc::c_int) {
        TERMINATION_REQUESTED_V1.store(true, Ordering::Release);
    }

    TERMINATION_REQUESTED_V1.store(false, Ordering::Release);
    // SAFETY: `signal` installs a function with the required C ABI. The
    // function performs only a lock-free atomic store and retains no pointers.
    let previous =
        unsafe { libc::signal(libc::SIGTERM, request_termination as libc::sighandler_t) };
    if previous == libc::SIG_ERR {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

fn handle_connection_v1(
    mut stream: UnixStream,
    workspace: &Path,
    store: Arc<Mutex<Store>>,
    handshake: HandshakeBindingV1,
    session_options: &GatewaySessionOptionsV1,
    stop: &AtomicBool,
    active: &AtomicUsize,
) -> Result<(), GatewayServiceError> {
    let mode = read_handshake_v1(
        &mut stream,
        &handshake.workspace_digest,
        &handshake.session_nonce,
        &handshake.compatibility_digest,
    )?;
    match mode {
        ConnectionModeV1::Status => {
            let status = GatewayDaemonStatusV1 {
                schema_version: 1,
                status: if stop.load(Ordering::Acquire) {
                    "draining"
                } else {
                    "ready"
                }
                .to_owned(),
                workspace_digest: hex_digest_v1(&handshake.workspace_digest),
                active_connections: active.load(Ordering::Acquire),
                max_active_connections: MAX_ACTIVE_CONNECTIONS_V1,
                peer_authentication: peer_authentication_name_v1().to_owned(),
                protocol_version: MCP_PROTOCOL_VERSION.to_owned(),
                binary_version: env!("CARGO_PKG_VERSION").to_owned(),
                idle_timeout_seconds: DAEMON_IDLE_TIMEOUT_V1.as_secs(),
            };
            write_response_v1(&mut stream, ResponseCodeV1::Ready, &status)
        }
        ConnectionModeV1::Stop => {
            write_response_v1(
                &mut stream,
                ResponseCodeV1::Ready,
                &serde_json::json!({"schemaVersion":1,"status":"stopping"}),
            )?;
            stop.store(true, Ordering::Release);
            Ok(())
        }
        ConnectionModeV1::Mcp => {
            if stop.load(Ordering::Acquire) {
                return write_response_v1(
                    &mut stream,
                    ResponseCodeV1::Draining,
                    &serde_json::json!({
                        "schemaVersion": 1,
                        "status": "draining",
                        "guidance": "retry after the existing sessions finish"
                    }),
                );
            }
            // Finish all fallible per-session initialization before claiming
            // readiness. A client will receive a typed internal refusal, never
            // a successful handshake followed by unexplained EOF.
            let gateway = match if session_options.execute_only {
                ExperimentalMcpGatewayV1::build_with_shared_store_execute_only_v1(workspace, store)
            } else {
                ExperimentalMcpGatewayV1::build_with_shared_store_v1(workspace, store)
            } {
                Ok(gateway) => gateway,
                Err(_) => {
                    return write_response_v1(
                        &mut stream,
                        ResponseCodeV1::Internal,
                        &serde_json::json!({
                            "schemaVersion": 1,
                            "status": "initialization_failed",
                            "guidance": "retry with bounded backoff"
                        }),
                    );
                }
            };
            write_response_v1(
                &mut stream,
                ResponseCodeV1::Ready,
                &serde_json::json!({"schemaVersion":1,"status":"ready"}),
            )?;
            stream.set_read_timeout(Some(MCP_IDLE_READ_TIMEOUT_V1))?;
            stream.set_write_timeout(Some(MCP_WRITE_TIMEOUT_V1))?;
            let reader_stream = stream.try_clone()?;
            let mut reader = BufReader::new(reader_stream);
            let recipient = AuthenticatedStdioRecipientV1::issue_for_local_daemon_v1();
            gateway
                .serve_authenticated_io(
                    &mut reader,
                    &mut stream,
                    &session_options.authorization_scope,
                    recipient,
                )
                .map_err(GatewayServiceError::Io)
        }
    }
}

/// Connect to a live daemon and verify both the socket metadata and the
/// server's kernel-reported peer uid before sending any workspace identity.
pub fn connect_mcp_v1(workspace: &Path) -> Result<UnixStream, GatewayServiceError> {
    connect_mode_v1(workspace, ConnectionModeV1::Mcp).map(|(stream, _)| stream)
}

pub fn daemon_status_v1(workspace: &Path) -> Result<GatewayDaemonStatusV1, GatewayServiceError> {
    let (_, payload) = connect_mode_v1(workspace, ConnectionModeV1::Status)?;
    serde_json::from_slice(&payload).map_err(|_| GatewayServiceError::InvalidHandshake)
}

pub fn stop_daemon_v1(workspace: &Path) -> Result<(), GatewayServiceError> {
    let _ = connect_mode_v1(workspace, ConnectionModeV1::Stop)?;
    Ok(())
}

fn connect_mode_v1(
    workspace: &Path,
    mode: ConnectionModeV1,
) -> Result<(UnixStream, Vec<u8>), GatewayServiceError> {
    let deadline = Instant::now() + CONNECT_RETRY_TIMEOUT_V1;
    let mut attempt = 0_u32;
    loop {
        match connect_mode_once_v1(workspace, mode) {
            Ok(connected) => return Ok(connected),
            Err(error) if retryable_connect_error_v1(&error) && Instant::now() < deadline => {
                thread::sleep(connect_retry_delay_v1(attempt));
                attempt = attempt.saturating_add(1);
            }
            Err(error) => return Err(error),
        }
    }
}

fn connect_mode_once_v1(
    workspace: &Path,
    mode: ConnectionModeV1,
) -> Result<(UnixStream, Vec<u8>), GatewayServiceError> {
    ensure_supported_platform_v1()?;
    let workspace =
        fs::canonicalize(workspace).map_err(|_| GatewayServiceError::InvalidWorkspace)?;
    let paths = gateway_runtime_paths_v1(&workspace, false)?;
    let (socket, session_nonce) = read_endpoint_v1(&paths)?;
    validate_socket_file_v1(&socket)?;
    let mut stream = UnixStream::connect(&socket)?;
    authenticate_peer_v1(&stream)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT_V1))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT_V1))?;
    let digest = canonical_workspace_digest_v1(&workspace);
    let mut request = [0_u8; HANDSHAKE_BYTES_V1];
    request[..8].copy_from_slice(HANDSHAKE_MAGIC_V1);
    request[8] = mode as u8;
    request[9..41].copy_from_slice(&digest);
    request[41..41 + SESSION_NONCE_BYTES_V1].copy_from_slice(&session_nonce);
    request[41 + SESSION_NONCE_BYTES_V1..].copy_from_slice(&compatibility_digest_v1()?);
    stream.write_all(&request)?;
    stream.flush()?;
    let (code, payload) = read_response_v1(&mut stream)?;
    if code != ResponseCodeV1::Ready {
        return Err(match code {
            ResponseCodeV1::Busy => GatewayServiceError::Busy,
            ResponseCodeV1::Invalid => GatewayServiceError::InvalidHandshake,
            ResponseCodeV1::Internal => GatewayServiceError::Initialization,
            ResponseCodeV1::Incompatible => GatewayServiceError::Incompatible,
            ResponseCodeV1::Draining => GatewayServiceError::Draining,
            ResponseCodeV1::Ready => unreachable!(),
        });
    }
    if mode == ConnectionModeV1::Mcp {
        stream.set_read_timeout(Some(MCP_IDLE_READ_TIMEOUT_V1))?;
        stream.set_write_timeout(Some(MCP_WRITE_TIMEOUT_V1))?;
    }
    Ok((stream, payload))
}

fn retryable_connect_error_v1(error: &GatewayServiceError) -> bool {
    match error {
        GatewayServiceError::Busy | GatewayServiceError::Initialization => true,
        GatewayServiceError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::ConnectionAborted
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::Interrupted
                | io::ErrorKind::TimedOut
                | io::ErrorKind::UnexpectedEof
                | io::ErrorKind::WouldBlock
        ),
        _ => false,
    }
}

fn connect_retry_delay_v1(attempt: u32) -> Duration {
    let exponent = attempt.min(5);
    let base = CONNECT_RETRY_MIN_DELAY_V1
        .checked_mul(1_u32 << exponent)
        .unwrap_or(CONNECT_RETRY_MAX_DELAY_V1)
        .min(CONNECT_RETRY_MAX_DELAY_V1);
    let jitter = Duration::from_millis(
        (u64::from(std::process::id()) + u64::from(attempt).wrapping_mul(17)) % 11,
    );
    (base + jitter).min(CONNECT_RETRY_MAX_DELAY_V1)
}

fn read_handshake_v1(
    stream: &mut UnixStream,
    expected_workspace: &[u8; 32],
    expected_session_nonce: &[u8; SESSION_NONCE_BYTES_V1],
    expected_compatibility_digest: &[u8; COMPATIBILITY_DIGEST_BYTES_V1],
) -> Result<ConnectionModeV1, GatewayServiceError> {
    let mut request = [0_u8; HANDSHAKE_BYTES_V1];
    stream.read_exact(&mut request)?;
    if &request[..8] != HANDSHAKE_MAGIC_V1
        || &request[9..41] != expected_workspace
        || &request[41..41 + SESSION_NONCE_BYTES_V1] != expected_session_nonce
    {
        let _ = write_response_v1(
            stream,
            ResponseCodeV1::Invalid,
            &serde_json::json!({"schemaVersion":1,"status":"refused"}),
        );
        return Err(GatewayServiceError::InvalidHandshake);
    }
    if request[41 + SESSION_NONCE_BYTES_V1..] != *expected_compatibility_digest {
        let _ = write_response_v1(
            stream,
            ResponseCodeV1::Incompatible,
            &serde_json::json!({
                "schemaVersion": 1,
                "status": "incompatible",
                "guidance": "upgrade Again and reconnect after existing sessions drain"
            }),
        );
        return Err(GatewayServiceError::Incompatible);
    }
    ConnectionModeV1::try_from(request[8])
}

fn write_response_v1(
    stream: &mut UnixStream,
    code: ResponseCodeV1,
    payload: &impl Serialize,
) -> Result<(), GatewayServiceError> {
    let payload = serde_json::to_vec(payload).map_err(|_| GatewayServiceError::InvalidHandshake)?;
    if payload.len() > MAX_CONTROL_PAYLOAD_BYTES_V1 {
        return Err(GatewayServiceError::InvalidHandshake);
    }
    stream.write_all(RESPONSE_MAGIC_V1)?;
    stream.write_all(&[code as u8])?;
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(&payload)?;
    stream.flush()?;
    Ok(())
}

fn read_response_v1(
    stream: &mut UnixStream,
) -> Result<(ResponseCodeV1, Vec<u8>), GatewayServiceError> {
    let mut header = [0_u8; 13];
    stream.read_exact(&mut header)?;
    if &header[..8] != RESPONSE_MAGIC_V1 {
        return Err(GatewayServiceError::InvalidHandshake);
    }
    let code = match header[8] {
        0 => ResponseCodeV1::Ready,
        1 => ResponseCodeV1::Invalid,
        2 => ResponseCodeV1::Busy,
        3 => ResponseCodeV1::Internal,
        4 => ResponseCodeV1::Incompatible,
        5 => ResponseCodeV1::Draining,
        _ => return Err(GatewayServiceError::InvalidHandshake),
    };
    let length = u32::from_be_bytes(header[9..13].try_into().expect("fixed header")) as usize;
    if length > MAX_CONTROL_PAYLOAD_BYTES_V1 {
        return Err(GatewayServiceError::InvalidHandshake);
    }
    let mut payload = vec![0_u8; length];
    stream.read_exact(&mut payload)?;
    Ok((code, payload))
}

fn gateway_runtime_paths_v1(
    workspace: &Path,
    create_parent: bool,
) -> Result<RuntimePathsV1, GatewayServiceError> {
    let temporary = fs::canonicalize(std::env::temp_dir())?;
    let root = temporary.join(format!("again-{}", effective_uid_v1()));
    if create_parent && !root.exists() {
        match DirBuilder::new().mode(0o700).create(&root) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    validate_private_directory_v1(&root)?;
    let digest = canonical_workspace_digest_v1(workspace);
    let workspace_name = &hex_digest_v1(&digest)[..32];
    Ok(RuntimePathsV1 {
        lock: root.join(format!("gateway-{workspace_name}.lock")),
        startup_lock: root.join(format!("gateway-{workspace_name}.startup.lock")),
        endpoint: root.join(format!("gateway-{workspace_name}.endpoint")),
        root,
    })
}

/// Attempt to become the one connector allowed to spawn a workspace daemon.
/// The returned descriptor is the authority and releases automatically on
/// drop, including after connector failure or process death.
pub(crate) fn try_acquire_daemon_start_lock_v1(
    workspace: &Path,
) -> Result<Option<File>, GatewayServiceError> {
    ensure_supported_platform_v1()?;
    let workspace =
        fs::canonicalize(workspace).map_err(|_| GatewayServiceError::InvalidWorkspace)?;
    let paths = gateway_runtime_paths_v1(&workspace, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&paths.startup_lock)?;
    validate_regular_metadata_v1(&file.metadata()?)?;
    // SAFETY: flock operates on the live descriptor and retains no pointer.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(Some(file))
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Ok(None)
        } else {
            Err(error.into())
        }
    }
}

fn cleanup_stale_endpoint_v1(paths: &RuntimePathsV1) -> Result<(), GatewayServiceError> {
    let endpoint = match open_validated_regular_v1(&paths.endpoint) {
        Ok(file) => file,
        Err(GatewayServiceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let endpoint_metadata = endpoint.metadata()?;
    if let Ok((socket, _)) = decode_endpoint_v1(endpoint, &paths.root) {
        match fs::symlink_metadata(&socket) {
            Ok(_) => {
                validate_socket_file_v1(&socket)?;
                fs::remove_file(socket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    let current = fs::symlink_metadata(&paths.endpoint)?;
    if !current.file_type().is_file()
        || current.dev() != endpoint_metadata.dev()
        || current.ino() != endpoint_metadata.ino()
    {
        return Err(GatewayServiceError::UnsafeSocketParent);
    }
    fs::remove_file(&paths.endpoint)?;
    Ok(())
}

fn publish_endpoint_v1(
    paths: &RuntimePathsV1,
) -> Result<
    (
        UnixListener,
        PathBuf,
        [u8; SESSION_NONCE_BYTES_V1],
        Metadata,
        Metadata,
    ),
    GatewayServiceError,
> {
    let socket_name = uuid::Uuid::new_v4().simple().to_string();
    debug_assert_eq!(socket_name.len(), SOCKET_NAME_BYTES_V1);
    let socket = paths.root.join(&socket_name);
    // macOS has a 104-byte sockaddr_un.sun_path including NUL; Linux has 108.
    if socket.as_os_str().as_encoded_bytes().len() >= 104 {
        return Err(GatewayServiceError::SocketPathTooLong);
    }
    let session_nonce = *uuid::Uuid::new_v4().as_bytes();
    let temporary = paths
        .root
        .join(format!(".endpoint-{}.tmp", uuid::Uuid::new_v4().simple()));
    let mut socket_identity = None;
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)?;
        validate_regular_metadata_v1(&file.metadata()?)?;
        let mut encoded = [0_u8; ENDPOINT_BYTES_V1];
        encoded[..8].copy_from_slice(ENDPOINT_MAGIC_V1);
        encoded[8..24].copy_from_slice(&session_nonce);
        encoded[24..].copy_from_slice(socket_name.as_bytes());
        file.write_all(&encoded)?;
        file.sync_all()?;
        // Publish the locator last. A connector can therefore never observe a
        // socket between bind(2) and its final owner-private permissions.
        let listener = UnixListener::bind(&socket)?;
        let bound_metadata = observe_bound_socket_v1(&socket)?;
        socket_identity = Some((bound_metadata.dev(), bound_metadata.ino()));
        fs::set_permissions(&socket, Permissions::from_mode(0o600))?;
        let socket_metadata = validate_socket_file_v1(&socket)?;
        fs::rename(&temporary, &paths.endpoint)?;
        let metadata = fs::symlink_metadata(&paths.endpoint)?;
        validate_regular_metadata_v1(&metadata)?;
        Ok((
            listener,
            socket.clone(),
            session_nonce,
            metadata,
            socket_metadata,
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
        if let Some((device, inode)) = socket_identity
            && let Ok(metadata) = fs::symlink_metadata(&socket)
            && metadata.file_type().is_socket()
            && metadata.dev() == device
            && metadata.ino() == inode
        {
            let _ = fs::remove_file(socket);
        }
    }
    result
}

fn read_endpoint_v1(
    paths: &RuntimePathsV1,
) -> Result<(PathBuf, [u8; SESSION_NONCE_BYTES_V1]), GatewayServiceError> {
    let endpoint = open_validated_regular_v1(&paths.endpoint)?;
    decode_endpoint_v1(endpoint, &paths.root)
}

fn decode_endpoint_v1(
    mut endpoint: File,
    root: &Path,
) -> Result<(PathBuf, [u8; SESSION_NONCE_BYTES_V1]), GatewayServiceError> {
    let mut encoded = [0_u8; ENDPOINT_BYTES_V1];
    endpoint.read_exact(&mut encoded)?;
    let mut trailing = [0_u8; 1];
    if endpoint.read(&mut trailing)? != 0 || &encoded[..8] != ENDPOINT_MAGIC_V1 {
        return Err(GatewayServiceError::InvalidHandshake);
    }
    let socket_name =
        std::str::from_utf8(&encoded[24..]).map_err(|_| GatewayServiceError::InvalidHandshake)?;
    if !valid_socket_name_v1(socket_name) {
        return Err(GatewayServiceError::InvalidHandshake);
    }
    let mut session_nonce = [0_u8; SESSION_NONCE_BYTES_V1];
    session_nonce.copy_from_slice(&encoded[8..24]);
    Ok((root.join(socket_name), session_nonce))
}

fn valid_socket_name_v1(name: &str) -> bool {
    name.len() == SOCKET_NAME_BYTES_V1 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_private_directory_v1(path: &Path) -> Result<(), GatewayServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(GatewayServiceError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o7777 != 0o700
    {
        return Err(GatewayServiceError::UnsafeSocketParent);
    }
    Ok(())
}

fn validate_regular_metadata_v1(metadata: &Metadata) -> Result<(), GatewayServiceError> {
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(GatewayServiceError::UnsafeSocketParent);
    }
    Ok(())
}

fn open_validated_regular_v1(path: &Path) -> Result<File, GatewayServiceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    validate_regular_metadata_v1(&file.metadata()?)?;
    Ok(file)
}

fn observe_bound_socket_v1(path: &Path) -> Result<Metadata, GatewayServiceError> {
    let metadata = fs::symlink_metadata(path)?;
    if !is_socket_v1(metadata.file_type())
        || metadata.uid() != effective_uid_v1()
        || metadata.nlink() != 1
    {
        return Err(GatewayServiceError::WrongPeer);
    }
    Ok(metadata)
}

fn validate_socket_file_v1(path: &Path) -> Result<Metadata, GatewayServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(GatewayServiceError::Io)?;
    if !is_socket_v1(metadata.file_type())
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(GatewayServiceError::WrongPeer);
    }
    Ok(metadata)
}

fn acquire_instance_lock_v1(lock: &Path) -> Result<File, GatewayServiceError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(lock)?;
    let metadata = file.metadata()?;
    validate_regular_metadata_v1(&metadata)?;
    // SAFETY: flock operates on the live lock-file descriptor and retains no
    // pointer. The descriptor remains owned by GatewayDaemonV1 for its life.
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(file)
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::WouldBlock {
            Err(GatewayServiceError::SocketExists)
        } else {
            Err(GatewayServiceError::Io(error))
        }
    }
}

fn is_socket_v1(file_type: FileType) -> bool {
    file_type.is_socket()
}

fn canonical_workspace_digest_v1(workspace: &Path) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key("again.gateway-daemon-workspace.v1");
    hasher.update(workspace.as_os_str().as_encoded_bytes());
    *hasher.finalize().as_bytes()
}

fn compatibility_digest_v1() -> Result<[u8; COMPATIBILITY_DIGEST_BYTES_V1], GatewayServiceError> {
    let mut hasher = blake3::Hasher::new_derive_key("again.gateway-daemon-compatibility.v1");
    hasher.update(env!("CARGO_PKG_VERSION").as_bytes());
    hasher.update(&[0]);
    hasher.update(MCP_PROTOCOL_VERSION.as_bytes());
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let metadata = fs::symlink_metadata(&executable)?;
    if !metadata.is_file() || metadata.len() > MAX_DAEMON_BINARY_BYTES_V1 {
        return Err(GatewayServiceError::Initialization);
    }
    hasher.update(executable.as_os_str().as_encoded_bytes());
    hasher.update(&metadata.dev().to_be_bytes());
    hasher.update(&metadata.ino().to_be_bytes());
    hasher.update(&metadata.len().to_be_bytes());
    hasher.update(&metadata.mtime().to_be_bytes());
    hasher.update(&metadata.mtime_nsec().to_be_bytes());
    hasher.update(&metadata.ctime().to_be_bytes());
    hasher.update(&metadata.ctime_nsec().to_be_bytes());
    Ok(*hasher.finalize().as_bytes())
}

fn hex_digest_v1(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn effective_uid_v1() -> u32 {
    // SAFETY: geteuid has no preconditions and mutates no process state.
    unsafe { libc::geteuid() }
}

#[cfg(target_os = "macos")]
fn peer_uid_v1(stream: &UnixStream) -> io::Result<u32> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: both output pointers are valid and the fd is a live Unix stream.
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result == 0 {
        Ok(uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn peer_uid_v1(_stream: &UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "no reviewed peer-credential implementation for this platform",
    ))
}

fn ensure_supported_platform_v1() -> Result<(), GatewayServiceError> {
    if cfg!(any(target_os = "macos", target_os = "linux")) {
        Ok(())
    } else {
        Err(GatewayServiceError::UnsupportedPlatform)
    }
}

#[cfg(target_os = "linux")]
fn peer_uid_v1(stream: &UnixStream) -> io::Result<u32> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the option buffer and length pointer are valid for SO_PEERCRED.
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut credentials).cast(),
            &raw mut length,
        )
    };
    if result == 0 && length as usize == std::mem::size_of::<libc::ucred>() {
        Ok(credentials.uid)
    } else {
        Err(io::Error::last_os_error())
    }
}

fn authenticate_peer_v1(stream: &UnixStream) -> Result<(), GatewayServiceError> {
    ensure_supported_platform_v1()?;
    let observed = peer_uid_v1(stream).map_err(|_| GatewayServiceError::WrongPeer)?;
    authenticate_observed_peer_v1(Some(observed))
}

fn authenticate_observed_peer_v1(observed_uid: Option<u32>) -> Result<(), GatewayServiceError> {
    match observed_uid {
        Some(uid) if uid == effective_uid_v1() => Ok(()),
        Some(_) => Err(GatewayServiceError::WrongPeer),
        None => Err(GatewayServiceError::UnsupportedPlatform),
    }
}

fn peer_authentication_name_v1() -> &'static str {
    #[cfg(target_os = "linux")]
    return "so_peercred_euid";
    #[cfg(target_os = "macos")]
    return "getpeereid_euid";
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    return "unsupported";
}

fn reap_finished_workers_v1(workers: &mut Vec<thread::JoinHandle<()>>, worker_panicked: &mut bool) {
    let mut index = 0;
    while index < workers.len() {
        if workers[index].is_finished() {
            let worker = workers.swap_remove(index);
            *worker_panicked |= worker.join().is_err();
        } else {
            index += 1;
        }
    }
}

fn join_workers_until_v1(
    workers: &mut Vec<thread::JoinHandle<()>>,
    deadline: Instant,
    worker_panicked: &mut bool,
) -> Result<(), GatewayServiceError> {
    while !workers.is_empty() {
        reap_finished_workers_v1(workers, worker_panicked);
        if workers.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(GatewayServiceError::ShutdownDeadline);
        }
        thread::sleep(ACCEPT_POLL_V1);
    }
    Ok(())
}

/// Bidirectionally proxy the current standard streams to an authenticated MCP
/// daemon connection without spawning helper processes or buffering frames.
pub fn proxy_current_stdio_v1(mut stream: UnixStream) -> Result<(), GatewayServiceError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut input_open = true;
    let mut input_closed_at = None;
    let mut buffer = [0_u8; 16 * 1024];

    loop {
        if input_closed_at.is_some_and(|closed: Instant| closed.elapsed() >= Duration::from_secs(1))
        {
            return Ok(());
        }
        let mut descriptors = [
            libc::pollfd {
                fd: input.as_raw_fd(),
                events: if input_open { libc::POLLIN } else { 0 },
                revents: 0,
            },
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: the pollfd array is valid for its declared length and poll
        // does not retain the pointer after returning.
        let poll_timeout_ms = if input_open { -1 } else { 100 };
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as _,
                poll_timeout_ms,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if input_open && descriptors[0].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match input.read(&mut buffer)? {
                0 => {
                    input_open = false;
                    stream.shutdown(std::net::Shutdown::Write)?;
                    input_closed_at = Some(Instant::now());
                }
                count => stream.write_all(&buffer[..count])?,
            }
        }
        if input_open && descriptors[0].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            input_open = false;
            stream.shutdown(std::net::Shutdown::Write)?;
            input_closed_at = Some(Instant::now());
        }
        if descriptors[1].revents & (libc::POLLIN | libc::POLLHUP) != 0 {
            match stream.read(&mut buffer)? {
                0 => return Ok(()),
                count => {
                    output.write_all(&buffer[..count])?;
                    output.flush()?;
                }
            }
        }
        if descriptors[1].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("gateway daemon stream failed").into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp_gateway::MCP_PROTOCOL_VERSION;
    use serde_json::{Value, json};
    use std::io::BufRead;
    use std::os::unix::fs::symlink;
    use std::process::Command;
    use std::sync::Barrier;

    // Retrieval and lease tests use a read whose cost makes exact admission
    // eligible. Small files take the direct context lane.
    fn leased_read_fixture_v1(prefix: &str) -> String {
        format!("{prefix}{}", "x".repeat(8192))
    }

    struct LocalMcpClientV1 {
        stream: UnixStream,
        reader: BufReader<UnixStream>,
        next_id: u64,
    }

    impl LocalMcpClientV1 {
        fn connect(workspace: &Path) -> Self {
            let stream = connect_mcp_v1(workspace).unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            let mut client = Self {
                stream,
                reader,
                next_id: 1,
            };
            let initialized = client.request(
                "initialize",
                json!({
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": { "name": "context-test", "version": "1" }
                }),
            );
            assert_eq!(
                initialized["result"]["protocolVersion"],
                MCP_PROTOCOL_VERSION
            );
            client
        }

        fn tool(&mut self, name: &str, arguments: Value) -> Value {
            self.request(
                "tools/call",
                json!({ "name": name, "arguments": arguments }),
            )
        }

        fn request(&mut self, method: &str, params: Value) -> Value {
            let id = self.next_id;
            self.next_id += 1;
            let request = json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params
            });
            serde_json::to_writer(&mut self.stream, &request).unwrap();
            self.stream.write_all(b"\n").unwrap();
            self.stream.flush().unwrap();
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            assert!(
                !line.is_empty(),
                "daemon closed before replying to {method}"
            );
            let response: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(response["id"], id);
            response
        }

        fn notify(&mut self, method: &str, params: Value) {
            let request = json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params
            });
            serde_json::to_writer(&mut self.stream, &request).unwrap();
            self.stream.write_all(b"\n").unwrap();
            self.stream.flush().unwrap();
        }
    }

    #[test]
    fn unsafe_runtime_permissions_and_symlinked_locator_fail_closed_without_chmod() {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            validate_private_directory_v1(directory.path()),
            Err(GatewayServiceError::UnsafeSocketParent)
        ));
        assert_eq!(
            fs::symlink_metadata(directory.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o755
        );

        fs::set_permissions(directory.path(), Permissions::from_mode(0o700)).unwrap();
        let target = directory.path().join("target");
        fs::write(&target, [0_u8; ENDPOINT_BYTES_V1]).unwrap();
        fs::set_permissions(&target, Permissions::from_mode(0o600)).unwrap();
        let locator = directory.path().join("locator");
        symlink(&target, &locator).unwrap();
        assert!(open_validated_regular_v1(&locator).is_err());
        assert!(
            fs::symlink_metadata(&locator)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn unverifiable_or_different_uid_peer_never_authenticates() {
        assert_eq!(
            authenticate_observed_peer_v1(None).unwrap_err().to_string(),
            GatewayServiceError::UnsupportedPlatform.to_string()
        );
        assert_eq!(
            authenticate_observed_peer_v1(Some(effective_uid_v1().wrapping_add(1)))
                .unwrap_err()
                .to_string(),
            GatewayServiceError::WrongPeer.to_string()
        );
        assert!(authenticate_observed_peer_v1(Some(effective_uid_v1())).is_ok());
    }

    #[test]
    fn replayed_session_material_and_partial_handshakes_are_rejected() {
        let workspace = [7_u8; 32];
        let old_nonce = [3_u8; SESSION_NONCE_BYTES_V1];
        let current_nonce = [4_u8; SESSION_NONCE_BYTES_V1];
        let compatibility = compatibility_digest_v1().unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut replay = [0_u8; HANDSHAKE_BYTES_V1];
        replay[..8].copy_from_slice(HANDSHAKE_MAGIC_V1);
        replay[8] = ConnectionModeV1::Status as u8;
        replay[9..41].copy_from_slice(&workspace);
        replay[41..41 + SESSION_NONCE_BYTES_V1].copy_from_slice(&old_nonce);
        replay[41 + SESSION_NONCE_BYTES_V1..].copy_from_slice(&compatibility);
        client.write_all(&replay).unwrap();
        assert!(matches!(
            read_handshake_v1(&mut server, &workspace, &current_nonce, &compatibility),
            Err(GatewayServiceError::InvalidHandshake)
        ));

        let (mut slow_client, mut slow_server) = UnixStream::pair().unwrap();
        slow_server
            .set_read_timeout(Some(Duration::from_millis(25)))
            .unwrap();
        slow_client.write_all(HANDSHAKE_MAGIC_V1).unwrap();
        assert!(matches!(
            read_handshake_v1(&mut slow_server, &workspace, &current_nonce, &compatibility),
            Err(GatewayServiceError::Io(_))
        ));
    }

    #[test]
    fn incompatible_binary_handshake_is_actionable_without_touching_live_sessions() {
        let workspace = [7_u8; 32];
        let nonce = [4_u8; SESSION_NONCE_BYTES_V1];
        let compatibility = compatibility_digest_v1().unwrap();
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let mut request = [0_u8; HANDSHAKE_BYTES_V1];
        request[..8].copy_from_slice(HANDSHAKE_MAGIC_V1);
        request[8] = ConnectionModeV1::Status as u8;
        request[9..41].copy_from_slice(&workspace);
        request[41..41 + SESSION_NONCE_BYTES_V1].copy_from_slice(&nonce);
        request[41 + SESSION_NONCE_BYTES_V1..].fill(9);
        client.write_all(&request).unwrap();
        assert!(matches!(
            read_handshake_v1(&mut server, &workspace, &nonce, &compatibility),
            Err(GatewayServiceError::Incompatible)
        ));
        let (code, payload) = read_response_v1(&mut client).unwrap();
        assert_eq!(code, ResponseCodeV1::Incompatible);
        let payload: Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(payload["status"], "incompatible");
        assert!(payload["guidance"].as_str().unwrap().contains("upgrade"));
    }

    #[test]
    fn idle_daemon_retires_endpoint_after_bounded_inactivity() {
        let workspace = tempfile::tempdir().unwrap();
        let daemon = GatewayDaemonV1::bind_with_idle_timeout_v1(
            workspace.path(),
            AuthorizationScopeId::new("idle-test-scope").unwrap(),
            Duration::from_millis(30),
        )
        .unwrap();
        let socket = daemon.socket_path().to_owned();
        thread::spawn(move || daemon.serve().unwrap())
            .join()
            .unwrap();
        assert!(!socket.exists());
    }

    #[test]
    fn locator_encoding_accepts_only_fixed_random_socket_names() {
        assert!(valid_socket_name_v1("0123456789abcdef0123456789abcdef"));
        assert!(!valid_socket_name_v1("../shared.sock"));
        assert!(!valid_socket_name_v1("0123456789abcdef0123456789abcdeg"));
    }

    #[test]
    fn current_brain_preview_skips_index_and_stale_observation_does_not() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        let source = workspace.path().join("src/ledger.py");
        fs::write(
            &source,
            b"def balance_helper(value):\n    return value + 1\n",
        )
        .unwrap();
        let root = fs::canonicalize(workspace.path()).unwrap();
        let scope = AuthorizationScopeId::new(crate::brain::local_brain_scope_v1(&root)).unwrap();
        let daemon = GatewayDaemonV1::bind(&root, scope).unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(&root);
        let prior = agent.tool(
            "task.start",
            json!({ "taskId": "prior-ledger", "task": "Investigate ledger balance helper behavior" }),
        );
        let prior_task_id = prior["result"]["structuredContent"]["taskId"]
            .as_str()
            .unwrap();
        Store::open_for_workspace(&root)
            .unwrap()
            .record_brain_event_v1(&crate::store::BrainEventV1 {
                session_id: "prior-ledger-session".to_owned(),
                event_id: "prior-ledger-read".to_owned(),
                task_id: prior_task_id.to_owned(),
                kind: "command".to_owned(),
                path: Some("src/ledger.py".to_owned()),
                source_digest: Some(
                    blake3::hash(&fs::read(&source).unwrap())
                        .to_hex()
                        .to_string(),
                ),
                read_start_line: None,
                read_end_line: None,
                command_digest: Some("a".repeat(64)),
                command_hint: None,
                exit_code: Some(0),
                created_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
                authorization_scope_digest: Some(crate::brain::local_brain_scope_digest_v1(&root)),
            })
            .unwrap();
        let returning = agent.tool(
            "task.start",
            json!({ "taskId": "returning-ledger", "task": "Fix ledger balance helper behavior", "includeSourcePreviews": true }),
        );
        let brief = &returning["result"]["structuredContent"];
        assert_eq!(
            brief["relevantCode"]["unknowns"][0]["kind"],
            "index_skipped_for_current_brain_preview"
        );
        assert_eq!(
            brief["againBrain"]["recentCurrentFiles"][0]["path"],
            "src/ledger.py"
        );
        assert!(
            brief["againBrain"]["recentCurrentFiles"][0]["currentCompletePreview"]
                .as_str()
                .unwrap()
                .contains("balance_helper")
        );
        assert_eq!(brief["sourcePreviews"], json!([]));

        let weak_match = agent.tool(
            "task.start",
            json!({ "taskId": "weak-ledger", "task": "Repair ledger reconciliation", "includeSourcePreviews": true }),
        );
        let weak_brief = &weak_match["result"]["structuredContent"];
        assert_ne!(
            weak_brief["relevantCode"]["unknowns"][0]["kind"],
            "index_skipped_for_current_brain_preview"
        );

        fs::write(
            &source,
            b"def balance_helper(value):\n    return value + 2\n",
        )
        .unwrap();
        let changed = agent.tool(
            "task.start",
            json!({ "taskId": "changed-ledger", "task": "Fix ledger balance helper behavior", "includeSourcePreviews": true }),
        );
        assert_ne!(
            changed["result"]["structuredContent"]["relevantCode"]["unknowns"][0]["kind"],
            "index_skipped_for_current_brain_preview"
        );
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(&root).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn two_authenticated_clients_share_facts_work_retrieval_and_mutation_deltas() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("first\n"),
        )
        .unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            b"pub fn shared_symbol() -> usize { 1 }\n",
        )
        .unwrap();
        let brain_store = Store::open_for_workspace(workspace.path()).unwrap();
        brain_store
            .record_brain_event_v1(&crate::store::BrainEventV1 {
                session_id: "prior-session".to_owned(),
                event_id: "prior-edit".to_owned(),
                task_id: "prior-task".to_owned(),
                kind: "file_change".to_owned(),
                path: Some("src/lib.rs".to_owned()),
                source_digest: Some(
                    blake3::hash(&fs::read(workspace.path().join("src/lib.rs")).unwrap())
                        .to_hex()
                        .to_string(),
                ),
                read_start_line: None,
                read_end_line: None,
                command_digest: None,
                command_hint: None,
                exit_code: None,
                created_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as i64,
                authorization_scope_digest: Some(crate::brain::local_brain_scope_digest_v1(
                    workspace.path(),
                )),
            })
            .unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("same-user-test-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());

        let mut agent_a = LocalMcpClientV1::connect(workspace.path());
        let first_start = agent_a.tool(
            "task.start",
            json!({ "taskId": "shared-task", "task": "update shared_symbol", "includeSourcePreviews": true }),
        );
        assert_eq!(
            first_start["result"]["structuredContent"]["presentation"],
            "full"
        );
        assert!(first_start["result"]["structuredContent"]["againBrain"].is_null());
        let previews = first_start["result"]["structuredContent"]["sourcePreviews"]
            .as_array()
            .unwrap();
        assert_eq!(previews.len(), 1);
        assert_eq!(previews[0]["path"], "src/lib.rs");
        assert_eq!(
            previews[0]["text"],
            "pub fn shared_symbol() -> usize { 1 }\n"
        );
        assert_eq!(previews[0]["complete"], true);
        assert_eq!(
            previews[0]["sourceDigest"],
            crate::workspace_authority::StateDigestV1::from_domain_and_bytes(
                b"again.code-intelligence.source-bytes.v1",
                b"pub fn shared_symbol() -> usize { 1 }\n"
            )
            .to_hex()
        );
        let text = first_start["result"]["content"][0]["text"]
            .as_str()
            .unwrap();
        let summary: Value = serde_json::from_str(text).unwrap();
        assert_eq!(summary["sourcePreviews"].as_array().unwrap(), previews);
        assert_eq!(summary["fullStructuredResultAvailable"], true);
        assert!(
            text.len()
                < serde_json::to_string(&first_start["result"]["structuredContent"])
                    .unwrap()
                    .len()
        );
        let read = agent_a.tool("repo.read", json!({ "path": "input.txt" }));
        assert!(read.get("error").is_none(), "{read}");
        let result_id = read["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        let work = agent_a.tool(
            "context.publish",
            json!({
                "taskId": "shared-task",
                "kind": "work_start",
                "workKey": "inspect-input",
                "summary": "inspect the shared input",
                "ttlMs": 30_000
            }),
        );
        assert_eq!(
            work["result"]["structuredContent"]["outcome"]["status"],
            "leader"
        );
        let suggestion = agent_a.tool(
            "context.publish",
            json!({
                "taskId": "shared-task",
                "kind": "suggestion",
                "subject": "shared-symbol",
                "statement": "Check shared_symbol(), then preserve its public API.\nThis remains unverified."
            }),
        );
        assert_eq!(
            suggestion["result"]["structuredContent"]["outcome"]["verified"],
            false
        );

        let mut agent_b = LocalMcpClientV1::connect(workspace.path());
        let shared = agent_b.tool(
            "task.start",
            json!({ "taskId": "shared-task", "task": "update shared_symbol" }),
        );
        assert_eq!(
            shared["result"]["structuredContent"]["presentation"],
            "full"
        );
        assert_eq!(
            shared["result"]["structuredContent"]["sourcePreviews"],
            json!([])
        );
        let context = &shared["result"]["structuredContent"]["context"];
        assert!(!context["current_facts"].as_array().unwrap().is_empty());
        assert_eq!(
            context["current_facts"][0]["sources"][0]["locator"],
            "repo.read:input.txt"
        );
        assert!(!context["suggestions"].as_array().unwrap().is_empty());
        assert!(!context["result_references"].as_array().unwrap().is_empty());
        assert!(!context["inflight_work"].as_array().unwrap().is_empty());
        assert!(
            !shared["result"]["structuredContent"]["relevantCode"]["candidates"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let cursor = shared["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();

        let retrieved = agent_b.tool(
            "context.retrieve",
            json!({ "taskId": "shared-task", "resultId": result_id }),
        );
        assert_eq!(
            retrieved["result"]["structuredContent"]["presentation"],
            "full"
        );
        assert_eq!(
            retrieved["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("first\n")
        );
        let cross_task = agent_b.tool(
            "context.retrieve",
            json!({ "taskId": "other-task", "resultId": result_id }),
        );
        assert_eq!(
            cross_task["error"]["data"]["reason"], "retrieval_refused",
            "{cross_task}"
        );

        let compact = agent_b.tool(
            "task.start",
            json!({ "taskId": "shared-task", "task": "update shared_symbol" }),
        );
        assert_eq!(
            compact["result"]["structuredContent"]["presentation"],
            "compact"
        );

        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("second\n"),
        )
        .unwrap();
        let reread = agent_b.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            reread["result"]["content"][0]["text"],
            leased_read_fixture_v1("second\n")
        );
        let delta = agent_b.tool(
            "context.delta",
            json!({ "taskId": "shared-task", "afterCursor": cursor, "limit": 64 }),
        );
        let events = delta["result"]["structuredContent"]["delta"]["events"]
            .as_array()
            .unwrap();
        assert!(events.iter().any(|event| event["kind"] == "invalidation"));

        agent_b.notify(
            "notifications/again/context-compacted",
            json!({ "compactionGeneration": 1 }),
        );
        let stale_delta = agent_b.tool(
            "context.delta",
            json!({ "taskId": "shared-task", "afterCursor": cursor, "limit": 64 }),
        );
        assert_eq!(
            stale_delta["error"]["data"]["reason"],
            "full_delivery_required"
        );
        let after_compaction = agent_b.tool(
            "task.start",
            json!({ "taskId": "shared-task", "task": "update shared_symbol" }),
        );
        assert_eq!(
            after_compaction["result"]["structuredContent"]["presentation"],
            "full"
        );
        let overflow_cursor = after_compaction["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        for index in 0..65 {
            let published = agent_b.tool(
                "context.publish",
                json!({
                    "taskId": "shared-task",
                    "kind": "unknown",
                    "subject": format!("unknown-{index}"),
                    "explanation": "bounded follow-up required"
                }),
            );
            assert!(published.get("error").is_none(), "{published}");
        }
        let bounded = agent_b.tool(
            "context.delta",
            json!({
                "taskId": "shared-task",
                "afterCursor": overflow_cursor,
                "limit": 64
            }),
        );
        assert_eq!(
            bounded["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .len(),
            64
        );
        assert_eq!(
            bounded["result"]["structuredContent"]["delta"]["has_more"],
            true
        );

        for index in 0..63 {
            let task = agent_b.tool(
                "task.start",
                json!({ "taskId": format!("bounded-task-{index}") }),
            );
            assert!(task.get("error").is_none(), "{task}");
        }
        let capacity = agent_b.tool("task.start", json!({ "taskId": "one-task-too-many" }));
        assert_eq!(
            capacity["error"]["data"]["reason"],
            "context_capacity_exceeded"
        );

        let cancelled = agent_b.tool("context.cancel", json!({ "taskId": "shared-task" }));
        assert_eq!(
            cancelled["result"]["structuredContent"]["status"],
            "retired"
        );
        let retired = agent_b.tool(
            "task.start",
            json!({ "taskId": "shared-task", "task": "must use a new lifecycle" }),
        );
        assert_eq!(
            retired["error"]["data"]["reason"],
            "task_definition_conflict"
        );

        agent_b.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent_a.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn preview_only_task_start_keeps_coordination_lease_available() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(workspace.path().join("source.py"), b"value = 1\n").unwrap();
        let scope = AuthorizationScopeId::new("prebrief-scope").unwrap();
        let daemon = GatewayDaemonV1::bind(workspace.path(), scope).unwrap();
        let server = thread::spawn(move || daemon.serve());

        let mut launcher = LocalMcpClientV1::connect(workspace.path());
        let preview = launcher.tool(
            "task.start",
            json!({
                "taskId": "edit-source",
                "task": "edit source.py",
                "includeSourcePreviews": true,
                "previewOnly": true
            }),
        );
        assert_eq!(
            preview["result"]["structuredContent"]["coordination"]["status"],
            "preview"
        );
        assert_eq!(
            preview["result"]["structuredContent"]["coordination"]["peerActive"],
            false
        );
        assert!(
            preview["result"]["structuredContent"]["coordination"]
                .get("leaseId")
                .is_none()
        );
        launcher.stream.shutdown(std::net::Shutdown::Both).unwrap();

        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let claimed = agent.tool(
            "task.start",
            json!({ "taskId": "edit-source", "task": "edit source.py" }),
        );
        assert_eq!(
            claimed["result"]["structuredContent"]["coordination"]["status"],
            "leader"
        );
        let mut observer = LocalMcpClientV1::connect(workspace.path());
        let peer_preview = observer.tool(
            "task.start",
            json!({ "taskId": "edit-source", "task": "edit source.py", "previewOnly": true }),
        );
        assert_eq!(
            peer_preview["result"]["structuredContent"]["coordination"]["peerActive"],
            true
        );
        observer.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn exact_prompts_converge_task_aliases_and_survive_daemon_restart() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            b"pub fn shared_task() {}\n",
        )
        .unwrap();
        let scope = AuthorizationScopeId::new("task-intent-scope").unwrap();
        let daemon = GatewayDaemonV1::bind(workspace.path(), scope.clone()).unwrap();
        let server = thread::spawn(move || daemon.serve());

        let mut agent_a = LocalMcpClientV1::connect(workspace.path());
        let mut agent_b = LocalMcpClientV1::connect(workspace.path());
        let first = agent_a.tool(
            "task.start",
            json!({ "taskId": "external-a", "task": "repair shared_task without changing its API" }),
        );
        assert_eq!(first["result"]["structuredContent"]["taskId"], "external-a");
        assert_eq!(
            first["result"]["structuredContent"]["taskIntent"]["matchedBy"],
            "created"
        );
        assert_eq!(
            first["result"]["structuredContent"]["coordination"]["status"],
            "leader"
        );
        let first_cursor = first["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();

        let joined = agent_b.tool(
            "task.start",
            json!({ "taskId": "external-b", "task": "repair shared_task without changing its API" }),
        );
        assert_eq!(
            joined["result"]["structuredContent"]["taskId"],
            "external-a"
        );
        assert_eq!(
            joined["result"]["structuredContent"]["requestedTaskId"],
            "external-b"
        );
        assert_eq!(
            joined["result"]["structuredContent"]["taskIntent"]["matchedBy"],
            "joined_by_prompt"
        );
        assert_eq!(
            joined["result"]["structuredContent"]["coordination"]["status"],
            "join"
        );

        let lease_id = first["result"]["structuredContent"]["coordination"]["leaseId"]
            .as_str()
            .unwrap();
        let renewed = agent_a.tool(
            "context.publish",
            json!({
                "taskId": "external-a",
                "kind": "work_heartbeat",
                "leaseId": lease_id,
                "ttlMs": 300_000
            }),
        );
        assert_eq!(
            renewed["result"]["structuredContent"]["outcome"]["status"],
            "renewed"
        );
        let follower_renewal = agent_b.tool(
            "context.publish",
            json!({
                "taskId": "external-b",
                "kind": "work_heartbeat",
                "leaseId": lease_id,
                "ttlMs": 300_000
            }),
        );
        assert_eq!(
            follower_renewal["error"]["data"]["reason"], "owner_mismatch",
            "{follower_renewal}"
        );

        let published = agent_b.tool(
            "context.publish",
            json!({
                "taskId": "external-b",
                "kind": "unknown",
                "subject": "shared-task-constraint",
                "explanation": "confirm callers before editing"
            }),
        );
        assert!(published.get("error").is_none(), "{published}");
        let shared_delta = agent_a.tool(
            "context.delta",
            json!({ "taskId": "external-a", "afterCursor": first_cursor, "limit": 64 }),
        );
        assert!(
            shared_delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "explicit_unknown")
        );

        let conflict = agent_b.tool(
            "task.start",
            json!({ "taskId": "external-b", "task": "delete the public API" }),
        );
        assert_eq!(
            conflict["error"]["data"]["reason"],
            "task_definition_conflict"
        );

        agent_b.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent_a.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();

        let daemon = GatewayDaemonV1::bind(workspace.path(), scope).unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent_c = LocalMcpClientV1::connect(workspace.path());
        let restarted = agent_c.tool(
            "task.start",
            json!({ "taskId": "external-c", "task": "repair shared_task without changing its API" }),
        );
        assert_eq!(
            restarted["result"]["structuredContent"]["taskId"],
            "external-a"
        );
        assert_eq!(
            restarted["result"]["structuredContent"]["taskIntent"]["matchedBy"],
            "joined_by_prompt"
        );
        assert_eq!(
            restarted["result"]["structuredContent"]["coordination"]["status"],
            "leader"
        );
        agent_c.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn paired_agents_converge_and_invalidate_as_one_local_product() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("first\n"),
        )
        .unwrap();
        fs::write(workspace.path().join("unrelated.txt"), b"stable\n").unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(
            workspace.path().join("src/lib.rs"),
            b"pub fn shared_value() -> &'static str { \"first\" }\n",
        )
        .unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("paired-product-gate-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());

        let mut agent_a = LocalMcpClientV1::connect(workspace.path());
        let mut agent_b = LocalMcpClientV1::connect(workspace.path());
        let start_a = agent_a.tool(
            "task.start",
            json!({ "taskId": "paired-gate", "task": "update shared_value safely" }),
        );
        let start_b = agent_b.tool(
            "task.start",
            json!({ "taskId": "paired-gate", "task": "update shared_value safely" }),
        );
        for start in [&start_a, &start_b] {
            assert_eq!(start["result"]["structuredContent"]["presentation"], "full");
            assert_eq!(
                start["result"]["structuredContent"]["validationPreview"]["status"],
                "execute_required"
            );
            assert!(
                start["result"]["structuredContent"]["validationPreview"]["selectors"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "an unqualified validation profile supplied a reusable selector"
            );
        }
        let start_cursor_a = start_a["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let start_cursor_b = start_b["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();

        let barrier = Arc::new(Barrier::new(3));
        let barrier_a = Arc::clone(&barrier);
        let reader_a = thread::spawn(move || {
            barrier_a.wait();
            let read = agent_a.tool("repo.read", json!({ "path": "input.txt" }));
            (agent_a, read)
        });
        let barrier_b = Arc::clone(&barrier);
        let reader_b = thread::spawn(move || {
            barrier_b.wait();
            let read = agent_b.tool("repo.read", json!({ "path": "input.txt" }));
            (agent_b, read)
        });
        barrier.wait();
        let (mut agent_a, read_a) = reader_a.join().unwrap();
        let (mut agent_b, read_b) = reader_b.join().unwrap();
        assert_eq!(read_a["result"]["content"], read_b["result"]["content"]);
        let initial_result_id = read_a["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            read_b["result"]["_meta"]["again"]["resultId"],
            initial_result_id
        );

        let stats = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.requested, 2, "{stats:?}");
        assert_eq!(stats.executed, 1, "{stats:?}");
        assert_eq!(stats.exact_hits + stats.inflight_joins, 1, "{stats:?}");
        assert_eq!(stats.false_hit_quarantines, 0, "{stats:?}");

        let delta_a = agent_a.tool(
            "context.delta",
            json!({ "taskId": "paired-gate", "afterCursor": start_cursor_a, "limit": 64 }),
        );
        let delta_b = agent_b.tool(
            "context.delta",
            json!({ "taskId": "paired-gate", "afterCursor": start_cursor_b, "limit": 64 }),
        );
        for delta in [&delta_a, &delta_b] {
            let events = delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap_or_else(|| panic!("context delta failed: {delta}"));
            assert!(
                events
                    .iter()
                    .any(|event| event["kind"] == "verified_fact_admission")
            );
            assert!(
                events
                    .iter()
                    .any(|event| event["kind"] == "result_reference")
            );
        }
        let admitted_cursor_a = delta_a["result"]["structuredContent"]["delta"]["cursor"]
            .as_u64()
            .unwrap();
        let admitted_cursor_b = delta_b["result"]["structuredContent"]["delta"]["cursor"]
            .as_u64()
            .unwrap();

        let retrieved = agent_b.tool(
            "context.retrieve",
            json!({ "taskId": "paired-gate", "resultId": initial_result_id }),
        );
        assert_eq!(
            retrieved["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("first\n")
        );
        for compact in [
            agent_a.tool(
                "task.start",
                json!({ "taskId": "paired-gate", "task": "update shared_value safely" }),
            ),
            agent_b.tool(
                "task.start",
                json!({ "taskId": "paired-gate", "task": "update shared_value safely" }),
            ),
        ] {
            assert_eq!(
                compact["result"]["structuredContent"]["presentation"],
                "compact"
            );
        }

        fs::write(
            workspace.path().join("unrelated.txt"),
            b"changed elsewhere\n",
        )
        .unwrap();
        let preserved = agent_a.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            preserved["result"]["content"][0]["text"],
            leased_read_fixture_v1("first\n")
        );
        assert!(preserved["result"].get("_meta").is_none());
        let after_irrelevant = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        // The repeated small read executes directly: fresh provider bytes are
        // cheaper than proving a cache hit, while the original verified fact
        // and reference remain available to the second agent.
        assert_eq!(after_irrelevant.executed, 2, "{after_irrelevant:?}");
        let quiet = agent_a.tool(
            "context.delta",
            json!({ "taskId": "paired-gate", "afterCursor": admitted_cursor_a, "limit": 64 }),
        );
        assert!(
            quiet["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .is_empty(),
            "an unrelated content edit invalidated the exact read"
        );

        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("second\n"),
        )
        .unwrap();
        let changed = agent_a.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            changed["result"]["content"][0]["text"],
            leased_read_fixture_v1("second\n")
        );
        let changed_result_id = changed["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_ne!(changed_result_id, initial_result_id);
        let after_relevant = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        // Divergence first consumes one direct observation, then the full
        // proof path executes once more to publish the changed source.
        assert_eq!(after_relevant.executed, 4, "{after_relevant:?}");
        assert_eq!(
            after_relevant.false_hit_quarantines, 0,
            "{after_relevant:?}"
        );

        let mutation_a = agent_a.tool(
            "context.delta",
            json!({ "taskId": "paired-gate", "afterCursor": admitted_cursor_a, "limit": 64 }),
        );
        let mutation_b = agent_b.tool(
            "context.delta",
            json!({ "taskId": "paired-gate", "afterCursor": admitted_cursor_b, "limit": 64 }),
        );
        for delta in [&mutation_a, &mutation_b] {
            assert!(
                delta["result"]["structuredContent"]["delta"]["events"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|event| event["kind"] == "invalidation"),
                "a recipient missed the relevant mutation delta"
            );
        }
        let stale_retrieval = agent_b.tool(
            "context.retrieve",
            json!({ "taskId": "paired-gate", "resultId": initial_result_id }),
        );
        assert_eq!(
            stale_retrieval["error"]["data"]["reason"],
            "retrieval_refused"
        );
        let current_retrieval = agent_b.tool(
            "context.retrieve",
            json!({ "taskId": "paired-gate", "resultId": changed_result_id }),
        );
        assert_eq!(
            current_retrieval["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("second\n")
        );

        fs::write(workspace.path().join("unrelated.txt"), b"changed twice\n").unwrap();
        let warm = agent_a.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            warm["result"]["content"][0]["text"],
            leased_read_fixture_v1("second\n")
        );
        assert!(warm["result"].get("_meta").is_none());
        let final_stats = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        assert_eq!(final_stats.executed, 5, "{final_stats:?}");
        assert_eq!(final_stats.false_hit_quarantines, 0, "{final_stats:?}");

        agent_b.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent_a.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn repeated_task_search_uses_fresh_output_and_rebuilds_context_after_mutation() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        fs::write(workspace.path().join("src/a.py"), b"needle = 1\n").unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("task-search-value-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "search-task", "task": "inspect needle references" }),
        );
        let cursor = start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let arguments = json!({ "path": "src", "pattern": "needle" });
        let first = agent.tool("repo.search", arguments.clone());
        let original_result_id = first["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        let repeat = agent.tool("repo.search", arguments.clone());
        assert_eq!(first["result"]["content"], repeat["result"]["content"]);
        assert!(repeat["result"].get("_meta").is_none());
        let stats = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.executed, 2, "{stats:?}");
        assert_eq!(stats.exact_hits, 0, "{stats:?}");

        fs::write(workspace.path().join("src/a.py"), b"other = 1\n").unwrap();
        let changed = agent.tool("repo.search", arguments);
        assert_eq!(
            changed["result"]["structuredContent"]["matches"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let changed_result_id = changed["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap();
        assert_ne!(changed_result_id, original_result_id);
        let delta = agent.tool(
            "context.delta",
            json!({ "taskId": "search-task", "afterCursor": cursor, "limit": 64 }),
        );
        assert!(
            delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation")
        );
        let stale = agent.tool(
            "context.retrieve",
            json!({ "taskId": "search-task", "resultId": original_result_id }),
        );
        assert_eq!(stale["error"]["data"]["reason"], "retrieval_refused");
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn repeated_large_task_read_compares_the_stored_digest_without_reuse() {
        let workspace = tempfile::tempdir().unwrap();
        let content = "x".repeat(300_000);
        fs::write(workspace.path().join("large.txt"), &content).unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("large-task-read-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "large-read", "task": "inspect large.txt" }),
        );
        assert!(start.get("error").is_none(), "{start}");
        let first = agent.tool("repo.read", json!({ "path": "large.txt" }));
        assert!(first["result"]["_meta"]["again"]["resultId"].is_string());
        let repeat = agent.tool("repo.read", json!({ "path": "large.txt" }));
        assert_eq!(repeat["result"]["content"][0]["text"], content);
        assert!(repeat["result"].get("_meta").is_none());
        let stats = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.executed, 2, "{stats:?}");
        assert_eq!(stats.exact_hits, 0, "{stats:?}");
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn deleted_task_source_retires_its_verified_fact_and_reference() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("current\n"),
        )
        .unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("deleted-task-source-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let mut peer = LocalMcpClientV1::connect(workspace.path());
        let mut other_task_agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "deleted-source", "task": "inspect input.txt" }),
        );
        let peer_start = peer.tool(
            "task.start",
            json!({ "taskId": "deleted-source", "task": "inspect input.txt" }),
        );
        assert!(peer_start.get("error").is_none(), "{peer_start}");
        let peer_cursor = peer_start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let cursor = start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let first = agent.tool("repo.read", json!({ "path": "input.txt" }));
        let result_id = first["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        let shared = peer.tool(
            "context.retrieve",
            json!({ "taskId": "deleted-source", "resultId": result_id }),
        );
        assert_eq!(
            shared["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("current\n")
        );
        let other_start = other_task_agent.tool(
            "task.start",
            json!({ "taskId": "other-source-task", "task": "inspect the same file" }),
        );
        assert!(other_start.get("error").is_none(), "{other_start}");
        let other_cursor = other_start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let other_read = other_task_agent.tool("repo.read", json!({ "path": "input.txt" }));
        let other_result_id = other_read["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        // Restore the first task's warm candidate after the second task read.
        let warm = agent.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            warm["result"]["content"][0]["text"],
            leased_read_fixture_v1("current\n")
        );
        fs::remove_file(workspace.path().join("input.txt")).unwrap();
        let missing = agent.tool("repo.read", json!({ "path": "input.txt" }));
        assert!(missing.get("error").is_some(), "{missing}");
        let delta = agent.tool(
            "context.delta",
            json!({ "taskId": "deleted-source", "afterCursor": cursor, "limit": 64 }),
        );
        assert!(
            delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation"),
            "deleted source remained current: {delta}"
        );
        let peer_delta = peer.tool(
            "context.delta",
            json!({ "taskId": "deleted-source", "afterCursor": peer_cursor, "limit": 64 }),
        );
        assert!(
            peer_delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation"),
            "peer missed deleted-source invalidation: {peer_delta}"
        );
        let stale = peer.tool(
            "context.retrieve",
            json!({ "taskId": "deleted-source", "resultId": result_id }),
        );
        assert_eq!(
            stale["error"]["data"]["reason"], "retrieval_refused",
            "{stale}"
        );
        let other_delta = other_task_agent.tool(
            "context.delta",
            json!({ "taskId": "other-source-task", "afterCursor": other_cursor, "limit": 64 }),
        );
        assert!(
            other_delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation"),
            "other task missed source invalidation: {other_delta}"
        );
        let other_stale = other_task_agent.tool(
            "context.retrieve",
            json!({ "taskId": "other-source-task", "resultId": other_result_id }),
        );
        assert_eq!(
            other_stale["error"]["data"]["reason"], "retrieval_refused",
            "{other_stale}"
        );
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("current\n"),
        )
        .unwrap();
        let restored = agent.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            restored["result"]["content"][0]["text"],
            leased_read_fixture_v1("current\n")
        );
        let restored_result_id = restored["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap();
        assert_ne!(restored_result_id, result_id);
        let recovered = peer.tool(
            "context.retrieve",
            json!({ "taskId": "deleted-source", "resultId": restored_result_id }),
        );
        assert_eq!(
            recovered["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("current\n"),
            "restored source did not regain a verified reference: {recovered}"
        );
        let other_restored = other_task_agent.tool("repo.read", json!({ "path": "input.txt" }));
        let other_restored_id = other_restored["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap_or_else(|| {
                panic!("other task did not admit restored result: {other_restored}")
            });
        let other_recovered = other_task_agent.tool(
            "context.retrieve",
            json!({ "taskId": "other-source-task", "resultId": other_restored_id }),
        );
        assert_eq!(
            other_recovered["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("current\n"),
            "other task did not regain a verified reference: {other_recovered}"
        );
        peer.stream.shutdown(std::net::Shutdown::Both).unwrap();
        other_task_agent
            .stream
            .shutdown(std::net::Shutdown::Both)
            .unwrap();
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn task_start_revalidates_unobserved_edit_after_daemon_restart() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("before\n"),
        )
        .unwrap();
        let scope = AuthorizationScopeId::new("restart-freshness-scope").unwrap();
        let daemon = GatewayDaemonV1::bind(workspace.path(), scope.clone()).unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "restart-freshness", "task": "inspect input.txt" }),
        );
        assert!(start.get("error").is_none(), "{start}");
        let first = agent.tool("repo.read", json!({ "path": "input.txt" }));
        let old_id = first["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();

        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("after\n"),
        )
        .unwrap();
        let daemon = GatewayDaemonV1::bind(workspace.path(), scope).unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut resumed = LocalMcpClientV1::connect(workspace.path());
        let reopened = resumed.tool(
            "task.start",
            json!({ "taskId": "restart-freshness", "task": "inspect input.txt" }),
        );
        assert!(reopened.get("error").is_none(), "{reopened}");
        let context = &reopened["result"]["structuredContent"]["context"];
        assert!(
            context["current_facts"].as_array().unwrap().is_empty(),
            "task start presented a stale fact: {reopened}"
        );
        assert!(
            context["result_references"].as_array().unwrap().is_empty(),
            "task start presented a stale reference: {reopened}"
        );
        let stale = resumed.tool(
            "context.retrieve",
            json!({ "taskId": "restart-freshness", "resultId": old_id }),
        );
        assert_eq!(
            stale["error"]["data"]["reason"], "retrieval_refused",
            "{stale}"
        );
        let refreshed = resumed.tool("repo.read", json!({ "path": "input.txt" }));
        assert_eq!(
            refreshed["result"]["content"][0]["text"],
            leased_read_fixture_v1("after\n")
        );
        resumed.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn task_start_returns_incomplete_brief_when_source_scan_exceeds_bound() {
        let workspace = tempfile::tempdir().unwrap();
        for index in 0..=256 {
            fs::write(
                workspace.path().join(format!("source-{index:03}.txt")),
                format!("source {index}\n"),
            )
            .unwrap();
        }
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("freshness-capacity-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let arguments = json!({ "taskId": "bounded-freshness", "task": "inspect sources" });
        let start = agent.tool("task.start", arguments.clone());
        assert!(start.get("error").is_none(), "{start}");
        let initial_cursor = start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        for index in 0..=256 {
            let read = agent.tool(
                "repo.read",
                json!({ "path": format!("source-{index:03}.txt") }),
            );
            assert!(
                read["result"].get("_meta").is_none()
                    && read["result"]["content"][0]["text"].is_string(),
                "{index}: {read}"
            );
        }
        fs::write(workspace.path().join("source-000.txt"), b"changed\n").unwrap();
        let delta = agent.tool(
            "context.delta",
            json!({ "taskId": "bounded-freshness", "afterCursor": initial_cursor, "limit": 64 }),
        );
        assert!(delta.get("error").is_none(), "{delta}");
        assert_eq!(
            delta["result"]["structuredContent"]["presentation"],
            "incomplete"
        );
        assert_eq!(
            delta["result"]["structuredContent"]["delta"]["events"],
            json!([])
        );
        let mut peer = LocalMcpClientV1::connect(workspace.path());
        let bounded = peer.tool("task.start", arguments);
        assert!(bounded.get("error").is_none(), "{bounded}");
        let brief = &bounded["result"]["structuredContent"];
        assert_eq!(brief["presentation"], "full");
        assert_eq!(brief["contextFreshness"]["status"], "incomplete");
        assert_eq!(
            brief["contextFreshness"]["reason"],
            "context_freshness_capacity_exceeded"
        );
        assert_eq!(brief["context"]["incomplete"], true);
        assert!(
            brief["context"]["current_facts"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            brief["context"]["result_references"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            brief["relevantCode"]["candidates"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        let again = peer.tool(
            "task.start",
            json!({ "taskId": "bounded-freshness", "task": "inspect sources" }),
        );
        assert_eq!(again["result"]["structuredContent"]["presentation"], "full");
        peer.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn large_index_task_start_previews_explicit_file_without_full_index() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        for index in 0..=4096 {
            fs::write(
                workspace.path().join(format!("src/module_{index:04}.py")),
                format!("value = {index}\n"),
            )
            .unwrap();
        }
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("large-index-preview-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let result = agent.tool(
            "task.start",
            json!({
                "taskId": "large-index-preview",
                "task": "Edit `src/module_0001.py` safely",
                "includeSourcePreviews": true
            }),
        );
        assert!(result.get("error").is_none(), "{result}");
        let brief = &result["result"]["structuredContent"];
        assert_eq!(brief["relevantCode"]["incomplete"], true);
        assert_eq!(
            brief["relevantCode"]["unknowns"][0]["kind"],
            "index_preflight_file_budget_exceeded"
        );
        assert_eq!(brief["sourcePreviews"][0]["path"], "src/module_0001.py");
        assert_eq!(brief["sourcePreviews"][0]["text"], "value = 1\n");
        assert_eq!(brief["sourcePreviews"][0]["complete"], true);
        let mut peer = LocalMcpClientV1::connect(workspace.path());
        let peer_start = peer.tool(
            "task.start",
            json!({ "taskId": "large-index-preview", "task": "Edit `src/module_0001.py` safely" }),
        );
        let peer_cursor = peer_start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let search = agent.tool(
            "repo.search",
            json!({ "path": "src", "pattern": "value = 4096", "maxResults": 2 }),
        );
        assert!(search["result"].get("_meta").is_none());
        assert_eq!(
            search["result"]["structuredContent"]["matches"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        let shared = peer.tool(
            "context.delta",
            json!({ "taskId": "large-index-preview", "afterCursor": peer_cursor, "limit": 64 }),
        );
        assert!(
            shared["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "verified_fact_admission"),
            "peer missed verified search match: {shared}"
        );
        let admitted_cursor = shared["result"]["structuredContent"]["delta"]["cursor"]
            .as_u64()
            .unwrap();
        let tree = agent.tool("repo.tree", json!({ "path": "src", "maxResults": 2 }));
        assert!(tree.get("error").is_none(), "{tree}");
        assert_eq!(tree["result"]["structuredContent"]["truncated"], true);
        assert_eq!(
            tree["result"]["structuredContent"]["entries"],
            json!([
                { "path": "src/module_0000.py", "kind": "file", "depth": 1, "bytes": 10 },
                { "path": "src/module_0001.py", "kind": "file", "depth": 1, "bytes": 10 }
            ])
        );
        fs::write(
            workspace.path().join("src/module_4096.py"),
            b"changed = 4096\n",
        )
        .unwrap();
        let changed = agent.tool(
            "repo.search",
            json!({ "path": "src", "pattern": "value = 4096", "maxResults": 2 }),
        );
        assert_eq!(
            changed["result"]["structuredContent"]["matches"]
                .as_array()
                .unwrap()
                .len(),
            0
        );
        let retired = peer.tool(
            "context.delta",
            json!({ "taskId": "large-index-preview", "afterCursor": admitted_cursor, "limit": 64 }),
        );
        assert!(
            retired["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation"),
            "peer retained a changed search match: {retired}"
        );
        let stats = Store::open_for_workspace(workspace.path())
            .unwrap()
            .gateway_stats()
            .unwrap();
        assert_eq!(stats.requested, 3, "{stats:?}");
        assert_eq!(stats.executed, 3, "{stats:?}");
        assert_eq!(stats.exact_hits, 0, "{stats:?}");
        peer.stream.shutdown(std::net::Shutdown::Both).unwrap();
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn named_source_preview_avoids_mid_sized_synchronous_index() {
        let workspace = tempfile::tempdir().unwrap();
        fs::create_dir(workspace.path().join("src")).unwrap();
        for index in 0..=256 {
            fs::write(
                workspace.path().join(format!("src/module_{index:04}.py")),
                format!("value = {index}\n"),
            )
            .unwrap();
        }
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("mid-index-preview-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let result = agent.tool(
            "task.start",
            json!({
                "taskId": "mid-index-preview",
                "task": "Edit `src/module_0001.py` safely",
                "includeSourcePreviews": true
            }),
        );
        assert!(result.get("error").is_none(), "{result}");
        let brief = &result["result"]["structuredContent"];
        assert_eq!(
            brief["relevantCode"]["unknowns"][0]["kind"],
            "index_skipped_for_complete_explicit_preview"
        );
        assert_eq!(brief["sourcePreviews"][0]["path"], "src/module_0001.py");
        assert_eq!(brief["sourcePreviews"][0]["text"], "value = 1\n");
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn retrieval_revalidates_unobserved_edit_without_a_new_tool_read() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("before\n"),
        )
        .unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("retrieval-freshness-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "retrieval-freshness", "task": "inspect input.txt" }),
        );
        assert!(start.get("error").is_none(), "{start}");
        let cursor = start["result"]["structuredContent"]["cursor"]
            .as_u64()
            .unwrap();
        let first = agent.tool("repo.read", json!({ "path": "input.txt" }));
        let old_id = first["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        let available = agent.tool(
            "context.retrieve",
            json!({ "taskId": "retrieval-freshness", "resultId": old_id }),
        );
        assert_eq!(
            available["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("before\n")
        );
        let search = agent.tool("repo.search", json!({ "path": ".", "pattern": "before" }));
        let search_id = search["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("after\n"),
        )
        .unwrap();
        let stale = agent.tool(
            "context.retrieve",
            json!({ "taskId": "retrieval-freshness", "resultId": old_id }),
        );
        assert_eq!(
            stale["error"]["data"]["reason"], "retrieval_refused",
            "{stale}"
        );
        let stale_search = agent.tool(
            "context.retrieve",
            json!({ "taskId": "retrieval-freshness", "resultId": search_id }),
        );
        assert_eq!(
            stale_search["error"]["data"]["reason"], "retrieval_refused",
            "{stale_search}"
        );
        let delta = agent.tool(
            "context.delta",
            json!({ "taskId": "retrieval-freshness", "afterCursor": cursor, "limit": 64 }),
        );
        assert!(
            delta["result"]["structuredContent"]["delta"]["events"]
                .as_array()
                .unwrap()
                .iter()
                .any(|event| event["kind"] == "invalidation"),
            "retrieval did not publish the unobserved edit: {delta}"
        );
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn task_start_preserves_fact_after_unrelated_unobserved_edit() {
        let workspace = tempfile::tempdir().unwrap();
        fs::write(
            workspace.path().join("input.txt"),
            leased_read_fixture_v1("stable\n"),
        )
        .unwrap();
        fs::write(workspace.path().join("other.txt"), b"before\n").unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("irrelevant-freshness-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "irrelevant-freshness", "task": "inspect input.txt" }),
        );
        assert!(start.get("error").is_none(), "{start}");
        let first = agent.tool("repo.read", json!({ "path": "input.txt" }));
        let result_id = first["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .unwrap()
            .to_owned();
        fs::write(workspace.path().join("other.txt"), b"after\n").unwrap();
        let resumed = agent.tool(
            "task.start",
            json!({ "taskId": "irrelevant-freshness", "task": "inspect input.txt" }),
        );
        assert!(resumed.get("error").is_none(), "{resumed}");
        let retrieved = agent.tool(
            "context.retrieve",
            json!({ "taskId": "irrelevant-freshness", "resultId": result_id }),
        );
        assert_eq!(
            retrieved["result"]["structuredContent"]["toolResult"]["content"][0]["text"],
            leased_read_fixture_v1("stable\n"),
            "unrelated edit retired the source: {retrieved}"
        );
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }

    #[test]
    fn git_status_reflects_unobserved_head_change_with_or_without_admission() {
        let workspace = tempfile::tempdir().unwrap();
        let git = |arguments: &[&str]| {
            let status = Command::new("git")
                .args(arguments)
                .current_dir(workspace.path())
                .status()
                .unwrap();
            assert!(
                status.success(),
                "git fixture command failed: {arguments:?}"
            );
        };
        git(&["init", "-q"]);
        fs::write(workspace.path().join("tracked.txt"), b"first\n").unwrap();
        git(&["add", "tracked.txt"]);
        git(&[
            "-c",
            "user.name=Again Test",
            "-c",
            "user.email=again@example.invalid",
            "commit",
            "-qm",
            "first",
        ]);
        fs::write(workspace.path().join("tracked.txt"), b"changed\n").unwrap();
        let daemon = GatewayDaemonV1::bind(
            workspace.path(),
            AuthorizationScopeId::new("git-head-freshness-scope").unwrap(),
        )
        .unwrap();
        let server = thread::spawn(move || daemon.serve());
        let mut agent = LocalMcpClientV1::connect(workspace.path());
        let start = agent.tool(
            "task.start",
            json!({ "taskId": "git-head-freshness", "task": "inspect Git status" }),
        );
        assert!(start.get("error").is_none(), "{start}");
        let status = agent.tool("git.status", json!({ "path": "." }));
        let result_id = status["result"]["_meta"]["again"]["resultId"]
            .as_str()
            .map(str::to_owned);
        assert_eq!(
            status["result"]["structuredContent"]["entries"][0]["path"], "tracked.txt",
            "{status}"
        );
        git(&["add", "tracked.txt"]);
        git(&[
            "-c",
            "user.name=Again Test",
            "-c",
            "user.email=again@example.invalid",
            "commit",
            "-qm",
            "second",
        ]);
        if let Some(result_id) = result_id {
            let stale = agent.tool(
                "context.retrieve",
                json!({ "taskId": "git-head-freshness", "resultId": result_id }),
            );
            assert_eq!(
                stale["error"]["data"]["reason"], "retrieval_refused",
                "{stale}"
            );
        }
        let fresh = agent.tool("git.status", json!({ "path": "." }));
        assert_eq!(
            fresh["result"]["structuredContent"]["entries"],
            json!([]),
            "Git status retained the old worktree after HEAD changed: {fresh}"
        );
        agent.stream.shutdown(std::net::Shutdown::Both).unwrap();
        stop_daemon_v1(workspace.path()).unwrap();
        server.join().unwrap().unwrap();
    }
}
