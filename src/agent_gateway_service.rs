//! Opt-in local gateway daemon with an OS-authenticated Unix transport.
//!
//! The daemon is an optimization boundary, not a new reuse authority. Every
//! MCP connection still constructs the normal repository-aware gateway and
//! earns reuse through the existing store proofs. The transport accepts only
//! the current effective uid, binds a canonical-workspace digest in a fixed
//! handshake, and places its predictable socket below an owner-private
//! directory. No caller-provided bearer token is accepted.

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
use std::time::Duration;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::agent_gateway_runtime::ExperimentalMcpGatewayV1;
use crate::mcp_gateway::AuthorizationScopeId;
use crate::store::Store;

const HANDSHAKE_MAGIC_V1: &[u8; 8] = b"AGNGW001";
const RESPONSE_MAGIC_V1: &[u8; 8] = b"AGNR0001";
const HANDSHAKE_BYTES_V1: usize = 41;
const MAX_CONTROL_PAYLOAD_BYTES_V1: usize = 4 * 1024;
const MAX_ACTIVE_CONNECTIONS_V1: usize = 32;
const HANDSHAKE_TIMEOUT_V1: Duration = Duration::from_secs(5);
const ACCEPT_POLL_V1: Duration = Duration::from_millis(10);

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

struct SocketCleanupV1 {
    path: PathBuf,
    device: u64,
    inode: u64,
}

impl Drop for SocketCleanupV1 {
    fn drop(&mut self) {
        let Ok(metadata) = fs::symlink_metadata(&self.path) else {
            return;
        };
        if metadata.file_type().is_socket()
            && metadata.dev() == self.device
            && metadata.ino() == self.inode
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct ActiveConnectionGuardV1 {
    id: u64,
    active: Arc<AtomicUsize>,
    peers: Arc<Mutex<BTreeMap<u64, UnixStream>>>,
}

impl Drop for ActiveConnectionGuardV1 {
    fn drop(&mut self) {
        self.peers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&self.id);
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

/// A live daemon listener. Construction validates but never chmods an existing
/// parent. After acquiring the exclusive instance lock it can reclaim only a
/// validated crash-stale socket. Drop unlinks only the exact socket inode
/// created by this instance.
pub struct GatewayDaemonV1 {
    workspace: PathBuf,
    workspace_digest: [u8; 32],
    authorization_scope: AuthorizationScopeId,
    listener: UnixListener,
    socket_cleanup: SocketCleanupV1,
    stop: Arc<AtomicBool>,
    active: Arc<AtomicUsize>,
    peers: Arc<Mutex<BTreeMap<u64, UnixStream>>>,
    next_connection: AtomicU64,
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
        let workspace =
            fs::canonicalize(workspace).map_err(|_| GatewayServiceError::InvalidWorkspace)?;
        if !workspace.is_dir() {
            return Err(GatewayServiceError::InvalidWorkspace);
        }

        // Prepare and validate the normal state root first. The daemon does not
        // create a second authority store and never places state in the repo.
        Store::open_for_workspace(&workspace).map_err(|_| GatewayServiceError::Initialization)?;
        let socket = gateway_socket_path_v1(&workspace, true)?;
        let instance_lock = acquire_instance_lock_v1(&socket)?;
        match fs::symlink_metadata(&socket) {
            Ok(_) => {
                validate_socket_file_v1(&socket)?;
                fs::remove_file(&socket)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let listener = UnixListener::bind(&socket)?;
        fs::set_permissions(&socket, Permissions::from_mode(0o600))?;
        let metadata = validate_socket_file_v1(&socket)?;
        listener.set_nonblocking(true)?;

        Ok(Self {
            workspace_digest: canonical_workspace_digest_v1(&workspace),
            workspace,
            authorization_scope,
            listener,
            socket_cleanup: SocketCleanupV1 {
                path: socket,
                device: metadata.dev(),
                inode: metadata.ino(),
            },
            stop: Arc::new(AtomicBool::new(false)),
            active: Arc::new(AtomicUsize::new(0)),
            peers: Arc::new(Mutex::new(BTreeMap::new())),
            next_connection: AtomicU64::new(1),
            _instance_lock: instance_lock,
        })
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_cleanup.path
    }

    /// Run until an authenticated same-uid stop request arrives. Active MCP
    /// streams are then shut down, causing the existing gateway cleanup paths
    /// to cancel provider work and retire connection-bound grants.
    pub fn serve(self) -> Result<(), GatewayServiceError> {
        let mut workers = Vec::new();
        let mut worker_panicked = false;
        while !self.stop.load(Ordering::Acquire) {
            reap_finished_workers_v1(&mut workers, &mut worker_panicked);
            if worker_panicked {
                self.stop.store(true, Ordering::Release);
                break;
            }
            match self.listener.accept() {
                Ok((stream, _)) => {
                    if self.active.load(Ordering::Acquire) >= MAX_ACTIVE_CONNECTIONS_V1 {
                        drop(stream);
                        continue;
                    }
                    if authenticate_peer_v1(&stream).is_err()
                        || stream.set_nonblocking(false).is_err()
                        || stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT_V1)).is_err()
                        || stream
                            .set_write_timeout(Some(HANDSHAKE_TIMEOUT_V1))
                            .is_err()
                    {
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
                    let workspace = self.workspace.clone();
                    let workspace_digest = self.workspace_digest;
                    let authorization_scope = self.authorization_scope.clone();
                    let stop = Arc::clone(&self.stop);
                    let active = Arc::clone(&self.active);
                    let active_for_handler = Arc::clone(&self.active);
                    let peers = Arc::clone(&self.peers);
                    workers.push(thread::spawn(move || {
                        let _guard = ActiveConnectionGuardV1 { id, active, peers };
                        let _ = handle_connection_v1(
                            stream,
                            &workspace,
                            workspace_digest,
                            &authorization_scope,
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

        let peers = self
            .peers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        for peer in peers.values() {
            let _ = peer.shutdown(std::net::Shutdown::Both);
        }
        drop(peers);
        for worker in workers {
            worker_panicked |= worker.join().is_err();
        }
        if worker_panicked {
            return Err(GatewayServiceError::Initialization);
        }
        Ok(())
    }
}

fn handle_connection_v1(
    mut stream: UnixStream,
    workspace: &Path,
    workspace_digest: [u8; 32],
    authorization_scope: &AuthorizationScopeId,
    stop: &AtomicBool,
    active: &AtomicUsize,
) -> Result<(), GatewayServiceError> {
    let mode = read_handshake_v1(&mut stream, &workspace_digest)?;
    match mode {
        ConnectionModeV1::Status => {
            let status = GatewayDaemonStatusV1 {
                schema_version: 1,
                status: "ready".to_owned(),
                workspace_digest: hex_digest_v1(&workspace_digest),
                active_connections: active.load(Ordering::Acquire),
                max_active_connections: MAX_ACTIVE_CONNECTIONS_V1,
                peer_authentication: peer_authentication_name_v1().to_owned(),
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
            write_response_v1(
                &mut stream,
                ResponseCodeV1::Ready,
                &serde_json::json!({"schemaVersion":1,"status":"ready"}),
            )?;
            stream.set_read_timeout(None)?;
            stream.set_write_timeout(None)?;
            let reader_stream = stream.try_clone()?;
            let mut reader = BufReader::new(reader_stream);
            let gateway = ExperimentalMcpGatewayV1::build(workspace)
                .map_err(|_| GatewayServiceError::Initialization)?;
            gateway
                .serve_io(&mut reader, &mut stream, authorization_scope)
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
    let workspace =
        fs::canonicalize(workspace).map_err(|_| GatewayServiceError::InvalidWorkspace)?;
    let socket = gateway_socket_path_v1(&workspace, false)?;
    validate_socket_file_v1(&socket)?;
    let mut stream = UnixStream::connect(&socket)?;
    authenticate_peer_v1(&stream)?;
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT_V1))?;
    stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT_V1))?;
    let digest = canonical_workspace_digest_v1(&workspace);
    let mut request = [0_u8; HANDSHAKE_BYTES_V1];
    request[..8].copy_from_slice(HANDSHAKE_MAGIC_V1);
    request[8] = mode as u8;
    request[9..].copy_from_slice(&digest);
    stream.write_all(&request)?;
    stream.flush()?;
    let (code, payload) = read_response_v1(&mut stream)?;
    if code != ResponseCodeV1::Ready {
        return Err(match code {
            ResponseCodeV1::Busy => GatewayServiceError::Busy,
            ResponseCodeV1::Invalid | ResponseCodeV1::Internal => {
                GatewayServiceError::InvalidHandshake
            }
            ResponseCodeV1::Ready => unreachable!(),
        });
    }
    if mode == ConnectionModeV1::Mcp {
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(None)?;
    }
    Ok((stream, payload))
}

fn read_handshake_v1(
    stream: &mut UnixStream,
    expected_workspace: &[u8; 32],
) -> Result<ConnectionModeV1, GatewayServiceError> {
    let mut request = [0_u8; HANDSHAKE_BYTES_V1];
    stream.read_exact(&mut request)?;
    if &request[..8] != HANDSHAKE_MAGIC_V1 || &request[9..] != expected_workspace {
        let _ = write_response_v1(
            stream,
            ResponseCodeV1::Invalid,
            &serde_json::json!({"schemaVersion":1,"status":"refused"}),
        );
        return Err(GatewayServiceError::InvalidHandshake);
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

fn gateway_socket_path_v1(
    workspace: &Path,
    create_parent: bool,
) -> Result<PathBuf, GatewayServiceError> {
    let temporary = fs::canonicalize(std::env::temp_dir())?;
    let parent = temporary.join(format!("again-{}", effective_uid_v1()));
    if create_parent && !parent.exists() {
        match DirBuilder::new().mode(0o700).create(&parent) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    validate_private_directory_v1(&parent)?;
    let digest = canonical_workspace_digest_v1(workspace);
    let socket = parent
        .join("gw")
        .with_extension(format!("{}.sock", &hex_digest_v1(&digest)[..24]));
    // macOS has a 104-byte sockaddr_un.sun_path including NUL; Linux has 108.
    if socket.as_os_str().as_encoded_bytes().len() >= 104 {
        return Err(GatewayServiceError::SocketPathTooLong);
    }
    Ok(socket)
}

fn validate_private_directory_v1(path: &Path) -> Result<(), GatewayServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(GatewayServiceError::Io)?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o077 != 0
    {
        return Err(GatewayServiceError::UnsafeSocketParent);
    }
    Ok(())
}

fn validate_socket_file_v1(path: &Path) -> Result<Metadata, GatewayServiceError> {
    let metadata = fs::symlink_metadata(path).map_err(GatewayServiceError::Io)?;
    if !is_socket_v1(metadata.file_type())
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(GatewayServiceError::WrongPeer);
    }
    Ok(metadata)
}

fn acquire_instance_lock_v1(socket: &Path) -> Result<File, GatewayServiceError> {
    let lock = socket.with_extension("lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&lock)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file()
        || metadata.uid() != effective_uid_v1()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(GatewayServiceError::UnsafeSocketParent);
    }
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

fn hex_digest_v1(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn effective_uid_v1() -> u32 {
    // SAFETY: geteuid has no preconditions and mutates no process state.
    unsafe { libc::geteuid() }
}

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
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
    if peer_uid_v1(stream)? == effective_uid_v1() {
        Ok(())
    } else {
        Err(GatewayServiceError::WrongPeer)
    }
}

fn peer_authentication_name_v1() -> &'static str {
    #[cfg(target_os = "linux")]
    return "so_peercred_euid";
    #[cfg(not(target_os = "linux"))]
    return "getpeereid_euid";
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

/// Bidirectionally proxy the current standard streams to an authenticated MCP
/// daemon connection without spawning helper processes or buffering frames.
pub fn proxy_current_stdio_v1(mut stream: UnixStream) -> Result<(), GatewayServiceError> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    let mut input_open = true;
    let mut buffer = [0_u8; 16 * 1024];

    loop {
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
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), descriptors.len() as _, -1) };
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
                }
                count => stream.write_all(&buffer[..count])?,
            }
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
