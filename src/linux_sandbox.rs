//! Rootless Linux Landlock planning and a disposable capability probe.
//!
//! This module validates candidate filesystem rules and proves that Landlock
//! and seccomp can be installed in one fixed `/usr/bin/true` child. It
//! deliberately exposes no API for executing caller-supplied programs: ABI 3
//! does not mediate every metadata input or effect, and inherited descriptors,
//! runtime breadth, and plan-to-apply races remain unresolved.

use std::collections::BTreeMap;
use std::ffi::CString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

use blake3::Hasher;
use thiserror::Error;

use crate::policy::{AccessPlan, AccessScope};

#[cfg(target_os = "linux")]
// ABI 3 is the first version that mediates standalone `truncate(2)`. It still
// does not provide a complete read-only or observable-input boundary.
const MIN_LANDLOCK_ABI: i32 = 3;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinuxSandboxAvailability {
    Available { abi: i32 },
    UnsupportedPlatform { target_os: &'static str },
    KernelUnavailable { errno: i32 },
    AbiTooOld { found: i32, required: i32 },
    ProbeFailed { errno: i32 },
}

impl LinuxSandboxAvailability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available { .. })
    }
}

impl fmt::Display for LinuxSandboxAvailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Available { abi } => write!(f, "available (Landlock ABI {abi})"),
            Self::UnsupportedPlatform { target_os } => {
                write!(f, "unsupported platform `{target_os}`")
            }
            Self::KernelUnavailable { errno } => write!(f, "Landlock unavailable (errno {errno})"),
            Self::AbiTooOld { found, required } => write!(
                f,
                "Landlock ABI {found} is older than required ABI {required}"
            ),
            Self::ProbeFailed { errno } => write!(f, "Landlock probe failed (errno {errno})"),
        }
    }
}

/// Check the kernel ABI needed by the candidate planner and fixed probe.
/// `Available` means only that this ABI check passed, not that an execution
/// boundary is ready for caller-supplied programs.
pub fn preflight() -> LinuxSandboxAvailability {
    #[cfg(target_os = "linux")]
    match landlock_abi() {
        Ok(abi) if abi >= MIN_LANDLOCK_ABI => LinuxSandboxAvailability::Available { abi },
        Ok(abi) => LinuxSandboxAvailability::AbiTooOld {
            found: abi,
            required: MIN_LANDLOCK_ABI,
        },
        Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EOPNOTSUPP)) => {
            LinuxSandboxAvailability::KernelUnavailable {
                errno: error.raw_os_error().unwrap_or(libc::ENOSYS),
            }
        }
        Err(error) => LinuxSandboxAvailability::ProbeFailed {
            errno: error.raw_os_error().unwrap_or(libc::EINVAL),
        },
    }
    #[cfg(not(target_os = "linux"))]
    LinuxSandboxAvailability::UnsupportedPlatform {
        target_os: std::env::consts::OS,
    }
}

#[derive(Debug, Error)]
pub enum LinuxSandboxProbeError {
    #[error("Linux Landlock planner/probe is unavailable: {0}")]
    Unavailable(LinuxSandboxAvailability),
    #[error("failed to launch probe ({kind}): {message}")]
    LaunchFailed {
        kind: io::ErrorKind,
        message: String,
    },
    #[error("probe was rejected (status {status:?}): {stderr}")]
    Rejected { status: Option<i32>, stderr: String },
}

/// Prove in a disposable child that `no_new_privs` and Landlock restriction can
/// be applied. The probe allows `/` only to keep `/usr/bin/true` runnable; it
/// is an applicability check, never a production policy.
pub fn probe_apply() -> Result<(), LinuxSandboxProbeError> {
    let availability = preflight();
    let abi = match availability {
        LinuxSandboxAvailability::Available { abi } => abi,
        unavailable => return Err(LinuxSandboxProbeError::Unavailable(unavailable)),
    };
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let rules = vec![
            PathRule::new(
                PathBuf::from("/"),
                fs_access::READ_FILE | fs_access::READ_DIR | fs_access::EXECUTE,
            )
            .expect("the root path is representable in a kernel rule"),
        ];
        let probe_filter = build_probe_seccomp_filter().map_err(|source| {
            LinuxSandboxProbeError::LaunchFailed {
                kind: source.kind(),
                message: source.to_string(),
            }
        })?;
        let mut command = Command::new("/usr/bin/true");
        // The fixed probe must not become an ambient loader hook. In
        // particular, inherited LD_PRELOAD/LD_AUDIT values could otherwise
        // execute caller-controlled code under the deliberately broad probe
        // rule for `/`.
        command.env_clear();
        // SAFETY: syscall-only closure; no Rust allocation or synchronization.
        unsafe {
            command.pre_exec(move || apply_probe_rules(abi, &rules, &probe_filter));
        }
        let output = command
            .output()
            .map_err(|source| LinuxSandboxProbeError::LaunchFailed {
                kind: source.kind(),
                message: source.to_string(),
            })?;
        if output.status.success() {
            Ok(())
        } else {
            Err(LinuxSandboxProbeError::Rejected {
                status: output.status.code(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = abi;
        Err(LinuxSandboxProbeError::Unavailable(preflight()))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LinuxLandlockCandidatePlan {
    abi: i32,
    executable: PathBuf,
    cwd: PathBuf,
    workspace: PathBuf,
    rules: Vec<PathRule>,
    rules_digest: String,
}

impl LinuxLandlockCandidatePlan {
    pub fn executable(&self) -> &Path {
        &self.executable
    }
    pub fn cwd(&self) -> &Path {
        &self.cwd
    }
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }
    pub fn landlock_abi(&self) -> i32 {
        self.abi
    }
    pub fn rules_digest(&self) -> &str {
        &self.rules_digest
    }
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

#[derive(Debug, Error)]
pub enum LinuxSandboxError {
    #[error("Linux Landlock planner is unavailable: {0}")]
    Unavailable(LinuxSandboxAvailability),
    #[error("access plan must contain at least one scope")]
    EmptyAccessPlan,
    #[error("{kind} path is not canonical: {path}")]
    NonCanonicalPath { kind: &'static str, path: PathBuf },
    #[error("{kind} escapes workspace `{workspace}`: {path}")]
    OutsideWorkspace {
        kind: &'static str,
        path: PathBuf,
        workspace: PathBuf,
    },
    #[error("scope path must be relative: {0}")]
    AbsoluteScopePath(PathBuf),
    #[error("whole-workspace scope is not an enforceable bounded Linux profile")]
    WholeWorkspaceScope,
    #[error("directory-listing scope cannot be bounded to immediate membership by Landlock")]
    DirectoryListingScope,
    #[error("executable is not a regular executable file: {0}")]
    ExecutableNotRegular(PathBuf),
    #[error("special file cannot be admitted to a Landlock scope: {0}")]
    SpecialFile(PathBuf),
    #[error("path cannot be represented in a kernel rule: {0}")]
    KernelPath(PathBuf),
    #[error("cannot {operation} `{path}`")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
}

/// Compile candidate Landlock rules for inspection only. This plan cannot
/// execute a child. Missing paths, special files, workspace escapes, and broad
/// `WholeWorkspace` grants fail closed.
pub fn compile_candidate_plan(
    canonical_executable: &Path,
    canonical_cwd: &Path,
    canonical_workspace: &Path,
    access_plan: &AccessPlan,
) -> Result<LinuxLandlockCandidatePlan, LinuxSandboxError> {
    let abi = match preflight() {
        LinuxSandboxAvailability::Available { abi } => abi,
        unavailable => return Err(LinuxSandboxError::Unavailable(unavailable)),
    };
    if access_plan.scopes.is_empty() {
        return Err(LinuxSandboxError::EmptyAccessPlan);
    }
    if access_plan
        .scopes
        .iter()
        .any(|scope| matches!(scope, AccessScope::WholeWorkspace))
    {
        return Err(LinuxSandboxError::WholeWorkspaceScope);
    }
    let workspace = require_canonical(canonical_workspace, "workspace")?;
    let cwd = require_canonical(canonical_cwd, "working directory")?;
    ensure_within(&cwd, &workspace, "working directory")?;
    if !metadata(&workspace, "inspect workspace")?.is_dir()
        || !metadata(&cwd, "inspect working directory")?.is_dir()
    {
        return Err(LinuxSandboxError::SpecialFile(workspace));
    }
    let executable = require_canonical(canonical_executable, "executable")?;
    let executable_metadata = metadata(&executable, "inspect executable")?;
    if !executable_metadata.is_file() || !is_executable(&executable_metadata) {
        return Err(LinuxSandboxError::ExecutableNotRegular(executable));
    }

    let mut grants = BTreeMap::new();
    merge_rule(
        &mut grants,
        &executable,
        fs_access::READ_FILE | fs_access::EXECUTE,
    );
    add_runtime_grants(&mut grants);
    for scope in &access_plan.scopes {
        match scope {
            AccessScope::IdentityOnly => {}
            AccessScope::ContentPath(relative) => {
                add_scope(&workspace, relative, ScopeMode::Content, &mut grants)?
            }
            AccessScope::RecursiveContentTree(relative) => {
                add_scope(&workspace, relative, ScopeMode::Tree, &mut grants)?
            }
            // READ_DIR on a Landlock path-beneath rule covers the entire
            // subtree; it cannot encode an immediate-membership-only proof.
            AccessScope::DirectoryListing(_) => {
                return Err(LinuxSandboxError::DirectoryListingScope);
            }
            AccessScope::WholeWorkspace => unreachable!("checked above"),
        }
    }
    let rules: Vec<_> = grants
        .into_iter()
        .map(|(path, access)| PathRule::new(path, access))
        .collect::<Result<_, _>>()?;
    let mut hasher = Hasher::new_derive_key("again linux landlock rules v1");
    hasher.update(&abi.to_be_bytes());
    for rule in &rules {
        hasher.update(&(rule.path.as_os_str().len() as u64).to_be_bytes());
        hasher.update(rule.path.as_os_str().as_encoded_bytes());
        hasher.update(&rule.access.to_be_bytes());
    }
    Ok(LinuxLandlockCandidatePlan {
        abi,
        executable,
        cwd,
        workspace,
        rules,
        rules_digest: hasher.finalize().to_hex().to_string(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PathRule {
    path: PathBuf,
    kernel_path: CString,
    access: u64,
}
impl PathRule {
    fn new(path: PathBuf, access: u64) -> Result<Self, LinuxSandboxError> {
        #[cfg(unix)]
        use std::os::unix::ffi::OsStrExt;
        #[cfg(unix)]
        let bytes = path.as_os_str().as_bytes();
        #[cfg(not(unix))]
        let bytes = path.as_os_str().as_encoded_bytes();
        let kernel_path =
            CString::new(bytes).map_err(|_| LinuxSandboxError::KernelPath(path.clone()))?;
        Ok(Self {
            path,
            kernel_path,
            access,
        })
    }
}
#[derive(Clone, Copy)]
enum ScopeMode {
    Content,
    Tree,
}

fn require_canonical(path: &Path, kind: &'static str) -> Result<PathBuf, LinuxSandboxError> {
    let canonical =
        fs::canonicalize(path).map_err(|source| io_error("canonicalize", path, source))?;
    if canonical != path {
        return Err(LinuxSandboxError::NonCanonicalPath {
            kind,
            path: path.to_path_buf(),
        });
    }
    Ok(canonical)
}

fn ensure_within(
    path: &Path,
    workspace: &Path,
    kind: &'static str,
) -> Result<(), LinuxSandboxError> {
    if path.starts_with(workspace) {
        Ok(())
    } else {
        Err(LinuxSandboxError::OutsideWorkspace {
            kind,
            path: path.to_path_buf(),
            workspace: workspace.to_path_buf(),
        })
    }
}

fn add_scope(
    workspace: &Path,
    relative: &Path,
    mode: ScopeMode,
    grants: &mut BTreeMap<PathBuf, u64>,
) -> Result<(), LinuxSandboxError> {
    if relative.is_absolute()
        || relative.components().any(|part| {
            matches!(
                part,
                Component::ParentDir | Component::RootDir | Component::Prefix(_)
            )
        })
    {
        return Err(LinuxSandboxError::AbsoluteScopePath(relative.to_path_buf()));
    }
    let input = workspace.join(relative);
    let target =
        fs::canonicalize(&input).map_err(|source| io_error("resolve scope", &input, source))?;
    ensure_within(&target, workspace, "scope")?;
    let info = metadata(&target, "inspect scope")?;
    if !info.is_file() && !info.is_dir() {
        return Err(LinuxSandboxError::SpecialFile(target));
    }
    let access = match mode {
        ScopeMode::Content if info.is_file() => fs_access::READ_FILE,
        ScopeMode::Tree if info.is_dir() => fs_access::READ_FILE | fs_access::READ_DIR,
        _ => return Err(LinuxSandboxError::SpecialFile(target)),
    };
    // Path traversal does not require READ_DIR rules on every ancestor.
    // Granting it at `/` would expose directory membership across the host.
    merge_rule(grants, &target, access);
    Ok(())
}

fn merge_rule(grants: &mut BTreeMap<PathBuf, u64>, path: &Path, access: u64) {
    grants
        .entry(path.to_path_buf())
        .and_modify(|existing| *existing |= access)
        .or_insert(access);
}

fn add_runtime_grants(grants: &mut BTreeMap<PathBuf, u64>) {
    for raw in ["/usr", "/lib", "/lib64", "/bin"] {
        if let Ok(path) = fs::canonicalize(raw) {
            merge_rule(
                grants,
                &path,
                fs_access::READ_FILE | fs_access::READ_DIR | fs_access::EXECUTE,
            );
        }
    }
    for raw in ["/etc/ld.so.cache", "/dev/null"] {
        if let Ok(path) = fs::canonicalize(raw) {
            merge_rule(grants, &path, fs_access::READ_FILE);
        }
    }
}

fn metadata(path: &Path, operation: &'static str) -> Result<fs::Metadata, LinuxSandboxError> {
    fs::metadata(path).map_err(|source| io_error(operation, path, source))
}
fn is_executable(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        metadata.mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        false
    }
}
fn io_error(operation: &'static str, path: &Path, source: io::Error) -> LinuxSandboxError {
    LinuxSandboxError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[allow(dead_code)]
mod fs_access {
    pub const EXECUTE: u64 = 1 << 0;
    pub const WRITE_FILE: u64 = 1 << 1;
    pub const READ_FILE: u64 = 1 << 2;
    pub const READ_DIR: u64 = 1 << 3;
    pub const REMOVE_DIR: u64 = 1 << 4;
    pub const REMOVE_FILE: u64 = 1 << 5;
    pub const MAKE_CHAR: u64 = 1 << 6;
    pub const MAKE_DIR: u64 = 1 << 7;
    pub const MAKE_REG: u64 = 1 << 8;
    pub const MAKE_SOCK: u64 = 1 << 9;
    pub const MAKE_FIFO: u64 = 1 << 10;
    pub const MAKE_BLOCK: u64 = 1 << 11;
    pub const MAKE_SYM: u64 = 1 << 12;
    pub const REFER: u64 = 1 << 13;
    pub const TRUNCATE: u64 = 1 << 14;
    pub const ALL_V1: u64 = EXECUTE
        | WRITE_FILE
        | READ_FILE
        | READ_DIR
        | REMOVE_DIR
        | REMOVE_FILE
        | MAKE_CHAR
        | MAKE_DIR
        | MAKE_REG
        | MAKE_SOCK
        | MAKE_FIFO
        | MAKE_BLOCK
        | MAKE_SYM;
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}
#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
    reserved: u32,
}
#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: i32 = 1;

#[cfg(target_os = "linux")]
fn landlock_abi() -> io::Result<i32> {
    let value = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<LandlockRulesetAttr>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value as i32)
    }
}
#[cfg(target_os = "linux")]
fn handled_fs(abi: i32) -> u64 {
    fs_access::ALL_V1
        | if abi >= 2 { fs_access::REFER } else { 0 }
        | if abi >= 3 { fs_access::TRUNCATE } else { 0 }
}
#[cfg(target_os = "linux")]
fn set_no_new_privs() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(target_os = "linux")]
fn apply_landlock(abi: i32, rules: &[PathRule]) -> io::Result<()> {
    set_no_new_privs()?;
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs(abi),
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            &attr,
            std::mem::size_of::<LandlockRulesetAttr>(),
            0u32,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    for rule in rules {
        let path_fd =
            unsafe { libc::open(rule.kernel_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if path_fd < 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd as i32);
            }
            return Err(error);
        }
        let attr = LandlockPathBeneathAttr {
            allowed_access: rule.access,
            parent_fd: path_fd,
            reserved: 0,
        };
        let add_result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                fd as i32,
                LANDLOCK_RULE_PATH_BENEATH,
                &attr,
                0u32,
            )
        };
        unsafe {
            libc::close(path_fd);
        }
        if add_result != 0 {
            let error = io::Error::last_os_error();
            unsafe {
                libc::close(fd as i32);
            }
            return Err(error);
        }
    }
    let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, fd as i32, 0u32) };
    unsafe {
        libc::close(fd as i32);
    }
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(target_os = "linux")]
fn apply_probe_rules(
    abi: i32,
    rules: &[PathRule],
    probe_filter: &[libc::sock_filter],
) -> io::Result<()> {
    apply_landlock(abi, rules)?;
    mark_extra_fds_close_on_exec()?;
    install_probe_seccomp(probe_filter)
}
#[cfg(target_os = "linux")]
fn mark_extra_fds_close_on_exec() -> io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_close_range,
            3u32,
            u32::MAX,
            libc::CLOSE_RANGE_CLOEXEC,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}
#[cfg(target_os = "linux")]
fn build_probe_seccomp_filter() -> io::Result<Vec<libc::sock_filter>> {
    const LD_NR: u16 = 0x20;
    const LD_ARCH: u16 = 0x20;
    const JEQ: u16 = 0x15;
    const JSET: u16 = 0x45;
    const RET: u16 = 0x06;
    const ALLOW: u32 = 0x7fff_0000;
    const ERRNO: u32 = 0x0005_0000;
    const KILL: u32 = 0;
    const SECCOMP_ARCH_OFFSET: u32 = 4;
    const SECCOMP_NR_OFFSET: u32 = 0;
    #[cfg(target_arch = "x86_64")]
    const X32_SYSCALL_BIT: u32 = 0x4000_0000;
    #[cfg(target_arch = "x86_64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const NATIVE_AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    const NATIVE_AUDIT_ARCH: u32 = 0;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP));

    let denied = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_recvmmsg,
        libc::SYS_shutdown,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        // Seccomp cannot inspect io_uring SQEs, which include socket, connect,
        // send, and receive operations. The fixed probe therefore denies the
        // io_uring API wholesale instead of presenting a false network claim.
        libc::SYS_io_uring_setup,
        libc::SYS_io_uring_enter,
        libc::SYS_io_uring_register,
    ];
    let mut filter = Vec::with_capacity(denied.len() * 2 + 8);
    // Reject calls made with a foreign syscall ABI. On x86-64, reject the x32
    // number namespace too, rather than letting it bypass the deny list.
    filter.push(libc::sock_filter {
        code: LD_ARCH,
        jt: 0,
        jf: 0,
        k: SECCOMP_ARCH_OFFSET,
    });
    filter.push(libc::sock_filter {
        code: JEQ,
        jt: 1,
        jf: 0,
        k: NATIVE_AUDIT_ARCH,
    });
    filter.push(libc::sock_filter {
        code: RET,
        jt: 0,
        jf: 0,
        k: KILL,
    });
    filter.push(libc::sock_filter {
        code: LD_NR,
        jt: 0,
        jf: 0,
        k: SECCOMP_NR_OFFSET,
    });
    #[cfg(target_arch = "x86_64")]
    {
        filter.push(libc::sock_filter {
            code: JSET,
            jt: 0,
            jf: 1,
            k: X32_SYSCALL_BIT,
        });
        filter.push(libc::sock_filter {
            code: RET,
            jt: 0,
            jf: 0,
            k: KILL,
        });
    }
    for syscall in denied {
        filter.push(libc::sock_filter {
            code: JEQ,
            jt: 0,
            jf: 1,
            k: syscall as u32,
        });
        filter.push(libc::sock_filter {
            code: RET,
            jt: 0,
            jf: 0,
            k: ERRNO | libc::EPERM as u32,
        });
    }
    filter.push(libc::sock_filter {
        code: RET,
        jt: 0,
        jf: 0,
        k: ALLOW,
    });
    Ok(filter)
}
#[cfg(target_os = "linux")]
fn install_probe_seccomp(filter: &[libc::sock_filter]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    if unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    use tempfile::TempDir;

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn probe_filter_denies_io_uring_and_batched_socket_calls() {
        const JEQ: u16 = 0x15;
        const RET: u16 = 0x06;
        const ERRNO: u32 = 0x0005_0000;
        let filter = build_probe_seccomp_filter().unwrap();
        for syscall in [
            libc::SYS_sendmmsg,
            libc::SYS_recvmmsg,
            libc::SYS_io_uring_setup,
            libc::SYS_io_uring_enter,
            libc::SYS_io_uring_register,
        ] {
            assert!(filter.windows(2).any(|pair| {
                pair[0].code == JEQ
                    && pair[0].k == syscall as u32
                    && pair[1].code == RET
                    && pair[1].k == ERRNO | libc::EPERM as u32
            }));
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn available_kernels_apply_the_fixed_true_probe_or_fail_closed() {
        match preflight() {
            LinuxSandboxAvailability::Available { .. } => probe_apply().unwrap(),
            unavailable => assert!(matches!(
                probe_apply(),
                Err(LinuxSandboxProbeError::Unavailable(found)) if found == unavailable
            )),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn available_kernels_compile_a_candidate_plan_or_fail_closed() {
        let temp = TempDir::new().unwrap();
        let workspace = temp.path().join("workspace");
        fs::create_dir(&workspace).unwrap();
        fs::write(workspace.join("input.txt"), b"input\n").unwrap();
        let workspace = fs::canonicalize(workspace).unwrap();
        let executable = fs::canonicalize("/usr/bin/cat")
            .or_else(|_| fs::canonicalize("/bin/cat"))
            .unwrap();
        let result = compile_candidate_plan(
            &executable,
            &workspace,
            &workspace,
            &AccessPlan {
                scopes: vec![AccessScope::ContentPath(PathBuf::from("input.txt"))],
            },
        );
        match preflight() {
            LinuxSandboxAvailability::Available { .. } => {
                let plan = result.unwrap();
                assert_eq!(plan.executable(), executable);
                assert_eq!(plan.cwd(), workspace);
                assert_eq!(plan.workspace(), workspace);
                assert!(plan.rule_count() > 0);
                assert_eq!(plan.rules_digest().len(), 64);
            }
            unavailable => assert!(
                matches!(result, Err(LinuxSandboxError::Unavailable(found)) if found == unavailable)
            ),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn whole_workspace_is_rejected_when_landlock_is_available() {
        let temp = TempDir::new().unwrap();
        let workspace = fs::canonicalize(temp.path()).unwrap();
        let executable = fs::canonicalize("/usr/bin/cat")
            .or_else(|_| fs::canonicalize("/bin/cat"))
            .unwrap();
        let result = compile_candidate_plan(
            &executable,
            &workspace,
            &workspace,
            &AccessPlan {
                scopes: vec![AccessScope::WholeWorkspace],
            },
        );
        match preflight() {
            LinuxSandboxAvailability::Available { .. } => {
                assert!(matches!(
                    result,
                    Err(LinuxSandboxError::WholeWorkspaceScope)
                ))
            }
            _ => assert!(matches!(result, Err(LinuxSandboxError::Unavailable(_)))),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn directory_listing_is_rejected_instead_of_widened_to_a_subtree() {
        let temp = TempDir::new().unwrap();
        let workspace = fs::canonicalize(temp.path()).unwrap();
        let executable = fs::canonicalize("/usr/bin/ls")
            .or_else(|_| fs::canonicalize("/bin/ls"))
            .unwrap();
        let result = compile_candidate_plan(
            &executable,
            &workspace,
            &workspace,
            &AccessPlan {
                scopes: vec![AccessScope::DirectoryListing(PathBuf::from("."))],
            },
        );
        match preflight() {
            LinuxSandboxAvailability::Available { .. } => assert!(matches!(
                result,
                Err(LinuxSandboxError::DirectoryListingScope)
            )),
            _ => assert!(matches!(result, Err(LinuxSandboxError::Unavailable(_)))),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn file_scope_does_not_grant_host_root_directory_reads() {
        if !preflight().is_available() {
            return;
        }
        let temp = TempDir::new().unwrap();
        let workspace_path = temp.path().join("workspace");
        fs::create_dir(&workspace_path).unwrap();
        fs::write(workspace_path.join("input.txt"), b"input\n").unwrap();
        let workspace = fs::canonicalize(workspace_path).unwrap();
        let executable = fs::canonicalize("/usr/bin/cat")
            .or_else(|_| fs::canonicalize("/bin/cat"))
            .unwrap();
        let plan = compile_candidate_plan(
            &executable,
            &workspace,
            &workspace,
            &AccessPlan {
                scopes: vec![AccessScope::ContentPath(PathBuf::from("input.txt"))],
            },
        )
        .unwrap();
        assert!(
            plan.rules.iter().all(|rule| rule.path != Path::new("/")),
            "path traversal must not be modeled as a READ_DIR grant on host root"
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn macos_is_explicitly_unsupported() {
        assert!(matches!(
            preflight(),
            LinuxSandboxAvailability::UnsupportedPlatform { .. }
        ));
        assert!(matches!(
            probe_apply(),
            Err(LinuxSandboxProbeError::Unavailable(
                LinuxSandboxAvailability::UnsupportedPlatform { .. }
            ))
        ));
    }
}
