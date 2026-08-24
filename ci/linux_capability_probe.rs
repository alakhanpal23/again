//! Read-only, non-qualifying Linux capability inventory for hosted CI.
//!
//! This executable is deliberately independent from Again's product sandbox.
//! It changes no host sysctl, LSM policy, mount, or host capability. The user
//! namespace check maps only a disposable child namespace. A successful report
//! is hosted-runner evidence only and never qualifies `linux-pytest-v1`.

use std::env;
use std::io::{self, Write};
use std::process;

#[cfg(all(target_os = "linux", not(target_env = "gnu")))]
compile_error!("the hosted Linux inventory probe supports only the GNU libc ABI");
#[cfg(all(
    target_os = "linux",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("the hosted Linux inventory probe supports only x86_64 and aarch64");

const REPORT_SCHEMA: &str = "again.linux-capability-evidence.v1";
const EXIT_SUPPORTED: i32 = 0;
const EXIT_BROKEN: i32 = 1;
const EXIT_UNAVAILABLE: i32 = 77;

#[derive(Clone, Debug)]
enum JsonValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Object(Vec<(String, JsonValue)>),
}

impl JsonValue {
    fn number(value: impl ToString) -> Self {
        Self::Number(value.to_string())
    }

    fn string(value: impl Into<String>) -> Self {
        Self::String(value.into())
    }
}

fn object(entries: Vec<(&str, JsonValue)>) -> JsonValue {
    JsonValue::Object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_owned(), value))
            .collect(),
    )
}

#[cfg(target_os = "linux")]
fn optional_string(value: Option<String>) -> JsonValue {
    value.map_or(JsonValue::Null, JsonValue::String)
}

fn encode_json(value: &JsonValue, output: &mut String) {
    match value {
        JsonValue::Null => output.push_str("null"),
        JsonValue::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        JsonValue::Number(value) => output.push_str(value),
        JsonValue::String(value) => encode_json_string(value, output),
        JsonValue::Object(entries) => {
            output.push('{');
            for (index, (name, value)) in entries.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                encode_json_string(name, output);
                output.push(':');
                encode_json(value, output);
            }
            output.push('}');
        }
    }
}

fn encode_json_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            control if control <= '\u{1f}' => {
                use std::fmt::Write as _;
                write!(output, "\\u{:04x}", control as u32)
                    .expect("writing to a String cannot fail");
            }
            ordinary => output.push(ordinary),
        }
    }
    output.push('"');
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProbeStatus {
    Supported,
    Unavailable,
    Broken,
}

impl ProbeStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Supported => "supported",
            Self::Unavailable => "unavailable",
            Self::Broken => "broken",
        }
    }
}

#[derive(Debug)]
struct ProbeResult {
    status: ProbeStatus,
    reason: &'static str,
    stage: &'static str,
    errno: Option<i32>,
    evidence: Vec<(&'static str, JsonValue)>,
}

impl ProbeResult {
    fn new(
        status: ProbeStatus,
        reason: &'static str,
        stage: &'static str,
        errno: Option<i32>,
        evidence: Vec<(&'static str, JsonValue)>,
    ) -> Self {
        Self {
            status,
            reason,
            stage,
            errno,
            evidence,
        }
    }

    fn to_json(&self) -> JsonValue {
        object(vec![
            ("status", JsonValue::string(self.status.as_str())),
            ("reason", JsonValue::string(self.reason)),
            ("stage", JsonValue::string(self.stage)),
            (
                "errno",
                self.errno.map_or(JsonValue::Null, JsonValue::number),
            ),
            (
                "evidence",
                object(
                    self.evidence
                        .iter()
                        .map(|(name, value)| (*name, value.clone()))
                        .collect(),
                ),
            ),
        ])
    }
}

fn runner_json() -> JsonValue {
    object(vec![
        ("image_os", optional_env("ImageOS")),
        ("image_version", optional_env("ImageVersion")),
        ("runner_os", optional_env("RUNNER_OS")),
        ("runner_arch", optional_env("RUNNER_ARCH")),
        ("github_sha", optional_env("GITHUB_SHA")),
    ])
}

fn optional_env(name: &str) -> JsonValue {
    env::var_os(name).map_or(JsonValue::Null, |value| {
        JsonValue::String(value.to_string_lossy().into_owned())
    })
}

fn main() {
    let results = platform::run_probes();
    let supported = results
        .iter()
        .filter(|(_, result)| result.status == ProbeStatus::Supported)
        .count();
    let unavailable = results
        .iter()
        .filter(|(_, result)| result.status == ProbeStatus::Unavailable)
        .count();
    let broken = results
        .iter()
        .filter(|(_, result)| result.status == ProbeStatus::Broken)
        .count();
    let exit_code = if broken != 0 {
        EXIT_BROKEN
    } else if unavailable != 0 {
        EXIT_UNAVAILABLE
    } else {
        EXIT_SUPPORTED
    };
    let results_json = JsonValue::Object(
        results
            .iter()
            .map(|(name, result)| ((*name).to_owned(), result.to_json()))
            .collect(),
    );
    let report = object(vec![
        ("schema", JsonValue::string(REPORT_SCHEMA)),
        (
            "scope",
            object(vec![
                ("kind", JsonValue::string("hosted_ci_capability_evidence")),
                ("profile_qualification", JsonValue::Bool(false)),
                ("host_policy_mutated", JsonValue::Bool(false)),
            ]),
        ),
        ("runner", runner_json()),
        ("platform", platform::platform_json()),
        ("process", platform::process_json()),
        ("security", platform::security_json()),
        ("results", results_json),
        (
            "summary",
            object(vec![
                ("supported", JsonValue::number(supported)),
                ("unavailable", JsonValue::number(unavailable)),
                ("broken", JsonValue::number(broken)),
                ("exit_code", JsonValue::number(exit_code)),
            ]),
        ),
    ]);
    let mut encoded = String::new();
    encode_json(&report, &mut encoded);
    encoded.push('\n');
    if io::stdout().lock().write_all(encoded.as_bytes()).is_err() {
        process::exit(EXIT_BROKEN);
    }
    process::exit(exit_code);
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use super::{JsonValue, ProbeResult, ProbeStatus, object};

    pub(super) fn run_probes() -> Vec<(&'static str, ProbeResult)> {
        [
            "ordinary_unprivileged_user",
            "user_namespace",
            "landlock_abi",
            "openat2",
            "close_range_unshare",
        ]
        .into_iter()
        .map(|name| {
            (
                name,
                ProbeResult::new(
                    ProbeStatus::Unavailable,
                    "unsupported_platform",
                    "platform",
                    None,
                    Vec::new(),
                ),
            )
        })
        .collect()
    }

    pub(super) fn platform_json() -> JsonValue {
        object(vec![
            ("os", JsonValue::string(std::env::consts::OS)),
            ("arch", JsonValue::string(std::env::consts::ARCH)),
            ("kernel_release", JsonValue::Null),
            ("kernel_version", JsonValue::Null),
            ("glibc", JsonValue::Null),
        ])
    }

    pub(super) fn process_json() -> JsonValue {
        object(vec![
            ("uid", JsonValue::Null),
            ("euid", JsonValue::Null),
            ("gid", JsonValue::Null),
            ("egid", JsonValue::Null),
            ("capabilities", JsonValue::Null),
            ("no_new_privs", JsonValue::Null),
            ("seccomp", JsonValue::Null),
            ("seccomp_filters", JsonValue::Null),
        ])
    }

    pub(super) fn security_json() -> JsonValue {
        object(vec![
            ("lsm", JsonValue::Null),
            ("apparmor_profile", JsonValue::Null),
            ("sysctls", JsonValue::Null),
        ])
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use std::collections::BTreeMap;
    use std::ffi::{CStr, CString, c_char, c_int, c_long, c_uint, c_void};
    use std::fs::{self, File};
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    use std::ptr;

    use super::{JsonValue, ProbeResult, ProbeStatus, object, optional_string};

    const EPERM: i32 = 1;
    const ENOENT: i32 = 2;
    const EINTR: i32 = 4;
    const E2BIG: i32 = 7;
    const EBADF: i32 = 9;
    const EAGAIN: i32 = 11;
    const ENOMEM: i32 = 12;
    const EACCES: i32 = 13;
    const EXDEV: i32 = 18;
    const EINVAL: i32 = 22;
    const ENOSPC: i32 = 28;
    const ENOSYS: i32 = 38;
    const ELOOP: i32 = 40;
    const EUSERS: i32 = 87;
    const EOPNOTSUPP: i32 = 95;

    const CLONE_FILES: c_int = 0x0000_0400;
    const CLONE_NEWUTS: c_int = 0x0400_0000;
    const CLONE_NEWUSER: c_int = 0x1000_0000;
    const SIGCHLD: c_int = 17;
    const F_GETFD: c_int = 1;

    const SYS_CLOSE_RANGE: c_long = 436;
    const SYS_OPENAT2: c_long = 437;
    const SYS_LANDLOCK_CREATE_RULESET: c_long = 444;
    const CLOSE_RANGE_UNSHARE: c_uint = 1 << 1;
    const LANDLOCK_CREATE_RULESET_VERSION: c_uint = 1;
    const MIN_LANDLOCK_ABI: c_long = 3;

    const O_CLOEXEC: u64 = 0x0008_0000;
    const AT_FDCWD: c_int = -100;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;

    const USER_MESSAGE_BYTES: usize = 16;
    const USER_MESSAGE_SUCCESS: u8 = 0;
    const USER_MESSAGE_OS_ERROR: u8 = 1;
    const USER_MESSAGE_INVARIANT: u8 = 2;
    const USER_STAGE_COMPLETE: u8 = 0;
    const USER_STAGE_UNSHARE: u8 = 1;
    const USER_STAGE_SETGROUPS: u8 = 2;
    const USER_STAGE_UID_MAP: u8 = 3;
    const USER_STAGE_GID_MAP: u8 = 4;
    const USER_STAGE_SET_IDS: u8 = 5;
    const USER_STAGE_VERIFY_IDENTITY: u8 = 6;
    const USER_STAGE_UNSHARE_UTS: u8 = 7;

    #[repr(C)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[repr(C)]
    struct UtsName {
        sysname: [c_char; 65],
        nodename: [c_char; 65],
        release: [c_char; 65],
        version: [c_char; 65],
        machine: [c_char; 65],
        domainname: [c_char; 65],
    }

    struct CloseRangeChild {
        sentinel_fd: c_int,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ChildWait {
        Exited(i32),
        Signaled { raw_status: i32, signal: i32 },
        WaitError(i32),
    }

    unsafe extern "C" {
        fn syscall(number: c_long, ...) -> c_long;
        fn fork() -> c_int;
        fn pipe(pipe_fds: *mut c_int) -> c_int;
        fn close(fd: c_int) -> c_int;
        fn write(fd: c_int, buffer: *const c_void, count: usize) -> isize;
        fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
        fn _exit(status: c_int) -> !;
        fn unshare(flags: c_int) -> c_int;
        fn getuid() -> c_uint;
        fn geteuid() -> c_uint;
        fn getgid() -> c_uint;
        fn getegid() -> c_uint;
        fn setresuid(real: c_uint, effective: c_uint, saved: c_uint) -> c_int;
        fn setresgid(real: c_uint, effective: c_uint, saved: c_uint) -> c_int;
        fn uname(name: *mut UtsName) -> c_int;
        fn gnu_get_libc_version() -> *const c_char;
        fn clone(
            callback: extern "C" fn(*mut c_void) -> c_int,
            child_stack: *mut c_void,
            flags: c_int,
            argument: *mut c_void,
            ...
        ) -> c_int;
        fn fcntl(fd: c_int, operation: c_int, ...) -> c_int;
    }

    pub(super) fn run_probes() -> Vec<(&'static str, ProbeResult)> {
        vec![
            ("ordinary_unprivileged_user", probe_execution_identity()),
            ("user_namespace", probe_user_namespace()),
            ("landlock_abi", probe_landlock_abi()),
            ("openat2", probe_openat2()),
            ("close_range_unshare", probe_close_range_unshare()),
        ]
    }

    pub(super) fn platform_json() -> JsonValue {
        let (kernel_release, kernel_version, machine, uname_errno) = uname_inventory();
        object(vec![
            ("os", JsonValue::string(std::env::consts::OS)),
            ("arch", JsonValue::string(std::env::consts::ARCH)),
            ("kernel_release", optional_string(kernel_release)),
            ("kernel_version", optional_string(kernel_version)),
            ("kernel_machine", optional_string(machine)),
            (
                "uname_errno",
                uname_errno.map_or(JsonValue::Null, JsonValue::number),
            ),
            ("glibc", optional_string(glibc_version())),
        ])
    }

    pub(super) fn process_json() -> JsonValue {
        let status = proc_status();
        object(vec![
            ("uid", JsonValue::number(current_uid())),
            ("euid", JsonValue::number(current_euid())),
            ("gid", JsonValue::number(current_gid())),
            ("egid", JsonValue::number(current_egid())),
            (
                "capabilities",
                object(vec![
                    ("inheritable", status_value(&status, "CapInh")),
                    ("permitted", status_value(&status, "CapPrm")),
                    ("effective", status_value(&status, "CapEff")),
                    ("bounding", status_value(&status, "CapBnd")),
                    ("ambient", status_value(&status, "CapAmb")),
                ]),
            ),
            ("no_new_privs", status_value(&status, "NoNewPrivs")),
            ("seccomp", status_value(&status, "Seccomp")),
            ("seccomp_filters", status_value(&status, "Seccomp_filters")),
        ])
    }

    pub(super) fn security_json() -> JsonValue {
        object(vec![
            ("lsm", inventory_file("/sys/kernel/security/lsm")),
            (
                "apparmor_profile",
                inventory_file("/proc/self/attr/current"),
            ),
            (
                "sysctls",
                object(vec![
                    (
                        "unprivileged_userns_clone",
                        inventory_file("/proc/sys/kernel/unprivileged_userns_clone"),
                    ),
                    (
                        "apparmor_restrict_unprivileged_userns",
                        inventory_file("/proc/sys/kernel/apparmor_restrict_unprivileged_userns"),
                    ),
                    (
                        "max_user_namespaces",
                        inventory_file("/proc/sys/user/max_user_namespaces"),
                    ),
                    (
                        "yama_ptrace_scope",
                        inventory_file("/proc/sys/kernel/yama/ptrace_scope"),
                    ),
                ]),
            ),
        ])
    }

    fn probe_execution_identity() -> ProbeResult {
        let euid = current_euid();
        let status = proc_status();
        let effective = status.get("CapEff").cloned();
        let parsed = effective
            .as_deref()
            .and_then(|value| u64::from_str_radix(value, 16).ok());
        let evidence = vec![
            ("euid", JsonValue::number(euid)),
            ("effective_capabilities", optional_string(effective)),
        ];
        if euid == 0 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "probe_ran_as_root",
                "identity",
                None,
                evidence,
            );
        }
        match parsed {
            Some(0) => ProbeResult::new(
                ProbeStatus::Supported,
                "ordinary_unprivileged_user_verified",
                "complete",
                None,
                evidence,
            ),
            Some(_) => ProbeResult::new(
                ProbeStatus::Broken,
                "effective_host_capabilities_present",
                "identity",
                None,
                evidence,
            ),
            None => ProbeResult::new(
                ProbeStatus::Broken,
                "capability_inventory_invalid",
                "proc_status",
                None,
                evidence,
            ),
        }
    }

    fn probe_user_namespace() -> ProbeResult {
        let before_inode = match fs::metadata("/proc/self/ns/user") {
            Ok(metadata) => metadata.ino(),
            Err(error) => {
                return ProbeResult::new(
                    ProbeStatus::Unavailable,
                    "namespace_inventory_unavailable",
                    "read_parent_namespace",
                    error.raw_os_error(),
                    Vec::new(),
                );
            }
        };
        let mut pipe_fds = [-1; 2];
        if unsafe { pipe(pipe_fds.as_mut_ptr()) } != 0 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "probe_pipe_failed",
                "create_pipe",
                last_errno(),
                Vec::new(),
            );
        }
        let uid = current_uid();
        let gid = current_gid();
        let child = unsafe { fork() };
        if child == 0 {
            unsafe {
                close(pipe_fds[0]);
            }
            user_namespace_child(pipe_fds[1], before_inode, uid, gid);
        }
        if child < 0 {
            let errno = last_errno();
            unsafe {
                close(pipe_fds[0]);
                close(pipe_fds[1]);
            }
            return classify_errno(
                "fork_unavailable",
                "fork",
                errno,
                &[EAGAIN, ENOMEM],
                Vec::new(),
            );
        }
        unsafe {
            close(pipe_fds[1]);
        }
        let mut message = [0_u8; USER_MESSAGE_BYTES];
        let read_result = unsafe { File::from_raw_fd(pipe_fds[0]) }.read_exact(&mut message);
        let wait_result = wait_for_child(child);
        if let Err(error) = read_result {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "probe_child_message_failed",
                "read_child_message",
                error.raw_os_error(),
                Vec::new(),
            );
        }
        match wait_result {
            ChildWait::Exited(0) => {}
            ChildWait::Exited(code) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "probe_child_exit_failed",
                    "wait_child",
                    None,
                    vec![("child_exit_code", JsonValue::number(code))],
                );
            }
            ChildWait::Signaled { raw_status, signal } => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "probe_child_signaled",
                    "wait_child",
                    None,
                    vec![
                        ("raw_wait_status", JsonValue::number(raw_status)),
                        ("signal", JsonValue::number(signal)),
                    ],
                );
            }
            ChildWait::WaitError(errno) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "probe_child_wait_failed",
                    "wait_child",
                    Some(errno),
                    Vec::new(),
                );
            }
        }
        let kind = message[0];
        let stage_code = message[1];
        let Some(stage) = user_stage(stage_code) else {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "probe_child_message_invalid",
                "decode_child_message",
                None,
                vec![("stage_code", JsonValue::number(stage_code))],
            );
        };
        let errno = i32::from_ne_bytes(message[4..8].try_into().expect("fixed message slice"));
        let inode_changed = message[8] == 1;
        let mapped_root = message[9] == 1;
        let reserved_clear = message[2..4].iter().all(|byte| *byte == 0)
            && message[10..].iter().all(|byte| *byte == 0);
        let evidence = vec![
            ("namespace_inode_changed", JsonValue::Bool(inode_changed)),
            ("mapped_namespace_root", JsonValue::Bool(mapped_root)),
            (
                "message_reserved_bytes_zero",
                JsonValue::Bool(reserved_clear),
            ),
            (
                "namespaced_capability_checked",
                JsonValue::string("CLONE_NEWUTS"),
            ),
        ];
        if message[8] > 1 || message[9] > 1 || !reserved_clear {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "probe_child_message_invalid",
                "decode_child_message",
                None,
                evidence,
            );
        }
        match kind {
            USER_MESSAGE_SUCCESS
                if stage_code == USER_STAGE_COMPLETE
                    && inode_changed
                    && mapped_root
                    && errno == 0 =>
            {
                ProbeResult::new(
                    ProbeStatus::Supported,
                    "mapped_user_namespace_and_capability_verified",
                    "complete",
                    None,
                    evidence,
                )
            }
            USER_MESSAGE_OS_ERROR if stage_code != USER_STAGE_COMPLETE && errno > 0 => {
                let unavailable_errnos: &[i32] = match stage_code {
                    USER_STAGE_UNSHARE => &[EPERM, EACCES, EINVAL, ENOSYS, EUSERS, ENOSPC, ENOMEM],
                    USER_STAGE_SETGROUPS | USER_STAGE_UID_MAP | USER_STAGE_GID_MAP => {
                        &[EPERM, EACCES, ENOENT]
                    }
                    USER_STAGE_SET_IDS => &[EPERM, EACCES],
                    USER_STAGE_UNSHARE_UTS => &[EPERM, EACCES, EINVAL, ENOSYS, ENOMEM],
                    _ => &[],
                };
                classify_errno(
                    "user_namespace_unavailable",
                    stage,
                    Some(errno),
                    unavailable_errnos,
                    evidence,
                )
            }
            USER_MESSAGE_INVARIANT => ProbeResult::new(
                ProbeStatus::Broken,
                "user_namespace_invariant_failed",
                stage,
                (errno != 0).then_some(errno),
                evidence,
            ),
            _ => ProbeResult::new(
                ProbeStatus::Broken,
                "probe_child_message_invalid",
                "decode_child_message",
                None,
                evidence,
            ),
        }
    }

    fn user_namespace_child(write_fd: c_int, before_inode: u64, uid: u32, gid: u32) -> ! {
        if unsafe { unshare(CLONE_NEWUSER) } != 0 {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_UNSHARE,
                last_errno().unwrap_or(EINVAL),
                false,
                false,
            );
        }
        let after_inode = match fs::metadata("/proc/self/ns/user") {
            Ok(metadata) => metadata.ino(),
            Err(error) => send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_UNSHARE,
                error.raw_os_error().unwrap_or(ENOENT),
                false,
                false,
            ),
        };
        let inode_changed = before_inode != after_inode;
        if let Err(error) = fs::write("/proc/self/setgroups", b"deny\n") {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_SETGROUPS,
                error.raw_os_error().unwrap_or(EACCES),
                inode_changed,
                false,
            );
        }
        if let Err(error) = fs::write("/proc/self/uid_map", format!("0 {uid} 1\n")) {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_UID_MAP,
                error.raw_os_error().unwrap_or(EACCES),
                inode_changed,
                false,
            );
        }
        if let Err(error) = fs::write("/proc/self/gid_map", format!("0 {gid} 1\n")) {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_GID_MAP,
                error.raw_os_error().unwrap_or(EACCES),
                inode_changed,
                false,
            );
        }
        if unsafe { setresgid(0, 0, 0) } != 0 || unsafe { setresuid(0, 0, 0) } != 0 {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_SET_IDS,
                last_errno().unwrap_or(EPERM),
                inode_changed,
                false,
            );
        }
        let mapped_root =
            current_uid() == 0 && current_euid() == 0 && current_gid() == 0 && current_egid() == 0;
        if !inode_changed || !mapped_root {
            send_user_message(
                write_fd,
                USER_MESSAGE_INVARIANT,
                USER_STAGE_VERIFY_IDENTITY,
                0,
                inode_changed,
                mapped_root,
            );
        }
        if unsafe { unshare(CLONE_NEWUTS) } != 0 {
            send_user_message(
                write_fd,
                USER_MESSAGE_OS_ERROR,
                USER_STAGE_UNSHARE_UTS,
                last_errno().unwrap_or(EPERM),
                inode_changed,
                mapped_root,
            );
        }
        send_user_message(
            write_fd,
            USER_MESSAGE_SUCCESS,
            USER_STAGE_COMPLETE,
            0,
            inode_changed,
            mapped_root,
        );
    }

    fn send_user_message(
        write_fd: c_int,
        kind: u8,
        stage: u8,
        errno: i32,
        inode_changed: bool,
        mapped_root: bool,
    ) -> ! {
        let mut message = [0_u8; USER_MESSAGE_BYTES];
        message[0] = kind;
        message[1] = stage;
        message[4..8].copy_from_slice(&errno.to_ne_bytes());
        message[8] = u8::from(inode_changed);
        message[9] = u8::from(mapped_root);
        let written = unsafe { write(write_fd, message.as_ptr().cast::<c_void>(), message.len()) };
        unsafe {
            close(write_fd);
            _exit(if written == message.len() as isize {
                0
            } else {
                251
            });
        }
    }

    fn user_stage(stage: u8) -> Option<&'static str> {
        match stage {
            USER_STAGE_COMPLETE => Some("complete"),
            USER_STAGE_UNSHARE => Some("unshare_user"),
            USER_STAGE_SETGROUPS => Some("write_setgroups"),
            USER_STAGE_UID_MAP => Some("write_uid_map"),
            USER_STAGE_GID_MAP => Some("write_gid_map"),
            USER_STAGE_SET_IDS => Some("set_namespace_ids"),
            USER_STAGE_VERIFY_IDENTITY => Some("verify_namespace_identity"),
            USER_STAGE_UNSHARE_UTS => Some("exercise_namespaced_capability"),
            _ => None,
        }
    }

    fn probe_landlock_abi() -> ProbeResult {
        let result = unsafe {
            syscall(
                SYS_LANDLOCK_CREATE_RULESET,
                ptr::null::<c_void>(),
                0_usize,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if result >= MIN_LANDLOCK_ABI {
            return ProbeResult::new(
                ProbeStatus::Supported,
                "landlock_abi_query_only",
                "complete",
                None,
                vec![
                    ("kernel_abi", JsonValue::number(result)),
                    ("minimum_abi", JsonValue::number(MIN_LANDLOCK_ABI)),
                    ("functional_ruleset_tested", JsonValue::Bool(false)),
                ],
            );
        }
        if result > 0 {
            return ProbeResult::new(
                ProbeStatus::Unavailable,
                "landlock_abi_too_old",
                "query_abi",
                None,
                vec![
                    ("kernel_abi", JsonValue::number(result)),
                    ("minimum_abi", JsonValue::number(MIN_LANDLOCK_ABI)),
                ],
            );
        }
        if result == 0 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "landlock_abi_invalid",
                "query_abi",
                None,
                vec![("kernel_abi", JsonValue::number(result))],
            );
        }
        classify_errno(
            "landlock_unavailable",
            "query_abi",
            last_errno(),
            &[ENOSYS, EOPNOTSUPP, EPERM, EACCES],
            vec![("minimum_abi", JsonValue::number(MIN_LANDLOCK_ABI))],
        )
    }

    fn probe_openat2() -> ProbeResult {
        let root_file = match File::open("/proc/self") {
            Ok(file) => file,
            Err(error) => {
                return classify_errno(
                    "procfs_unavailable",
                    "open_proc_self",
                    error.raw_os_error(),
                    &[ENOENT, EPERM, EACCES],
                    Vec::new(),
                );
            }
        };
        let inside_name = CString::new("status").expect("static path contains no NUL");
        let inside_fd = match openat2_bounded(
            root_file.as_raw_fd(),
            &inside_name,
            RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS,
        ) {
            Ok(fd) => fd,
            Err(errno) if matches!(errno, ENOSYS | EPERM | EACCES | EOPNOTSUPP | EAGAIN) => {
                return ProbeResult::new(
                    ProbeStatus::Unavailable,
                    "openat2_unavailable",
                    "open_inside",
                    Some(errno),
                    Vec::new(),
                );
            }
            Err(errno @ (EINVAL | E2BIG)) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "openat2_abi_contract_failed",
                    "open_inside",
                    Some(errno),
                    Vec::new(),
                );
            }
            Err(errno) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "openat2_inside_failed",
                    "open_inside",
                    Some(errno),
                    Vec::new(),
                );
            }
        };
        let mut contents = Vec::new();
        let read_result = unsafe { File::from_raw_fd(inside_fd) }.read_to_end(&mut contents);
        if let Err(error) = read_result {
            return fixture_broken("read_inside_file", error);
        }
        if !contents
            .windows(b"Name:".len())
            .any(|window| window == b"Name:")
        {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "openat2_content_mismatch",
                "read_inside_file",
                None,
                Vec::new(),
            );
        }
        let escape_name = CString::new("../version").expect("static path contains no NUL");
        match openat2_bounded(root_file.as_raw_fd(), &escape_name, RESOLVE_BENEATH) {
            Err(EXDEV) => {}
            Err(EAGAIN) => {
                return ProbeResult::new(
                    ProbeStatus::Unavailable,
                    "openat2_resolution_race_persistent",
                    "resolve_beneath",
                    Some(EAGAIN),
                    Vec::new(),
                );
            }
            Ok(fd) => {
                unsafe {
                    close(fd);
                }
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "openat2_escape_succeeded",
                    "resolve_beneath",
                    None,
                    Vec::new(),
                );
            }
            Err(errno) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "openat2_escape_errno_mismatch",
                    "resolve_beneath",
                    Some(errno),
                    vec![("expected_errno", JsonValue::number(EXDEV))],
                );
            }
        }
        let outside_file = match File::open("/dev/null") {
            Ok(file) => file,
            Err(error) => return fixture_broken("open_magic_link_target", error),
        };
        let magic_path = match CString::new(format!("/proc/self/fd/{}", outside_file.as_raw_fd())) {
            Ok(path) => path,
            Err(_) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "magic_link_path_invalid",
                    "construct_magic_link",
                    None,
                    Vec::new(),
                );
            }
        };
        match openat2_bounded(AT_FDCWD, &magic_path, RESOLVE_NO_MAGICLINKS) {
            Err(ELOOP) => ProbeResult::new(
                ProbeStatus::Supported,
                "openat2_resolution_semantics_verified",
                "complete",
                None,
                vec![
                    ("beneath_escape_errno", JsonValue::number(EXDEV)),
                    ("magic_link_errno", JsonValue::number(ELOOP)),
                ],
            ),
            Err(ENOENT) => ProbeResult::new(
                ProbeStatus::Unavailable,
                "procfs_magic_link_unavailable",
                "resolve_no_magiclinks",
                Some(ENOENT),
                Vec::new(),
            ),
            Err(EAGAIN) => ProbeResult::new(
                ProbeStatus::Unavailable,
                "openat2_resolution_race_persistent",
                "resolve_no_magiclinks",
                Some(EAGAIN),
                Vec::new(),
            ),
            Ok(fd) => {
                unsafe {
                    close(fd);
                }
                ProbeResult::new(
                    ProbeStatus::Broken,
                    "openat2_magic_link_succeeded",
                    "resolve_no_magiclinks",
                    None,
                    Vec::new(),
                )
            }
            Err(errno) => ProbeResult::new(
                ProbeStatus::Broken,
                "openat2_magic_link_errno_mismatch",
                "resolve_no_magiclinks",
                Some(errno),
                vec![("expected_errno", JsonValue::number(ELOOP))],
            ),
        }
    }

    fn openat2_bounded(dirfd: c_int, path: &CStr, resolve: u64) -> Result<c_int, i32> {
        const MAX_EAGAIN_ATTEMPTS: usize = 4;
        for _ in 0..MAX_EAGAIN_ATTEMPTS {
            match openat2_once(dirfd, path, resolve) {
                Err(EAGAIN) => continue,
                result => return result,
            }
        }
        Err(EAGAIN)
    }

    fn openat2_once(dirfd: c_int, path: &CStr, resolve: u64) -> Result<c_int, i32> {
        let how = OpenHow {
            flags: O_CLOEXEC,
            mode: 0,
            resolve,
        };
        let result = unsafe {
            syscall(
                SYS_OPENAT2,
                dirfd,
                path.as_ptr(),
                &how,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if result < 0 {
            Err(last_errno().unwrap_or(EINVAL))
        } else {
            Ok(result as c_int)
        }
    }

    fn probe_close_range_unshare() -> ProbeResult {
        let sentinel = match File::open("/dev/null") {
            Ok(file) => file,
            Err(error) => return fixture_broken("open_sentinel", error),
        };
        let sentinel_fd = sentinel.as_raw_fd();
        if sentinel_fd < 3 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "sentinel_fd_invalid",
                "open_sentinel",
                None,
                vec![("sentinel_fd", JsonValue::number(sentinel_fd))],
            );
        }
        let mut context = CloseRangeChild { sentinel_fd };
        let mut stack = vec![0_u8; 1024 * 1024];
        let stack_end = unsafe { stack.as_mut_ptr().add(stack.len()) } as usize;
        let stack_pointer = (stack_end & !15_usize) as *mut c_void;
        let child = unsafe {
            clone(
                close_range_child,
                stack_pointer,
                CLONE_FILES | SIGCHLD,
                (&mut context as *mut CloseRangeChild).cast::<c_void>(),
            )
        };
        if child < 0 {
            return classify_errno(
                "clone_files_unavailable",
                "clone_shared_fd_table",
                last_errno(),
                &[EAGAIN, ENOMEM, EPERM, EACCES, ENOSYS],
                Vec::new(),
            );
        }
        let child_exit = match wait_for_child(child) {
            ChildWait::Exited(code) => code,
            ChildWait::Signaled { raw_status, signal } => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "close_range_child_signaled",
                    "wait_child",
                    None,
                    vec![
                        ("raw_wait_status", JsonValue::number(raw_status)),
                        ("signal", JsonValue::number(signal)),
                    ],
                );
            }
            ChildWait::WaitError(errno) => {
                return ProbeResult::new(
                    ProbeStatus::Broken,
                    "close_range_child_wait_failed",
                    "wait_child",
                    Some(errno),
                    Vec::new(),
                );
            }
        };
        if (100..=254).contains(&child_exit) {
            return classify_errno(
                "close_range_unshare_unavailable",
                "close_range",
                Some(child_exit - 100),
                &[ENOSYS, EPERM, EACCES, EOPNOTSUPP],
                Vec::new(),
            );
        }
        if child_exit != 0 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "close_range_child_invariant_failed",
                "verify_child_fd",
                None,
                vec![("child_exit_code", JsonValue::number(child_exit))],
            );
        }
        if unsafe { fcntl(sentinel_fd, F_GETFD) } < 0 {
            return ProbeResult::new(
                ProbeStatus::Broken,
                "close_range_did_not_unshare_fd_table",
                "verify_parent_fd",
                last_errno(),
                Vec::new(),
            );
        }
        ProbeResult::new(
            ProbeStatus::Supported,
            "close_range_unshare_semantics_verified",
            "complete",
            None,
            vec![
                ("shared_fd_table_fixture", JsonValue::Bool(true)),
                ("sentinel_fd", JsonValue::number(sentinel_fd)),
            ],
        )
    }

    extern "C" fn close_range_child(argument: *mut c_void) -> c_int {
        let sentinel_fd = unsafe { (*(argument.cast::<CloseRangeChild>())).sentinel_fd };
        let sentinel = sentinel_fd as c_uint;
        let result = unsafe { syscall(SYS_CLOSE_RANGE, sentinel, sentinel, CLOSE_RANGE_UNSHARE) };
        if result != 0 {
            return last_errno()
                .filter(|errno| *errno <= 154)
                .map_or(255, |errno| 100 + errno);
        }
        let descriptor_result = unsafe { fcntl(sentinel_fd, F_GETFD) };
        if descriptor_result < 0 && last_errno() == Some(EBADF) {
            0
        } else if descriptor_result >= 0 {
            2
        } else {
            3
        }
    }

    fn wait_for_child(child: c_int) -> ChildWait {
        let mut status = 0;
        loop {
            let result = unsafe { waitpid(child, &mut status, 0) };
            if result == child {
                break;
            }
            let errno = last_errno().unwrap_or(EINVAL);
            if result < 0 && errno == EINTR {
                continue;
            }
            return ChildWait::WaitError(errno);
        }
        if status & 0x7f == 0 {
            ChildWait::Exited((status >> 8) & 0xff)
        } else {
            ChildWait::Signaled {
                raw_status: status,
                signal: status & 0x7f,
            }
        }
    }

    fn classify_errno(
        unavailable_reason: &'static str,
        stage: &'static str,
        errno: Option<i32>,
        unavailable_errnos: &[i32],
        evidence: Vec<(&'static str, JsonValue)>,
    ) -> ProbeResult {
        if errno.is_some_and(|value| unavailable_errnos.contains(&value)) {
            ProbeResult::new(
                ProbeStatus::Unavailable,
                unavailable_reason,
                stage,
                errno,
                evidence,
            )
        } else {
            ProbeResult::new(
                ProbeStatus::Broken,
                "unexpected_os_error",
                stage,
                errno,
                evidence,
            )
        }
    }

    fn fixture_broken(stage: &'static str, error: std::io::Error) -> ProbeResult {
        ProbeResult::new(
            ProbeStatus::Broken,
            "fixture_io_failed",
            stage,
            error.raw_os_error(),
            Vec::new(),
        )
    }

    fn inventory_file(path: &str) -> JsonValue {
        match fs::read_to_string(path) {
            Ok(value) => object(vec![
                ("status", JsonValue::string("read")),
                ("value", JsonValue::string(value.trim_end().to_owned())),
                ("errno", JsonValue::Null),
            ]),
            Err(error) => object(vec![
                ("status", JsonValue::string("unavailable")),
                ("value", JsonValue::Null),
                (
                    "errno",
                    error
                        .raw_os_error()
                        .map_or(JsonValue::Null, JsonValue::number),
                ),
            ]),
        }
    }

    fn proc_status() -> BTreeMap<String, String> {
        let Ok(contents) = fs::read_to_string("/proc/self/status") else {
            return BTreeMap::new();
        };
        contents
            .lines()
            .filter_map(|line| {
                let (name, value) = line.split_once(':')?;
                Some((name.to_owned(), value.trim().to_owned()))
            })
            .collect()
    }

    fn status_value(status: &BTreeMap<String, String>, name: &str) -> JsonValue {
        optional_string(status.get(name).cloned())
    }

    fn uname_inventory() -> (Option<String>, Option<String>, Option<String>, Option<i32>) {
        let mut name = UtsName {
            sysname: [0; 65],
            nodename: [0; 65],
            release: [0; 65],
            version: [0; 65],
            machine: [0; 65],
            domainname: [0; 65],
        };
        if unsafe { uname(&mut name) } != 0 {
            return (None, None, None, last_errno());
        }
        (
            Some(c_char_array(&name.release)),
            Some(c_char_array(&name.version)),
            Some(c_char_array(&name.machine)),
            None,
        )
    }

    fn c_char_array(bytes: &[c_char]) -> String {
        let bytes = unsafe { std::slice::from_raw_parts(bytes.as_ptr().cast::<u8>(), bytes.len()) };
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        String::from_utf8_lossy(&bytes[..end]).into_owned()
    }

    fn glibc_version() -> Option<String> {
        let version = unsafe { gnu_get_libc_version() };
        if version.is_null() {
            None
        } else {
            Some(
                unsafe { CStr::from_ptr(version) }
                    .to_string_lossy()
                    .into_owned(),
            )
        }
    }

    fn last_errno() -> Option<i32> {
        std::io::Error::last_os_error().raw_os_error()
    }

    fn current_uid() -> u32 {
        unsafe { getuid() }
    }

    fn current_euid() -> u32 {
        unsafe { geteuid() }
    }

    fn current_gid() -> u32 {
        unsafe { getgid() }
    }

    fn current_egid() -> u32 {
        unsafe { getegid() }
    }
}
