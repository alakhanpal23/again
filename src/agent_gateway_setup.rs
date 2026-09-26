//! Deterministic, non-executing setup plans for the Again MCP gateway.
//!
//! Planning is always a dry run. It authenticates the explicit workspace path,
//! but never reads or writes agent configuration. The optional file installer
//! is deliberately conservative: it creates only a previously absent
//! configuration file and a sibling ownership record, or accepts an exact file
//! it already owns. It never merges into or overwrites user-managed
//! configuration; normal installations should use the emitted local CLI
//! command.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::Value;
use thiserror::Error;

const PLAN_VERSION: u32 = 3;
const SERVER_NAME: &str = "again";
const MAX_PATH_BYTES: usize = 4_096;
const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const OWNERSHIP_SUFFIX: &str = ".again-owner-v2";
const CLIENT_COMMAND_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_CLIENT_OUTPUT_BYTES: u64 = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentGatewayClientV1 {
    Codex,
    Claude,
}

impl AgentGatewayClientV1 {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StdioMcpCommandV1 {
    pub transport: &'static str,
    pub command: PathBuf,
    pub args: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentGatewaySetupPlanV1 {
    pub version: u32,
    pub client: AgentGatewayClientV1,
    pub server_name: &'static str,
    pub stdio: StdioMcpCommandV1,
    pub local_cli_command: String,
    pub workspace: PathBuf,
    pub config_path: PathBuf,
    pub ownership_path: PathBuf,
    pub ownership_digest: String,
    pub writes_by_default: bool,
    pub install_policy: &'static str,
    config_document: String,
}

impl AgentGatewaySetupPlanV1 {
    /// Construct a deterministic dry-run plan. This function authenticates the
    /// workspace directory, but never reads or writes configuration and never
    /// executes the emitted command.
    pub fn dry_run(
        client: AgentGatewayClientV1,
        config_path: impl AsRef<Path>,
        workspace: impl AsRef<Path>,
    ) -> Result<Self> {
        let executable = std::env::current_exe().map_err(AgentGatewaySetupError::Io)?;
        Self::dry_run_with_executable(client, config_path, workspace, executable)
    }

    /// Construct a deterministic dry-run plan pinned to an explicit Again
    /// executable. The executable is resolved to its canonical regular file so
    /// the installed MCP client cannot silently select another `again` through
    /// `PATH`.
    pub fn dry_run_with_executable(
        client: AgentGatewayClientV1,
        config_path: impl AsRef<Path>,
        workspace: impl AsRef<Path>,
        executable: impl AsRef<Path>,
    ) -> Result<Self> {
        let config_path = validate_config_path(config_path.as_ref())?;
        let workspace = validate_workspace(workspace.as_ref())?;
        let executable = validate_executable(executable.as_ref())?;
        let ownership_path = ownership_path_for(&config_path)?;
        let args = vec![
            "mcp".to_owned(),
            "connect".to_owned(),
            "--workspace".to_owned(),
            workspace.to_string_lossy().into_owned(),
        ];
        let local_cli_command = local_cli_command(client, &executable, &args);
        let config_document = managed_config_document(client, &executable, &args)?;
        if config_document.len() > MAX_CONFIG_BYTES {
            return Err(AgentGatewaySetupError::ConfigTooLarge);
        }
        let ownership_digest = ownership_digest(client, &config_path, &workspace, &config_document);
        Ok(Self {
            version: PLAN_VERSION,
            client,
            server_name: SERVER_NAME,
            stdio: StdioMcpCommandV1 {
                transport: "stdio",
                command: executable,
                args,
            },
            local_cli_command,
            workspace,
            config_path,
            ownership_path,
            ownership_digest,
            writes_by_default: false,
            install_policy: "official_client_cli_only_v1",
            config_document,
        })
    }

    pub fn codex(config_path: impl AsRef<Path>, workspace: impl AsRef<Path>) -> Result<Self> {
        Self::dry_run(AgentGatewayClientV1::Codex, config_path, workspace)
    }

    pub fn claude(config_path: impl AsRef<Path>, workspace: impl AsRef<Path>) -> Result<Self> {
        Self::dry_run(AgentGatewayClientV1::Claude, config_path, workspace)
    }

    pub fn machine_readable_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(AgentGatewaySetupError::SerializePlan)
    }

    pub fn managed_config_document(&self) -> &str {
        &self.config_document
    }

    fn ownership_record(&self) -> String {
        format!(
            "again-agent-gateway-owner-v2\nclient={}\nserver={}\nworkspace_digest={}\ndigest={}\n",
            self.client.as_str(),
            self.server_name,
            blake3::hash(self.workspace.as_os_str().as_encoded_bytes()).to_hex(),
            self.ownership_digest
        )
    }
}

impl fmt::Display for AgentGatewaySetupPlanV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "Dry run only. Install with:\n{}",
            self.local_cli_command
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnedInstallOutcomeV1 {
    Installed,
    AlreadyInstalledOwned,
}

#[derive(Debug, Error)]
pub enum AgentGatewaySetupError {
    #[error("gateway config path must be an absolute, bounded UTF-8 file path")]
    InvalidConfigPath,
    #[error("gateway executable must resolve to an absolute, bounded UTF-8 executable file")]
    InvalidExecutablePath,
    #[error("gateway workspace must be an explicit canonical, bounded, non-symlink directory")]
    InvalidWorkspace,
    #[error("gateway managed config exceeds its fixed size bound")]
    ConfigTooLarge,
    #[error("gateway setup plan serialization failed: {0}")]
    SerializePlan(serde_json::Error),
    #[error("gateway setup plan is internally inconsistent")]
    InvalidPlan,
    #[error("{client} CLI is unavailable or unsupported; run manually: {manual_command}")]
    UnsupportedClient {
        client: &'static str,
        manual_command: String,
    },
    #[error("{client} MCP entry conflicts with the exact Again command; refusing to change it")]
    ConflictingClientEntry { client: &'static str },
    #[error("{client} CLI command timed out")]
    ClientCommandTimeout { client: &'static str },
    #[error("{client} CLI output exceeded the fixed diagnostic bound")]
    ClientOutputTooLarge { client: &'static str },
    #[error("{client} CLI rejected the requested MCP change")]
    ClientCommandFailed { client: &'static str },
    #[error("{client} MCP change could not be verified exactly")]
    ClientVerificationFailed { client: &'static str },
    #[error("{client} MCP apply failed verification and its exact rollback could not be verified")]
    ClientRollbackFailed { client: &'static str },
    #[error("gateway config parent is missing, not a directory, or is a symlink")]
    UnsafeConfigParent,
    #[error("gateway config or ownership record is a symlink or non-regular file")]
    UnsafeExistingPath,
    #[error("gateway config exists without matching Again ownership; refusing to overwrite it")]
    UnownedConfiguration,
    #[error("gateway ownership record conflicts with this exact setup plan")]
    OwnershipConflict,
    #[error("gateway config I/O failed: {0}")]
    Io(#[from] io::Error),
}

pub type Result<T> = std::result::Result<T, AgentGatewaySetupError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientSetupActionV1 {
    Inspect,
    Apply,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientEntryStateV1 {
    Absent,
    Exact,
    Conflict,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ClientSetupOutcomeV1 {
    pub client: AgentGatewayClientV1,
    pub action: &'static str,
    pub before: ClientEntryStateV1,
    pub after: ClientEntryStateV1,
    pub changed: bool,
    pub verified: bool,
}

#[derive(Debug)]
struct BoundedOutputV1 {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

/// Inspect, apply, or remove the exact Again entry through the client's
/// supported CLI. This function never opens a client configuration file.
pub fn execute_client_setup_v1(
    plan: &AgentGatewaySetupPlanV1,
    action: ClientSetupActionV1,
) -> Result<ClientSetupOutcomeV1> {
    validate_plan_paths(plan)?;
    probe_client_cli_v1(plan)?;
    let before = inspect_client_entry_v1(plan)?;
    match action {
        ClientSetupActionV1::Inspect => Ok(ClientSetupOutcomeV1 {
            client: plan.client,
            action: "inspect",
            before,
            after: before,
            changed: false,
            verified: true,
        }),
        ClientSetupActionV1::Apply => {
            if before == ClientEntryStateV1::Conflict {
                return Err(AgentGatewaySetupError::ConflictingClientEntry {
                    client: plan.client.as_str(),
                });
            }
            if before == ClientEntryStateV1::Exact {
                return Ok(ClientSetupOutcomeV1 {
                    client: plan.client,
                    action: "apply",
                    before,
                    after: before,
                    changed: false,
                    verified: true,
                });
            }
            let output = run_client_command_v1(plan, &add_arguments_v1(plan))?;
            if !output.status.success() {
                return Err(AgentGatewaySetupError::ClientCommandFailed {
                    client: plan.client.as_str(),
                });
            }
            match inspect_client_entry_v1(plan) {
                Ok(ClientEntryStateV1::Exact) => Ok(ClientSetupOutcomeV1 {
                    client: plan.client,
                    action: "apply",
                    before,
                    after: ClientEntryStateV1::Exact,
                    changed: true,
                    verified: true,
                }),
                _ => {
                    // The entry was absent before this invocation, so removing
                    // it is a bounded rollback of only our own attempted add.
                    let rollback = run_client_command_v1(plan, &remove_arguments_v1(plan));
                    if rollback.is_err()
                        || !rollback.is_ok_and(|output| output.status.success())
                        || inspect_client_entry_v1(plan).ok() != Some(ClientEntryStateV1::Absent)
                    {
                        Err(AgentGatewaySetupError::ClientRollbackFailed {
                            client: plan.client.as_str(),
                        })
                    } else {
                        Err(AgentGatewaySetupError::ClientVerificationFailed {
                            client: plan.client.as_str(),
                        })
                    }
                }
            }
        }
        ClientSetupActionV1::Remove => {
            if before == ClientEntryStateV1::Conflict {
                return Err(AgentGatewaySetupError::ConflictingClientEntry {
                    client: plan.client.as_str(),
                });
            }
            if before == ClientEntryStateV1::Absent {
                return Ok(ClientSetupOutcomeV1 {
                    client: plan.client,
                    action: "remove",
                    before,
                    after: before,
                    changed: false,
                    verified: true,
                });
            }
            let output = run_client_command_v1(plan, &remove_arguments_v1(plan))?;
            if !output.status.success() {
                return Err(AgentGatewaySetupError::ClientCommandFailed {
                    client: plan.client.as_str(),
                });
            }
            let after = inspect_client_entry_v1(plan)?;
            if after != ClientEntryStateV1::Absent {
                return Err(AgentGatewaySetupError::ClientVerificationFailed {
                    client: plan.client.as_str(),
                });
            }
            Ok(ClientSetupOutcomeV1 {
                client: plan.client,
                action: "remove",
                before,
                after,
                changed: true,
                verified: true,
            })
        }
    }
}

fn probe_client_cli_v1(plan: &AgentGatewaySetupPlanV1) -> Result<()> {
    for arguments in [
        vec!["mcp".to_owned(), "add".to_owned(), "--help".to_owned()],
        vec!["mcp".to_owned(), "get".to_owned(), "--help".to_owned()],
        vec!["mcp".to_owned(), "list".to_owned(), "--help".to_owned()],
        vec!["mcp".to_owned(), "remove".to_owned(), "--help".to_owned()],
    ] {
        let output = match run_client_command_v1(plan, &arguments) {
            Ok(output) => output,
            Err(AgentGatewaySetupError::Io(_)) => return Err(unsupported_client_v1(plan)),
            Err(error) => return Err(error),
        };
        if !output.status.success() {
            return Err(unsupported_client_v1(plan));
        }
        let combined = [output.stdout.as_slice(), output.stderr.as_slice()].concat();
        if !combined.windows(3).any(|window| window == b"mcp")
            && !combined.windows(5).any(|window| window == b"Usage")
        {
            return Err(unsupported_client_v1(plan));
        }
        if plan.client == AgentGatewayClientV1::Codex
            && arguments[1] == "get"
            && !combined.windows(6).any(|window| window == b"--json")
        {
            return Err(unsupported_client_v1(plan));
        }
        if plan.client == AgentGatewayClientV1::Claude
            && arguments[1] == "add"
            && (!combined.windows(11).any(|window| window == b"--transport")
                || !combined.windows(7).any(|window| window == b"--scope"))
        {
            return Err(unsupported_client_v1(plan));
        }
    }
    Ok(())
}

fn unsupported_client_v1(plan: &AgentGatewaySetupPlanV1) -> AgentGatewaySetupError {
    AgentGatewaySetupError::UnsupportedClient {
        client: plan.client.as_str(),
        manual_command: plan.local_cli_command.clone(),
    }
}

fn inspect_client_entry_v1(plan: &AgentGatewaySetupPlanV1) -> Result<ClientEntryStateV1> {
    let mut get_arguments = vec!["mcp".to_owned(), "get".to_owned(), SERVER_NAME.to_owned()];
    if plan.client == AgentGatewayClientV1::Codex {
        get_arguments.push("--json".to_owned());
    }
    let get = run_client_command_v1(plan, &get_arguments)?;
    if get.status.success() {
        let definition = match plan.client {
            AgentGatewayClientV1::Codex => {
                let value: Value =
                    serde_json::from_slice(&get.stdout).map_err(|_| unsupported_client_v1(plan))?;
                find_client_definition_v1(&value)
            }
            AgentGatewayClientV1::Claude => parse_claude_definition_v1(&get.stdout),
        };
        let Some((command, args)) = definition else {
            return Err(unsupported_client_v1(plan));
        };
        return Ok(
            if command == plan.stdio.command && args == plan.stdio.args {
                ClientEntryStateV1::Exact
            } else {
                ClientEntryStateV1::Conflict
            },
        );
    }

    let mut list_arguments = vec!["mcp".to_owned(), "list".to_owned()];
    if plan.client == AgentGatewayClientV1::Codex {
        list_arguments.push("--json".to_owned());
    }
    let list = run_client_command_v1(plan, &list_arguments)?;
    if !list.status.success() {
        return Err(unsupported_client_v1(plan));
    }
    let contains_server = match plan.client {
        AgentGatewayClientV1::Codex => {
            let value: Value =
                serde_json::from_slice(&list.stdout).map_err(|_| unsupported_client_v1(plan))?;
            json_contains_named_server_v1(&value, SERVER_NAME)
        }
        AgentGatewayClientV1::Claude => text_contains_named_server_v1(&list.stdout, SERVER_NAME),
    };
    if contains_server {
        Err(unsupported_client_v1(plan))
    } else {
        Ok(ClientEntryStateV1::Absent)
    }
}

fn parse_claude_definition_v1(output: &[u8]) -> Option<(PathBuf, Vec<String>)> {
    let output = std::str::from_utf8(output).ok()?;
    let mut command = None;
    let mut args = None;
    for line in output.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("Command:") {
            command = Some(PathBuf::from(value.trim()));
        } else if let Some(value) = line.strip_prefix("Args:") {
            args = shell_words::split(value.trim()).ok();
        }
    }
    Some((command?, args?))
}

fn text_contains_named_server_v1(output: &[u8], name: &str) -> bool {
    std::str::from_utf8(output).is_ok_and(|output| {
        output.lines().any(|line| {
            let first = line
                .trim_start()
                .split_ascii_whitespace()
                .next()
                .unwrap_or_default()
                .trim_end_matches(':');
            first == name
        })
    })
}

fn find_client_definition_v1(value: &Value) -> Option<(PathBuf, Vec<String>)> {
    match value {
        Value::Object(object) => {
            let candidate = object
                .get("transport")
                .and_then(Value::as_object)
                .unwrap_or(object);
            if let (Some(command), Some(args)) = (
                candidate.get("command").and_then(Value::as_str),
                candidate.get("args").and_then(Value::as_array),
            ) {
                let args = args
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()?
                    .into_iter()
                    .map(str::to_owned)
                    .collect();
                return Some((PathBuf::from(command), args));
            }
            object.values().find_map(find_client_definition_v1)
        }
        Value::Array(values) => values.iter().find_map(find_client_definition_v1),
        _ => None,
    }
}

fn json_contains_named_server_v1(value: &Value, name: &str) -> bool {
    match value {
        Value::Object(object) => {
            object.get("name").and_then(Value::as_str) == Some(name)
                || object.contains_key(name)
                || object
                    .values()
                    .any(|value| json_contains_named_server_v1(value, name))
        }
        Value::Array(values) => values
            .iter()
            .any(|value| json_contains_named_server_v1(value, name)),
        _ => false,
    }
}

fn add_arguments_v1(plan: &AgentGatewaySetupPlanV1) -> Vec<String> {
    let mut arguments = match plan.client {
        AgentGatewayClientV1::Codex => vec!["mcp", "add", SERVER_NAME, "--"],
        AgentGatewayClientV1::Claude => vec![
            "mcp",
            "add",
            "--transport",
            "stdio",
            "--scope",
            "user",
            SERVER_NAME,
            "--",
        ],
    }
    .into_iter()
    .map(str::to_owned)
    .collect::<Vec<_>>();
    arguments.push(plan.stdio.command.to_string_lossy().into_owned());
    arguments.extend(plan.stdio.args.iter().cloned());
    arguments
}

fn remove_arguments_v1(plan: &AgentGatewaySetupPlanV1) -> Vec<String> {
    match plan.client {
        AgentGatewayClientV1::Codex => vec!["mcp", "remove", SERVER_NAME],
        AgentGatewayClientV1::Claude => {
            vec!["mcp", "remove", SERVER_NAME, "--scope", "user"]
        }
    }
    .into_iter()
    .map(str::to_owned)
    .collect()
}

fn run_client_command_v1(
    plan: &AgentGatewaySetupPlanV1,
    arguments: &[String],
) -> Result<BoundedOutputV1> {
    let mut child = Command::new(plan.client.as_str())
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(AgentGatewaySetupError::Io)?;
    let stdout = child
        .stdout
        .take()
        .ok_or(AgentGatewaySetupError::InvalidPlan)?;
    let stderr = child
        .stderr
        .take()
        .ok_or(AgentGatewaySetupError::InvalidPlan)?;
    let stdout_reader = thread::spawn(move || read_bounded_v1(stdout));
    let stderr_reader = thread::spawn(move || read_bounded_v1(stderr));
    let deadline = Instant::now() + CLIENT_COMMAND_TIMEOUT;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            let _ = stdout_reader.join();
            let _ = stderr_reader.join();
            return Err(AgentGatewaySetupError::ClientCommandTimeout {
                client: plan.client.as_str(),
            });
        }
        thread::sleep(Duration::from_millis(10));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| AgentGatewaySetupError::InvalidPlan)??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| AgentGatewaySetupError::InvalidPlan)??;
    if stdout.len() as u64 > MAX_CLIENT_OUTPUT_BYTES
        || stderr.len() as u64 > MAX_CLIENT_OUTPUT_BYTES
    {
        return Err(AgentGatewaySetupError::ClientOutputTooLarge {
            client: plan.client.as_str(),
        });
    }
    Ok(BoundedOutputV1 {
        status,
        stdout,
        stderr,
    })
}

fn read_bounded_v1(reader: impl Read) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    reader
        .take(MAX_CLIENT_OUTPUT_BYTES + 1)
        .read_to_end(&mut output)?;
    Ok(output)
}

/// Explicitly install a plan into a previously absent file. Planning never
/// calls this function. Existing user-managed configuration is always refused,
/// even when it happens to contain an equivalent `again` entry.
pub fn install_owned_config(plan: &AgentGatewaySetupPlanV1) -> Result<OwnedInstallOutcomeV1> {
    validate_plan_paths(plan)?;
    validate_config_parent_v1(&plan.config_path)?;
    let ownership_record = plan.ownership_record();
    let config = inspect_regular_file(&plan.config_path, MAX_CONFIG_BYTES)?;
    let ownership = inspect_regular_file(&plan.ownership_path, 1_024)?;

    match (config, ownership) {
        (Some(config), Some(owner)) => {
            if owner != ownership_record {
                return Err(AgentGatewaySetupError::OwnershipConflict);
            }
            if config != plan.config_document {
                return Err(AgentGatewaySetupError::UnownedConfiguration);
            }
            Ok(OwnedInstallOutcomeV1::AlreadyInstalledOwned)
        }
        (Some(_), None) => Err(AgentGatewaySetupError::UnownedConfiguration),
        (None, Some(owner)) => {
            if owner != ownership_record {
                return Err(AgentGatewaySetupError::OwnershipConflict);
            }
            create_new_private_file(&plan.config_path, plan.config_document.as_bytes())?;
            Ok(OwnedInstallOutcomeV1::Installed)
        }
        (None, None) => {
            // Publish ownership first. If config publication is interrupted, a
            // subsequent exact plan can safely recover the missing config; no
            // user-managed file is ever replaced.
            create_new_private_file(&plan.ownership_path, ownership_record.as_bytes())?;
            create_new_private_file(&plan.config_path, plan.config_document.as_bytes())?;
            Ok(OwnedInstallOutcomeV1::Installed)
        }
    }
}

fn validate_plan_paths(plan: &AgentGatewaySetupPlanV1) -> Result<()> {
    let workspace = validate_workspace(&plan.workspace)?;
    let executable = validate_executable(&plan.stdio.command)?;
    let expected_args = vec![
        "mcp".to_owned(),
        "connect".to_owned(),
        "--workspace".to_owned(),
        workspace.to_string_lossy().into_owned(),
    ];
    let expected_document = managed_config_document(plan.client, &executable, &expected_args)?;
    if plan.version != PLAN_VERSION
        || plan.server_name != SERVER_NAME
        || plan.stdio.transport != "stdio"
        || plan.stdio.command != executable
        || plan.stdio.args != expected_args
        || plan.local_cli_command != local_cli_command(plan.client, &executable, &expected_args)
        || plan.writes_by_default
        || plan.install_policy != "official_client_cli_only_v1"
        || plan.config_document != expected_document
    {
        return Err(AgentGatewaySetupError::InvalidPlan);
    }
    if validate_config_path(&plan.config_path)? != plan.config_path
        || ownership_path_for(&plan.config_path)? != plan.ownership_path
        || workspace != plan.workspace
        || ownership_digest(
            plan.client,
            &plan.config_path,
            &plan.workspace,
            &plan.config_document,
        ) != plan.ownership_digest
    {
        return Err(AgentGatewaySetupError::InvalidConfigPath);
    }
    Ok(())
}

fn validate_config_parent_v1(config_path: &Path) -> Result<()> {
    let Some(parent) = config_path.parent() else {
        return Err(AgentGatewaySetupError::UnsafeConfigParent);
    };
    let metadata =
        fs::symlink_metadata(parent).map_err(|_| AgentGatewaySetupError::UnsafeConfigParent)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AgentGatewaySetupError::UnsafeConfigParent);
    }
    Ok(())
}

fn validate_workspace(path: &Path) -> Result<PathBuf> {
    let Some(path_text) = path.to_str() else {
        return Err(AgentGatewaySetupError::InvalidWorkspace);
    };
    if !path.is_absolute()
        || path_text.is_empty()
        || path_text.len() > MAX_PATH_BYTES
        || path_text.contains('\0')
    {
        return Err(AgentGatewaySetupError::InvalidWorkspace);
    }
    let metadata =
        fs::symlink_metadata(path).map_err(|_| AgentGatewaySetupError::InvalidWorkspace)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(AgentGatewaySetupError::InvalidWorkspace);
    }
    let canonical = fs::canonicalize(path).map_err(|_| AgentGatewaySetupError::InvalidWorkspace)?;
    if canonical != path {
        return Err(AgentGatewaySetupError::InvalidWorkspace);
    }
    Ok(canonical)
}

fn validate_executable(path: &Path) -> Result<PathBuf> {
    let Some(path_text) = path.to_str() else {
        return Err(AgentGatewaySetupError::InvalidExecutablePath);
    };
    if !path.is_absolute()
        || path_text.is_empty()
        || path_text.len() > MAX_PATH_BYTES
        || path_text.contains('\0')
    {
        return Err(AgentGatewaySetupError::InvalidExecutablePath);
    }
    let canonical =
        fs::canonicalize(path).map_err(|_| AgentGatewaySetupError::InvalidExecutablePath)?;
    let Some(canonical_text) = canonical.to_str() else {
        return Err(AgentGatewaySetupError::InvalidExecutablePath);
    };
    if canonical_text.len() > MAX_PATH_BYTES || canonical_text.contains('\0') {
        return Err(AgentGatewaySetupError::InvalidExecutablePath);
    }
    let metadata = fs::symlink_metadata(&canonical)
        .map_err(|_| AgentGatewaySetupError::InvalidExecutablePath)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AgentGatewaySetupError::InvalidExecutablePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(AgentGatewaySetupError::InvalidExecutablePath);
        }
    }
    Ok(canonical)
}

fn validate_config_path(path: &Path) -> Result<PathBuf> {
    let Some(path_text) = path.to_str() else {
        return Err(AgentGatewaySetupError::InvalidConfigPath);
    };
    if !path.is_absolute()
        || path_text.is_empty()
        || path_text.len() > MAX_PATH_BYTES
        || path_text.contains('\0')
        || path.file_name().is_none()
    {
        return Err(AgentGatewaySetupError::InvalidConfigPath);
    }
    Ok(path.to_path_buf())
}

fn ownership_path_for(config_path: &Path) -> Result<PathBuf> {
    let Some(file_name) = config_path.file_name().and_then(|name| name.to_str()) else {
        return Err(AgentGatewaySetupError::InvalidConfigPath);
    };
    let owned_name = format!("{file_name}{OWNERSHIP_SUFFIX}");
    if owned_name.len() > 255 {
        return Err(AgentGatewaySetupError::InvalidConfigPath);
    }
    Ok(config_path.with_file_name(owned_name))
}

fn managed_config_document(
    client: AgentGatewayClientV1,
    executable: &Path,
    args: &[String],
) -> Result<String> {
    let executable = executable
        .to_str()
        .ok_or(AgentGatewaySetupError::InvalidExecutablePath)?;
    match client {
        AgentGatewayClientV1::Codex => {
            let encoded = args
                .iter()
                .map(serde_json::to_string)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(AgentGatewaySetupError::SerializePlan)?
                .join(", ");
            Ok(format!(
                "# Created and wholly owned by Again gateway setup v2.\n[mcp_servers.again]\ncommand = {}\nargs = [{encoded}]\n",
                serde_json::to_string(executable).map_err(AgentGatewaySetupError::SerializePlan)?
            ))
        }
        AgentGatewayClientV1::Claude => serde_json::to_string_pretty(&serde_json::json!({
            "mcpServers": {
                "again": {
                    "type": "stdio",
                    "command": executable,
                    "args": args,
                }
            }
        }))
        .map(|value| format!("{value}\n"))
        .map_err(AgentGatewaySetupError::SerializePlan),
    }
}

fn local_cli_command(client: AgentGatewayClientV1, executable: &Path, args: &[String]) -> String {
    let mut command = match client {
        AgentGatewayClientV1::Codex => "codex mcp add again --".to_owned(),
        AgentGatewayClientV1::Claude => {
            "claude mcp add --transport stdio --scope user again --".to_owned()
        }
    };
    command.push(' ');
    command.push_str(&shell_quote(&executable.to_string_lossy()));
    for argument in args {
        command.push(' ');
        command.push_str(&shell_quote(argument));
    }
    command
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./,:=@%+-".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn ownership_digest(
    client: AgentGatewayClientV1,
    config_path: &Path,
    workspace: &Path,
    config_document: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.agent-gateway-setup.owner.v2\0");
    hash_field(&mut hasher, client.as_str().as_bytes());
    hash_field(&mut hasher, config_path.as_os_str().as_encoded_bytes());
    hash_field(&mut hasher, workspace.as_os_str().as_encoded_bytes());
    hash_field(&mut hasher, config_document.as_bytes());
    hasher.finalize().to_hex().to_string()
}

fn hash_field(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn inspect_regular_file(path: &Path, max_bytes: usize) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(AgentGatewaySetupError::UnsafeExistingPath);
    }
    let length = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
    if length > max_bytes {
        return Err(AgentGatewaySetupError::ConfigTooLarge);
    }
    fs::read_to_string(path)
        .map(Some)
        .map_err(AgentGatewaySetupError::Io)
}

fn create_new_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file: File = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
