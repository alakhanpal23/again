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
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

const PLAN_VERSION: u32 = 2;
const SERVER_NAME: &str = "again";
const MAX_PATH_BYTES: usize = 4_096;
const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const OWNERSHIP_SUFFIX: &str = ".again-owner-v2";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentGatewayClientV1 {
    Codex,
    Claude,
}

impl AgentGatewayClientV1 {
    fn as_str(self) -> &'static str {
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
            "serve".to_owned(),
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
            install_policy: "create_absent_or_verify_exact_owned_v1",
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

/// Explicitly install a plan into a previously absent file. Planning never
/// calls this function. Existing user-managed configuration is always refused,
/// even when it happens to contain an equivalent `again` entry.
pub fn install_owned_config(plan: &AgentGatewaySetupPlanV1) -> Result<OwnedInstallOutcomeV1> {
    validate_plan_paths(plan)?;
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
        "serve".to_owned(),
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
        || plan.install_policy != "create_absent_or_verify_exact_owned_v1"
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
    let Some(parent) = plan.config_path.parent() else {
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
        AgentGatewayClientV1::Claude => "claude mcp add -s user again --".to_owned(),
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
