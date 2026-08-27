//! Deterministic, non-executing setup plans for the Again MCP gateway.
//!
//! Planning is always a dry run. The optional file installer is deliberately
//! conservative: it creates only a previously absent configuration file and a
//! sibling ownership record, or accepts an exact file it already owns. It never
//! merges into or overwrites user-managed configuration; normal installations
//! should use the emitted local CLI command.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::Serialize;
use thiserror::Error;

const PLAN_VERSION: u32 = 1;
const SERVER_NAME: &str = "again";
const COMMAND: &str = "again";
const ARGS: [&str; 2] = ["mcp", "serve"];
const MAX_PATH_BYTES: usize = 4_096;
const MAX_CONFIG_BYTES: usize = 64 * 1_024;
const OWNERSHIP_SUFFIX: &str = ".again-owner-v1";

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

    fn local_cli_command(self) -> &'static str {
        match self {
            Self::Codex => "codex mcp add again -- again mcp serve",
            Self::Claude => "claude mcp add -s user again -- again mcp serve",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StdioMcpCommandV1 {
    pub transport: &'static str,
    pub command: &'static str,
    pub args: [&'static str; 2],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AgentGatewaySetupPlanV1 {
    pub version: u32,
    pub client: AgentGatewayClientV1,
    pub server_name: &'static str,
    pub stdio: StdioMcpCommandV1,
    pub local_cli_command: &'static str,
    pub config_path: PathBuf,
    pub ownership_path: PathBuf,
    pub ownership_digest: String,
    pub writes_by_default: bool,
    pub install_policy: &'static str,
    config_document: String,
}

impl AgentGatewaySetupPlanV1 {
    /// Construct a deterministic dry-run plan. This function never reads or
    /// writes configuration and never executes the emitted command.
    pub fn dry_run(client: AgentGatewayClientV1, config_path: impl AsRef<Path>) -> Result<Self> {
        let config_path = validate_config_path(config_path.as_ref())?;
        let ownership_path = ownership_path_for(&config_path)?;
        let config_document = managed_config_document(client);
        if config_document.len() > MAX_CONFIG_BYTES {
            return Err(AgentGatewaySetupError::ConfigTooLarge);
        }
        let ownership_digest = ownership_digest(client, &config_path, &config_document);
        Ok(Self {
            version: PLAN_VERSION,
            client,
            server_name: SERVER_NAME,
            stdio: StdioMcpCommandV1 {
                transport: "stdio",
                command: COMMAND,
                args: ARGS,
            },
            local_cli_command: client.local_cli_command(),
            config_path,
            ownership_path,
            ownership_digest,
            writes_by_default: false,
            install_policy: "create_absent_or_verify_exact_owned_v1",
            config_document,
        })
    }

    pub fn codex(config_path: impl AsRef<Path>) -> Result<Self> {
        Self::dry_run(AgentGatewayClientV1::Codex, config_path)
    }

    pub fn claude(config_path: impl AsRef<Path>) -> Result<Self> {
        Self::dry_run(AgentGatewayClientV1::Claude, config_path)
    }

    pub fn machine_readable_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).map_err(AgentGatewaySetupError::SerializePlan)
    }

    pub fn managed_config_document(&self) -> &str {
        &self.config_document
    }

    fn ownership_record(&self) -> String {
        format!(
            "again-agent-gateway-owner-v1\nclient={}\nserver={}\ndigest={}\n",
            self.client.as_str(),
            self.server_name,
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
    #[error("gateway managed config exceeds its fixed size bound")]
    ConfigTooLarge,
    #[error("gateway setup plan serialization failed: {0}")]
    SerializePlan(serde_json::Error),
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
    if validate_config_path(&plan.config_path)? != plan.config_path
        || ownership_path_for(&plan.config_path)? != plan.ownership_path
        || ownership_digest(plan.client, &plan.config_path, &plan.config_document)
            != plan.ownership_digest
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

fn managed_config_document(client: AgentGatewayClientV1) -> String {
    match client {
        AgentGatewayClientV1::Codex => concat!(
            "# Created and wholly owned by Again gateway setup v1.\n",
            "[mcp_servers.again]\n",
            "command = \"again\"\n",
            "args = [\"mcp\", \"serve\"]\n",
        )
        .to_owned(),
        AgentGatewayClientV1::Claude => concat!(
            "{\n",
            "  \"mcpServers\": {\n",
            "    \"again\": {\n",
            "      \"type\": \"stdio\",\n",
            "      \"command\": \"again\",\n",
            "      \"args\": [\"mcp\", \"serve\"]\n",
            "    }\n",
            "  }\n",
            "}\n",
        )
        .to_owned(),
    }
}

fn ownership_digest(
    client: AgentGatewayClientV1,
    config_path: &Path,
    config_document: &str,
) -> String {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"again.agent-gateway-setup.owner.v1\0");
    hash_field(&mut hasher, client.as_str().as_bytes());
    hash_field(&mut hasher, config_path.as_os_str().as_encoded_bytes());
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
