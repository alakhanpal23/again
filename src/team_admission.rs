//! Shared local admission for `again team run` and `again team inspect`.
//!
//! The two user-facing paths deliberately share this module so bootstrap
//! output cannot be computed from a weaker or merely similar request model.
//! Admission reads strict local configuration, resolves and authenticates the
//! executable, seals the reviewed runtime, and builds the exact portable key
//! through the caller-provided strong digest cache. It performs no network I/O
//! and never executes the requested command.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::engine::{discover_workspace, resolve_executable};
use crate::fingerprint::FileDigestCache;
use crate::privacy::{
    LocalOnlyReason, RemoteRequestAdmissionV1, RepositorySharingPolicy, admit_remote_request_v1,
};
use crate::runtime_attestation::{
    RuntimeAttestationError, TeamRuntimeAttestationV1, attest_team_runtime_from_checkpoint_v1,
    audit_team_runtime_to_checkpoint_v1,
};
use crate::team_config::{
    TeamProfileV1, load_sharing_policy, load_team_profile,
    validate_profile_state_external_to_workspace,
};
use crate::team_manifest_v2::ImmutableExecutionProfileV1;
use crate::team_request_key::{
    TeamRequestKeyInput, TeamRequestKeyV1, UnboundTeamRequestKeyInput,
    build_team_request_key_v1_with_cache, preflight_team_request_v1,
};

const TEAM_ENVIRONMENT: [(&str, &str); 2] = [("LANG", "C"), ("LC_ALL", "C")];

/// Strict local bindings admitted before TTY routing or runtime inspection.
pub(crate) struct TeamPreflight {
    profile_path: PathBuf,
    command: Vec<OsString>,
    command_name: String,
    profile: TeamProfileV1,
    sharing_policy: RepositorySharingPolicy,
    cwd: PathBuf,
    workspace: PathBuf,
    environment: Vec<(OsString, OsString)>,
    executable: PathBuf,
}

impl TeamPreflight {
    pub(crate) fn profile_path(&self) -> &Path {
        &self.profile_path
    }

    pub(crate) fn command(&self) -> &[OsString] {
        &self.command
    }

    pub(crate) fn command_name(&self) -> &str {
        &self.command_name
    }

    pub(crate) fn profile(&self) -> &TeamProfileV1 {
        &self.profile
    }

    pub(crate) fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub(crate) fn workspace(&self) -> &Path {
        &self.workspace
    }

    pub(crate) fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }

    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }
}

/// Fully sealed, non-interactive request shared by inspection and execution.
pub(crate) struct TeamAdmission {
    preflight: TeamPreflight,
    execution_profile: ImmutableExecutionProfileV1,
    runtime: TeamRuntimeAttestationV1,
    request: TeamRequestKeyV1,
    remote_request_admission: Result<RemoteRequestAdmissionV1, LocalOnlyReason>,
}

impl TeamAdmission {
    pub(crate) fn profile_path(&self) -> &Path {
        self.preflight.profile_path()
    }

    pub(crate) fn command(&self) -> &[OsString] {
        self.preflight.command()
    }

    pub(crate) fn command_name(&self) -> &str {
        self.preflight.command_name()
    }

    pub(crate) fn profile(&self) -> &TeamProfileV1 {
        self.preflight.profile()
    }

    pub(crate) fn sharing_policy(&self) -> &RepositorySharingPolicy {
        &self.preflight.sharing_policy
    }

    pub(crate) fn cwd(&self) -> &Path {
        self.preflight.cwd()
    }

    pub(crate) fn workspace(&self) -> &Path {
        self.preflight.workspace()
    }

    pub(crate) fn environment(&self) -> &[(OsString, OsString)] {
        self.preflight.environment()
    }

    pub(crate) fn executable(&self) -> &Path {
        self.preflight.executable()
    }

    pub(crate) fn execution_profile(&self) -> &ImmutableExecutionProfileV1 {
        &self.execution_profile
    }

    pub(crate) fn runtime(&self) -> &TeamRuntimeAttestationV1 {
        &self.runtime
    }

    pub(crate) fn request(&self) -> &TeamRequestKeyV1 {
        &self.request
    }

    /// Output-independent permission to let this exact request cross the
    /// remote boundary. A denial is retained so `team run` can execute once
    /// locally instead of turning a conservative privacy decision into a
    /// command failure.
    pub(crate) fn remote_request_admission(
        &self,
    ) -> Result<&RemoteRequestAdmissionV1, &LocalOnlyReason> {
        self.remote_request_admission.as_ref()
    }

    /// Reconstruct the exact live input for pull/publication boundary rechecks.
    pub(crate) fn request_input(&self) -> Result<TeamRequestKeyInput<'_>> {
        request_input(&self.preflight, &self.execution_profile, &self.runtime)
    }
}

/// Admit strict local configuration and the portable command shape before the
/// comparatively expensive runtime audit.
pub(crate) fn preflight_team_command(
    profile_path: PathBuf,
    command: Vec<OsString>,
) -> Result<TeamPreflight> {
    let command_name = bare_command_name(&command)?.to_owned();
    let profile = load_team_profile(&profile_path).context("load strict team profile")?;
    let sharing_policy =
        load_sharing_policy(&profile).context("load profile-bound repository sharing policy")?;
    let cwd = fs::canonicalize(std::env::current_dir()?).context("resolve working directory")?;
    let workspace = discover_workspace(&cwd)?;
    validate_profile_state_external_to_workspace(&profile_path, &profile, &workspace)
        .context("keep team state and credentials outside the active workspace")?;
    let environment = exact_team_environment();
    preflight_team_request_v1(&workspace, &cwd, &command, &environment)
        .context("preflight portable team request")?;
    let resolution_environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let executable = resolve_executable(OsStr::new(&command_name), &cwd, &resolution_environment)?;
    Ok(TeamPreflight {
        profile_path,
        command,
        command_name,
        profile,
        sharing_policy,
        cwd,
        workspace,
        environment,
        executable,
    })
}

/// Finish the exact non-interactive admission through the shared strong digest
/// cache. A successful return is the sole source for inspection bindings and
/// the request handed to the team transport path.
pub(crate) fn admit_team_command(
    preflight: TeamPreflight,
    cache: &mut dyn FileDigestCache,
) -> Result<TeamAdmission> {
    let execution_profile =
        ImmutableExecutionProfileV1::inspect(preflight.command_name(), preflight.executable())
            .context("inspect immutable team execution profile")?;
    let runtime = load_or_create_runtime_attestation(
        preflight.command_name(),
        preflight.executable(),
        preflight.profile().runtime_attestation_checkpoint_file(),
    )
    .context("attest exact team runtime")?;
    let input = request_input(&preflight, &execution_profile, &runtime)?;
    let request = build_team_request_key_v1_with_cache(&input, cache)
        .context("admit portable team request")?;
    let remote_request_admission = admit_remote_request_v1(&preflight.sharing_policy, &request);
    Ok(TeamAdmission {
        preflight,
        execution_profile,
        runtime,
        request,
        remote_request_admission,
    })
}

fn request_input<'a>(
    preflight: &'a TeamPreflight,
    execution_profile: &ImmutableExecutionProfileV1,
    runtime: &TeamRuntimeAttestationV1,
) -> Result<TeamRequestKeyInput<'a>> {
    TeamRequestKeyInput::new_attested(
        UnboundTeamRequestKeyInput {
            tenant_id: preflight.profile().tenant_id(),
            repository_id: preflight.profile().repository_id(),
            generation_id: preflight.profile().generation_id(),
            workspace: preflight.workspace(),
            cwd: preflight.cwd(),
            argv: preflight.command(),
            environment: preflight.environment(),
            stdin_is_tty: false,
            stdout_is_tty: false,
            stderr_is_tty: false,
            policy_digest: preflight.sharing_policy.digest(),
            execution_profile_digest: execution_profile.digest(),
        },
        runtime,
    )
    .context("bind portable request to exact runtime")
}

pub(crate) fn bare_command_name(command: &[OsString]) -> Result<&str> {
    let Some(program) = command.first() else {
        bail!("a command is required after `--`");
    };
    let name = program
        .to_str()
        .ok_or_else(|| anyhow!("team commands require portable UTF-8 argv"))?;
    let mut components = Path::new(name).components();
    if !matches!(components.next(), Some(Component::Normal(_))) || components.next().is_some() {
        bail!("team commands require a bare executable name resolved from the current PATH");
    }
    Ok(name)
}

pub(crate) fn exact_team_environment() -> Vec<(OsString, OsString)> {
    TEAM_ENVIRONMENT
        .iter()
        .map(|(name, value)| (OsString::from(name), OsString::from(value)))
        .collect()
}

pub(crate) fn load_or_create_runtime_attestation(
    command_name: &str,
    executable: &Path,
    checkpoint: &Path,
) -> Result<TeamRuntimeAttestationV1> {
    match attest_team_runtime_from_checkpoint_v1(command_name, executable, checkpoint) {
        Ok(runtime) => Ok(runtime),
        Err(error) if runtime_checkpoint_refresh_allowed(&error) => {
            audit_team_runtime_to_checkpoint_v1(command_name, executable, checkpoint)
                .context("perform first-run or scheduled full runtime audit")
        }
        // Corruption, unsafe metadata, mismatch, rollback and clock anomalies
        // are never healed implicitly; doing so would erase attack evidence.
        Err(error) => Err(error).context("verify fresh runtime audit checkpoint"),
    }
}

pub(crate) fn runtime_checkpoint_refresh_allowed(error: &RuntimeAttestationError) -> bool {
    matches!(
        error,
        RuntimeAttestationError::CheckpointMissing | RuntimeAttestationError::CheckpointStale
    )
}
