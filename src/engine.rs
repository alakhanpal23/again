//! CLI and execution orchestration.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};

use crate::executable::{
    ExecutableIdentity, ToolKind, host_audited_apple_profile, verify_executable,
};
use crate::fingerprint::{
    FingerprintInput, FingerprintResult, ScopeEntry, fingerprint_scoped_with_cache,
};
use crate::hook::{CodexHookInput, parse_hook_input, rewrite_output};
use crate::policy::{AccessPlan, AccessScope, Decision, PolicyContext, classify};
use crate::setup::{
    SetupScope, codex_skill_dir, codex_skill_scope_status, install_codex_skill, remove_codex_skill,
};
use crate::store::{EventDisposition, PendingCall, Store, StoredResult};

const POLICY_VERSION: &str = "strict-read-v0.5";
const MAX_STORABLE_STREAM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "again",
    version,
    about = "Proof-carrying reuse for agent tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandName,
}

#[derive(Debug, Subcommand)]
enum CommandName {
    /// Install, inspect, or remove agent integrations.
    Setup(SetupArgs),
    /// Execute a strictly admitted command through the local engine.
    Run(RunArgs),
    /// Emit a compact reference to an existing validated local result.
    Reference(ReferenceArgs),
    /// Reuse or publish an encrypted result through an explicit team profile.
    Team(TeamArgs),
    /// Handle one Codex tool or compaction lifecycle hook event on stdin.
    #[command(hide = true)]
    Hook(HookArgs),
    /// Execute an opaque call created by the Codex hook.
    #[command(hide = true)]
    Exec(ExecArgs),
    /// Explain the latest decision, or inspect a stored result.
    Explain(ExplainArgs),
    /// Print exact stored stdout and stderr.
    Show(ShowArgs),
    /// Show local savings counters.
    Stats(StatsArgs),
    /// Check the local runtime and Codex integration.
    Doctor(DoctorArgs),
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// Install the instruction-only Codex skill integration.
    #[arg(long)]
    codex: bool,
    /// Install in the current repository instead of the personal skill scope.
    #[arg(long, conflicts_with = "global")]
    project: bool,
    /// Explicitly select the personal skill scope (the default).
    #[arg(long)]
    global: bool,
    /// Print the change without writing it.
    #[arg(long)]
    dry_run: bool,
    /// Remove Again's owned skill while preserving unrelated files.
    #[arg(long)]
    remove: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// Command argv. Put `--` before the executable.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct ReferenceArgs {
    /// Command argv. Put `--` before the executable. A miss never executes it.
    #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct TeamArgs {
    #[command(subcommand)]
    command: TeamCommand,
}

#[derive(Debug, Subcommand)]
enum TeamCommand {
    /// Run one bare command through the sealed team-cache boundary.
    Run(TeamRunArgs),
    /// Inspect one sealed team request without network or command execution.
    Inspect(TeamInspectArgs),
}

#[derive(Debug, Args)]
struct TeamRunArgs {
    /// Absolute owner-private team profile path.
    #[arg(long)]
    profile: PathBuf,
    /// Bare command argv. The `--` delimiter is mandatory.
    #[arg(required = true, last = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct TeamInspectArgs {
    /// Absolute owner-private team profile path.
    #[arg(long)]
    profile: PathBuf,
    /// Emit the strict machine-readable bootstrap document.
    #[arg(long, required = true)]
    json: bool,
    /// Bare command argv. The `--` delimiter is mandatory.
    #[arg(required = true, last = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[derive(Debug, Args)]
struct HookArgs {
    /// Controlled differential-testing escape hatch. This path is known not
    /// to model hidden Codex invocation inputs and must never be installed.
    #[arg(long, hide = true)]
    experimental_unsafe_rewrite: bool,
}

#[derive(Debug, Args)]
struct ExecArgs {
    #[arg(long)]
    call: String,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Stored result id. Omit it to explain the latest local event.
    id: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ShowArgs {
    id: String,
}

#[derive(Debug, Args)]
struct StatsArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    #[arg(long)]
    json: bool,
}

#[derive(Debug)]
struct CapturedResult {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    capture_complete: bool,
    presentation_broken_pipe: bool,
    exit_code: i32,
    duration_ms: u64,
}

#[derive(Debug, Clone, Copy)]
enum StreamPresentation {
    Stdout,
    Stderr,
    Suppress,
}

#[derive(Debug)]
struct CapturedStream {
    bytes: Vec<u8>,
    complete: bool,
    broken_pipe: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitPresentation {
    ExactStreams,
    ExplicitReference,
}

#[derive(Debug, Serialize)]
struct ExplicitResultReference<'a> {
    schema: &'static str,
    result_id: &'a str,
    exit_code: i32,
    stdout: ReferencedStream<'a>,
    stderr: ReferencedStream<'a>,
}

#[derive(Debug, Serialize)]
struct ReferencedStream<'a> {
    blake3: &'a str,
    bytes: u64,
}

#[derive(Debug, Serialize)]
struct V0Proof<'a> {
    schema: &'static str,
    policy_version: &'static str,
    admission: &'static str,
    execution_boundary: &'static str,
    boundary_digest: &'a str,
    runtime_context_digest: &'a str,
    executable_identity: &'a ExecutableIdentity,
    access_plan: &'a AccessPlan,
    request_digest: &'a str,
    workspace_digest: &'a str,
    environment_digest: &'a str,
    executable_digest: &'a str,
    workspace_entries: u64,
    validation_runs: u8,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredV0Proof {
    schema: String,
    policy_version: String,
    admission: String,
    execution_boundary: String,
    boundary_digest: String,
    runtime_context_digest: String,
    executable_identity: ExecutableIdentity,
    access_plan: AccessPlan,
    request_digest: String,
    workspace_digest: String,
    environment_digest: String,
    executable_digest: String,
    workspace_entries: u64,
    validation_runs: u8,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    version: &'static str,
    executable: String,
    state_dir: String,
    state_writable: bool,
    policy_version: &'static str,
    audited_apple_tool_profile: String,
    personal_codex_skill_dir: String,
    project_codex_skill_dir: String,
    personal_codex_skill_installed: bool,
    project_codex_skill_installed: bool,
    duplicate_codex_skill_scopes: bool,
    profile: &'static str,
    execution_boundary: &'static str,
    seatbelt_preflight: String,
    seatbelt_runtime_probe: String,
    seatbelt_used_for_profile: bool,
    trace_backed_replay: bool,
}

pub fn run_cli() -> Result<i32> {
    let cli = Cli::parse_from(normalized_args());
    match cli.command {
        CommandName::Setup(args) => setup(args),
        CommandName::Run(args) => direct_run(args.command),
        CommandName::Reference(args) => direct_reference(args.command),
        CommandName::Team(args) => match args.command {
            TeamCommand::Run(args) => crate::team_cli::run(args.profile, args.command),
            TeamCommand::Inspect(args) => {
                crate::team_inspect::inspect(args.profile, args.command, args.json)
            }
        },
        CommandName::Hook(args) => handle_hook(args.experimental_unsafe_rewrite),
        CommandName::Exec(args) => execute_pending_call(&args.call),
        CommandName::Explain(args) => explain(args),
        CommandName::Show(args) => show(&args.id),
        CommandName::Stats(args) => stats(args.json),
        CommandName::Doctor(args) => doctor(args.json),
    }
}

/// Let the README-friendly `again -- rg ...` spelling behave like `again run -- rg ...`.
fn normalized_args() -> Vec<OsString> {
    let mut arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.get(1).is_some_and(|argument| argument == "--") {
        arguments[1] = OsString::from("run");
    }
    arguments
}

fn setup(args: SetupArgs) -> Result<i32> {
    if !args.codex {
        bail!("select an integration; currently supported: --codex");
    }
    let cwd = std::env::current_dir()?;
    let workspace = discover_workspace(&cwd)?;
    let scope = if args.project {
        SetupScope::Project
    } else {
        SetupScope::Global
    };
    let project = (scope == SetupScope::Project).then_some(workspace.as_path());
    let skill_dir = codex_skill_dir(scope, project)?;
    let change = if args.remove {
        remove_codex_skill(&skill_dir, args.dry_run)?
    } else {
        install_codex_skill(&skill_dir, args.dry_run)?
    };

    if args.dry_run {
        println!("# dry run: {}", change.path.display());
        print!("{}", change.rendered);
    } else if args.remove {
        if change.changed {
            println!(
                "Removed Again's Codex skill from {}.",
                change.path.display()
            );
        } else {
            println!(
                "Again's Codex skill was not installed at {}.",
                change.path.display()
            );
        }
    } else if change.changed {
        println!(
            "Installed Again's Codex skill at {}.",
            change.path.display()
        );
        println!("Start a new Codex session to load the skill.");
    } else {
        println!(
            "Again's Codex skill is already current at {}.",
            change.path.display()
        );
    }
    if !args.dry_run {
        let personal = codex_skill_dir(SetupScope::Global, None)?;
        let project = codex_skill_dir(SetupScope::Project, Some(&workspace))?;
        if let Ok(status) = codex_skill_scope_status(&personal, &project)
            && status.duplicate_again_skills()
        {
            eprintln!(
                "Warning: Again is installed in both personal and project Codex skill scopes; remove one to avoid duplicate instructions."
            );
        }
    }
    Ok(0)
}

fn handle_hook(experimental_unsafe_rewrite: bool) -> Result<i32> {
    // Production integration is instruction-only. Return before reading or
    // validating stdin so every current or future Codex lifecycle envelope is
    // a true state-free no-op with no accidental schema coupling.
    if !experimental_unsafe_rewrite {
        return Ok(0);
    }
    let input = match parse_hook_input(io::stdin().lock())? {
        CodexHookInput::PreToolUse(input) => input,
        // Output-delivery compaction is disabled until Codex exposes enough
        // information to prove what reached the model. Lifecycle events must
        // therefore be true no-ops and must not create repository state.
        CodexHookInput::Compact { .. } => return Ok(0),
    };
    // Official Codex hooks expose session cwd but hide effective per-call
    // workdir, TTY, sandbox and remote-environment inputs. Replacing a tool call
    // without those values can change behavior or fail after an allow decision,
    // so production hooks are instruction-only and this legacy rewrite path is
    // disabled by default.
    // The explicit, conspicuously unsafe switch exists only for controlled
    // differential tests while the future native integration is developed.
    if !input.rewrite_compatible() {
        return Ok(0);
    }
    let raw_command = input.command()?.to_owned();
    let cwd = fs::canonicalize(PathBuf::from(&input.cwd))
        .with_context(|| format!("resolve hook working directory {}", input.cwd))?;
    let workspace = discover_workspace(&cwd)?;
    let mut policy_context = PolicyContext::new(workspace.as_path(), cwd.as_path());
    policy_context.require_explicit_executable = true;
    let decision = classify(&raw_command, policy_context);

    let Decision::ExactReuse { argv, .. } = decision else {
        // The absence of hook output is intentional: Codex applies its unmodified
        // approval and sandbox path to every command Again cannot prove eligible.
        return Ok(0);
    };

    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    if !ambient_inputs_supported(&argv, &environment) {
        return Ok(0);
    }
    let executable = match resolve_executable(OsStr::new(&argv[0]), &cwd, &environment) {
        Ok(executable) => executable,
        Err(_) => return Ok(0),
    };
    if verify_executable(&argv[0], &executable).is_err() {
        // A familiar basename earlier on PATH is not enough. Only audited binary
        // identities may be auto-approved and rewritten by the hook.
        return Ok(0);
    }

    let store = Store::open_for_workspace(&workspace)?;
    let call = store.create_call(
        &input.session_id,
        Some(&input.turn_id),
        // Codex currently hides max_output_tokens from hooks, so Again cannot
        // prove the full stream reached the model. Keep exact-output
        // compaction disabled until PostToolUse can provide a stable delivery
        // receipt; cached execution reuse remains active.
        None,
        &cwd,
        &raw_command,
        &argv,
    )?;
    let executable = std::env::current_exe().context("locate Again executable")?;
    let output = rewrite_output(&executable, &call.id, &input.tool_input)?;
    serde_json::to_writer(io::stdout().lock(), &output)?;
    println!();
    Ok(0)
}

fn execute_pending_call(call_id: &str) -> Result<i32> {
    let invocation_started = Instant::now();
    let invocation_cwd = fs::canonicalize(std::env::current_dir()?)
        .context("resolve rewritten tool working directory")?;
    let invocation_workspace = discover_workspace(&invocation_cwd)?;
    let mut store = Store::open_for_workspace(&invocation_workspace)?;
    let call = store
        .get_call(call_id)?
        .ok_or_else(|| anyhow!("opaque call {call_id} does not exist or expired"))?;
    let workspace = discover_workspace(&call.cwd)?;
    if workspace != invocation_workspace {
        store.delete_call(call_id)?;
        bail!("stored call context does not match the rewritten tool invocation");
    }
    if call.cwd != invocation_cwd
        || io::stdin().is_terminal()
        || io::stdout().is_terminal()
        || io::stderr().is_terminal()
    {
        let code = run_uncached_inherited(&call, &invocation_workspace, &invocation_cwd, true)?;
        store.delete_call(call_id)?;
        return Ok(code);
    }
    let mut policy_context = PolicyContext::new(workspace.as_path(), call.cwd.as_path());
    policy_context.require_explicit_executable = true;
    let decision = classify(&call.raw_command, policy_context);
    let Decision::ExactReuse { argv, access_plan } = decision else {
        // The hook already returned allow in order to rewrite this call. Never execute
        // a request here if current policy does not independently admit it.
        store.delete_call(call_id)?;
        bail!("stored call is no longer eligible; refusing rewritten execution");
    };
    if argv != call.argv {
        store.delete_call(call_id)?;
        bail!("stored call argv failed integrity reparse");
    }
    let code = run_admitted(
        &mut store,
        &call,
        &workspace,
        &access_plan,
        invocation_started,
        HitPresentation::ExactStreams,
    )?;
    store.delete_call(call_id)?;
    Ok(code)
}

/// Codex does not expose effective per-call workdir or TTY settings to hooks.
/// When either differs at wrapper runtime, revalidate the same audited
/// read-only argv against the actual cwd and execute it once with inherited
/// streams. It is never fingerprinted, stored or replayed.
fn run_uncached_inherited(
    call: &PendingCall,
    workspace: &Path,
    cwd: &Path,
    require_explicit_executable: bool,
) -> Result<i32> {
    let mut policy_context = PolicyContext::new(workspace, cwd);
    policy_context.require_explicit_executable = require_explicit_executable;
    let decision = classify(&call.raw_command, policy_context);
    let Decision::ExactReuse { argv, .. } = decision else {
        bail!("runtime tool context is not eligible for safe uncached execution");
    };
    if argv != call.argv {
        bail!("runtime tool argv failed integrity reparse");
    }
    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    if !ambient_inputs_supported(&argv, &environment) {
        bail!("runtime command has unsupported ambient inputs");
    }
    let executable = resolve_executable(OsStr::new(&argv[0]), cwd, &environment)?;
    verify_executable(&argv[0], &executable)
        .context("runtime command executable is outside the audited read-only set")?;
    let status = Command::new(executable)
        .args(argv.iter().skip(1))
        .current_dir(cwd)
        .env_clear()
        .envs(environment)
        .status()
        .context("execute audited command uncached with inherited streams")?;
    Ok(exit_code_for_status(status))
}

fn direct_run(command: Vec<OsString>) -> Result<i32> {
    direct_request(command, HitPresentation::ExactStreams)
}

fn direct_reference(command: Vec<OsString>) -> Result<i32> {
    direct_request(command, HitPresentation::ExplicitReference)
}

fn direct_request(command: Vec<OsString>, presentation: HitPresentation) -> Result<i32> {
    let invocation_started = Instant::now();
    if command.is_empty() {
        bail!("a command is required");
    }
    let cwd = std::env::current_dir()?;
    let workspace = discover_workspace(&cwd)?;
    let raw_command = shell_join_for_policy(&command)?;
    let original_argv = command
        .iter()
        .map(|argument| {
            argument
                .to_str()
                .map(ToOwned::to_owned)
                .ok_or_else(|| anyhow!("v0 requires UTF-8 command arguments"))
        })
        .collect::<Result<Vec<_>>>()?;
    let decision = classify(
        &raw_command,
        PolicyContext::new(workspace.as_path(), cwd.as_path()),
    );
    let Decision::ExactReuse { argv, access_plan } = decision else {
        let reason = decision
            .reason()
            .map(|reason| reason.as_str())
            .unwrap_or("NOT_ELIGIBLE");
        bail!("command is not eligible for v0 exact reuse ({reason}); run it normally");
    };
    if argv != original_argv {
        bail!("internal argv round-trip mismatch; refusing execution");
    }
    let call = PendingCall {
        id: format!("direct_{}", std::process::id()),
        session_id: format!("direct_{}_{}", std::process::id(), monotonic_nonce()),
        turn_id: None,
        context_id: None,
        cwd,
        raw_command,
        argv,
    };
    if presentation == HitPresentation::ExactStreams
        && (io::stdin().is_terminal() || io::stdout().is_terminal() || io::stderr().is_terminal())
    {
        return run_uncached_inherited(&call, &workspace, &call.cwd, false);
    }
    let mut store = Store::open_for_workspace(&workspace)?;
    run_admitted(
        &mut store,
        &call,
        &workspace,
        &access_plan,
        invocation_started,
        presentation,
    )
}

fn run_admitted(
    store: &mut Store,
    call: &PendingCall,
    workspace: &Path,
    access_plan: &AccessPlan,
    invocation_started: Instant,
    presentation: HitPresentation,
) -> Result<i32> {
    let environment: Vec<(OsString, OsString)> = std::env::vars_os().collect();
    let argv: Vec<OsString> = call.argv.iter().map(OsString::from).collect();
    let executable = resolve_executable(&argv[0], &call.cwd, &environment)?;
    let executable_identity = verify_executable(&call.argv[0], &executable).with_context(|| {
        format!(
            "executable for {} is not in the audited v0 set",
            call.argv[0]
        )
    })?;
    if !ambient_inputs_supported(&call.argv, &environment) {
        bail!("command has ambient inputs that the v0 proof does not model");
    }
    let boundary_digest = audited_boundary_digest(&executable_identity)?;
    let runtime_context_digest = runtime_context_digest()?;
    let scopes = fingerprint_scopes(access_plan);
    let before = fingerprint_scoped_with_cache(
        &FingerprintInput {
            argv: &argv,
            cwd: &call.cwd,
            workspace,
            environment: &environment,
            executable: &executable,
        },
        &scopes,
        store,
    )?;
    let cached_key = request_key(&before, &boundary_digest, &runtime_context_digest)?;

    if let Some(result) = store.get_result(&cached_key)? {
        if let Err(error) = validate_cached_result(
            &result,
            &cached_key,
            &before,
            &boundary_digest,
            &runtime_context_digest,
            &executable_identity,
            access_plan,
        ) {
            store.quarantine(&result.id, "result_metadata_mismatch")?;
            return Err(error).context(format!(
                "cached result {} failed metadata validation and was quarantined",
                result.id
            ));
        }
        verify_current_exec_capability(&executable_identity, &executable, &call.cwd, &environment)?;
        let stdout = load_cached_blob_or_quarantine(
            store,
            &result.id,
            &result.stdout_digest,
            "stdout_blob_invalid",
        )?;
        let stderr = load_cached_blob_or_quarantine(
            store,
            &result.id,
            &result.stderr_digest,
            "stderr_blob_invalid",
        )?;
        if stdout.len() as u64 != result.stdout_bytes || stderr.len() as u64 != result.stderr_bytes
        {
            store.quarantine(&result.id, "blob_length_mismatch")?;
            bail!("cached result {} failed blob length validation", result.id);
        }
        let (disposition, reason, bytes_omitted) = match presentation {
            HitPresentation::ExactStreams => {
                if let Err(error) = emit_bytes(&stdout, &stderr) {
                    if error.kind() == io::ErrorKind::BrokenPipe {
                        return Ok(signal_exit_code(libc::SIGPIPE));
                    }
                    return Err(error).context("present cached output");
                }
                (EventDisposition::ReplayedFull, "EXACT_REUSE_NET_V1", 0)
            }
            HitPresentation::ExplicitReference => {
                let presented_bytes = match emit_explicit_reference(&result) {
                    Ok(presented_bytes) => presented_bytes,
                    Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                        return Ok(signal_exit_code(libc::SIGPIPE));
                    }
                    Err(error) => return Err(error).context("present explicit result reference"),
                };
                let full_bytes = result.stdout_bytes.saturating_add(result.stderr_bytes);
                (
                    EventDisposition::ReplayedCompact,
                    "EXPLICIT_REFERENCE_NET_V1",
                    full_bytes.saturating_sub(presented_bytes),
                )
            }
        };
        // Once the selected output representation has been presented,
        // bookkeeping must never change the command's successful status.
        let _ = store.note_hit(&result.id);
        let estimated_net_ms_saved =
            estimated_net_saved_millis(result.duration_ms, invocation_started.elapsed());
        let _ = store.record_event(
            Some(&call.id),
            Some(&result.id),
            disposition,
            reason,
            estimated_net_ms_saved,
            bytes_omitted,
        );
        return Ok(result.exit_code);
    }

    if presentation == HitPresentation::ExplicitReference {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::PassedThrough,
            "REFERENCE_MISS_NO_EXECUTION",
            0,
            0,
        );
        bail!(
            "no validated cached result exists for this request; no command was executed; run it once with `again run --`"
        );
    }

    let first = execute_once(&executable, &argv[1..], &call.cwd, &environment, true)?;
    if first.presentation_broken_pipe {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "OUTPUT_BROKEN_PIPE",
            first.duration_ms,
            0,
        );
        return Ok(signal_exit_code(libc::SIGPIPE));
    }
    if first.exit_code != 0 {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "NONZERO_EXIT",
            first.duration_ms,
            0,
        );
        return Ok(first.exit_code);
    }
    if !first.capture_complete {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "OUTPUT_LIMIT",
            first.duration_ms,
            0,
        );
        return Ok(first.exit_code);
    }
    // Cache hits replay streams independently. Admit only successful commands
    // with an empty stderr so replay cannot change observable cross-stream
    // ordering. Non-empty stderr was already streamed on this cold execution.
    if !first.stderr.is_empty() {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "NONEMPTY_STDERR",
            first.duration_ms,
            0,
        );
        return Ok(first.exit_code);
    }

    let after_first = match fingerprint_scoped_with_cache(
        &FingerprintInput {
            argv: &argv,
            cwd: &call.cwd,
            workspace,
            environment: &environment,
            executable: &executable,
        },
        &scopes,
        store,
    ) {
        Ok(value) => value,
        Err(_) => {
            let _ = store.record_event(
                Some(&call.id),
                None,
                EventDisposition::BypassedNoStore,
                "POST_EXECUTION_VALIDATION_ERROR",
                first.duration_ms,
                0,
            );
            return Ok(first.exit_code);
        }
    };
    let after_first_key = match request_key(&after_first, &boundary_digest, &runtime_context_digest)
    {
        Ok(value) => value,
        Err(_) => return Ok(first.exit_code),
    };
    if after_first_key != cached_key {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "WORKSPACE_CHANGED_DURING_EXECUTION",
            first.duration_ms,
            0,
        );
        return Ok(first.exit_code);
    }

    // A candidate is admitted only after an immediate independent execution agrees.
    // This is validation evidence, not a substitute for the scoped v0 proof.
    let shadow = match execute_once(&executable, &argv[1..], &call.cwd, &environment, false) {
        Ok(value) => value,
        Err(_) => {
            let _ = store.record_event(
                Some(&call.id),
                None,
                EventDisposition::BypassedNoStore,
                "SHADOW_EXECUTION_ERROR",
                first.duration_ms,
                0,
            );
            return Ok(first.exit_code);
        }
    };
    let after_shadow = match fingerprint_scoped_with_cache(
        &FingerprintInput {
            argv: &argv,
            cwd: &call.cwd,
            workspace,
            environment: &environment,
            executable: &executable,
        },
        &scopes,
        store,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(first.exit_code),
    };
    let after_shadow_key =
        match request_key(&after_shadow, &boundary_digest, &runtime_context_digest) {
            Ok(value) => value,
            Err(_) => return Ok(first.exit_code),
        };
    if !shadow.capture_complete
        || shadow.exit_code != first.exit_code
        || shadow.stdout != first.stdout
        || shadow.stderr != first.stderr
        || after_shadow_key != cached_key
    {
        let _ = store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "SHADOW_DIVERGENCE",
            first.duration_ms.saturating_add(shadow.duration_ms),
            0,
        );
        return Ok(first.exit_code);
    }

    let proof = V0Proof {
        schema: "again.scoped_read.v0",
        policy_version: POLICY_VERSION,
        admission: "two_exact_executions",
        execution_boundary: "audited_native_read_only_v0",
        boundary_digest: &boundary_digest,
        runtime_context_digest: &runtime_context_digest,
        executable_identity: &executable_identity,
        access_plan,
        request_digest: &before.request_digest,
        workspace_digest: &before.workspace_digest,
        environment_digest: &before.environment_digest,
        executable_digest: &before.executable_digest,
        workspace_entries: before.workspace_entries,
        validation_runs: 2,
    };
    let proof_json = match serde_json::to_string(&proof) {
        Ok(value) => value,
        Err(_) => return Ok(first.exit_code),
    };
    let result = match store.insert_result(
        &cached_key,
        &first.stdout,
        &first.stderr,
        first.exit_code,
        first.duration_ms,
        POLICY_VERSION,
        &proof_json,
    ) {
        Ok(value) => value,
        Err(_) => return Ok(first.exit_code),
    };
    let _ = store.record_event(
        Some(&call.id),
        Some(&result.id),
        EventDisposition::Executed,
        "DOUBLE_EXECUTION_VALIDATED",
        first.duration_ms.saturating_add(shadow.duration_ms),
        0,
    );
    Ok(first.exit_code)
}

fn estimated_net_saved_millis(
    original_duration_ms: u64,
    replay_elapsed: std::time::Duration,
) -> u64 {
    let replay_elapsed_ms = replay_elapsed.as_millis().min(u64::MAX as u128) as u64;
    original_duration_ms.saturating_sub(replay_elapsed_ms)
}

fn fingerprint_scopes(plan: &AccessPlan) -> Vec<ScopeEntry> {
    plan.scopes
        .iter()
        .map(|scope| match scope {
            AccessScope::IdentityOnly => ScopeEntry::IdentityOnly,
            AccessScope::ContentPath(path) => ScopeEntry::ContentPath(path.clone()),
            AccessScope::RecursiveContentTree(path) => {
                ScopeEntry::RecursiveContentTree(path.clone())
            }
            AccessScope::DirectoryListing(path) => ScopeEntry::DirectoryListing(path.clone()),
            AccessScope::WholeWorkspace => ScopeEntry::WholeWorkspace,
        })
        .collect()
}

fn execute_once(
    executable: &Path,
    arguments: &[OsString],
    cwd: &Path,
    environment: &[(OsString, OsString)],
    present: bool,
) -> Result<CapturedResult> {
    let started = Instant::now();
    let mut child = Command::new(executable)
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("execute {}", executable.display()))?;
    let child_stdout = child.stdout.take().context("capture child stdout")?;
    let child_stderr = child.stderr.take().context("capture child stderr")?;
    let stdout_presentation = if present {
        StreamPresentation::Stdout
    } else {
        StreamPresentation::Suppress
    };
    let stderr_presentation = if present {
        StreamPresentation::Stderr
    } else {
        StreamPresentation::Suppress
    };
    let stdout_thread =
        thread::spawn(move || capture_child_stream(child_stdout, stdout_presentation));
    let stderr_thread =
        thread::spawn(move || capture_child_stream(child_stderr, stderr_presentation));
    let status = child
        .wait()
        .with_context(|| format!("wait for {}", executable.display()))?;
    let stdout = join_capture_thread(stdout_thread, "stdout")?;
    let stderr = join_capture_thread(stderr_thread, "stderr")?;
    let exit_code = exit_code_for_status(status);
    Ok(CapturedResult {
        stdout: stdout.bytes,
        stderr: stderr.bytes,
        capture_complete: stdout.complete && stderr.complete,
        presentation_broken_pipe: stdout.broken_pipe || stderr.broken_pipe,
        exit_code,
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

fn capture_child_stream(
    reader: impl Read,
    presentation: StreamPresentation,
) -> Result<CapturedStream> {
    match presentation {
        StreamPresentation::Stdout => capture_and_present(reader, io::stdout().lock()),
        StreamPresentation::Stderr => capture_and_present(reader, io::stderr().lock()),
        StreamPresentation::Suppress => capture_and_present(reader, io::sink()),
    }
}

fn capture_and_present(mut reader: impl Read, mut writer: impl Write) -> Result<CapturedStream> {
    let mut bytes = Vec::new();
    let mut complete = true;
    let mut broken_pipe = false;
    let mut buffer = [0_u8; 64 * 1024];
    let mut write_error = None;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        if write_error.is_none()
            && let Err(error) = writer.write_all(&buffer[..read])
        {
            if error.kind() == io::ErrorKind::BrokenPipe {
                // Drop the child's read end immediately. A native producer
                // would observe the same closed downstream pipe.
                broken_pipe = true;
                complete = false;
                break;
            }
            // Continue draining so the child cannot deadlock on a full
            // pipe, then surface other presentation failures after exit.
            write_error = Some(error);
        }
        if complete {
            let remaining = MAX_STORABLE_STREAM_BYTES.saturating_sub(bytes.len());
            if read <= remaining {
                bytes.extend_from_slice(&buffer[..read]);
            } else {
                bytes.extend_from_slice(&buffer[..remaining]);
                complete = false;
            }
        }
    }
    if !broken_pipe
        && write_error.is_none()
        && let Err(error) = writer.flush()
    {
        if error.kind() == io::ErrorKind::BrokenPipe {
            broken_pipe = true;
            complete = false;
        } else {
            write_error = Some(error);
        }
    }
    if let Some(error) = write_error {
        return Err(error).context("present child output");
    }
    Ok(CapturedStream {
        bytes,
        complete,
        broken_pipe,
    })
}

fn join_capture_thread(
    handle: thread::JoinHandle<Result<CapturedStream>>,
    stream: &str,
) -> Result<CapturedStream> {
    handle
        .join()
        .map_err(|_| anyhow!("{stream} capture thread panicked"))?
        .with_context(|| format!("capture child {stream}"))
}

fn emit_bytes(stdout: &[u8], stderr: &[u8]) -> io::Result<()> {
    io::stdout().lock().write_all(stdout)?;
    io::stderr().lock().write_all(stderr)?;
    Ok(())
}

fn load_cached_blob_or_quarantine(
    store: &Store,
    result_id: &str,
    digest: &str,
    quarantine_reason: &str,
) -> Result<Vec<u8>> {
    match store.get_blob(digest) {
        Ok(bytes) => Ok(bytes),
        Err(error) => {
            if let Err(quarantine_error) = store.quarantine(result_id, quarantine_reason) {
                return Err(error).context(format!(
                    "cached result {result_id} contains an invalid blob and quarantine failed: {quarantine_error:#}"
                ));
            }
            Err(error).context(format!(
                "cached result {result_id} contains an invalid blob and was quarantined"
            ))
        }
    }
}

fn emit_explicit_reference(result: &StoredResult) -> io::Result<u64> {
    let reference = ExplicitResultReference {
        schema: "again.reference.v1",
        result_id: &result.id,
        exit_code: result.exit_code,
        stdout: ReferencedStream {
            blake3: &result.stdout_digest,
            bytes: result.stdout_bytes,
        },
        stderr: ReferencedStream {
            blake3: &result.stderr_digest,
            bytes: result.stderr_bytes,
        },
    };
    let mut encoded = serde_json::to_vec(&reference).map_err(io::Error::other)?;
    encoded.push(b'\n');
    let encoded_bytes = encoded.len() as u64;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&encoded)?;
    stdout.flush()?;
    Ok(encoded_bytes)
}

fn signal_exit_code(signal: i32) -> i32 {
    128_i32.saturating_add(signal).min(255)
}

fn exit_code_for_status(status: std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return signal_exit_code(signal);
        }
    }
    128
}

fn ambient_inputs_supported(argv: &[String], environment: &[(OsString, OsString)]) -> bool {
    if environment.iter().any(|(name, _)| {
        let Some(name) = name.to_str() else {
            return false;
        };
        name.starts_with("DYLD_")
            || name.starts_with("LD_")
            || name.starts_with("Malloc")
            || name.starts_with("MALLOC_")
            || matches!(
                name,
                "ASAN_OPTIONS"
                    | "LSAN_OPTIONS"
                    | "MSAN_OPTIONS"
                    | "TSAN_OPTIONS"
                    | "UBSAN_OPTIONS"
                    | "GCONV_PATH"
                    | "LOCPATH"
                    | "NLSPATH"
                    | "PATH_LOCALE"
                    | "TERMCAP"
                    | "TERMINFO"
                    | "TERMINFO_DIRS"
                    | "TZDIR"
            )
    }) {
        // These families can redirect executable loading, instrumentation,
        // locale conversion, terminal data, or timezone data to mutable files
        // outside the scoped fingerprint. Hashing only the environment text
        // does not bind the referenced bytes.
        return false;
    }
    let program = argv.first().and_then(|program| {
        Path::new(program)
            .file_name()
            .and_then(|name| name.to_str())
    });
    if program == Some("rg")
        && environment
            .iter()
            .any(|(name, _)| name == "RIPGREP_CONFIG_PATH")
    {
        // The environment digest covers the config *path*, but not an arbitrary
        // file outside the workspace changing in place. Passing through is the
        // only correct v0 behavior.
        return false;
    }
    if program == Some("grep") && environment.iter().any(|(name, _)| name == "GREP_OPTIONS") {
        // BSD grep prepends GREP_OPTIONS to argv. It can inject -f and make an
        // arbitrary pattern file an unmodeled input, or change which supplied
        // token is the pattern. Hashing the option string alone is insufficient.
        return false;
    }
    true
}

fn audited_boundary_digest(identity: &ExecutableIdentity) -> Result<String> {
    let encoded = serde_json::to_vec(identity)?;
    let mut hasher = Hasher::new_derive_key("again audited execution boundary v0");
    put_field(&mut hasher, POLICY_VERSION.as_bytes());
    put_field(&mut hasher, &encoded);
    Ok(hasher.finalize().to_hex().to_string())
}

fn request_key(
    fingerprint: &FingerprintResult,
    boundary_digest: &str,
    runtime_context_digest: &str,
) -> Result<String> {
    let mut hasher = Hasher::new_derive_key("again.engine.request.v0");
    put_field(&mut hasher, POLICY_VERSION.as_bytes());
    put_field(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    put_field(&mut hasher, std::env::consts::OS.as_bytes());
    put_field(&mut hasher, std::env::consts::ARCH.as_bytes());
    put_field(&mut hasher, platform_epoch()?.as_bytes());
    put_field(&mut hasher, boundary_digest.as_bytes());
    put_field(&mut hasher, runtime_context_digest.as_bytes());
    put_field(&mut hasher, fingerprint.request_digest.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

fn verify_current_exec_capability(
    identity: &ExecutableIdentity,
    executable: &Path,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<()> {
    let (arguments, expected_code): (&[&str], i32) = match identity.tool {
        ToolKind::Cat => (&[], 0),
        // BSD head rejects a zero line count. Reading one line from the fixed
        // null stdin still emits no bytes while proving current exec/read
        // authority on the exact audited binary.
        ToolKind::Head => (&["-n", "1"], 0),
        ToolKind::Tail => (&["-n", "0"], 0),
        ToolKind::Wc => (&["-c"], 0),
        ToolKind::Grep => (&["--", "__again_exec_probe_never_match__"], 1),
        ToolKind::Ls => (&["--color=never", "-d", "."], 0),
        ToolKind::Pwd => (&["-P"], 0),
        ToolKind::Rg => (&["--version"], 0),
    };
    let status = Command::new(executable)
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("probe current exec authority for {}", executable.display()))?;
    if status.code() != Some(expected_code) {
        bail!(
            "current runtime cannot execute the audited {:?} capability probe",
            identity.tool
        );
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn runtime_context_digest() -> Result<String> {
    let mut hasher = Hasher::new_derive_key("again.runtime-context.macos.v1");
    // SAFETY: credential getters have no preconditions and do not dereference pointers.
    let credentials = unsafe {
        [
            libc::getuid() as u64,
            libc::geteuid() as u64,
            libc::getgid() as u64,
            libc::getegid() as u64,
        ]
    };
    for credential in credentials {
        put_field(&mut hasher, &credential.to_be_bytes());
    }

    // SAFETY: the first call requests only the count. The second buffer has
    // exactly that many gid_t elements and remains live for the call.
    let group_count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if group_count < 0 {
        return Err(io::Error::last_os_error()).context("query supplementary group count");
    }
    let mut groups = vec![0 as libc::gid_t; group_count as usize];
    // SAFETY: `groups` is allocated for `group_count` gid_t values.
    let actual_groups = unsafe { libc::getgroups(group_count, groups.as_mut_ptr()) };
    if actual_groups < 0 {
        return Err(io::Error::last_os_error()).context("query supplementary groups");
    }
    groups.truncate(actual_groups as usize);
    put_field(&mut hasher, &(groups.len() as u64).to_be_bytes());
    for group in groups {
        put_field(&mut hasher, &(group as u64).to_be_bytes());
    }

    let limits: &[(&[u8], libc::c_int)] = &[
        (b"cpu", libc::RLIMIT_CPU),
        (b"fsize", libc::RLIMIT_FSIZE),
        (b"data", libc::RLIMIT_DATA),
        (b"stack", libc::RLIMIT_STACK),
        (b"core", libc::RLIMIT_CORE),
        (b"rss", libc::RLIMIT_RSS),
        (b"memlock", libc::RLIMIT_MEMLOCK),
        (b"nproc", libc::RLIMIT_NPROC),
        (b"nofile", libc::RLIMIT_NOFILE),
        (b"as", libc::RLIMIT_AS),
    ];
    for (name, resource) in limits {
        // SAFETY: `limit` is valid writable storage and `resource` is one of
        // the platform's declared RLIMIT constants.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        // SAFETY: arguments satisfy getrlimit's contract as described above.
        if unsafe { libc::getrlimit(*resource, &mut limit) } != 0 {
            return Err(io::Error::last_os_error()).with_context(|| {
                format!("query {} resource limit", String::from_utf8_lossy(name))
            });
        }
        put_field(&mut hasher, name);
        put_field(&mut hasher, &limit.rlim_cur.to_be_bytes());
        put_field(&mut hasher, &limit.rlim_max.to_be_bytes());
    }

    // SAFETY: zeroed sigset_t is immediately initialized by pthread_sigmask.
    let mut signal_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    // With a null `set`, POSIX specifies that `how` is ignored and the current
    // thread mask is copied into `oldset` without mutation.
    // SAFETY: oldset points to valid writable sigset_t storage.
    let mask_status =
        unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut signal_mask) };
    if mask_status != 0 {
        return Err(io::Error::from_raw_os_error(mask_status)).context("query signal mask");
    }
    // Darwin's current signal namespace is contiguous through SIGUSR2 (31).
    for signal in 1..=libc::SIGUSR2 {
        // SAFETY: signal_mask was initialized above and signal is in range.
        let masked = unsafe { libc::sigismember(&signal_mask, signal) };
        if masked < 0 {
            return Err(io::Error::last_os_error()).context("inspect signal mask");
        }
        let (disposition, flags) = if signal == libc::SIGKILL || signal == libc::SIGSTOP {
            // These signals are unmaskable and have an immutable default
            // disposition; Darwin rejects a sigaction query for them.
            (0_u8, 0_u64)
        } else {
            // SAFETY: zeroed sigaction is valid writable output for sigaction.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            // SAFETY: a null new action performs a read-only disposition query.
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut action) } != 0 {
                return Err(io::Error::last_os_error())
                    .with_context(|| format!("query disposition for signal {signal}"));
            }
            let disposition = if action.sa_sigaction == libc::SIG_DFL {
                0_u8
            } else if action.sa_sigaction == libc::SIG_IGN {
                1_u8
            } else {
                // Caught dispositions reset to default across exec; the handler
                // address itself is not an inherited child input.
                2_u8
            };
            (disposition, action.sa_flags as u64)
        };
        put_field(&mut hasher, &signal.to_be_bytes());
        put_field(&mut hasher, &[masked as u8, disposition]);
        put_field(&mut hasher, &flags.to_be_bytes());
    }
    Ok(hasher.finalize().to_hex().to_string())
}

#[cfg(not(target_os = "macos"))]
fn runtime_context_digest() -> Result<String> {
    let mut hasher = Hasher::new_derive_key("again.runtime-context.unsupported.v1");
    put_field(&mut hasher, std::env::consts::OS.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

fn put_field(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
}

fn validate_cached_result(
    result: &StoredResult,
    expected_request_key: &str,
    fingerprint: &FingerprintResult,
    boundary_digest: &str,
    runtime_context_digest: &str,
    executable_identity: &ExecutableIdentity,
    access_plan: &AccessPlan,
) -> Result<()> {
    if result.request_key != expected_request_key {
        bail!("result request key does not match the recomputed request");
    }
    if result.exit_code != 0 {
        bail!("cached result has a non-zero exit code");
    }
    if result.policy_version != POLICY_VERSION {
        bail!("cached result policy version is not active");
    }
    if result.stdout_bytes > MAX_STORABLE_STREAM_BYTES as u64
        || result.stderr_bytes > MAX_STORABLE_STREAM_BYTES as u64
    {
        bail!("cached result exceeds the local stream limit");
    }
    if result.stderr_bytes != 0 {
        bail!("cached result has stderr that cannot be order-preserving replayed");
    }
    for digest in [&result.stdout_digest, &result.stderr_digest] {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("cached result contains a malformed blob digest");
        }
    }
    if result.proof_json.len() > 64 * 1024 {
        bail!("cached result proof exceeds the metadata limit");
    }
    let proof: StoredV0Proof =
        serde_json::from_str(&result.proof_json).context("parse cached v0 proof")?;
    if proof.schema != "again.scoped_read.v0"
        || proof.policy_version != POLICY_VERSION
        || proof.admission != "two_exact_executions"
        || proof.execution_boundary != "audited_native_read_only_v0"
        || proof.validation_runs != 2
    {
        bail!("cached result proof uses an unsupported profile");
    }
    if proof.boundary_digest != boundary_digest
        || proof.runtime_context_digest != runtime_context_digest
        || proof.executable_identity != *executable_identity
        || proof.access_plan != *access_plan
        || proof.request_digest != fingerprint.request_digest
        || proof.workspace_digest != fingerprint.workspace_digest
        || proof.environment_digest != fingerprint.environment_digest
        || proof.executable_digest != fingerprint.executable_digest
        || proof.workspace_entries != fingerprint.workspace_entries
    {
        bail!("cached result proof does not match recomputed execution inputs");
    }
    Ok(())
}

fn platform_epoch() -> Result<String> {
    let candidates: &[&str] = if cfg!(target_os = "macos") {
        &["/System/Library/CoreServices/SystemVersion.plist"]
    } else {
        &["/etc/os-release", "/proc/sys/kernel/osrelease"]
    };
    let mut hasher = Hasher::new_derive_key("again.platform.epoch.v0");
    put_field(&mut hasher, std::env::consts::OS.as_bytes());
    put_field(&mut hasher, std::env::consts::ARCH.as_bytes());
    for candidate in candidates {
        let path = Path::new(candidate);
        put_field(&mut hasher, candidate.as_bytes());
        match fs::read(path) {
            Ok(bytes) => put_field(&mut hasher, &bytes),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                put_field(&mut hasher, b"absent")
            }
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("read platform identity {}", path.display()));
            }
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

pub(crate) fn resolve_executable(
    program: &OsStr,
    cwd: &Path,
    environment: &[(OsString, OsString)],
) -> Result<PathBuf> {
    let program_path = Path::new(program);
    if program_path.components().count() > 1 {
        let candidate = if program_path.is_absolute() {
            program_path.to_path_buf()
        } else {
            cwd.join(program_path)
        };
        return fs::canonicalize(&candidate)
            .with_context(|| format!("resolve executable {}", candidate.display()));
    }
    let path = environment
        .iter()
        .find(|(name, _)| name == "PATH")
        .map(|(_, value)| value)
        .ok_or_else(|| anyhow!("PATH is unavailable"))?;
    for directory in std::env::split_paths(path) {
        let directory = if directory.as_os_str().is_empty() {
            cwd.to_path_buf()
        } else if directory.is_absolute() {
            directory
        } else {
            cwd.join(directory)
        };
        let candidate = directory.join(program);
        if candidate.is_file() {
            return fs::canonicalize(&candidate)
                .with_context(|| format!("resolve executable {}", candidate.display()));
        }
    }
    bail!("executable {program:?} was not found on PATH")
}

pub(crate) fn discover_workspace(cwd: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(cwd)
        .with_context(|| format!("resolve working directory {}", cwd.display()))?;
    if !canonical.is_dir() {
        bail!(
            "working directory is not a directory: {}",
            canonical.display()
        );
    }
    for candidate in canonical.ancestors() {
        if candidate.join(".git").exists() {
            return Ok(candidate.to_path_buf());
        }
    }
    Ok(canonical)
}

fn shell_join_for_policy(arguments: &[OsString]) -> Result<String> {
    let mut result = String::new();
    for (index, argument) in arguments.iter().enumerate() {
        let argument = argument
            .to_str()
            .ok_or_else(|| anyhow!("v0 requires UTF-8 command arguments"))?;
        if index > 0 {
            result.push(' ');
        }
        if argument.is_empty() {
            result.push_str("''");
        } else if argument
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_./,:=@%+-".contains(&byte))
        {
            result.push_str(argument);
        } else {
            result.push('\'');
            result.push_str(&argument.replace('\'', "'\\''"));
            result.push('\'');
        }
    }
    Ok(result)
}

fn monotonic_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}

fn show(id: &str) -> Result<i32> {
    let store = open_store_for_current_workspace()?;
    let result = store
        .get_result_by_id(id)?
        .ok_or_else(|| anyhow!("result {id} not found or quarantined"))?;
    emit_bytes(
        &store.get_blob(&result.stdout_digest)?,
        &store.get_blob(&result.stderr_digest)?,
    )?;
    Ok(result.exit_code)
}

fn explain(args: ExplainArgs) -> Result<i32> {
    let store = open_store_for_current_workspace()?;
    if let Some(id) = args.id {
        let result = store
            .get_result_by_id(&id)?
            .ok_or_else(|| anyhow!("result {id} not found or quarantined"))?;
        if args.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!("result: {}", result.id);
            println!("decision: exact local reuse eligible");
            println!("policy: {}", result.policy_version);
            println!("original duration: {} ms", result.duration_ms);
            println!(
                "stdout/stderr: {}/{} bytes",
                result.stdout_bytes, result.stderr_bytes
            );
            println!("proof: {}", result.proof_json);
        }
    } else if let Some((disposition, reason, result_id)) = store.last_event()? {
        if args.json {
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "disposition": disposition,
                    "reason": reason,
                    "result_id": result_id,
                }))?
            );
        } else {
            println!("decision: {disposition}");
            println!("reason: {reason}");
            if let Some(result_id) = result_id {
                println!("result: {result_id}");
            }
        }
    } else {
        println!("No Again execution events have been recorded yet.");
    }
    Ok(0)
}

fn stats(json: bool) -> Result<i32> {
    let stats = open_store_for_current_workspace()?.stats()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&stats)?);
    } else {
        println!("executions: {}", stats.executions);
        println!("full replays: {}", stats.full_replays);
        println!("compact replays: {}", stats.compact_replays);
        println!("bypasses: {}", stats.bypasses);
        println!("quarantines: {}", stats.quarantines);
        println!("duplicate bytes omitted: {}", stats.duplicate_bytes_omitted);
        println!(
            "estimated net execution time saved: {} ms",
            stats.estimated_execution_ms_saved
        );
    }
    Ok(0)
}

fn doctor(json: bool) -> Result<i32> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let store = open_store_for_current_workspace()?;
    let cwd = std::env::current_dir()?;
    let workspace = discover_workspace(&cwd)?;
    let personal_skill = codex_skill_dir(SetupScope::Global, None)?;
    let project_skill = codex_skill_dir(SetupScope::Project, Some(&workspace))?;
    let skills = codex_skill_scope_status(&personal_skill, &project_skill)?;
    let seatbelt_preflight = crate::sandbox::preflight().to_string();
    let seatbelt_runtime_probe = match crate::sandbox::probe_apply() {
        Ok(()) => "available".to_owned(),
        Err(error) => format!("unavailable: {error}"),
    };
    let report = DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        executable: executable.display().to_string(),
        state_dir: store.root().display().to_string(),
        state_writable: store.root().is_dir(),
        policy_version: POLICY_VERSION,
        audited_apple_tool_profile: match host_audited_apple_profile() {
            Ok(profile) => profile.to_owned(),
            Err(error) => format!("unsupported: {error}"),
        },
        personal_codex_skill_dir: skills.personal_dir.display().to_string(),
        project_codex_skill_dir: skills.project_dir.display().to_string(),
        personal_codex_skill_installed: skills.personal_installed,
        project_codex_skill_installed: skills.project_installed,
        duplicate_codex_skill_scopes: skills.duplicate_again_skills(),
        profile: "scoped_audited_read_only_v0",
        execution_boundary: "audited_native_read_only_v0",
        seatbelt_preflight,
        seatbelt_runtime_probe,
        seatbelt_used_for_profile: false,
        trace_backed_replay: false,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Again {}", report.version);
        println!("executable: {}", report.executable);
        println!("state: {}", report.state_dir);
        println!("policy: {}", report.policy_version);
        println!(
            "audited Apple tool profile: {}",
            report.audited_apple_tool_profile
        );
        println!(
            "Codex skill: personal={}, project={}",
            report.personal_codex_skill_installed, report.project_codex_skill_installed
        );
        if report.duplicate_codex_skill_scopes {
            println!("warning: duplicate Again instructions are active in both skill scopes");
        }
        println!("active profile: {}", report.profile);
        println!("execution boundary: {}", report.execution_boundary);
        println!("Seatbelt preflight: {}", report.seatbelt_preflight);
        println!("Seatbelt runtime probe: {}", report.seatbelt_runtime_probe);
        println!("Seatbelt used by active profile: no");
        println!(
            "trace-backed replay: unavailable; explicit ineligible calls fail before execution"
        );
    }
    Ok(0)
}

fn open_store_for_current_workspace() -> Result<Store> {
    let cwd = std::env::current_dir()?;
    let workspace = discover_workspace(&cwd)?;
    Store::open_for_workspace(&workspace)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::executable::ExecutableProvenance;
    use std::io::{Cursor, repeat};
    use tempfile::TempDir;

    struct BrokenPipeWriter;

    impl Write for BrokenPipeWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "downstream closed",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn child_stream_capture_is_exact_and_memory_bounded() {
        let payload = b"streamed output";
        let mut presented = Vec::new();
        let exact = capture_and_present(Cursor::new(payload), &mut presented).unwrap();
        assert!(exact.complete);
        assert_eq!(exact.bytes, payload);
        assert_eq!(presented, payload);

        let oversized = repeat(0).take(MAX_STORABLE_STREAM_BYTES as u64 + 1);
        let bounded = capture_and_present(oversized, io::sink()).unwrap();
        assert!(!bounded.complete);
        assert_eq!(bounded.bytes.len(), MAX_STORABLE_STREAM_BYTES);
    }

    #[test]
    fn savings_metric_is_positive_net_wall_time_and_never_underflows() {
        assert_eq!(
            estimated_net_saved_millis(500, std::time::Duration::from_millis(12)),
            488
        );
        assert_eq!(
            estimated_net_saved_millis(2, std::time::Duration::from_millis(7)),
            0
        );
    }

    #[test]
    fn broken_downstream_pipe_stops_capture_without_admitting_output() {
        let captured =
            capture_and_present(Cursor::new(b"streamed output"), BrokenPipeWriter).unwrap();
        assert!(captured.broken_pipe);
        assert!(!captured.complete);
        assert!(captured.bytes.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn signal_status_uses_shell_compatible_exit_code() {
        let status = Command::new("/bin/sh")
            .args(["-c", "kill -TERM $$"])
            .status()
            .unwrap();
        assert_eq!(exit_code_for_status(status), 143);
        assert_eq!(signal_exit_code(libc::SIGPIPE), 141);
    }

    #[test]
    fn workspace_discovery_uses_nearest_git_root() {
        let temp = TempDir::new().unwrap();
        fs::create_dir(temp.path().join(".git")).unwrap();
        fs::create_dir(temp.path().join("nested")).unwrap();
        assert_eq!(
            discover_workspace(&temp.path().join("nested")).unwrap(),
            temp.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn policy_join_round_trips_simple_arguments() {
        let args = vec![
            OsString::from("rg"),
            OsString::from("two words"),
            OsString::from(""),
            OsString::from("single'quote"),
            OsString::from("src"),
        ];
        let raw = shell_join_for_policy(&args).unwrap();
        assert_eq!(
            shell_words::split(&raw).unwrap(),
            vec!["rg", "two words", "", "single'quote", "src"]
        );
    }

    #[test]
    fn team_cli_requires_explicit_profile_and_command_delimiter() {
        let parsed = Cli::try_parse_from([
            "again",
            "team",
            "run",
            "--profile",
            "/private/profile.json",
            "--",
            "wc",
            "-c",
            "README.md",
        ])
        .unwrap();
        let CommandName::Team(TeamArgs {
            command: TeamCommand::Run(args),
        }) = parsed.command
        else {
            panic!("team run did not parse to the team command");
        };
        assert_eq!(args.profile, PathBuf::from("/private/profile.json"));
        assert_eq!(args.command, ["wc", "-c", "README.md"].map(OsString::from));

        assert!(
            Cli::try_parse_from([
                "again",
                "team",
                "run",
                "--profile",
                "/private/profile.json",
                "wc",
                "-c",
                "README.md",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from(["again", "team", "run", "--", "wc", "-c", "README.md"]).is_err()
        );

        let inspected = Cli::try_parse_from([
            "again",
            "team",
            "inspect",
            "--profile",
            "/private/profile.json",
            "--json",
            "--",
            "wc",
            "-c",
            "README.md",
        ])
        .unwrap();
        let CommandName::Team(TeamArgs {
            command: TeamCommand::Inspect(args),
        }) = inspected.command
        else {
            panic!("team inspect did not parse to the team command");
        };
        assert_eq!(args.profile, PathBuf::from("/private/profile.json"));
        assert!(args.json);
        assert_eq!(args.command, ["wc", "-c", "README.md"].map(OsString::from));

        assert!(
            Cli::try_parse_from([
                "again",
                "team",
                "inspect",
                "--profile",
                "/private/profile.json",
                "--",
                "wc",
                "-c",
                "README.md",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "again",
                "team",
                "inspect",
                "--profile",
                "/private/profile.json",
                "--json",
                "wc",
                "-c",
                "README.md",
            ])
            .is_err()
        );
    }

    #[test]
    fn ambient_option_sources_fail_closed() {
        let environment = vec![(OsString::from("PATH"), OsString::from("/usr/bin:/bin"))];
        assert!(ambient_inputs_supported(&["grep".to_owned()], &environment));
        assert!(ambient_inputs_supported(&["rg".to_owned()], &environment));

        let grep_options = vec![(
            OsString::from("GREP_OPTIONS"),
            OsString::from("-f patterns"),
        )];
        assert!(!ambient_inputs_supported(
            &["grep".to_owned()],
            &grep_options
        ));
        assert!(!ambient_inputs_supported(
            &["/usr/bin/grep".to_owned()],
            &grep_options
        ));
        let rg_config = vec![(
            OsString::from("RIPGREP_CONFIG_PATH"),
            OsString::from("/tmp/rg.conf"),
        )];
        assert!(!ambient_inputs_supported(&["rg".to_owned()], &rg_config));
        assert!(!ambient_inputs_supported(
            &["/Applications/Codex.app/Contents/Resources/rg".to_owned()],
            &rg_config
        ));

        for name in [
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
            "MallocScribble",
            "ASAN_OPTIONS",
            "LOCPATH",
            "TERMINFO_DIRS",
            "TZDIR",
        ] {
            assert!(!ambient_inputs_supported(
                &["cat".to_owned()],
                &[(OsString::from(name), OsString::from("/tmp/external"))],
            ));
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn every_audited_apple_tool_capability_probe_succeeds_on_the_reviewed_host() {
        if crate::executable::host_audited_apple_profile().is_err() {
            return;
        }
        let cwd = TempDir::new().unwrap();
        let environment = [
            (OsString::from("LANG"), OsString::from("C")),
            (OsString::from("LC_ALL"), OsString::from("C")),
            (OsString::from("PATH"), OsString::from("/usr/bin:/bin")),
        ];
        for (name, path) in [
            ("cat", Path::new("/bin/cat")),
            ("head", Path::new("/usr/bin/head")),
            ("tail", Path::new("/usr/bin/tail")),
            ("wc", Path::new("/usr/bin/wc")),
            ("grep", Path::new("/usr/bin/grep")),
            ("ls", Path::new("/bin/ls")),
            ("pwd", Path::new("/bin/pwd")),
        ] {
            let identity = verify_executable(name, path).unwrap();
            verify_current_exec_capability(&identity, path, cwd.path(), &environment)
                .unwrap_or_else(|error| panic!("{name} capability probe failed: {error:#}"));
        }
    }

    #[test]
    fn cached_result_metadata_must_match_recomputed_v0_proof() {
        let identity = ExecutableIdentity {
            tool: ToolKind::Cat,
            canonical_path: PathBuf::from("/bin/cat"),
            provenance: ExecutableProvenance::AppleSystem,
            semantic_profile: "test-system-profile".to_owned(),
        };
        let access_plan = AccessPlan {
            scopes: vec![AccessScope::ContentPath(PathBuf::from("input.txt"))],
        };
        let fingerprint = FingerprintResult {
            request_digest: "1".repeat(64),
            workspace_digest: "2".repeat(64),
            workspace_tree_digest: "3".repeat(64),
            environment_digest: "4".repeat(64),
            executable_digest: "5".repeat(64),
            canonical_workspace: PathBuf::from("/workspace"),
            canonical_cwd: PathBuf::from("/workspace"),
            canonical_executable: PathBuf::from("/bin/cat"),
            workspace_entries: 2,
        };
        let boundary = "6".repeat(64);
        let runtime_context = "a".repeat(64);
        let request_key = "7".repeat(64);
        let proof = V0Proof {
            schema: "again.scoped_read.v0",
            policy_version: POLICY_VERSION,
            admission: "two_exact_executions",
            execution_boundary: "audited_native_read_only_v0",
            boundary_digest: &boundary,
            runtime_context_digest: &runtime_context,
            executable_identity: &identity,
            access_plan: &access_plan,
            request_digest: &fingerprint.request_digest,
            workspace_digest: &fingerprint.workspace_digest,
            environment_digest: &fingerprint.environment_digest,
            executable_digest: &fingerprint.executable_digest,
            workspace_entries: fingerprint.workspace_entries,
            validation_runs: 2,
        };
        let result = StoredResult {
            id: "r_0123456789abcdef0123456789abcdef".to_owned(),
            request_key: request_key.clone(),
            stdout_digest: "8".repeat(64),
            stderr_digest: "9".repeat(64),
            stdout_bytes: 12,
            stderr_bytes: 0,
            exit_code: 0,
            duration_ms: 10,
            policy_version: POLICY_VERSION.to_owned(),
            proof_json: serde_json::to_string(&proof).unwrap(),
        };
        assert!(
            validate_cached_result(
                &result,
                &request_key,
                &fingerprint,
                &boundary,
                &runtime_context,
                &identity,
                &access_plan,
            )
            .is_ok()
        );

        let mut tampered = result.clone();
        tampered.policy_version = "attacker-policy".to_owned();
        assert!(
            validate_cached_result(
                &tampered,
                &request_key,
                &fingerprint,
                &boundary,
                &runtime_context,
                &identity,
                &access_plan,
            )
            .is_err()
        );

        let mut tampered = result.clone();
        tampered.proof_json = tampered
            .proof_json
            .replace(&fingerprint.workspace_digest, &"a".repeat(64));
        assert!(
            validate_cached_result(
                &tampered,
                &request_key,
                &fingerprint,
                &boundary,
                &runtime_context,
                &identity,
                &access_plan,
            )
            .is_err()
        );

        let mut tampered = result;
        tampered.stdout_digest = "A".repeat(64);
        assert!(
            validate_cached_result(
                &tampered,
                &request_key,
                &fingerprint,
                &boundary,
                &runtime_context,
                &identity,
                &access_plan,
            )
            .is_err()
        );
    }
}
