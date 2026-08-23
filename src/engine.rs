//! CLI and execution orchestration.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use clap::{Args, Parser, Subcommand};
use serde::Serialize;

use crate::executable::{ExecutableIdentity, verify_executable};
use crate::fingerprint::{
    FingerprintInput, FingerprintResult, ScopeEntry, fingerprint_scoped_with_cache,
};
use crate::hook::{parse_input, rewrite_output};
use crate::policy::{AccessPlan, AccessScope, Decision, PolicyContext, classify};
use crate::setup::{
    SetupScope, hook_path, install_codex_hook, is_codex_hook_installed, remove_codex_hook,
};
use crate::store::{EventDisposition, PendingCall, Store};

const POLICY_VERSION: &str = "strict-read-v0.1";
const MAX_STORABLE_STREAM_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Parser)]
#[command(
    name = "again",
    version,
    about = "Proof-carrying reuse and compact output for agent tool calls"
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
    /// Handle one Codex PreToolUse hook event on stdin.
    #[command(hide = true)]
    Hook,
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
    /// Configure the Codex PreToolUse integration.
    #[arg(long)]
    codex: bool,
    /// Install in the current repository instead of the user config.
    #[arg(long, conflicts_with = "global")]
    project: bool,
    /// Explicitly select the user-level config (the default).
    #[arg(long)]
    global: bool,
    /// Print the change without writing it.
    #[arg(long)]
    dry_run: bool,
    /// Remove Again's handler while preserving unrelated hooks.
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
    exit_code: i32,
    duration_ms: u64,
}

#[derive(Debug, Serialize)]
struct V0Proof<'a> {
    schema: &'static str,
    policy_version: &'static str,
    admission: &'static str,
    execution_boundary: &'static str,
    boundary_digest: &'a str,
    executable_identity: &'a ExecutableIdentity,
    access_plan: &'a AccessPlan,
    request_digest: &'a str,
    workspace_digest: &'a str,
    environment_digest: &'a str,
    executable_digest: &'a str,
    workspace_entries: u64,
    validation_runs: u8,
}

#[derive(Debug, Serialize)]
struct DoctorReport {
    version: &'static str,
    executable: String,
    state_dir: String,
    state_writable: bool,
    codex_hook_path: String,
    codex_hook_installed: bool,
    profile: &'static str,
    trace_backed_replay: bool,
}

pub fn run_cli() -> Result<i32> {
    let cli = Cli::parse_from(normalized_args());
    match cli.command {
        CommandName::Setup(args) => setup(args),
        CommandName::Run(args) => direct_run(args.command),
        CommandName::Hook => handle_hook(),
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
    let scope = if args.project {
        SetupScope::Project
    } else {
        SetupScope::Global
    };
    let project = (scope == SetupScope::Project).then_some(cwd.as_path());
    let path = hook_path(scope, project)?;
    let executable = std::env::current_exe().context("locate Again executable")?;
    let change = if args.remove {
        remove_codex_hook(&path, args.dry_run)?
    } else {
        install_codex_hook(&path, &executable, args.dry_run)?
    };

    if args.dry_run {
        println!("# dry run: {}", change.path.display());
        print!("{}", change.rendered);
    } else if args.remove {
        if change.changed {
            println!("Removed Again's Codex hook from {}.", change.path.display());
        } else {
            println!(
                "Again's Codex hook was not installed at {}.",
                change.path.display()
            );
        }
    } else if change.changed {
        println!("Installed Again's Codex hook at {}.", change.path.display());
        if let Some(backup) = change.backup {
            println!("Preserved the previous file at {}.", backup.display());
        }
        println!("In Codex, run /hooks and trust the reviewed Again hook once.");
    } else {
        println!(
            "Again's Codex hook is already current at {}.",
            change.path.display()
        );
    }
    Ok(0)
}

fn handle_hook() -> Result<i32> {
    let input = parse_input(io::stdin().lock())?;
    let raw_command = input.command()?.to_owned();
    let cwd = fs::canonicalize(PathBuf::from(&input.cwd))
        .with_context(|| format!("resolve hook working directory {}", input.cwd))?;
    let workspace = discover_workspace(&cwd)?;
    let decision = classify(
        &raw_command,
        PolicyContext::new(workspace.as_path(), cwd.as_path()),
    );

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
        input.turn_id.as_deref(),
        &cwd,
        &raw_command,
        &argv,
    )?;
    let executable = std::env::current_exe().context("locate Again executable")?;
    let output = rewrite_output(&executable, &call.id)?;
    serde_json::to_writer(io::stdout().lock(), &output)?;
    println!();
    Ok(0)
}

fn execute_pending_call(call_id: &str) -> Result<i32> {
    let invocation_cwd = fs::canonicalize(std::env::current_dir()?)
        .context("resolve rewritten tool working directory")?;
    let invocation_workspace = discover_workspace(&invocation_cwd)?;
    let mut store = Store::open_for_workspace(&invocation_workspace)?;
    let call = store
        .get_call(call_id)?
        .ok_or_else(|| anyhow!("opaque call {call_id} does not exist or expired"))?;
    let workspace = discover_workspace(&call.cwd)?;
    if workspace != invocation_workspace || call.cwd != invocation_cwd {
        store.delete_call(call_id)?;
        bail!("stored call context does not match the rewritten tool invocation");
    }
    let decision = classify(
        &call.raw_command,
        PolicyContext::new(workspace.as_path(), call.cwd.as_path()),
    );
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
    let code = run_admitted(&mut store, &call, &workspace, &access_plan)?;
    store.delete_call(call_id)?;
    Ok(code)
}

fn direct_run(command: Vec<OsString>) -> Result<i32> {
    if command.is_empty() {
        bail!("a command is required");
    }
    let cwd = std::env::current_dir()?;
    let workspace = discover_workspace(&cwd)?;
    let raw_command = shell_join_for_policy(&command)?;
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
    let mut store = Store::open_for_workspace(&workspace)?;
    let call = PendingCall {
        id: format!("direct_{}", std::process::id()),
        session_id: format!("direct_{}_{}", std::process::id(), monotonic_nonce()),
        turn_id: None,
        cwd,
        raw_command,
        argv,
    };
    run_admitted(&mut store, &call, &workspace, &access_plan)
}

fn run_admitted(
    store: &mut Store,
    call: &PendingCall,
    workspace: &Path,
    access_plan: &AccessPlan,
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
    let cached_key = request_key(&before, &boundary_digest)?;

    if let Some(result) = store.get_result(&cached_key)? {
        let stdout = store.get_blob(&result.stdout_digest)?;
        let stderr = store.get_blob(&result.stderr_digest)?;
        if stdout.len() as u64 != result.stdout_bytes || stderr.len() as u64 != result.stderr_bytes
        {
            store.quarantine(&result.id, "blob_length_mismatch")?;
            bail!("cached result {} failed blob length validation", result.id);
        }
        store.note_hit(&result.id)?;
        if std::env::var_os("AGAIN_FULL").is_none()
            && store.was_delivered(&call.session_id, &result.id)?
        {
            let omitted = result.stdout_bytes.saturating_add(result.stderr_bytes);
            let message = format!(
                "[again: exact repeat of result {}; {} duplicate bytes omitted; run `again show {}` for full output]\n",
                result.id, omitted, result.id
            );
            io::stdout().lock().write_all(message.as_bytes())?;
            store.record_event(
                Some(&call.id),
                Some(&result.id),
                EventDisposition::ReplayedCompact,
                "EXACT_SAME_SESSION_REPEAT",
                result.duration_ms,
                omitted,
            )?;
        } else {
            emit_bytes(&stdout, &stderr)?;
            store.mark_delivered(&call.session_id, &result.id)?;
            store.record_event(
                Some(&call.id),
                Some(&result.id),
                EventDisposition::ReplayedFull,
                "EXACT_REUSE",
                result.duration_ms,
                0,
            )?;
        }
        return Ok(result.exit_code);
    }

    let first = execute_once(&executable, &argv[1..], &call.cwd, &environment)?;
    emit_bytes(&first.stdout, &first.stderr)?;
    if first.exit_code != 0 {
        store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "NONZERO_EXIT",
            first.duration_ms,
            0,
        )?;
        return Ok(first.exit_code);
    }
    if first.stdout.len() > MAX_STORABLE_STREAM_BYTES
        || first.stderr.len() > MAX_STORABLE_STREAM_BYTES
    {
        store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "OUTPUT_LIMIT",
            first.duration_ms,
            0,
        )?;
        return Ok(first.exit_code);
    }

    let after_first = fingerprint_scoped_with_cache(
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
    if request_key(&after_first, &boundary_digest)? != cached_key {
        store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "WORKSPACE_CHANGED_DURING_EXECUTION",
            first.duration_ms,
            0,
        )?;
        return Ok(first.exit_code);
    }

    // A candidate is admitted only after an immediate independent execution agrees.
    // This is validation evidence, not a substitute for the v0 whole-workspace proof.
    let shadow = execute_once(&executable, &argv[1..], &call.cwd, &environment)?;
    let after_shadow = fingerprint_scoped_with_cache(
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
    if shadow.exit_code != first.exit_code
        || shadow.stdout != first.stdout
        || shadow.stderr != first.stderr
        || request_key(&after_shadow, &boundary_digest)? != cached_key
    {
        store.record_event(
            Some(&call.id),
            None,
            EventDisposition::BypassedNoStore,
            "SHADOW_DIVERGENCE",
            first.duration_ms.saturating_add(shadow.duration_ms),
            0,
        )?;
        return Ok(first.exit_code);
    }

    let proof = V0Proof {
        schema: "again.scoped_read.v0",
        policy_version: POLICY_VERSION,
        admission: "two_exact_executions",
        execution_boundary: "audited_native_read_only_v0",
        boundary_digest: &boundary_digest,
        executable_identity: &executable_identity,
        access_plan,
        request_digest: &before.request_digest,
        workspace_digest: &before.workspace_digest,
        environment_digest: &before.environment_digest,
        executable_digest: &before.executable_digest,
        workspace_entries: before.workspace_entries,
        validation_runs: 2,
    };
    let result = store.insert_result(
        &cached_key,
        &first.stdout,
        &first.stderr,
        first.exit_code,
        first.duration_ms,
        POLICY_VERSION,
        &serde_json::to_string(&proof)?,
    )?;
    store.mark_delivered(&call.session_id, &result.id)?;
    store.record_event(
        Some(&call.id),
        Some(&result.id),
        EventDisposition::Executed,
        "DOUBLE_EXECUTION_VALIDATED",
        first.duration_ms.saturating_add(shadow.duration_ms),
        0,
    )?;
    Ok(first.exit_code)
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
) -> Result<CapturedResult> {
    let started = Instant::now();
    let Output {
        status,
        stdout,
        stderr,
    } = Command::new(executable)
        .args(arguments)
        .current_dir(cwd)
        .env_clear()
        .envs(environment.iter().cloned())
        .output()
        .with_context(|| format!("execute {}", executable.display()))?;
    let exit_code = status.code().unwrap_or(128);
    Ok(CapturedResult {
        stdout,
        stderr,
        exit_code,
        duration_ms: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
    })
}

fn emit_bytes(stdout: &[u8], stderr: &[u8]) -> Result<()> {
    io::stdout().lock().write_all(stdout)?;
    io::stderr().lock().write_all(stderr)?;
    Ok(())
}

fn ambient_inputs_supported(argv: &[String], environment: &[(OsString, OsString)]) -> bool {
    if argv.first().is_some_and(|program| program == "rg")
        && environment
            .iter()
            .any(|(name, _)| name == "RIPGREP_CONFIG_PATH")
    {
        // The environment digest covers the config *path*, but not an arbitrary
        // file outside the workspace changing in place. Passing through is the
        // only correct v0 behavior.
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

fn request_key(fingerprint: &FingerprintResult, boundary_digest: &str) -> Result<String> {
    let mut hasher = Hasher::new_derive_key("again.engine.request.v0");
    put_field(&mut hasher, POLICY_VERSION.as_bytes());
    put_field(&mut hasher, env!("CARGO_PKG_VERSION").as_bytes());
    put_field(&mut hasher, std::env::consts::OS.as_bytes());
    put_field(&mut hasher, std::env::consts::ARCH.as_bytes());
    put_field(&mut hasher, platform_epoch()?.as_bytes());
    put_field(&mut hasher, boundary_digest.as_bytes());
    put_field(&mut hasher, fingerprint.request_digest.as_bytes());
    Ok(hasher.finalize().to_hex().to_string())
}

fn put_field(hasher: &mut Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_be_bytes());
    hasher.update(value);
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

fn resolve_executable(
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
    bail!("executable {:?} was not found on PATH", program)
}

fn discover_workspace(cwd: &Path) -> Result<PathBuf> {
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
        if argument
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
            "estimated execution time saved: {} ms",
            stats.estimated_execution_ms_saved
        );
    }
    Ok(0)
}

fn doctor(json: bool) -> Result<i32> {
    let executable = std::env::current_exe()?.canonicalize()?;
    let store = open_store_for_current_workspace()?;
    let hook = hook_path(SetupScope::Global, None)?;
    let report = DoctorReport {
        version: env!("CARGO_PKG_VERSION"),
        executable: executable.display().to_string(),
        state_dir: store.root().display().to_string(),
        state_writable: store.root().is_dir(),
        codex_hook_path: hook.display().to_string(),
        codex_hook_installed: is_codex_hook_installed(&hook)?,
        profile: "whole_workspace_read_v0",
        trace_backed_replay: false,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Again {}", report.version);
        println!("executable: {}", report.executable);
        println!("state: {}", report.state_dir);
        println!(
            "Codex hook: {}",
            if report.codex_hook_installed {
                "installed"
            } else {
                "not installed"
            }
        );
        println!("active profile: {}", report.profile);
        println!("trace-backed replay: not yet available; unsafe/unknown calls pass through");
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
    use tempfile::TempDir;

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
            OsString::from("src"),
        ];
        let raw = shell_join_for_policy(&args).unwrap();
        assert_eq!(
            shell_words::split(&raw).unwrap(),
            vec!["rg", "two words", "src"]
        );
    }
}
