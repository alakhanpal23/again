//! CLI and execution orchestration.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
#[cfg(all(feature = "daemon", unix))]
use std::io::{BufRead, BufReader};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
#[cfg(all(feature = "daemon", unix))]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(all(feature = "daemon", unix))]
use std::sync::{Arc, Mutex};
use std::thread;
#[cfg(feature = "daemon")]
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use blake3::Hasher;
use clap::{Args, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};

use crate::agent_gateway_runtime::ExperimentalMcpGatewayV1;
use crate::agent_gateway_setup::{
    AgentGatewayClientV1, AgentGatewaySetupPlanV1, ClientSetupActionV1, execute_client_setup_v1,
};
use crate::executable::{
    ExecutableIdentity, ToolKind, host_audited_apple_profile, verify_executable,
};
use crate::fingerprint::{
    FingerprintInput, FingerprintResult, ScopeEntry, fingerprint_scoped_with_cache,
};
#[cfg(feature = "hook")]
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
    about = "Repository-aware execution memory for coding-agent tool calls"
)]
struct Cli {
    #[command(subcommand)]
    command: CommandName,
}

#[derive(Debug, Subcommand)]
enum CommandName {
    /// Report the source revision embedded when this binary was built.
    BuildInfo,
    /// Install, inspect, or remove agent integrations.
    Setup(SetupArgs),
    /// Execute a strictly admitted command through the local engine.
    Run(RunArgs),
    /// Emit a compact reference to an existing validated local result.
    Reference(ReferenceArgs),
    #[cfg(feature = "team-alpha")]
    /// Reuse or publish an encrypted result through an explicit team profile.
    Team(TeamArgs),
    /// Run or configure the repository-aware MCP gateway.
    Mcp(McpArgs),
    #[cfg(feature = "daemon")]
    /// Launch Codex with an authenticated, verified task brief.
    Codex(CodexArgs),
    #[cfg(feature = "daemon")]
    /// Launch Claude Code with an authenticated, verified task brief.
    Claude(ClaudeArgs),
    /// Inspect, export, delete, or prune durable local tasks.
    Task(TaskArgs),
    #[cfg(feature = "daemon")]
    /// Inspect or clear the local Again Brain's observed agent activity.
    Brain(BrainArgs),
    #[cfg(feature = "hook")]
    #[command(hide = true)]
    Hook(HookArgs),
    #[cfg(feature = "hook")]
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
    #[cfg(feature = "linux-pytest")]
    /// Run the fixed no-command Linux namespace diagnostic.
    #[command(name = "__linux-pytest-namespace-probe-v1", hide = true)]
    LinuxPytestNamespaceProbeV1,
    #[cfg(feature = "linux-pytest")]
    /// Run the fixed no-command Linux ptrace transport diagnostic.
    #[command(name = "__linux-pytest-ptrace-transport-probe-v1", hide = true)]
    LinuxPytestPtraceTransportProbeV1,
    #[cfg(feature = "linux-pytest")]
    /// Run the fixed no-command Linux two-task supervisor diagnostic.
    #[command(name = "__linux-pytest-supervisor-tree-probe-v1", hide = true)]
    LinuxPytestSupervisorTreeProbeV1,
    #[cfg(feature = "linux-pytest")]
    /// Run the fixed no-command Linux filesystem-ready diagnostic.
    #[command(name = "__linux-pytest-filesystem-ready-probe-v1", hide = true)]
    LinuxPytestFilesystemReadyProbeV1,
}

#[derive(Debug, Args)]
struct McpArgs {
    #[command(subcommand)]
    command: McpCommand,
}

#[derive(Debug, Subcommand)]
enum McpCommand {
    /// Serve repository tools over bounded stdio JSON-RPC.
    Serve(McpServeArgs),
    /// Print an opt-in Codex or Claude MCP setup plan.
    Setup(McpSetupArgs),
    #[cfg(feature = "daemon")]
    /// Run, inspect, or stop the same-user local gateway daemon.
    Daemon(McpDaemonArgs),
    #[cfg(feature = "daemon")]
    /// Start or join the workspace daemon and proxy MCP over stdio.
    Connect(McpConnectArgs),
    #[cfg(feature = "daemon")]
    /// Print a verified task brief without claiming a coordination lease.
    Brief(McpBriefArgs),
}

#[derive(Debug, Args)]
struct McpServeArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Stable, non-secret local authorization-scope identifier.
    #[arg(long)]
    authorization_scope: Option<String>,
    /// Diagnostic: execute every eligible tool without reuse or candidate storage.
    #[arg(long, hide = true)]
    execute_only: bool,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct McpDaemonArgs {
    #[command(subcommand)]
    command: McpDaemonCommand,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Subcommand)]
enum McpDaemonCommand {
    /// Serve workspace-bound MCP connections until an authenticated stop.
    Serve(McpDaemonServeArgs),
    /// Query a live daemon without opening an MCP session.
    Status(McpDaemonWorkspaceArgs),
    /// Stop a live daemon and retire its active MCP sessions.
    Stop(McpDaemonWorkspaceArgs),
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct McpDaemonServeArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Stable, non-secret local authorization-scope identifier.
    #[arg(long)]
    authorization_scope: Option<String>,
    /// Diagnostic: execute eligible tools without reuse or candidate storage.
    #[arg(long, hide = true)]
    execute_only: bool,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct McpDaemonWorkspaceArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long)]
    workspace: Option<PathBuf>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct McpConnectArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long)]
    workspace: Option<PathBuf>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct McpBriefArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long)]
    workspace: Option<PathBuf>,
    /// Stable task ID shared by cooperating agents.
    #[arg(long)]
    task_id: String,
    /// Exact task text, without secrets.
    #[arg(long)]
    task: String,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct CodexArgs {
    #[command(flatten)]
    brief: McpBriefArgs,
    /// Wait this many seconds for an exact-task leader before launching a follower.
    #[arg(long, default_value_t = 30)]
    peer_wait_seconds: u64,
    /// Additional codex exec flags after `--`.
    #[arg(last = true, num_args = 0..)]
    codex_args: Vec<OsString>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct ClaudeArgs {
    #[command(flatten)]
    brief: McpBriefArgs,
    /// Wait this many seconds for an exact-task leader before launching a follower.
    #[arg(long, default_value_t = 30)]
    peer_wait_seconds: u64,
    /// Additional Claude Code print-mode flags after `--`.
    #[arg(last = true, num_args = 0..)]
    claude_args: Vec<OsString>,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Args)]
struct BrainArgs {
    #[command(subcommand)]
    command: BrainCommand,
}

#[cfg(feature = "daemon")]
#[derive(Debug, Subcommand)]
enum BrainCommand {
    /// Show bounded completed activity metadata from this repository.
    Show {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u8).range(1..=128))]
        limit: u8,
    },
    /// Clear retained activity metadata for this repository.
    Clear {
        #[arg(long)]
        workspace: Option<PathBuf>,
    },
    /// Ingest one completed Codex PostToolUse event from stdin.
    #[command(hide = true)]
    ObserveCodexHook,
    /// Configure repository-scoped observation of completed Codex Bash calls.
    HookSetup {
        #[arg(long)]
        workspace: Option<PathBuf>,
        #[arg(long, conflicts_with = "remove")]
        apply: bool,
        #[arg(long, conflicts_with = "apply")]
        remove: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum McpClientArg {
    Codex,
    Claude,
}

#[derive(Debug, Args)]
struct McpSetupArgs {
    #[arg(long, value_enum)]
    client: McpClientArg,
    /// Explicit canonical repository root to bind into the installed server command.
    #[arg(long)]
    workspace: PathBuf,
    /// Emit the machine-readable setup plan.
    #[arg(long)]
    json: bool,
    /// Apply the exact setup plan through the official client CLI.
    #[arg(long, conflicts_with_all = ["inspect", "remove"])]
    apply: bool,
    /// Inspect and verify the current client entry without changing it.
    #[arg(long, conflicts_with_all = ["apply", "remove"])]
    inspect: bool,
    /// Remove an exact Again-owned entry through the official client CLI.
    #[arg(long, conflicts_with_all = ["apply", "inspect"])]
    remove: bool,
    /// Install or inspect the personal Codex skill alongside the MCP entry.
    #[arg(long, conflicts_with = "remove")]
    with_skill: bool,
    /// Install or inspect the project Codex Brain observer alongside the MCP entry.
    #[arg(long, conflicts_with = "remove")]
    with_brain_hook: bool,
}

#[derive(Debug, Args)]
struct TaskArgs {
    /// Repository root; defaults to the repository containing the current directory.
    #[arg(long, global = true)]
    workspace: Option<PathBuf>,
    /// Stable, non-secret local authorization-scope identifier.
    #[arg(long, global = true)]
    authorization_scope: Option<String>,
    #[command(subcommand)]
    command: TaskCommand,
}

#[derive(Debug, Subcommand)]
enum TaskCommand {
    /// List durable tasks in this workspace and authorization scope.
    List(TaskListArgs),
    /// Inspect one task definition and lifecycle state.
    Inspect(TaskInspectArgs),
    /// Export one task and its transition history to a new private file.
    Export(TaskExportArgs),
    /// Permanently delete one terminal, unreferenced task.
    Delete(TaskDeleteArgs),
    /// Preview or explicitly apply bounded terminal-task pruning.
    Prune(TaskPruneArgs),
}

#[derive(Debug, Args)]
struct TaskListArgs {
    /// Maximum tasks to return.
    #[arg(long, default_value_t = crate::task_lifecycle::MAX_TASK_LIST_ITEMS_V1)]
    limit: usize,
}

#[derive(Debug, Args)]
struct TaskInspectArgs {
    id: String,
}

#[derive(Debug, Args)]
struct TaskExportArgs {
    id: String,
    /// Absolute output path. Existing paths are never replaced.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, Args)]
struct TaskDeleteArgs {
    id: String,
    /// Confirm permanent deletion.
    #[arg(long)]
    yes: bool,
}

#[derive(Debug, Args)]
struct TaskPruneArgs {
    /// Select terminal tasks last updated before this many days ago.
    #[arg(long)]
    terminal_before_days: u64,
    /// Preview candidates without deleting them.
    #[arg(long, conflicts_with = "apply")]
    dry_run: bool,
    /// Delete every eligible candidate, in bounded transactional batches.
    #[arg(long, conflicts_with = "dry_run")]
    apply: bool,
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

#[cfg(feature = "team-alpha")]
#[derive(Debug, Args)]
struct TeamArgs {
    #[command(subcommand)]
    command: TeamCommand,
}

#[cfg(feature = "team-alpha")]
#[derive(Debug, Subcommand)]
enum TeamCommand {
    /// Run one bare command through the sealed team-cache boundary.
    Run(TeamRunArgs),
    /// Inspect one sealed team request without network or command execution.
    Inspect(TeamInspectArgs),
}

#[cfg(feature = "team-alpha")]
#[derive(Debug, Args)]
struct TeamRunArgs {
    /// Absolute owner-private team profile path.
    #[arg(long)]
    profile: PathBuf,
    /// Bare command argv. The `--` delimiter is mandatory.
    #[arg(required = true, last = true, allow_hyphen_values = true)]
    command: Vec<OsString>,
}

#[cfg(feature = "team-alpha")]
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

#[cfg(feature = "hook")]
#[derive(Debug, Args)]
struct HookArgs {
    /// Controlled differential-testing escape hatch. This path is known not
    /// to model hidden Codex invocation inputs and must never be installed.
    #[arg(long, hide = true)]
    experimental_unsafe_rewrite: bool,
}

#[cfg(feature = "hook")]
#[derive(Debug, Args)]
struct ExecArgs {
    /// Opaque pending-call identifier issued by the hook adapter.
    #[arg(long)]
    call: String,
}

#[derive(Debug, Args)]
struct ExplainArgs {
    /// Stored result id. Omit it to explain the latest local event.
    id: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct ShowArgs {
    /// Stored result id to retrieve.
    id: String,
}

#[derive(Debug, Args)]
struct StatsArgs {
    /// Emit machine-readable JSON with local-engine and gateway counters.
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Args)]
struct DoctorArgs {
    /// Emit the complete diagnostic report as machine-readable JSON.
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
    coordinator: CoordinatorDoctorReport,
    pytest_profile: PytestProfileDoctorReport,
}

#[derive(Debug, Serialize)]
struct CoordinatorDoctorReport {
    status: &'static str,
    feature_enabled: bool,
    platform_supported: bool,
    transport: &'static str,
    same_user_authenticated: bool,
    ordinary_stdio_grants_recipient_authority: bool,
    public_tools: [&'static str; 9],
    blockers: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct PytestProfileDoctorReport {
    profile_id: &'static str,
    registry_status: &'static str,
    routing: &'static str,
    portable_control_plane_enabled: bool,
    native_linux_qualification_host: bool,
    execution_qualified: bool,
    promotion_issuer_available: bool,
    reuse_enabled: bool,
    blockers: Vec<&'static str>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct RootlessNamespaceProbeReport {
    schema: &'static str,
    profile_id: &'static str,
    scope: RootlessNamespaceProbeScope,
    status: &'static str,
    refusal: Option<FixedProbeRefusal>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct RootlessNamespaceProbeScope {
    kind: &'static str,
    profile_qualification: bool,
    accepts_command: bool,
    execution_authority: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedProbeRefusal {
    code: &'static str,
    stage: &'static str,
    reason: &'static str,
    errno: Option<i32>,
    cleanup_complete: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedPtraceTransportProbeReport {
    schema: &'static str,
    profile_id: &'static str,
    scope: FixedPtraceTransportProbeScope,
    status: &'static str,
    result: Option<FixedPtraceTransportProbeResult>,
    refusal: Option<FixedProbeRefusal>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedPtraceTransportProbeScope {
    kind: &'static str,
    profile_qualification: bool,
    accepts_command: bool,
    effect_ir_authority: bool,
    execution_authority: bool,
    reuse_authority: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedPtraceTransportProbeResult {
    logical_task_id: u32,
    task_count: u8,
    event_count: u8,
    seccomp_stop_count: u8,
    ptrace_exit_event_count: u8,
    terminal_reap_count: u8,
    unknown_event_count: u8,
    lost_event_count: u8,
    cleanup_complete: bool,
    protocol_fingerprint: String,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedSupervisorTreeProbeReport {
    schema: &'static str,
    profile_id: &'static str,
    scope: FixedSupervisorTreeProbeScope,
    status: &'static str,
    result: Option<FixedSupervisorTreeProbeResult>,
    refusal: Option<FixedSupervisorTreeProbeRefusal>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedSupervisorTreeProbeScope {
    kind: &'static str,
    profile_qualification: bool,
    accepts_command: bool,
    effect_ir_authority: bool,
    execution_authority: bool,
    reuse_authority: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedSupervisorTreeProbeResult {
    fork_delivery_order: &'static str,
    task_count: u16,
    accepted_transition_count: u64,
    fork_birth_count: u64,
    seccomp_entry_count: u64,
    syscall_exit_count: u64,
    no_return_resolution_count: u64,
    ptrace_exit_event_count: u64,
    terminal_reap_count: u64,
    cleanup_complete: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedSupervisorTreeProbeRefusal {
    code: &'static str,
    stage: &'static str,
    reason: &'static str,
    errno: Option<i32>,
    cleanup_complete: bool,
    cleanup_errno: Option<i32>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedFilesystemReadyProbeReport {
    schema: &'static str,
    profile_id: &'static str,
    scope: FixedFilesystemReadyProbeScope,
    status: &'static str,
    result: Option<FixedFilesystemReadyProbeResult>,
    refusal: Option<FixedProbeRefusal>,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedFilesystemReadyProbeScope {
    kind: &'static str,
    profile_qualification: bool,
    accepts_command: bool,
    filesystem_checkpoint_authority: bool,
    execution_authority: bool,
    candidate_authority: bool,
    replay_authority: bool,
    reuse_authority: bool,
}

#[cfg(feature = "linux-pytest")]
#[derive(Serialize)]
struct FixedFilesystemReadyProbeResult {
    successful_attachment_count: u8,
    injected_refusal_count: u8,
    terminal_reap_count: u8,
    cleanup_complete: bool,
}

pub fn run_cli() -> Result<i32> {
    let cli = Cli::parse_from(normalized_args());
    match cli.command {
        CommandName::BuildInfo => {
            print_pretty_json_v1(&serde_json::json!({
                "sourceSha": env!("AGAIN_BUILD_SOURCE_SHA"),
                "sourceCleanAtBuild": env!("AGAIN_BUILD_SOURCE_CLEAN") == "true",
            }))?;
            Ok(0)
        }
        CommandName::Setup(args) => setup(args),
        CommandName::Run(args) => direct_run(args.command),
        CommandName::Reference(args) => direct_reference(args.command),
        #[cfg(feature = "team-alpha")]
        CommandName::Team(args) => match args.command {
            TeamCommand::Run(args) => crate::team_cli::run(args.profile, args.command),
            TeamCommand::Inspect(args) => {
                crate::team_inspect::inspect(args.profile, args.command, args.json)
            }
        },
        CommandName::Mcp(args) => match args.command {
            McpCommand::Serve(args) => mcp_serve(args),
            McpCommand::Setup(args) => mcp_setup(args),
            #[cfg(feature = "daemon")]
            McpCommand::Daemon(args) => mcp_daemon(args),
            #[cfg(feature = "daemon")]
            McpCommand::Connect(args) => mcp_connect(args),
            #[cfg(feature = "daemon")]
            McpCommand::Brief(args) => mcp_brief(args),
        },
        #[cfg(feature = "daemon")]
        CommandName::Codex(args) => codex_launch(args),
        #[cfg(feature = "daemon")]
        CommandName::Claude(args) => claude_launch(args),
        CommandName::Task(args) => task_cli(args),
        #[cfg(feature = "daemon")]
        CommandName::Brain(args) => brain_cli(args),
        #[cfg(feature = "hook")]
        CommandName::Hook(args) => handle_hook(args.experimental_unsafe_rewrite),
        #[cfg(feature = "hook")]
        CommandName::Exec(args) => execute_pending_call(&args.call),
        CommandName::Explain(args) => explain(args),
        CommandName::Show(args) => show(&args.id),
        CommandName::Stats(args) => stats(args.json),
        CommandName::Doctor(args) => doctor(args.json),
        #[cfg(feature = "linux-pytest")]
        CommandName::LinuxPytestNamespaceProbeV1 => linux_pytest_namespace_probe_v1(),
        #[cfg(feature = "linux-pytest")]
        CommandName::LinuxPytestPtraceTransportProbeV1 => linux_pytest_ptrace_transport_probe_v1(),
        #[cfg(feature = "linux-pytest")]
        CommandName::LinuxPytestSupervisorTreeProbeV1 => linux_pytest_supervisor_tree_probe_v1(),
        #[cfg(feature = "linux-pytest")]
        CommandName::LinuxPytestFilesystemReadyProbeV1 => linux_pytest_filesystem_ready_probe_v1(),
    }
}

#[cfg(feature = "linux-pytest")]
fn linux_pytest_namespace_probe_v1() -> Result<i32> {
    use crate::linux_pytest::{LINUX_PYTEST_PROFILE_ID, RootlessNamespaceProbeDiagnosticV1};

    let scope = RootlessNamespaceProbeScope {
        kind: "fixed_no_command_namespace_bootstrap",
        profile_qualification: false,
        accepts_command: false,
        execution_authority: false,
    };
    let (report, exit_code) = match crate::linux_pytest::diagnose_rootless_namespace_tuple_v1() {
        RootlessNamespaceProbeDiagnosticV1::Completed => (
            RootlessNamespaceProbeReport {
                schema: "again.linux-pytest-namespace-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: "completed",
                refusal: None,
            },
            0,
        ),
        RootlessNamespaceProbeDiagnosticV1::Refused {
            code,
            stage,
            reason,
            errno,
            cleanup_complete,
            expected_unavailable,
        } => (
            RootlessNamespaceProbeReport {
                schema: "again.linux-pytest-namespace-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: if expected_unavailable {
                    "unavailable"
                } else {
                    "broken"
                },
                refusal: Some(FixedProbeRefusal {
                    code: code.as_str(),
                    stage,
                    reason,
                    errno,
                    cleanup_complete,
                }),
            },
            if expected_unavailable { 77 } else { 1 },
        ),
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)?;
    output.write_all(b"\n")?;
    Ok(exit_code)
}

#[cfg(feature = "linux-pytest")]
fn linux_pytest_filesystem_ready_probe_v1() -> Result<i32> {
    use crate::linux_pytest::{
        FixedFilesystemReadyProbeDiagnosticV1, LINUX_PYTEST_PROFILE_ID,
        diagnose_fixed_filesystem_ready_v1,
    };

    let scope = FixedFilesystemReadyProbeScope {
        kind: "fixed_no_command_filesystem_ready",
        profile_qualification: false,
        accepts_command: false,
        filesystem_checkpoint_authority: false,
        execution_authority: false,
        candidate_authority: false,
        replay_authority: false,
        reuse_authority: false,
    };
    let (report, exit_code) = match diagnose_fixed_filesystem_ready_v1() {
        FixedFilesystemReadyProbeDiagnosticV1::Completed {
            successful_attachment_count,
            injected_refusal_count,
            terminal_reap_count,
            cleanup_complete,
        } => (
            FixedFilesystemReadyProbeReport {
                schema: "again.linux-pytest-filesystem-ready-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: "completed",
                result: Some(FixedFilesystemReadyProbeResult {
                    successful_attachment_count,
                    injected_refusal_count,
                    terminal_reap_count,
                    cleanup_complete,
                }),
                refusal: None,
            },
            0,
        ),
        FixedFilesystemReadyProbeDiagnosticV1::Refused {
            code,
            stage,
            reason,
            errno,
            cleanup_complete,
            expected_unavailable,
        } => (
            FixedFilesystemReadyProbeReport {
                schema: "again.linux-pytest-filesystem-ready-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: if expected_unavailable {
                    "unavailable"
                } else {
                    "broken"
                },
                result: None,
                refusal: Some(FixedProbeRefusal {
                    code: code.as_str(),
                    stage,
                    reason,
                    errno,
                    cleanup_complete,
                }),
            },
            if expected_unavailable { 77 } else { 1 },
        ),
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)?;
    output.write_all(b"\n")?;
    Ok(exit_code)
}

#[cfg(feature = "linux-pytest")]
fn linux_pytest_ptrace_transport_probe_v1() -> Result<i32> {
    use crate::linux_pytest::{FixedPtraceTransportProbeDiagnosticV1, LINUX_PYTEST_PROFILE_ID};

    let scope = FixedPtraceTransportProbeScope {
        kind: "fixed_no_command_ptrace_transport",
        profile_qualification: false,
        accepts_command: false,
        effect_ir_authority: false,
        execution_authority: false,
        reuse_authority: false,
    };
    let (report, exit_code) = match crate::linux_pytest::diagnose_fixed_ptrace_transport_v1() {
        FixedPtraceTransportProbeDiagnosticV1::Completed {
            logical_task_id,
            event_count,
            seccomp_stop_count,
            ptrace_exit_event_count,
            terminal_reap_count,
            protocol_fingerprint,
        } => (
            FixedPtraceTransportProbeReport {
                schema: "again.linux-pytest-ptrace-transport-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: "completed",
                result: Some(FixedPtraceTransportProbeResult {
                    logical_task_id,
                    task_count: 1,
                    event_count,
                    seccomp_stop_count,
                    ptrace_exit_event_count,
                    terminal_reap_count,
                    unknown_event_count: 0,
                    lost_event_count: 0,
                    cleanup_complete: true,
                    protocol_fingerprint: format!("{protocol_fingerprint:016x}"),
                }),
                refusal: None,
            },
            0,
        ),
        FixedPtraceTransportProbeDiagnosticV1::Refused {
            code,
            stage,
            reason,
            errno,
            cleanup_complete,
            expected_unavailable,
        } => (
            FixedPtraceTransportProbeReport {
                schema: "again.linux-pytest-ptrace-transport-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: if expected_unavailable {
                    "unavailable"
                } else {
                    "broken"
                },
                result: None,
                refusal: Some(FixedProbeRefusal {
                    code: code.as_str(),
                    stage,
                    reason,
                    errno,
                    cleanup_complete,
                }),
            },
            if expected_unavailable { 77 } else { 1 },
        ),
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)?;
    output.write_all(b"\n")?;
    Ok(exit_code)
}

#[cfg(feature = "linux-pytest")]
fn linux_pytest_supervisor_tree_probe_v1() -> Result<i32> {
    use crate::linux_pytest::{FixedTwoTaskSupervisorProbeDiagnosticV1, LINUX_PYTEST_PROFILE_ID};

    let scope = FixedSupervisorTreeProbeScope {
        kind: "fixed_no_command_two_task_supervisor",
        profile_qualification: false,
        accepts_command: false,
        effect_ir_authority: false,
        execution_authority: false,
        reuse_authority: false,
    };
    let (report, exit_code) = match crate::linux_pytest::diagnose_fixed_two_task_supervisor_v1() {
        FixedTwoTaskSupervisorProbeDiagnosticV1::Completed {
            fork_delivery_order,
            task_count,
            accepted_transition_count,
            fork_birth_count,
            seccomp_entry_count,
            syscall_exit_count,
            no_return_resolution_count,
            ptrace_exit_event_count,
            terminal_reap_count,
        } => (
            FixedSupervisorTreeProbeReport {
                schema: "again.linux-pytest-supervisor-tree-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: "completed",
                result: Some(FixedSupervisorTreeProbeResult {
                    fork_delivery_order,
                    task_count,
                    accepted_transition_count,
                    fork_birth_count,
                    seccomp_entry_count,
                    syscall_exit_count,
                    no_return_resolution_count,
                    ptrace_exit_event_count,
                    terminal_reap_count,
                    cleanup_complete: true,
                }),
                refusal: None,
            },
            0,
        ),
        FixedTwoTaskSupervisorProbeDiagnosticV1::Refused {
            code,
            stage,
            reason,
            errno,
            cleanup_complete,
            cleanup_errno,
            expected_unavailable,
        } => (
            FixedSupervisorTreeProbeReport {
                schema: "again.linux-pytest-supervisor-tree-probe.v1",
                profile_id: LINUX_PYTEST_PROFILE_ID,
                scope,
                status: if expected_unavailable {
                    "unavailable"
                } else {
                    "broken"
                },
                result: None,
                refusal: Some(FixedSupervisorTreeProbeRefusal {
                    code: code.as_str(),
                    stage,
                    reason,
                    errno,
                    cleanup_complete,
                    cleanup_errno,
                }),
            },
            if expected_unavailable { 77 } else { 1 },
        ),
    };

    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer(&mut output, &report)?;
    output.write_all(b"\n")?;
    Ok(exit_code)
}

/// Let the README-friendly `again -- rg ...` spelling behave like `again run -- rg ...`.
fn normalized_args() -> Vec<OsString> {
    let mut arguments: Vec<OsString> = std::env::args_os().collect();
    if arguments.get(1).is_some_and(|argument| argument == "--") {
        arguments[1] = OsString::from("run");
    }
    arguments
}

fn mcp_serve(args: McpServeArgs) -> Result<i32> {
    let workspace = resolve_mcp_workspace(args.workspace)?;
    let authorization_scope =
        local_mcp_authorization_scope_v1(&workspace, args.authorization_scope)?;
    eprintln!(
        "Again MCP gateway is experimental; only bounded built-in repository reads are reuse-eligible."
    );
    let gateway = if args.execute_only {
        ExperimentalMcpGatewayV1::build_execute_only_v1(&workspace)?
    } else {
        ExperimentalMcpGatewayV1::build(&workspace)?
    };
    gateway.serve_stdio(&authorization_scope)?;
    Ok(0)
}

fn resolve_mcp_workspace(workspace: Option<PathBuf>) -> Result<PathBuf> {
    let cwd = std::env::current_dir()?;
    match workspace {
        Some(workspace) => fs::canonicalize(&workspace)
            .with_context(|| format!("resolve MCP workspace {}", workspace.display())),
        None => discover_workspace(&cwd),
    }
}

fn local_mcp_authorization_scope_v1(
    workspace: &Path,
    explicit: Option<String>,
) -> Result<crate::mcp_gateway::AuthorizationScopeId> {
    if let Some(scope) = explicit {
        return Ok(crate::mcp_gateway::AuthorizationScopeId::new(scope)?);
    }
    Ok(crate::mcp_gateway::AuthorizationScopeId::new(
        crate::brain::local_brain_scope_v1(workspace),
    )?)
}

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn mcp_daemon(args: McpDaemonArgs) -> Result<i32> {
    use crate::agent_gateway_service::{
        GatewayDaemonV1, daemon_status_v1, install_termination_handler_v1, stop_daemon_v1,
    };

    match args.command {
        McpDaemonCommand::Serve(args) => {
            close_inherited_daemon_fds_v1()?;
            let workspace = resolve_mcp_workspace(args.workspace)?;
            let authorization_scope =
                local_mcp_authorization_scope_v1(&workspace, args.authorization_scope)?;
            let daemon = if args.execute_only {
                GatewayDaemonV1::bind_execute_only_v1(&workspace, authorization_scope)?
            } else {
                GatewayDaemonV1::bind(&workspace, authorization_scope)?
            };
            install_termination_handler_v1()?;
            eprintln!(
                "Again MCP daemon is experimental; socket peers are restricted to the current uid."
            );
            daemon.serve()?;
            Ok(0)
        }
        McpDaemonCommand::Status(args) => {
            let workspace = resolve_mcp_workspace(args.workspace)?;
            println!("{}", serde_json::to_string(&daemon_status_v1(&workspace)?)?);
            Ok(0)
        }
        McpDaemonCommand::Stop(args) => {
            let workspace = resolve_mcp_workspace(args.workspace)?;
            stop_daemon_v1(&workspace)?;
            println!("{{\"schemaVersion\":1,\"status\":\"stopping\"}}");
            Ok(0)
        }
    }
}

#[cfg(all(feature = "daemon", target_os = "macos"))]
fn close_inherited_daemon_fds_v1() -> Result<()> {
    // Concurrent client launches can pass unrelated pipe descriptors to the
    // elected daemon. Keeping a writer open prevents a client's output() from
    // observing EOF after that client has exited.
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid writable rlimit value.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    for fd in 3..limit.rlim_cur.min(i32::MAX as u64) as i32 {
        // SAFETY: closing an inherited descriptor in this freshly exec'd
        // daemon is safe; EBADF means that descriptor was not open.
        unsafe { libc::close(fd) };
    }
    Ok(())
}

#[cfg(all(feature = "daemon", unix, not(target_os = "macos")))]
fn close_inherited_daemon_fds_v1() -> Result<()> {
    Ok(())
}

#[cfg(feature = "daemon")]
#[cfg(not(unix))]
fn mcp_daemon(_args: McpDaemonArgs) -> Result<i32> {
    Err(crate::agent_gateway_service::GatewayServiceError::UnsupportedPlatform.into())
}

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn mcp_connect(args: McpConnectArgs) -> Result<i32> {
    let workspace = resolve_mcp_workspace(args.workspace)?;
    let stream = connect_or_start_daemon_v1(&workspace)?;
    crate::agent_gateway_service::proxy_current_stdio_v1(stream)?;
    Ok(0)
}

#[cfg(all(feature = "daemon", unix))]
const MAX_TASK_BRIEF_FRAME_BYTES_V1: u64 = 1024 * 1024;

#[cfg(all(feature = "daemon", unix))]
fn daemon_request_v1(
    stream: &mut std::os::unix::net::UnixStream,
    reader: &mut BufReader<std::os::unix::net::UnixStream>,
    id: u64,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let request = serde_json::json!({
        "jsonrpc": "2.0", "id": id, "method": method, "params": params
    });
    serde_json::to_writer(&mut *stream, &request)?;
    stream.write_all(b"\n")?;
    stream.flush()?;
    let mut frame = Vec::new();
    reader
        .take(MAX_TASK_BRIEF_FRAME_BYTES_V1 + 1)
        .read_until(b'\n', &mut frame)?;
    if frame.is_empty()
        || frame.len() as u64 > MAX_TASK_BRIEF_FRAME_BYTES_V1
        || !frame.ends_with(b"\n")
    {
        bail!("authenticated task brief response was missing or too large");
    }
    let response: serde_json::Value =
        serde_json::from_slice(&frame).context("parse authenticated task brief response")?;
    if response["id"] != id {
        bail!("authenticated task brief response ID mismatch");
    }
    if !response["error"].is_null() {
        bail!(
            "authenticated task brief request failed: {}",
            response["error"]
        );
    }
    Ok(response["result"].clone())
}

#[cfg(all(feature = "daemon", unix))]
struct TaskBriefSessionV1 {
    workspace: PathBuf,
    brief: serde_json::Value,
    stream: std::os::unix::net::UnixStream,
    reader: BufReader<std::os::unix::net::UnixStream>,
    next_request_id: u64,
}

#[cfg(all(feature = "daemon", unix))]
impl TaskBriefSessionV1 {
    fn tool(&mut self, name: &str, arguments: serde_json::Value) -> Result<serde_json::Value> {
        let result = daemon_request_v1(
            &mut self.stream,
            &mut self.reader,
            self.next_request_id,
            "tools/call",
            serde_json::json!({ "name": name, "arguments": arguments }),
        )?;
        self.next_request_id = self
            .next_request_id
            .checked_add(1)
            .ok_or_else(|| anyhow!("task brief request ID overflow"))?;
        if result["isError"] == true {
            bail!(
                "authenticated {name} request was refused: {}",
                result["content"]
            );
        }
        let structured = result["structuredContent"]
            .as_object()
            .ok_or_else(|| anyhow!("authenticated {name} response lacked structured content"))?;
        Ok(serde_json::Value::Object(structured.clone()))
    }
}

#[cfg(all(feature = "daemon", unix))]
fn verified_task_brief_v1(
    args: &McpBriefArgs,
    claim_for_launch: bool,
) -> Result<TaskBriefSessionV1> {
    use crate::mcp_gateway::MCP_PROTOCOL_VERSION;

    let workspace = resolve_mcp_workspace(args.workspace.clone())?;
    let mut stream = connect_or_start_daemon_v1(&workspace)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let initialized = daemon_request_v1(
        &mut stream,
        &mut reader,
        1,
        "initialize",
        serde_json::json!({
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "again-prebrief", "version": env!("CARGO_PKG_VERSION") }
        }),
    )?;
    if initialized["protocolVersion"] != MCP_PROTOCOL_VERSION {
        bail!("authenticated task brief protocol mismatch");
    }
    let result = daemon_request_v1(
        &mut stream,
        &mut reader,
        2,
        "tools/call",
        serde_json::json!({
            "name": "task.start",
            "arguments": {
                "taskId": args.task_id,
                "task": args.task,
                "includeSourcePreviews": true,
                "previewOnly": !claim_for_launch
            }
        }),
    )?;
    if result["isError"] == true {
        bail!(
            "authenticated task brief was refused: {}",
            result["content"]
        );
    }
    let brief = result["structuredContent"]
        .as_object()
        .ok_or_else(|| anyhow!("authenticated task brief lacked structured content"))?;
    let coordination = brief
        .get("coordination")
        .and_then(|value| value.get("status"))
        .and_then(serde_json::Value::as_str);
    let expected_coordination = if claim_for_launch {
        matches!(
            coordination,
            Some("leader" | "join" | "waiting" | "terminal")
        )
    } else {
        coordination == Some("preview")
    };
    if brief.get("operation").and_then(serde_json::Value::as_str) != Some("task.start")
        || !expected_coordination
    {
        bail!("authenticated task brief had an unexpected operation or coordination status");
    }
    Ok(TaskBriefSessionV1 {
        workspace,
        brief: serde_json::Value::Object(brief.clone()),
        stream,
        reader,
        next_request_id: 3,
    })
}

#[cfg(all(feature = "daemon", unix))]
fn mcp_brief(args: McpBriefArgs) -> Result<i32> {
    let session = verified_task_brief_v1(&args, false)?;
    println!("{}", serde_json::to_string(&session.brief)?);
    Ok(0)
}

#[cfg(feature = "daemon")]
fn brain_cli(args: BrainArgs) -> Result<i32> {
    match args.command {
        BrainCommand::HookSetup {
            workspace,
            apply,
            remove,
        } => {
            let workspace = resolve_mcp_workspace(workspace)?;
            let executable = fs::canonicalize(std::env::current_exe()?)?;
            let change = crate::observer_setup::configure_codex_brain_hook_v1(
                &workspace,
                &executable,
                apply,
                remove,
            )?;
            println!("{}", serde_json::to_string_pretty(&change)?);
            return Ok(0);
        }
        BrainCommand::ObserveCodexHook => {
            let mut input = Vec::new();
            io::stdin().take(1024 * 1024 + 1).read_to_end(&mut input)?;
            if input.len() > 1024 * 1024 {
                return Ok(0);
            }
            let Ok(value) = serde_json::from_slice::<serde_json::Value>(&input) else {
                return Ok(0);
            };
            let Some(cwd) = value["cwd"].as_str() else {
                return Ok(0);
            };
            let Ok(cwd) = fs::canonicalize(cwd) else {
                return Ok(0);
            };
            let Ok(workspace) = discover_workspace(&cwd) else {
                return Ok(0);
            };
            if let Some(events) = crate::brain::codex_post_tool_event_v1(&value, &workspace) {
                if let Ok(store) = Store::open_for_workspace(&workspace) {
                    for event in events {
                        let _ = store.record_brain_event_v1(&event);
                    }
                }
            }
            return Ok(0);
        }
        BrainCommand::Show { workspace, limit } => {
            let workspace = resolve_mcp_workspace(workspace)?;
            let store = Store::open_for_workspace(&workspace)?;
            let events = store.recent_brain_events_v1(limit as usize)?;
            let files = store.recent_brain_files_v1(limit as usize)?;
            let runs = store.recent_brain_runs_v1(limit as usize)?;
            let test_hint = store.brain_test_hint_v1()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "recentEvents": events,
                    "recentRuns": runs,
                    "runAuthority": "client-observed activity and usage; task acceptance not verified",
                    "fileObservations": files,
                    "fileObservationsFreshness": "historical; not rechecked by this command",
                    "previousSuccessfulTestCommand": test_hint,
                    "testCommandAuthority": "unverified suggestion; run required validation"
                }))?
            );
        }
        BrainCommand::Clear { workspace } => {
            let workspace = resolve_mcp_workspace(workspace)?;
            let store = Store::open_for_workspace(&workspace)?;
            let removed = store.clear_brain_events_v1()?;
            println!(
                "Cleared {removed} Again Brain records for {}",
                workspace.display()
            );
        }
    }
    Ok(0)
}

#[cfg(all(feature = "daemon", unix))]
fn codex_launch(args: CodexArgs) -> Result<i32> {
    let mut session = verified_task_brief_v1(&args.brief, true)?;
    if args.peer_wait_seconds > 300 {
        bail!("--peer-wait-seconds must be between 0 and 300");
    }
    validate_agent_launch_task_v1(&session.brief)?;
    wait_for_peer_v1(
        &mut session,
        &args.brief,
        Duration::from_secs(args.peer_wait_seconds),
    )?;
    validate_agent_launch_task_v1(&session.brief)?;
    let mut prompt = agent_prebrief_prompt_v1(&args.brief.task, &session.brief)?;
    let workspace = &session.workspace;
    append_repository_brain_v1(&mut prompt, &session.brief);
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let bridge_args = [
        "mcp",
        "connect",
        "--workspace",
        workspace
            .to_str()
            .ok_or_else(|| anyhow!("workspace path is not UTF-8"))?,
    ];
    let raw_json = args.codex_args.iter().any(|arg| arg == "--json");
    let mut command = Command::new("codex");
    command.arg("exec");
    if !raw_json {
        command.arg("--json");
    }
    let mut child = command
        .args(&args.codex_args)
        .arg("-C")
        .arg(workspace)
        .arg("-c")
        .arg(format!(
            "mcp_servers.again.command={}",
            serde_json::to_string(&executable.to_string_lossy())?
        ))
        .arg("-c")
        .arg(format!(
            "mcp_servers.again.args={}",
            serde_json::to_string(&bridge_args)?
        ))
        .arg(prompt)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()
        .context("launch Codex with authenticated task brief")?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("Codex event stream was unavailable"))?;
    let brain_workspace = session.workspace.clone();
    let brain_task_id = session.brief["taskId"]
        .as_str()
        .ok_or_else(|| anyhow!("task brief omitted task ID"))?
        .to_owned();
    let brain_session_id = uuid::Uuid::new_v4().to_string();
    let brain_started_ms = crate::brain::current_ms_v1();
    let reader_workspace = brain_workspace.clone();
    let reader_task_id = brain_task_id.clone();
    let reader_session_id = brain_session_id.clone();
    let observation = Arc::new(Mutex::new(crate::brain::CodexRunObservationV1::default()));
    let reader_observation = Arc::clone(&observation);
    let capture_issue = Arc::new(Mutex::new(None));
    let reader_capture_issue = Arc::clone(&capture_issue);
    let event_reader = thread::spawn(move || -> Result<()> {
        let brain_store = match Store::open_for_workspace(&brain_workspace) {
            Ok(store) => Some(store),
            Err(error) => {
                remember_codex_capture_issue_v1(
                    &reader_capture_issue,
                    format!("could not open Brain for completed events: {error:#}"),
                );
                None
            }
        };
        let mut output = io::stdout().lock();
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            let parsed = serde_json::from_str::<serde_json::Value>(&line);
            if raw_json {
                writeln!(output, "{line}")?;
            } else if let Ok(ref value) = parsed {
                if let Some(display) = crate::brain::codex_display_text_v1(value) {
                    write!(output, "{display}")?;
                    if !display.ends_with('\n') {
                        writeln!(output)?;
                    }
                }
            } else {
                writeln!(output, "{line}")?;
            }
            output.flush()?;
            match parsed {
                Ok(value) => {
                    let events = crate::brain::codex_completed_events_v1(
                        &value,
                        &brain_workspace,
                        &brain_session_id,
                        &brain_task_id,
                    );
                    reader_observation
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .observe(&value, &events);
                    if let Some(store) = &brain_store {
                        for event in events {
                            if let Err(error) = store.record_brain_event_v1(&event) {
                                remember_codex_capture_issue_v1(
                                    &reader_capture_issue,
                                    format!("could not record a completed event: {error:#}"),
                                );
                            }
                        }
                    }
                }
                Err(error) if !line.trim().is_empty() => {
                    remember_codex_capture_issue_v1(
                        &reader_capture_issue,
                        format!("Codex emitted a non-JSON event line: {error}"),
                    );
                }
                Err(_) => {}
            }
        }
        Ok(())
    });
    run_agent_child_v1(
        session,
        child,
        "Codex",
        Some(CodexRunReaderV1 {
            handle: event_reader,
            observation,
            capture_issue,
            workspace: reader_workspace,
            task_id: reader_task_id,
            session_id: reader_session_id,
            started_ms: brain_started_ms,
        }),
    )
}

#[cfg(all(feature = "daemon", unix))]
fn claude_launch(args: ClaudeArgs) -> Result<i32> {
    let mut session = verified_task_brief_v1(&args.brief, true)?;
    if args.peer_wait_seconds > 300 {
        bail!("--peer-wait-seconds must be between 0 and 300");
    }
    validate_agent_launch_task_v1(&session.brief)?;
    wait_for_peer_v1(
        &mut session,
        &args.brief,
        Duration::from_secs(args.peer_wait_seconds),
    )?;
    validate_agent_launch_task_v1(&session.brief)?;
    let mut prompt = agent_prebrief_prompt_v1(&args.brief.task, &session.brief)?;
    let executable = fs::canonicalize(std::env::current_exe()?)?;
    let workspace = &session.workspace;
    append_repository_brain_v1(&mut prompt, &session.brief);
    let mcp_config = serde_json::json!({
        "mcpServers": {
            "again": {
                "command": executable,
                "args": ["mcp", "connect", "--workspace", workspace]
            }
        }
    });
    let child = Command::new("claude")
        .arg("-p")
        .args(&args.claude_args)
        .arg("--mcp-config")
        .arg(serde_json::to_string(&mcp_config)?)
        .arg(prompt)
        .current_dir(workspace)
        .stdin(Stdio::null())
        .spawn()
        .context("launch Claude Code with authenticated task brief")?;
    run_agent_child_v1(session, child, "Claude Code", None)
}

#[cfg(all(feature = "daemon", unix))]
struct CodexRunReaderV1 {
    handle: thread::JoinHandle<Result<()>>,
    observation: Arc<Mutex<crate::brain::CodexRunObservationV1>>,
    capture_issue: Arc<Mutex<Option<String>>>,
    workspace: PathBuf,
    task_id: String,
    session_id: String,
    started_ms: i64,
}

#[cfg(all(feature = "daemon", unix))]
fn remember_codex_capture_issue_v1(issue: &Arc<Mutex<Option<String>>>, message: String) {
    let mut current = issue.lock().unwrap_or_else(|poison| poison.into_inner());
    if current.is_none() {
        *current = Some(message);
    }
}

#[cfg(all(feature = "daemon", unix))]
fn run_agent_child_v1(
    mut session: TaskBriefSessionV1,
    mut child: std::process::Child,
    client_name: &str,
    event_reader: Option<CodexRunReaderV1>,
) -> Result<i32> {
    // The daemon closes an MCP connection after 60 seconds without a request.
    // Renew well before then so a long edit or test cannot lose its lease.
    const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(20);
    let lease_id = session.brief["coordination"]["leaseId"]
        .as_str()
        .filter(|_| session.brief["coordination"]["status"] == "leader")
        .map(str::to_owned);
    let mut next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
    let mut heartbeat_failure = None;
    loop {
        if let Some(status) = child.try_wait()? {
            if let Some(reader) = event_reader {
                let mut capture_issue = None;
                // A descendant may retain stdout after the direct child exits.
                // Do not hang the launcher indefinitely on that descriptor.
                let deadline = Instant::now() + Duration::from_secs(2);
                while !reader.handle.is_finished() && Instant::now() < deadline {
                    thread::sleep(Duration::from_millis(10));
                }
                if reader.handle.is_finished() {
                    match reader.handle.join() {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            capture_issue = Some(format!("event reader stopped early: {error:#}"));
                        }
                        Err(_) => capture_issue = Some("event reader panicked".to_owned()),
                    }
                } else {
                    eprintln!(
                        "Again Brain: event stream remained open after {client_name} exited; retaining observed events"
                    );
                }
                if capture_issue.is_none() {
                    capture_issue = reader
                        .capture_issue
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .clone();
                }
                let observation = reader
                    .observation
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .clone();
                let run = observation.into_run(
                    reader.session_id,
                    reader.task_id,
                    &reader.workspace,
                    reader.started_ms,
                    status.code().unwrap_or(1),
                );
                if status.success() && (!run.turn_completed || run.input_tokens.is_none()) {
                    capture_issue.get_or_insert_with(|| {
                        "Codex exited successfully without a completed turn and valid token usage"
                            .to_owned()
                    });
                }
                if let Err(error) = Store::open_for_workspace(&reader.workspace)
                    .and_then(|store| store.record_brain_run_v1(&run))
                {
                    capture_issue.get_or_insert_with(|| {
                        format!("could not record the completed run: {error:#}")
                    });
                }
                if let Some(issue) = capture_issue {
                    if status.success() {
                        bail!(
                            "{client_name} completed its task, but Again Brain capture is incomplete: {issue}"
                        );
                    }
                    eprintln!("Again Brain capture is incomplete: {issue}");
                }
            }
            if let Some(error) = heartbeat_failure {
                return Err(error);
            }
            return Ok(status.code().unwrap_or(1));
        }
        if Instant::now() >= next_heartbeat {
            if let Some(ref lease_id) = lease_id {
                let task_id = session.brief["taskId"].clone();
                let heartbeat = session.tool(
                    "context.publish",
                    serde_json::json!({
                        "taskId": task_id,
                        "kind": "work_heartbeat",
                        "leaseId": lease_id,
                        "ttlMs": 300_000
                    }),
                );
                let failure = match heartbeat {
                    Ok(response) if response["outcome"]["status"] == "renewed" => None,
                    Ok(response) => Some(anyhow!(
                        "lease renewal returned status {}",
                        response["outcome"]["status"]
                    )),
                    Err(error) => Some(error.context("lease renewal request failed")),
                };
                if let Some(error) = failure {
                    let _ = child.kill();
                    let _ = child.wait();
                    heartbeat_failure = Some(error.context(format!(
                        "task lease heartbeat failed; stopped {client_name} before uncoordinated work"
                    )));
                    continue;
                }
            }
            next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(all(feature = "daemon", unix))]
fn wait_for_peer_v1(
    session: &mut TaskBriefSessionV1,
    args: &McpBriefArgs,
    max_wait: Duration,
) -> Result<()> {
    if session.brief["coordination"]["status"] != "join" || max_wait.is_zero() {
        return Ok(());
    }
    eprintln!(
        "Again: another agent leads this exact task; waiting up to {} seconds before launching the coding agent.",
        max_wait.as_secs()
    );
    let task_id = session.brief["taskId"]
        .as_str()
        .ok_or_else(|| anyhow!("task brief omitted canonical task ID"))?
        .to_owned();
    let state_generation = session.brief["taskIntent"]["stateGeneration"]
        .as_u64()
        .ok_or_else(|| anyhow!("task brief omitted state generation"))?;
    let deadline = Instant::now() + max_wait;
    let mut poll_delay = Duration::from_millis(250);
    loop {
        let claim = session.tool(
            "task.claim",
            serde_json::json!({
                "taskId": task_id,
                "expectedStateGeneration": state_generation,
                "ttlMs": 300_000
            }),
        )?;
        match claim["outcome"]["status"].as_str() {
            Some("leader") => {
                let lease_id = claim["outcome"]["lease_id"]
                    .as_str()
                    .ok_or_else(|| anyhow!("task claim omitted leader lease ID"))?;
                let mut refreshed = session.tool(
                    "task.start",
                    serde_json::json!({
                        "taskId": args.task_id,
                        "task": args.task,
                        "includeSourcePreviews": true,
                        "previewOnly": true
                    }),
                )?;
                if refreshed["operation"] != "task.start"
                    || refreshed["coordination"]["status"] != "preview"
                {
                    bail!("refreshed task brief had an unexpected operation");
                }
                refreshed["coordination"] = serde_json::json!({
                    "status": "leader",
                    "leaseId": lease_id,
                    "stateGeneration": claim["outcome"]["state_generation"],
                    "expiresAtMs": claim["outcome"]["expires_at_ms"]
                });
                session.brief = refreshed;
                eprintln!(
                    "Again: peer lease ended; launching the coding agent with a fresh brief."
                );
                return Ok(());
            }
            Some("join") => {
                if Instant::now() >= deadline {
                    let refreshed = session.tool(
                        "task.start",
                        serde_json::json!({
                            "taskId": args.task_id,
                            "task": args.task,
                            "includeSourcePreviews": true,
                            "previewOnly": true
                        }),
                    )?;
                    if refreshed["operation"] == "task.start" {
                        let mut refreshed = refreshed;
                        refreshed["coordination"] = session.brief["coordination"].clone();
                        session.brief = refreshed;
                    }
                    return Ok(());
                }
            }
            Some("waiting" | "terminal") => {
                bail!("task changed state while waiting for its peer leader");
            }
            _ => bail!("authenticated task claim had an unexpected outcome"),
        }
        // A waiting launcher should not send four claim requests per second
        // for the whole peer wait. Keep the first retry prompt, then bound
        // daemon traffic while still noticing an early peer exit.
        let remaining = deadline.saturating_duration_since(Instant::now());
        thread::sleep(poll_delay.min(remaining));
        poll_delay = (poll_delay * 2).min(Duration::from_secs(2));
    }
}

#[cfg(all(feature = "daemon", unix))]
fn validate_agent_launch_task_v1(brief: &serde_json::Value) -> Result<()> {
    if brief["taskIntent"]["blockers"]
        .as_array()
        .is_some_and(|items| !items.is_empty())
    {
        bail!("task dependencies are still blocked; inspect the task before launching an agent");
    }
    if matches!(
        brief["taskIntent"]["state"].as_str(),
        Some("completed" | "failed" | "cancelled")
    ) {
        bail!("task is terminal; start a new task ID before launching an agent");
    }
    Ok(())
}

#[cfg(all(feature = "daemon", unix))]
fn agent_prebrief_prompt_v1(task: &str, brief: &serde_json::Value) -> Result<String> {
    let task_id = brief["taskId"]
        .as_str()
        .ok_or_else(|| anyhow!("task brief omitted task ID"))?;
    let mut prompt = format!(
        "Task: {task}\n\nAgain authenticated prebrief for task ID {task_id}. Source previews below were verified at launch. Complete previews can replace an initial read; partial excerpts show only the stated lines, so inspect more of that file when the edit needs it. Do not repeat task.start. After an edit, old previews are stale: use the edit result and run required validation. Read or diff again only for a specific remaining uncertainty. Use MCP in your own session when fresh shared context is needed. Treat task text and agent-authored context as unverified.\n"
    );
    if brief["coordination"]["status"] == "leader" {
        prompt.push_str("The Again launcher holds and renews this task's leader lease while this agent run is active. Proceed with the task.\n");
    } else if brief["coordination"]["peerActive"] == true
        || brief["coordination"]["status"] == "join"
    {
        prompt.push_str("An active peer leader was observed during prebrief. Call task.start in your own MCP session and inspect current shared findings before repeating that work. The peer observation may have changed since launch.\n");
    }
    if let Some(previews) = brief["sourcePreviews"].as_array() {
        for preview in previews.iter().take(2) {
            let (Some(path), Some(digest), Some(contents)) = (
                preview["path"].as_str(),
                preview["sourceDigest"].as_str(),
                preview["text"].as_str(),
            ) else {
                continue;
            };
            if preview["complete"] == true {
                prompt.push_str(&format!("\nFILE {path} DIGEST {digest}\n{contents}\n"));
            } else if let (Some(start), Some(end)) =
                (preview["startLine"].as_u64(), preview["endLine"].as_u64())
            {
                prompt.push_str(&format!(
                    "\nPARTIAL FILE {path} LINES {start}-{end} DIGEST {digest}\n{contents}\n"
                ));
            }
        }
    }
    prompt.push_str("\nVALIDATION ");
    prompt.push_str(&serde_json::to_string(&brief["validationPreview"])?);
    if brief["validationPreview"]["selectors"]
        .as_array()
        .is_some_and(|selectors| {
            selectors.iter().any(|selector| {
                selector["workingDirectory"]
                    .as_str()
                    .is_some_and(|directory| directory != ".")
            })
        })
    {
        prompt.push_str("\nRun each suggested validation command from its workingDirectory relative to the repository root. These are suggestions; execute required validation after editing.\n");
    }
    if brief["contextFreshness"]["status"] == "current" {
        let context = &brief["context"];
        let shared = serde_json::json!({
            "cursor": brief["cursor"],
            "currentFacts": context["current_facts"].as_array().map(|items| &items[..items.len().min(4)]).unwrap_or(&[]),
            "suggestions": context["suggestions"].as_array().map(|items| &items[..items.len().min(4)]).unwrap_or(&[]),
            "explicitUnknowns": context["explicit_unknowns"].as_array().map(|items| &items[..items.len().min(4)]).unwrap_or(&[]),
            "resultReferences": context["result_references"].as_array().map(|items| &items[..items.len().min(4)]).unwrap_or(&[]),
        });
        let serialized = serde_json::to_string(&shared)?;
        let has_shared_items = [
            "currentFacts",
            "suggestions",
            "explicitUnknowns",
            "resultReferences",
        ]
        .iter()
        .any(|key| {
            shared[*key]
                .as_array()
                .is_some_and(|items| !items.is_empty())
        });
        if has_shared_items && serialized.len() <= 4096 {
            prompt.push_str("\nSHARED_CONTEXT ");
            prompt.push_str(&serialized);
            prompt.push_str("\nShared facts were source checked at launch; recheck after relevant edits. Suggestions are unverified agent statements. Explicit unknowns still need investigation. Retrieve referenced results through MCP in your own session if needed.");
        } else if has_shared_items {
            prompt.push_str("\nSHARED_CONTEXT omitted due to size; call task.start in your own MCP session if needed.");
        }
    } else {
        prompt.push_str("\nSHARED_CONTEXT freshness incomplete; call task.start in your own MCP session before relying on earlier findings.");
    }
    Ok(prompt)
}

#[cfg(all(feature = "daemon", unix))]
fn append_repository_brain_v1(prompt: &mut String, brief: &serde_json::Value) {
    if let Some(brain) = brief.get("againBrain").filter(|brain| !brain.is_null()) {
        let mut metadata = brain.clone();
        let mut partial_previews = Vec::new();
        if let Some(files) = metadata["recentCurrentFiles"].as_array_mut() {
            for file in files {
                let preview = &file["currentPartialPreview"];
                if let (Some(path), Some(digest), Some(start), Some(end), Some(text)) = (
                    file["path"].as_str(),
                    file["currentDigest"].as_str(),
                    preview["startLine"].as_u64(),
                    preview["endLine"].as_u64(),
                    preview["text"].as_str(),
                ) {
                    partial_previews.push(format!(
                        "\nBRAIN_PARTIAL FILE {path} LINES {start}-{end} DIGEST {digest}\n{text}\n"
                    ));
                    file["currentPartialPreview"] = serde_json::Value::Null;
                }
            }
        }
        let Ok(serialized) = serde_json::to_string(&metadata) else {
            return;
        };
        if !partial_previews.is_empty() {
            prompt.push_str("\nThe Brain excerpts below were rechecked against current file bytes. Start at those locations. Read adjacent source when needed for the edit; repeat a locating search only if the excerpt does not identify the relevant code.\n");
        }
        prompt.push_str("\nAGAIN_BRAIN ");
        prompt.push_str(&serialized);
        for preview in partial_previews {
            prompt.push_str(&preview);
        }
        prompt.push_str("\nBrain previews were rechecked against current file bytes at launch. Use complete previews without rereading until an edit. A partial preview covers only its stated lines: if it fully shows the code needed for a local edit, edit directly; inspect omitted lines when they matter. Other history is guidance only. Run required validation.");
    }
}

#[cfg(all(feature = "daemon", not(unix)))]
fn mcp_brief(_args: McpBriefArgs) -> Result<i32> {
    Err(crate::agent_gateway_service::GatewayServiceError::UnsupportedPlatform.into())
}

#[cfg(all(feature = "daemon", not(unix)))]
fn codex_launch(_args: CodexArgs) -> Result<i32> {
    Err(crate::agent_gateway_service::GatewayServiceError::UnsupportedPlatform.into())
}

#[cfg(all(feature = "daemon", not(unix)))]
fn claude_launch(_args: ClaudeArgs) -> Result<i32> {
    Err(crate::agent_gateway_service::GatewayServiceError::UnsupportedPlatform.into())
}

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn connect_or_start_daemon_v1(workspace: &Path) -> Result<std::os::unix::net::UnixStream> {
    use crate::agent_gateway_service::{
        GatewayServiceError, connect_mcp_v1, try_acquire_daemon_start_lock_v1,
    };

    // A distinct, owner-private startup lock prevents a cold connector storm
    // from launching one losing daemon process per client. The elected
    // connector holds it until the daemon is ready; waiters use bounded
    // backoff and can take over automatically if that connector exits.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attempt = 0_u32;
    let mut last_error: GatewayServiceError;
    loop {
        match connect_mcp_v1(workspace) {
            Ok(stream) => return Ok(stream),
            Err(error) if daemon_start_is_safe_v1(&error) => last_error = error,
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            bail!("workspace daemon did not become ready within 5 seconds: {last_error}");
        }

        if let Some(_startup_lock) = try_acquire_daemon_start_lock_v1(workspace)? {
            // The daemon may have become ready between the failed connect and
            // acquisition. Never spawn without checking again under the lock.
            match connect_mcp_v1(workspace) {
                Ok(stream) => return Ok(stream),
                Err(error) if daemon_start_is_safe_v1(&error) => {}
                Err(error) => return Err(error.into()),
            }

            let executable = fs::canonicalize(std::env::current_exe()?)
                .context("resolve the exact Again executable for daemon startup")?;
            let mut daemon_command = Command::new(&executable);
            daemon_command
                .args([OsStr::new("mcp"), OsStr::new("daemon"), OsStr::new("serve")])
                .arg("--workspace")
                .arg(workspace)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            let mut child = daemon_command
                .spawn()
                .with_context(|| format!("start workspace daemon with {}", executable.display()))?;

            loop {
                match connect_mcp_v1(workspace) {
                    Ok(stream) => {
                        // Rust deliberately does not reap a dropped Child. The
                        // elected connector hands the daemon to a bounded
                        // reaper that waits for idle or authenticated shutdown.
                        let _ = thread::spawn(move || {
                            let _ = child.wait();
                        });
                        return Ok(stream);
                    }
                    Err(GatewayServiceError::Incompatible) => {
                        return Err(GatewayServiceError::Incompatible.into());
                    }
                    Err(error) => last_error = error,
                }
                if let Some(status) = child.try_wait()? {
                    bail!("workspace daemon exited before readiness with {status}: {last_error}");
                }
                if Instant::now() >= deadline {
                    child.kill()?;
                    let _ = child.wait();
                    bail!("workspace daemon did not become ready within 5 seconds: {last_error}");
                }
                thread::sleep(daemon_start_retry_delay_v1(attempt));
                attempt = attempt.saturating_add(1);
            }
        }

        thread::sleep(daemon_start_retry_delay_v1(attempt));
        attempt = attempt.saturating_add(1);
    }
}

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn daemon_start_retry_delay_v1(attempt: u32) -> Duration {
    let delay_ms = 10_u64.saturating_mul(1_u64 << attempt.min(4));
    Duration::from_millis(delay_ms.min(160))
}

#[cfg(feature = "daemon")]
#[cfg(unix)]
fn daemon_start_is_safe_v1(error: &crate::agent_gateway_service::GatewayServiceError) -> bool {
    use crate::agent_gateway_service::GatewayServiceError;
    match error {
        GatewayServiceError::InvalidHandshake => true,
        GatewayServiceError::Io(error) => matches!(
            error.kind(),
            io::ErrorKind::NotFound
                | io::ErrorKind::ConnectionRefused
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::BrokenPipe
                | io::ErrorKind::UnexpectedEof
        ),
        _ => false,
    }
}

#[cfg(feature = "daemon")]
#[cfg(not(unix))]
fn mcp_connect(_args: McpConnectArgs) -> Result<i32> {
    Err(crate::agent_gateway_service::GatewayServiceError::UnsupportedPlatform.into())
}

fn mcp_setup(args: McpSetupArgs) -> Result<i32> {
    if (args.apply || args.inspect) && !cfg!(all(feature = "daemon", unix)) {
        bail!("MCP client setup requires an Again binary built with --features daemon on Unix");
    }
    let client = match args.client {
        McpClientArg::Codex => AgentGatewayClientV1::Codex,
        McpClientArg::Claude => AgentGatewayClientV1::Claude,
    };
    let home = std::env::var_os("HOME")
        .filter(|home| !home.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| anyhow!("HOME is unavailable; setup cannot describe the client scope"))?;
    // This path is descriptive legacy plan metadata only. Setup never opens it;
    // every mutation and verification goes through the official client CLI.
    let config_path = match client {
        AgentGatewayClientV1::Codex => home.join(".codex").join("config.toml"),
        AgentGatewayClientV1::Claude => home.join(".claude.json"),
    };
    let plan = AgentGatewaySetupPlanV1::dry_run(client, &config_path, &args.workspace)?;
    if args.with_skill && client != AgentGatewayClientV1::Codex {
        bail!("--with-skill is currently supported only for Codex");
    }
    if args.with_skill && !args.apply && !args.inspect {
        bail!("--with-skill requires --apply or --inspect");
    }
    if args.with_brain_hook && client != AgentGatewayClientV1::Codex {
        bail!("--with-brain-hook is currently supported only for Codex");
    }
    if args.with_brain_hook && !args.apply && !args.inspect {
        bail!("--with-brain-hook requires --apply or --inspect");
    }
    let skill_dir = args
        .with_skill
        .then(|| codex_skill_dir(SetupScope::Global, None))
        .transpose()?;
    // Preflight ownership before the official client CLI can be changed.
    let skill_plan = skill_dir
        .as_deref()
        .map(|directory| install_codex_skill(directory, true))
        .transpose()?;
    let skill_was_absent = skill_dir
        .as_ref()
        .is_some_and(|directory| !directory.join("SKILL.md").exists());
    let hook_plan = if args.with_brain_hook {
        Some(crate::observer_setup::configure_codex_brain_hook_v1(
            &plan.workspace,
            &plan.stdio.command,
            false,
            false,
        )?)
    } else {
        None
    };
    let action = if args.apply {
        Some(ClientSetupActionV1::Apply)
    } else if args.inspect {
        Some(ClientSetupActionV1::Inspect)
    } else if args.remove {
        Some(ClientSetupActionV1::Remove)
    } else {
        None
    };
    if let Some(action) = action {
        let outcome = execute_client_setup_v1(&plan, action)?;
        let skill_outcome = if args.apply {
            if let Some(directory) = skill_dir.as_deref() {
                match install_codex_skill(directory, false) {
                    Ok(change) => Some(change),
                    Err(error) => {
                        if outcome.changed {
                            execute_client_setup_v1(&plan, ClientSetupActionV1::Remove).context(
                                "roll back newly added MCP entry after skill install failed",
                            )?;
                        }
                        return Err(error).context("install Codex skill after MCP setup");
                    }
                }
            } else {
                None
            }
        } else {
            skill_plan
        };
        let hook_outcome = if args.apply {
            if args.with_brain_hook {
                match crate::observer_setup::configure_codex_brain_hook_v1(
                    &plan.workspace,
                    &plan.stdio.command,
                    true,
                    false,
                ) {
                    Ok(change) => Some(change),
                    Err(error) => {
                        if skill_was_absent
                            && skill_outcome.as_ref().is_some_and(|skill| skill.changed)
                        {
                            if let Some(directory) = skill_dir.as_deref() {
                                remove_codex_skill(directory, false)
                                    .context("roll back newly installed Codex skill")?;
                            }
                        }
                        if outcome.changed {
                            execute_client_setup_v1(&plan, ClientSetupActionV1::Remove)
                                .context("roll back newly added MCP entry")?;
                        }
                        return Err(error).context("install Codex Brain observer after MCP setup");
                    }
                }
            } else {
                None
            }
        } else {
            hook_plan
        };
        if args.json {
            if skill_outcome.is_some() || hook_outcome.is_some() {
                let mut combined = serde_json::json!({"mcp": outcome});
                if let Some(skill) = skill_outcome {
                    combined["codexSkill"] = serde_json::json!({
                        "path": skill.path,
                        "current": args.apply || !skill.changed,
                        "changed": args.apply && skill.changed
                    });
                }
                if let Some(hook) = hook_outcome {
                    combined["codexBrainHook"] = serde_json::json!({
                        "path": hook.path,
                        "current": args.apply || (hook.installed && !hook.changed),
                        "changed": args.apply && hook.changed,
                        "trustStatus": "not_verified",
                        "activation": "review_and_trust_in_codex_hooks"
                    });
                }
                print_pretty_json_v1(&combined)?;
            } else {
                println!("{}", serde_json::to_string_pretty(&outcome)?);
            }
        } else {
            println!(
                "{} MCP setup: action={}, before={:?}, after={:?}, changed={}, verified={}",
                client.as_str(),
                outcome.action,
                outcome.before,
                outcome.after,
                outcome.changed,
                outcome.verified
            );
            if let Some(skill) = skill_outcome {
                println!(
                    "Codex skill: path={}, current={}, changed={}",
                    skill.path.display(),
                    args.apply || !skill.changed,
                    args.apply && skill.changed
                );
            }
            if let Some(hook) = hook_outcome {
                println!(
                    "Codex Brain hook: path={}, config_current={}, changed={}, trust=not_verified (review in Codex /hooks)",
                    hook.path.display(),
                    args.apply || (hook.installed && !hook.changed),
                    args.apply && hook.changed
                );
            }
        }
    } else if args.json {
        println!("{}", plan.machine_readable_json()?);
    } else {
        println!("{plan}");
        println!("# dry run; no configuration was changed");
    }
    Ok(0)
}

struct HumanTaskScopeV1 {
    store: Store,
    repository_id: String,
    workspace_id: String,
    authorization_scope_digest: String,
}

fn task_cli(args: TaskArgs) -> Result<i32> {
    let scope = open_human_task_scope_v1(args.workspace, args.authorization_scope)?;
    match args.command {
        TaskCommand::List(args) => {
            let tasks = scope.store.list_tasks_v1(
                &scope.repository_id,
                &scope.workspace_id,
                &scope.authorization_scope_digest,
                args.limit,
            )?;
            let quota = scope
                .store
                .task_quota_status_v1(&scope.repository_id, &scope.workspace_id)?;
            print_pretty_json_v1(&serde_json::json!({
                "schemaVersion": 1,
                "operation": "task.list",
                "tasks": tasks,
                "quota": quota
            }))?;
        }
        TaskCommand::Inspect(args) => {
            let task = scope
                .store
                .inspect_task_v1(
                    &scope.repository_id,
                    &scope.workspace_id,
                    &scope.authorization_scope_digest,
                    &args.id,
                )?
                .ok_or_else(|| anyhow!("task does not exist in this workspace scope"))?;
            print_pretty_json_v1(&serde_json::json!({
                "schemaVersion": 1,
                "operation": "task.inspect",
                "task": task
            }))?;
        }
        TaskCommand::Export(args) => {
            if !args.output.is_absolute() {
                bail!("task export output must be an absolute path");
            }
            let export = scope
                .store
                .export_task_v1(
                    &scope.repository_id,
                    &scope.workspace_id,
                    &scope.authorization_scope_digest,
                    &args.id,
                )?
                .ok_or_else(|| anyhow!("task does not exist in this workspace scope"))?;
            let mut bytes = serde_json::to_vec_pretty(&serde_json::json!({
                "schemaVersion": 1,
                "operation": "task.export",
                "export": export
            }))?;
            bytes.push(b'\n');
            write_private_task_export_v1(&args.output, &bytes)?;
            print_pretty_json_v1(&serde_json::json!({
                "schemaVersion": 1,
                "operation": "task.export",
                "status": "exported",
                "output": args.output
            }))?;
        }
        TaskCommand::Delete(args) => {
            if !args.yes {
                bail!("task delete requires --yes");
            }
            let deleted = scope.store.delete_task_v1(
                &scope.repository_id,
                &scope.workspace_id,
                &scope.authorization_scope_digest,
                &args.id,
            )?;
            if !deleted {
                bail!("task does not exist in this workspace scope");
            }
            print_pretty_json_v1(&serde_json::json!({
                "schemaVersion": 1,
                "operation": "task.delete",
                "taskId": args.id,
                "status": "deleted"
            }))?;
        }
        TaskCommand::Prune(args) => task_prune_v1(&scope, args)?,
    }
    Ok(0)
}

fn open_human_task_scope_v1(
    workspace: Option<PathBuf>,
    authorization_scope: Option<String>,
) -> Result<HumanTaskScopeV1> {
    let workspace = resolve_mcp_workspace(workspace)?;
    let authorization_scope = local_mcp_authorization_scope_v1(&workspace, authorization_scope)?;
    let authorization_scope_digest =
        crate::mcp_gateway::authorization_scope_digest_v1(&authorization_scope);
    let mut hasher = Hasher::new();
    hasher.update(b"again.local-context.workspace.v1\0");
    hasher.update(workspace.as_os_str().as_encoded_bytes());
    let digest = hasher.finalize().to_hex().to_string();
    Ok(HumanTaskScopeV1 {
        store: Store::open_for_workspace(&workspace)?,
        repository_id: format!("repository:{}", &digest[..24]),
        workspace_id: format!("workspace:{}", &digest[..24]),
        authorization_scope_digest,
    })
}

fn task_prune_v1(scope: &HumanTaskScopeV1, args: TaskPruneArgs) -> Result<()> {
    if args.dry_run == args.apply {
        bail!("task prune requires exactly one of --dry-run or --apply");
    }
    if args.terminal_before_days > 36_500 {
        bail!("terminal-before-days exceeds the bounded interval");
    }
    let age_ms = args
        .terminal_before_days
        .checked_mul(24 * 60 * 60 * 1_000)
        .ok_or_else(|| anyhow!("terminal-before-days overflow"))?;
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock precedes the Unix epoch")?
        .as_millis();
    let now_ms = i64::try_from(now_ms).context("system clock exceeds the supported range")?;
    let cutoff_ms = now_ms.saturating_sub(i64::try_from(age_ms)?);
    let batch_limit = crate::task_lifecycle::MAX_TASK_LIST_ITEMS_V1;

    if args.dry_run {
        let tasks = scope.store.list_deletable_terminal_tasks_before_v1(
            &scope.repository_id,
            &scope.workspace_id,
            &scope.authorization_scope_digest,
            cutoff_ms,
            batch_limit,
        )?;
        let task_ids = tasks
            .iter()
            .map(|task| task.canonical_task_id.as_str())
            .collect::<Vec<_>>();
        return print_pretty_json_v1(&serde_json::json!({
            "schemaVersion": 1,
            "operation": "task.prune",
            "mode": "dry_run",
            "terminalBeforeDays": args.terminal_before_days,
            "candidateTaskIds": task_ids,
            "candidateCount": task_ids.len(),
            "truncated": task_ids.len() == batch_limit
        }));
    }

    let mut deleted = Vec::new();
    loop {
        let tasks = scope.store.list_deletable_terminal_tasks_before_v1(
            &scope.repository_id,
            &scope.workspace_id,
            &scope.authorization_scope_digest,
            cutoff_ms,
            batch_limit,
        )?;
        if tasks.is_empty() {
            break;
        }
        let count = tasks.len();
        for task in tasks {
            let task_id = task.canonical_task_id;
            if scope.store.delete_task_v1(
                &scope.repository_id,
                &scope.workspace_id,
                &scope.authorization_scope_digest,
                &task_id,
            )? {
                deleted.push(task_id);
            }
        }
        if count < batch_limit {
            break;
        }
    }
    print_pretty_json_v1(&serde_json::json!({
        "schemaVersion": 1,
        "operation": "task.prune",
        "mode": "apply",
        "terminalBeforeDays": args.terminal_before_days,
        "deletedTaskIds": deleted,
        "deletedCount": deleted.len()
    }))
}

fn print_pretty_json_v1(value: &impl Serialize) -> Result<()> {
    let stdout = io::stdout();
    let mut output = stdout.lock();
    serde_json::to_writer_pretty(&mut output, value)?;
    output.write_all(b"\n")?;
    Ok(())
}

#[cfg(unix)]
fn write_private_task_export_v1(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("task export output has no parent directory"))?;
    let parent_metadata = fs::symlink_metadata(parent)
        .with_context(|| format!("inspect task export parent {}", parent.display()))?;
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        bail!("task export parent must be a real directory");
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| format!("create new private task export {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o777 != 0o600 {
        bail!("task export permissions are not private");
    }
    Ok(())
}

#[cfg(not(unix))]
fn write_private_task_export_v1(_path: &Path, _bytes: &[u8]) -> Result<()> {
    bail!("private task export is unsupported on this platform")
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
        if args.remove {
            println!(
                "# dry run: {} {}",
                if change.changed {
                    "would remove"
                } else {
                    "nothing to remove at"
                },
                change.path.display()
            );
        } else {
            println!("# dry run: would install {}", change.path.display());
            print!("{}", change.rendered);
        }
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

#[cfg(feature = "hook")]
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

#[cfg(feature = "hook")]
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
    } else if let Some(explanation) = store.latest_decision_explanation_v1()? {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&explanation)?);
        } else {
            println!("decision: {}", explanation.decision);
            println!("source: {}", explanation.source);
            println!("reason: {}", explanation.reason);
            println!("event: {}", explanation.raw_event);
            if let Some(result_id) = explanation.result_id {
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
        println!("gateway requests: {}", stats.requested);
        println!("gateway provider executions: {}", stats.executed);
        println!("gateway exact hits: {}", stats.exact_hits);
        println!("gateway coverage hits: {}", stats.coverage_hits);
        println!("gateway in-flight joins: {}", stats.inflight_joins);
        println!("gateway compact deliveries: {}", stats.compact_deliveries);
        println!("gateway facts reused: {}", stats.facts_reused);
        println!(
            "gateway investigations avoided: {}",
            stats.investigations_avoided
        );
        println!(
            "gateway provider calls avoided: {}",
            stats.provider_calls_avoided
        );
        println!(
            "gateway false-hit quarantines: {}",
            stats.false_hit_quarantines
        );
        println!(
            "estimated gateway execution time saved: {} ms",
            stats.estimated_execution_time_saved_ms
        );
        println!("context ledger events: {}", stats.context_events);
        println!("context canonical tasks: {}", stats.context_tasks);
        println!("context task aliases: {}", stats.context_task_aliases);
        println!(
            "context task aliases converged: {}",
            stats.context_task_aliases_converged
        );
        println!(
            "context verified facts admitted: {}",
            stats.verified_facts_admitted
        );
        println!(
            "context suggestions published: {}",
            stats.suggestions_published
        );
        println!(
            "context completed observations: {}",
            stats.completed_observations
        );
        println!("context explicit unknowns: {}", stats.explicit_unknowns);
        println!(
            "context result references admitted: {}",
            stats.result_references_admitted
        );
        println!(
            "context current verified facts: {}",
            stats.current_verified_facts
        );
        println!(
            "context current result references: {}",
            stats.current_result_references
        );
        println!("context active work leases: {}", stats.active_work_leases);
        println!("context invalidation events: {}", stats.invalidation_events);
        println!(
            "context delivery receipts: {}",
            stats.context_delivery_receipts
        );
        println!(
            "context acknowledged bytes omitted: {}",
            stats.context_delivery_confirmed_bytes_omitted
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
    let coordinator_feature_enabled = cfg!(feature = "daemon");
    let coordinator_platform_supported = cfg!(unix);
    let mut coordinator_blockers = Vec::new();
    if !coordinator_feature_enabled {
        coordinator_blockers.push("daemon_feature_disabled");
    }
    if !coordinator_platform_supported {
        coordinator_blockers.push("same_user_unix_transport_unavailable");
    }
    let coordinator_status = if coordinator_blockers.is_empty() {
        "ready"
    } else {
        "unavailable"
    };
    let native_linux_qualification_host = cfg!(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ));
    let mut pytest_blockers = Vec::new();
    if !cfg!(feature = "linux-pytest") {
        pytest_blockers.push("linux_pytest_feature_disabled");
    }
    if !native_linux_qualification_host {
        pytest_blockers.push("native_x86_64_linux_qualification_required");
    }
    pytest_blockers.push("same_child_filter_and_tree_supervision_qualification_required");
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
        coordinator: CoordinatorDoctorReport {
            status: coordinator_status,
            feature_enabled: coordinator_feature_enabled,
            platform_supported: coordinator_platform_supported,
            transport: "same_user_os_authenticated_unix",
            same_user_authenticated: coordinator_platform_supported,
            ordinary_stdio_grants_recipient_authority: false,
            public_tools: [
                "task.start",
                "task.inspect",
                "task.list",
                "task.claim",
                "task.transition",
                "context.delta",
                "context.publish",
                "context.retrieve",
                "context.cancel",
            ],
            blockers: coordinator_blockers,
        },
        pytest_profile: PytestProfileDoctorReport {
            profile_id: "linux-pytest-v1",
            registry_status: "contract_only",
            routing: "passthrough_without_storage",
            portable_control_plane_enabled: cfg!(feature = "linux-pytest"),
            native_linux_qualification_host,
            execution_qualified: false,
            promotion_issuer_available: false,
            reuse_enabled: false,
            blockers: pytest_blockers,
        },
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Again {}", report.version);
        println!("executable: {}", report.executable);
        println!("state: {}", report.state_dir);
        println!("state writable: {}", report.state_writable);
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
        println!("local coordinator: {}", report.coordinator.status);
        println!(
            "coordinator transport: {} (same-user authenticated: {})",
            report.coordinator.transport, report.coordinator.same_user_authenticated
        );
        println!(
            "ordinary stdio recipient authority: {}",
            report.coordinator.ordinary_stdio_grants_recipient_authority
        );
        if !report.coordinator.blockers.is_empty() {
            println!(
                "coordinator blockers: {}",
                report.coordinator.blockers.join(", ")
            );
        }
        println!(
            "pytest profile: {} ({}, {})",
            report.pytest_profile.profile_id,
            report.pytest_profile.registry_status,
            report.pytest_profile.routing
        );
        println!(
            "pytest reuse enabled: {}",
            report.pytest_profile.reuse_enabled
        );
        println!(
            "pytest blockers: {}",
            report.pytest_profile.blockers.join(", ")
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

    #[cfg(all(feature = "daemon", unix))]
    #[test]
    fn brain_partial_preview_is_readable_without_duplicating_escaped_source() {
        let brief = serde_json::json!({
            "againBrain": {
                "recentCurrentFiles": [{
                    "path": "src/util.py",
                    "currentDigest": "current-digest",
                    "currentCompletePreview": null,
                    "currentPartialPreview": {
                        "text": "def adjust_total(value):\n    return value + 1\n",
                        "startLine": 1,
                        "endLine": 2,
                        "complete": false
                    }
                }],
                "previousSuccessfulTestCommand": null
            }
        });
        let mut prompt = String::new();
        append_repository_brain_v1(&mut prompt, &brief);
        let metadata = prompt
            .split_once("AGAIN_BRAIN ")
            .unwrap()
            .1
            .split_once('\n')
            .unwrap()
            .0;
        let metadata: serde_json::Value = serde_json::from_str(metadata).unwrap();
        assert_eq!(metadata["recentCurrentFiles"][0]["path"], "src/util.py");
        assert!(metadata["recentCurrentFiles"][0]["currentPartialPreview"].is_null());
        assert!(prompt.contains("BRAIN_PARTIAL FILE src/util.py LINES 1-2 DIGEST current-digest\ndef adjust_total(value):\n    return value + 1\n"));
        assert!(prompt.contains("Start at those locations"));
        assert!(!prompt.contains("def adjust_total(value):\\n"));
    }

    #[cfg(all(feature = "daemon", unix))]
    #[test]
    fn codex_prebrief_carries_bounded_current_shared_context() {
        let brief = serde_json::json!({
            "taskId": "repair",
            "sourcePreviews": [{"path":"a.py", "sourceDigest":"abc", "text":"value=1\n", "complete":true}],
            "validationPreview": {"status":"execute_required"},
            "cursor": 7,
            "contextFreshness": {"status":"current"},
            "context": {
                "current_facts": [{"topic":"a.py", "statement":"value is one"}],
                "explicit_unknowns": [{"subject":"test", "explanation":"check edge cases"}],
                "result_references": []
            }
        });
        let prompt = agent_prebrief_prompt_v1("repair a.py", &brief).unwrap();
        assert!(prompt.contains("Do not repeat task.start"));
        assert!(prompt.contains("FILE a.py DIGEST abc"));
        assert!(prompt.contains("value is one"));
        assert!(prompt.contains("check edge cases"));
        let mut excerpt = brief.clone();
        excerpt["sourcePreviews"] = serde_json::json!([{
            "path":"large.rs", "sourceDigest":"current", "text":"fn target() {}\n",
            "complete":false, "startLine":80, "endLine":80
        }]);
        let excerpt_prompt = agent_prebrief_prompt_v1("repair large.rs", &excerpt).unwrap();
        assert!(excerpt_prompt.contains("PARTIAL FILE large.rs LINES 80-80 DIGEST current"));
        assert!(excerpt_prompt.contains("inspect more of that file"));
        let mut nested = brief.clone();
        nested["validationPreview"]["selectors"] = serde_json::json!([{
            "command": "npm test", "workingDirectory": "packages/alpha", "verified": false
        }]);
        let nested_prompt = agent_prebrief_prompt_v1("repair a.py", &nested).unwrap();
        assert!(
            nested_prompt
                .contains("Run each suggested validation command from its workingDirectory")
        );
        let mut leader = brief.clone();
        leader["coordination"]["status"] = serde_json::json!("leader");
        let leader_prompt = agent_prebrief_prompt_v1("repair a.py", &leader).unwrap();
        assert!(leader_prompt.contains("while this agent run is active"));
        assert!(!leader_prompt.contains("Codex run"));
        let mut stale = brief;
        stale["coordination"]["peerActive"] = serde_json::json!(true);
        let peer_prompt = agent_prebrief_prompt_v1("repair a.py", &stale).unwrap();
        assert!(peer_prompt.contains("active peer leader"));
        stale["contextFreshness"]["status"] = serde_json::json!("incomplete");
        let prompt = agent_prebrief_prompt_v1("repair a.py", &stale).unwrap();
        assert!(!prompt.contains("value is one"));
        assert!(prompt.contains("freshness incomplete"));
    }

    #[cfg(all(feature = "daemon", unix))]
    #[test]
    fn codex_launch_refuses_blocked_and_terminal_tasks() {
        let ready = serde_json::json!({
            "taskIntent": {"state": "waiting", "blockers": []}
        });
        assert!(validate_agent_launch_task_v1(&ready).is_ok());
        let blocked = serde_json::json!({
            "taskIntent": {"state": "waiting", "blockers": ["prerequisite"]}
        });
        assert!(validate_agent_launch_task_v1(&blocked).is_err());
        let terminal = serde_json::json!({
            "taskIntent": {"state": "completed", "blockers": []}
        });
        assert!(validate_agent_launch_task_v1(&terminal).is_err());
    }

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

    #[cfg(feature = "team-alpha")]
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
