# Ephemeral Linux supervisor qualification runner

The manual
[`linux-supervisor-qualification`](../.github/workflows/linux-supervisor-qualification.yml)
workflow is limited to the pinned Gate 2 kernel-evidence lane. A qualifying run
executes a fixed, argument-free, non-authoritative diagnostic 100 times and
requires both observed fork-delivery orders. It does not accept a workload or
grant Python, EffectIR, execution-profile, execution, or reuse authority.

## Required runner contract

Register one fresh, repository-scoped GitHub Actions runner with all four
labels used by the workflow:

```text
self-hosted, linux, x64, again-linux-pytest-v1
```

The job process must run on Linux x86_64. Its running kernel must expose
`CONFIG_SECCOMP_FILTER=y` and `CONFIG_CHECKPOINT_RESTORE=y` through
`/proc/config.gz` or `/boot/config-$(uname -r)`. The job process must have
effective `CAP_SYS_ADMIN` in the user namespace governing the diagnostic
tracees, which is required for `PTRACE_SECCOMP_GET_FILTER`.

Run `scripts/preflight_linux_supervisor_runner.sh` from an ordinary shell in
the intended runner environment before registration. The preflight only reads
kernel identity, kernel configuration, and `/proc/self/status`; it does not
change capabilities, namespaces, sysctls, mounts, or host configuration.

## Security boundary

- Use a dedicated, disposable VM or equivalently disposable host and a fresh
  runner directory. Do not attach a persistent developer workstation.
- Prefer a dedicated user namespace that maps a non-root host UID to namespace
  root. Never grant host-user-namespace `CAP_SYS_ADMIN` to a reusable runner.
- Register the runner to this repository, not an organization or enterprise.
  Do not share it with other repositories or let an earlier job use it.
- Dispatch only a reviewed immutable commit. Checkout and the pinned Rust build
  execute repository code and dependencies with the runner's namespace
  capability; the preflight does not make untrusted code safe.
- Provide no cloud credentials, repository write token, SSH key, package-publish
  secret, or unrelated service secret. The workflow itself has only
  `contents: read`, disables persisted checkout credentials, and remains manual.
- Treat the VM, runner work directory, compiler caches, logs, and all local
  state as contaminated after the job. Destroy them instead of reusing them.

These controls limit the blast radius of the required namespace capability.
They do not turn the diagnostic into an isolation or execution authority and do
not make the runner safe against its host administrator.

## Register, run once, and remove

1. Create the disposable Linux x86_64 environment and verify the contract with
   the preflight script.
2. In the repository's **Settings → Actions → Runners**, choose **New
   self-hosted runner** and follow GitHub's generated Linux download and
   checksum instructions inside the fresh runner directory.
3. Use the generated, short-lived repository registration token once. Append
   `--ephemeral --labels again-linux-pytest-v1` to the generated `config.sh`
   registration command. Do not put the token in a repository file, image,
   script, persistent environment, CI log, or shell-history file.
4. Verify that GitHub shows the default `self-hosted`, `linux`, and `x64` labels
   plus `again-linux-pytest-v1`. Start `run.sh` in the foreground, then manually
   dispatch `linux-supervisor-qualification` at the reviewed commit SHA.
5. An ephemeral runner accepts at most one job and normally deregisters after
   it finishes. Verify its repository runner entry is gone. If registration
   must be canceled before a job, obtain a fresh removal token from repository
   settings and use the runner's `config.sh remove` flow; do not preserve that
   token. Delete any stale offline entry in settings, then destroy the entire
   disposable environment.

Never install this lane as an automatically restarted service. A canceled,
timed-out, or failed job still requires runner removal and host destruction.

## Expected retained evidence

A successful run uploads the 30-day artifact
`linux-supervisor-<run-id>-<run-attempt>-<source-sha>`. Its
`linux-supervisor-qualification/` directory contains 100 numbered raw-sample
directories, `validated.jsonl`, and `report.json`. The report must bind the
exact 40-character source commit, record `validated_sample_count: 100`, and
contain both `child_stop_first` and `parent_event_first`. Every scope authority
field remains false.

The artifact is qualification evidence only after an independent reviewer
checks the workflow `headSha`, nonempty successful steps, artifact identity and
retention, exact report schema, all 100 raw results, empty sample stderr, and
both delivery orders. Merely registering a runner, passing the host preflight,
or uploading a partial artifact does not close Gate 2.
