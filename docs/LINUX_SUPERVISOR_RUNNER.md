# Disposable hosted Linux supervisor qualification

The manual
[`linux-supervisor-qualification`](../.github/workflows/linux-supervisor-qualification.yml)
workflow is limited to the pinned Gate 2 kernel-evidence lane. A qualifying run
executes one bounded cohort of 100 independent copies of the fixed,
argument-free, non-authoritative diagnostic and requires both observed
fork-delivery orders. Cohort contention gives the kernel both real scheduling
paths without choosing a wait target or synthesizing an event. The diagnostic
does not accept a workload or grant Python, EffectIR, execution-profile,
execution, or reuse authority.

## Required runner contract

The manual workflow is pinned to GitHub's disposable `ubuntu-22.04` x86_64
VM. Its running kernel must expose
`CONFIG_SECCOMP_FILTER=y` and `CONFIG_CHECKPOINT_RESTORE=y` through
`/proc/config.gz` or `/boot/config-$(uname -r)`. The job process must have
effective `CAP_SYS_ADMIN` in the user namespace governing the diagnostic
tracees, which is required for `PTRACE_SECCOMP_GET_FILTER`.

The hosted job starts unprivileged. It uses `sudo` only for the read-only
preflight and the fixed, argument-free diagnostic. Compilation, checkout, and
all source validation stay unprivileged. The preflight only reads kernel
identity, kernel configuration, and `/proc/self/status`; it does not change
capabilities, namespaces, sysctls, mounts, or host configuration.

## Security boundary

- Use only the disposable hosted VM. Never move this lane to a persistent or
  automatically restarted runner while it uses elevated capability.
- Dispatch only a reviewed immutable commit. Checkout and the pinned Rust build
  run before elevation. The privileged diagnostic accepts no arguments or
  workload; the preflight does not make untrusted code safe.
- Provide no cloud credentials, repository write token, SSH key, package-publish
  secret, or unrelated service secret. The workflow itself has only
  `contents: read`, disables persisted checkout credentials, and remains manual.
- GitHub destroys the hosted VM after the job. Do not add persistent caches,
  service containers, deployment credentials, or later privileged steps.

These controls limit the blast radius of the required namespace capability.
They do not turn the diagnostic into an isolation or execution authority and do
not make the runner safe against its host administrator.

## Run once

Review an immutable commit, manually dispatch
`linux-supervisor-qualification` at that ref, and retain the completed run and
artifact identifiers. A failed preflight is a host-image non-pass, never
qualification. No runner registration, Rosetta installation, developer-host
mutation, or cleanup credential is required.

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
