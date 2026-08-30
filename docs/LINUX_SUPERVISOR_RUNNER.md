# Disposable hosted Linux supervisor qualification

The manual
[`linux-supervisor-qualification`](../.github/workflows/linux-supervisor-qualification.yml)
workflow is limited to the pinned Gate 2 kernel-evidence lane. A qualifying run
executes 100 independent, sequential copies of the fixed, argument-free,
non-authoritative diagnostic and requires both observed fork-delivery orders.
The kernel chooses every live delivery order; the lane does not select a wait
target, alter scheduling policy, or synthesize an event. The diagnostic does
not accept a workload or grant Python, EffectIR, execution-profile, execution,
or reuse authority.

## Required runner contract

The manual workflow uses GitHub's disposable `ubuntu-22.04` x86_64 VM only as
an outer KVM host. It requires hardware virtualization and launches a native
x86_64 Ubuntu VM from the exact image fingerprint checked into the workflow.
The guest identity is sealed to KVM and kernel `6.8.0-138-generic`; neither
Rosetta nor CPU emulation is involved. Its running kernel must expose
`CONFIG_SECCOMP_FILTER=y` and `CONFIG_CHECKPOINT_RESTORE=y` through
`/proc/config.gz` or `/boot/config-$(uname -r)`. The job process must have
effective `CAP_SYS_ADMIN` in the user namespace governing the diagnostic
tracees, which is required for `PTRACE_SECCOMP_GET_FILTER`.

Checkout, compilation, and all source validation stay unprivileged on the
outer host. Host elevation is limited to provisioning, inspecting, copying
into, and destroying the disposable KVM guest. The workflow verifies the
copied diagnostic byte-for-byte before running the read-only preflight and
fixed diagnostic as root inside the guest. The preflight only reads kernel
identity, kernel configuration, and `/proc/self/status`; it does not change
capabilities, namespaces, sysctls, mounts, or host configuration.

## Security boundary

- Use only the disposable hosted VM and its disposable sealed KVM guest. Never
  move this lane to a persistent or automatically restarted runner while it
  uses elevated capability.
- Dispatch only a reviewed immutable commit. Checkout and the pinned Rust build
  run before elevation. The privileged diagnostic accepts no arguments or
  workload; the preflight does not make untrusted code safe.
- Provide no cloud credentials, repository write token, SSH key, package-publish
  secret, or unrelated service secret. The workflow itself has only
  `contents: read`, disables persisted checkout credentials, and remains manual.
- The workflow destroys the nested guest even after qualification failure, and
  GitHub destroys the outer hosted VM after the job. Do not add persistent
  caches, service containers, deployment credentials, or later privileged
  steps.

These controls limit the blast radius of the required namespace capability.
They do not turn the diagnostic into an isolation or execution authority and do
not make the runner safe against its host administrator.

## Run once

Review an immutable commit, manually dispatch
`linux-supervisor-qualification` at that ref, and retain the completed run and
artifact identifiers. A failed preflight is a host-image non-pass, never
qualification. A VM-image, kernel, architecture, or KVM identity mismatch also
fails closed. No runner registration, Rosetta installation, developer-host
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
