# Linux pytest trace profile v1

## Status and exact slice

This document is an implementation contract, not a statement that the profile
exists or has passed its gates. The profile identifier is
`linux-pytest-v1`. It is the next local product slice after the current
read-only profile and has exactly one public invocation shape:

```text
again run -- .venv/bin/python -I -m pytest <selector> [<selector> ...]
```

It is not a generic Linux command runner. Admission requires all of the
following before any Python process starts:

- the current directory is the canonical workspace root;
- `argv[0]` is the exact spelling `.venv/bin/python`, and its complete symlink
  chain resolves to the snapshotted virtual environment and audited Python
  runtime;
- `argv[1..4]` is exactly `-I -m pytest`;
- there is at least one selector and no option, option value, response file,
  shell operator, or extra Python argument;
- each selector is UTF-8 and has the form
  `<workspace-relative-path>[::<node>[::<node>...]]`; the path portion is
  nonempty, does not start with `-`, contains no empty or `.` component and no
  `..` component, and resolves beneath the immutable workspace
  snapshot to a regular file or directory; and
- stdin is closed or an empty non-TTY stream, and stdout and stderr are
  non-TTY streams.

Node suffixes are passed to pytest byte-for-byte. They do not widen the path
portion. Pytest configuration, conftest files, installed plugins, imported
modules, and descendant processes are allowed only because they execute under
the same bounded profile and enter the recorded runtime closure. They do not
make another top-level argv shape eligible. A selector beginning with `-`, a
bare `--`, `-k`, `-q`, another interpreter path, `python -c`, `python script`,
or `python -m` for any module other than pytest is refused without execution.

The first implementation targets rootless, glibc-based Linux on `x86_64`,
with `openat2(2)`, `close_range(2)`, seccomp filter mode, ptrace fork/clone
events, all six required namespace types, tmpfs, and Landlock ABI 3 or newer.
An exact kernel/configuration/runtime tuple is enabled only after that tuple
passes this document's gates. A missing or administratively disabled user
namespace, unsupported filesystem operation, untested architecture, old
Landlock ABI, or failed isolation probe is a typed refusal before Python
executes, never a best-effort unsandboxed fallback.

## Product promise

For an admitted invocation, Again runs pytest in a disposable rootless Linux
environment with no host network and no writable view of the host workspace.
The foreground run returns that run's exact stdout bytes, exact stderr bytes,
and wait status. Files created or changed by pytest exist only in its private
branch and are discarded. After two independently isolated executions from
the same immutable inputs agree and all completeness requirements pass, a
later identical invocation may return the promoted result without rerunning
the selected tests.

The reusable semantic unit is the whole admitted pytest invocation. V1 does
not select, skip, or cache individual tests. A hit is permitted only after
current workspace dependencies, negative and directory dependencies,
environment, interpreter, pytest/plugins, native libraries, kernel profile,
and policy all match the promoted record. Cache replay preserves each stream
individually; it does not claim to reproduce the timing or interleaving
between writes to stdout and stderr.

There are three outcomes:

1. **Refused:** admission or the mandatory isolation preflight fails. Python
   is not executed.
2. **Executed only:** the invocation safely finishes in the sandbox and its
   exact result is returned, but an unsupported effect, incomplete trace,
   nondeterministic interface, limit, or policy violation prevents both a
   shadow and reuse.
3. **Candidate/promoted:** a complete foreground result becomes a pending
   candidate; a separate asynchronous shadow invocation may promote it. Only
   a promoted pair can be served as a hit.

Once foreground streams have been delivered, failure to enqueue or finish a
shadow cannot change the foreground status. It only leaves no reusable entry.
Diagnostics go to the existing explain/event surface, not into child stdout or
stderr.

## Nonclaims

`linux-pytest-v1` does not claim any of the following:

- arbitrary-command, arbitrary-Python, interactive, macOS, remote, or
  cross-machine reuse;
- compatibility with pytest flags, stdin-driven tests, a virtual environment
  outside `.venv`, or invocation below the workspace root;
- preservation or replay of `.pytest_cache`, `__pycache__`, coverage files,
  snapshots, databases, or any other filesystem effect from the private
  branch;
- access to the user's home directory, credentials, agents, host IPC, devices,
  containers, or network services;
- support for tests whose correctness requires real time, fresh entropy,
  physical PIDs/inodes, uncontrolled thread scheduling, privileged syscalls,
  or a descendant executable outside the sealed runtime;
- protection from the current uid or host root maliciously racing or editing
  Again's private state; the boundary is against the sandboxed process and
  accidental host mutation, not a hostile local administrator;
- that passing tests are correct, that two matching executions prove general
  determinism, or that an observed dependency model is complete without the
  independently enforced completeness bitmap; or
- any latency, overhead, compatibility, or correctness result until the exact
  gates below have been run and their artifacts published.

## Invocation and identity

Admission parses `OsString` argv directly and never reparses a shell string.
The selector grammar is versioned with the profile. The cache shape key binds:

- the ordered argv byte strings and workspace-relative cwd (`.` in v1);
- canonical workspace identity and the ordered selector targets;
- stdin kind and the assertion that it contains zero bytes;
- a keyed, domain-separated digest of every passed environment name/value,
  with no raw value persisted;
- the executable symlink chain, Python executable, `pyvenv.cfg`, pytest and
  pluggy distributions, loaded plugins, Python standard library, imported
  bytecode/source, extension modules, ELF interpreter, and loaded shared
  objects;
- architecture, kernel release/config capability digest, namespace policy,
  Landlock ABI/rules digest, seccomp program digest, tracer/runtime version,
  ambient broker version, and EffectIR schema; and
- all previously observed content, metadata, symlink, directory-membership,
  and negative-path dependencies.

The final request key is BLAKE3 over deterministic length-prefixed fields with
the domain `again linux pytest request v1`. Host paths are represented by
their fixed sandbox paths plus workspace identity; raw home paths and raw
environment values are not serialized. Hash equality is an identity check,
not proof of trace completeness.

`-I` is part of the admitted argv and is never inferred. Again still passes a
profile-defined environment. `HOME=/home/again`, `TMPDIR=/tmp`, the hostname,
locale, timezone, CPU affinity, and logical clocks are profile inputs rather
than ambient host inputs. All remaining caller variables are passed exactly
and locally keyed into the request; loader injection variables are refused.
The environment policy and its exact normalized values are included in the
profile digest. Pytest configuration or plugin discovery through the
workspace or runtime is permitted only when the corresponding file and
directory observations are complete.

Closed stdin and an empty non-TTY stdin are both normalized to a profile-owned
EOF descriptor at fd 0 before the descriptor audit. Foreground stdout/stderr
continue streaming even after a reusable capture limit is exceeded; that run
then becomes execute-only.

All safety and storage limits are fixed profile inputs and therefore part of
the profile digest. The initial values are 16 MiB per captured stream, 256
descendant tasks, 10 million trace events, 512 MiB of trace encoding, and 15
minutes of foreground or shadow wall time. Snapshot, branch, scratch, memory,
open-file, and per-file limits are enforced by the smallest applicable tmpfs,
rlimit, syscall counter, and supervisor budget and are serialized in the
profile. Exceeding any limit terminates or finishes the foreground according
to its documented resource behavior, sets a stable execute-only reason, and
can never be promoted.

## Immutable input and root filesystem

Every execution uses two distinct trees:

- **sealed input:** a descriptor-walked reflink snapshot, or a full byte copy
  when reflink is unsupported, of the workspace and runtime material needed
  by the profile; and
- **execution branch:** a new reflink/copy made from the sealed input for one
  invocation. Pytest can write this branch, but cannot write the sealed input.

The host workspace is never an overlayfs lower directory, a bind-mounted live
lower directory, or a lazy fallback. Overlaying a private upper directory on
the live repository is specifically forbidden: lower-file replacement,
metadata, negative lookups, and directory membership could otherwise change
during the run. Reflink is only an optimization for making independent files;
the source and destination have separate logical contents under copy-on-write
semantics. Failure of `FICLONE` falls back to copying, not to a live mount.

Snapshot construction starts from owned directory file descriptors and uses
`openat2` beneath/in-root resolution with magic links denied. It records
regular files, directories, symlinks, hard-link groups, modes, uid/gid,
timestamps, xattrs required by the profile, and negative selector resolution.
FIFOs, sockets, devices, mount crossings, unreadable objects, sparse-file or
xattr loss, source mutation during copy, and an unrepresentable filename make
the foreground safe but execute-only, or refuse before execution when the
object is needed to construct the root. A pre/post descriptor identity check
and a second manifest pass must agree. The immutable manifest and every file
digest are computed from destination bytes, never assumed from source
metadata.

The mount namespace is made recursively private before any mount operation.
Its `/` is a new size-limited tmpfs with `nodev,nosuid`; fixed directories are
created there, the old root is detached after `pivot_root`, and no path to it
remains. The execution branch appears at `/workspace`. The sealed virtual
environment appears read-only at `/workspace/.venv`; runtime files are mounted
read-only at their fixed sandbox paths. `/tmp`, `/run`, and `/home/again` are
fresh bounded tmpfs directories. `/proc` is a new procfs for the new PID
namespace. `/dev` contains only profile-created `null`, `zero`, and controlled
stdio/random endpoints. `/sys`, host procfs, host home, and the Again state
directory are absent.

The runtime-closure builder must safely parse ELF metadata rather than run
`ldd`. It seals the resolved Python executable and symlink chain, ELF program
interpreter and `DT_NEEDED` closure, venv configuration and packages, standard
library, extension modules, pytest plugins and metadata used for discovery,
locale data, and every later `execve`/`dlopen` target. A descendant exec not
already present in the sealed workspace/runtime returns `EPERM`, is recorded,
and makes the run execute-only. Executable mappings from anonymous or writable
memory and native objects containing unaudited direct clock/entropy
instructions are likewise execute-only. Runtime closure is revalidated on
every hit; an EffectIR v1 or ordinary v0 proof cannot be upgraded into this
profile.

## Rootless namespace boundary

The launcher creates a fresh user namespace first, writes a one-entry uid map
from namespace uid 0 to the caller's real uid, writes `deny` to `setgroups`,
and writes the corresponding gid map. It then creates fresh mount, PID,
network, UTS, and IPC namespaces. No host capability is requested or retained.
The profile records and verifies all six namespace inode identities.

- The mount namespace owns the tmpfs root and private mounts described above.
- A minimal PID-1 reaper launches pytest, forwards the foreground termination
  signals, reaps orphans, and kills the namespace when the invocation or
  tracer ends.
- The network namespace has no veth, route, address, or configured loopback.
  The tracee cannot move an interface into it.
- The UTS namespace has the fixed hostname `again` and an empty domain name.
- The IPC namespace starts empty. Host System V IPC, POSIX message queues, and
  abstract Unix sockets are not visible.

V1 does not use a time namespace: it cannot virtualize wall-clock time and is
not a substitute for the ambient broker below. Any failure to create, verify,
or tear down one required namespace is a refusal or incomplete execution,
never a reusable result.

## File-descriptor boundary

The setup child finishes mounts and Landlock setup, closes every internal
ruleset, mount, directory, namespace, and control descriptor, then calls:

```c
close_range(3, ~0U, CLOSE_RANGE_UNSHARE);
```

There is no numeric close-loop success fallback. If `close_range` is absent or
fails, the profile is unavailable. At the pre-exec ptrace stop the supervisor
checks `/proc/<outer-pid>/fd` and requires exactly descriptors 0, 1, and 2,
each pointing to the profile-owned stdin/stdout/stderr endpoint. The seccomp
policy denies `pidfd_getfd`, descriptor receipt from an external Unix socket,
namespace escape, and reopening host procfs. All supervisor descriptors are
`O_CLOEXEC`. A failed audit, inherited connected socket, leaked secret-marker
fd, or fd received from outside the descendant tree clears completeness and
kills the candidate.

## Landlock as defense in depth

After the private root is complete and before Python execs, the child sets
`no_new_privs` and installs a Landlock ruleset using every filesystem access
right supported and tested by the selected ABI. It grants read/execute only
to sealed runtime/input paths and write/create/remove only to the execution
branch and bounded scratch mounts. Device ioctls and host-root traversal are
not granted. Where available, TCP restrictions and abstract-Unix-socket
scoping are installed too. Rules are inherited by all descendants.

Landlock is additive defense, not the observation proof. It does not mediate
every metadata read or every possible effect, and descriptors opened before a
ruleset retain important rights. The tmpfs/pivoted root, immutable copies, fd
scrub, network namespace, seccomp policy, and complete trace remain mandatory.
An unavailable or untested Landlock ABI disables the profile rather than
silently removing this layer.

## Seccomp and ptrace for every descendant

The initial tracee stops before exec. The supervisor applies
`PTRACE_O_EXITKILL`, `PTRACE_O_TRACESYSGOOD`, and trace options for fork,
vfork, clone, exec, seccomp, and exit. It does not release the first user
instruction until the exact seccomp program and ptrace options are confirmed.
Seccomp filters are installed with `no_new_privs`, synchronized across any
setup threads, inherited across fork/clone, and preserved across exec.

The architecture-specific filter has three explicit classes:

- a small generated allowlist of syscalls that cannot observe external state,
  mutate outside the branch, create an escape, or affect scheduling;
- `SECCOMP_RET_TRACE` for modeled filesystem, process, signal, time, random,
  identity, and synchronization calls; and
- deny/kill for network-capable domains, mount and namespace manipulation,
  ptrace/process-memory access, BPF/perf, keyrings, device creation,
  `open_by_handle_at`, `io_uring`, unknown syscalls, and escape primitives.

The default is trace/deny, never allow. Argument-bearing calls such as
`openat*`, `clone3`, `socket`, and `ioctl` are decoded from stopped tracee
memory with bounded copies and architecture checks. `CLONE_UNTRACED`, nested
user/mount/network namespaces, and tracee ptrace are denied. Fork, vfork,
clone, and clone3 are not considered complete until the new task is observed,
assigned a logical id, configured with inherited options, and later reaped.
The supervisor drains `waitpid(..., __WALL)` until the namespace contains no
task; the leader exiting is not enough. If the tracer dies,
`PTRACE_O_EXITKILL` kills tracees. Lost, malformed, out-of-order, or unknown
events clear completeness and prevent promotion.

Filesystem tracking is conservative. A successful read-capable open makes the
whole sealed file content and relevant metadata an input; a directory open or
`getdents64` makes its complete sorted name/type membership an input; failed
resolution records the absent component and parent membership; symlink hops
are explicit; executable and file-backed mmap pages enter the runtime/input
closure. All `*at` calls are resolved against the tracee's recorded cwd/root
and dirfd table. Stat-family and directory results expose profile-stable
logical device/inode/mount identifiers derived from the sealed manifest, so a
reflink/copy's allocation details do not leak into the program. Unsupported
metadata fields, ioctl behavior, shared writable mmap, splice-like path, or
path-resolution state makes the run execute-only.

Every write, truncate, chmod/chown, xattr, timestamp change, link, rename,
unlink, mkdir/rmdir, and writable mapping is recorded in order against the
branch. Finalization also walks the branch and computes a canonical final
Merkle root; the syscall effect stream and final diff must agree. Branch
effects are validation evidence only and are never applied to the host.

## No-network invariant

No-network is enforced, not inferred from an empty trace:

1. the new network namespace contains no host interface or route and leaves
   loopback down;
2. `close_range` removes inherited sockets;
3. seccomp rejects `AF_INET`, `AF_INET6`, `AF_PACKET`, `AF_NETLINK`, and other
   external network domains and rejects socket configuration, `setns`, and
   io_uring bypasses;
4. Unix sockets are limited to endpoints created inside the sandbox's own
   filesystem/network domain, and external descriptor passing is impossible;
5. Landlock network/scope controls are added when the audited ABI supports
   them; and
6. any attempted denied network operation is a policy violation and makes the
   foreground execute-only even if the test expects `EPERM` and exits zero.

The test harness must observe both host and sandbox namespace counters. DNS,
raw sockets, localhost, abstract/path Unix sockets, inherited connected fds,
SCM_RIGHTS, netlink, packet sockets, and io_uring are separate adversarial
fixtures.

## Ambient nondeterminism

Time, random values, PID/TID allocation, and scheduling are semantic inputs,
not noise that can be ignored after two equal outputs. Promotion requires a
complete deterministic implementation or proof that the interface was not
reachable. A second matching run never upgrades an incomplete ambient bit.

For known time interfaces, the tracer removes `AT_SYSINFO_EHDR`/legacy vDSO
entry points before the dynamic loader's first instruction, then brokers
clock/time syscalls. Realtime has a profile-fixed epoch; monotonic clocks start
at zero and advance by deterministic traced events and explicitly requested
sleeps. Supported sleep and timeout behavior is modeled in logical time.
Timer, clock-id, vDSO/vsyscall, or direct instruction behavior the broker
cannot model makes the run execute-only. This is mandatory because seccomp
alone cannot see calls completed in vDSO userspace.

For known random interfaces, `getrandom` and profile-created `/dev/random` and
`/dev/urandom` endpoints draw from a deterministic BLAKE3 XOF keyed by the
profile, input root, logical process id, and call index. The sealed native
runtime is statically audited for direct hardware entropy/clock instructions
and writable-executable/JIT paths are denied. An unaudited `RDRAND`, `RDSEED`,
`RDTSC`, device ioctl, or new executable mapping makes the profile unavailable
or the run execute-only; shadow agreement cannot waive it.

The PID namespace starts from a fixed topology. The broker assigns stable
logical process/thread ids in observed creation order and normalizes supported
PID-returning syscalls, wait results, procfs views, and stat/getdents identity
fields. Any identity surface that cannot be normalized is execute-only.

V1 permits promotion only while at most one workload task is runnable.
Synchronous subprocesses are allowed when the parent is blocked and the
supervisor can prove that invariant. Threads, racing children, futex/robust or
rseq behavior outside the audited single-runnable case, asynchronous signals,
CPU-time reads, and uncontrolled scheduler affinity are execute-only. The
foreground is allowed to finish under the sandbox; it is simply never
shadowed or reused. CPU affinity and reported CPU count are fixed profile
inputs, ASLR is disabled where the audited runtime requires stable addresses,
and failure to establish either condition disables promotion.

## EffectIR v2 and completeness bitmap

V2 is a new schema, `again.effect_ir.v2`; it does not reinterpret
`effect_ir.v1`. Its canonical record contains:

```text
EffectRecordV2 {
  schema, record_id, profile_id, profile_digest,
  invocation, workspace_identity, environment_digest,
  sealed_snapshot { snapshot_id, workspace_root, runtime_root, manifest_blob },
  platform { arch, kernel, capability_digest, namespace_ids, policy_digests },
  trace { required, complete, unsupported, violation, counters, first_failure },
  observations[], ambient_events[], ordered_effects[], final_workspace_root,
  result { stdout_blob, stderr_blob, wait_status, byte_counts },
  disposition, primary_record_id?, comparison_digest?, created_monotonic_ns
}
```

Canonical encoding uses integers, byte strings, ordered arrays, and sorted
map keys; it contains no floats, raw environment values, host home path, or
duration in any semantic comparison. Digests use explicit domain-separated,
length-prefixed BLAKE3 inputs. JSON diagnostics render each bitmap as exactly
16 lowercase hexadecimal digits so JavaScript number precision cannot change
it.

`required`, `complete`, `unsupported`, and `violation` are `u64` bitmaps. V1
requires bits 0 through 31, so `required` is `00000000ffffffff`. A complete bit
means the implementation observed or deterministically mediated that entire
dimension for every descendant through final reap; it is set only during
finalization. `unsupported` means a reachable operation had no complete
model. `violation` means an enforced profile rule was attempted or broken.
Unknown set bits or a different required mask require a schema/profile bump
and are ineligible.

| Bit | Name | Complete only when |
|---:|---|---|
| 0 | `sealed_snapshot` | the destination-byte manifest and stability passes agree |
| 1 | `runtime_closure` | every interpreter, module, plugin, exec, mapping, and library is sealed |
| 2 | `tmpfs_mount_root` | root is private tmpfs, old root is detached, and mounts match policy |
| 3 | `namespace_set` | user, mount, PID, net, UTS, and IPC namespaces are fresh and verified |
| 4 | `fd_hygiene` | the pre-exec table is exactly 0/1/2 and no external fd is later acquired |
| 5 | `descendant_lifecycle` | every creation/exec/exit is traced and every task is killed or reaped |
| 6 | `seccomp_stream` | the exact filter is active for all descendants with no unknown/lost event |
| 7 | `path_resolution` | cwd/root/dirfd and every path hop are resolved without ambiguity |
| 8 | `file_content` | every read-capable file input has destination bytes and digest |
| 9 | `file_mapping` | executable and data mappings are accounted for, including mmap writes |
| 10 | `file_metadata` | all exposed stat/access/xattr/ioctl metadata is modeled |
| 11 | `directory_membership` | each observed directory has complete canonical membership |
| 12 | `negative_lookup` | each failed lookup and its relevant parents are represented |
| 13 | `symlink_magiclink` | every symlink is explicit and no magic-link escape is possible |
| 14 | `exec_library_identity` | executable, loader, shared objects, and descendants match the closure |
| 15 | `environment` | all passed/normalized variables and config discovery inputs are bound |
| 16 | `stdin` | stdin is verified empty and cannot later receive bytes |
| 17 | `stdout` | capture is complete and its blob length/digest agree |
| 18 | `stderr` | capture is complete and its blob length/digest agree |
| 19 | `filesystem_effects` | ordered effects and branch diff are both complete |
| 20 | `final_workspace_root` | the finalized branch Merkle root is complete and stable |
| 21 | `network_isolation` | namespace, fd, syscall, and attempted-network audits all pass |
| 22 | `ipc_isolation` | host IPC/Unix endpoints and descriptor passing are unreachable |
| 23 | `signals_exit_status` | signals, waits, and final status are unambiguous for the whole tree |
| 24 | `logical_time` | every reachable time source is deterministically mediated |
| 25 | `logical_random` | every reachable entropy source is deterministically mediated |
| 26 | `logical_pid_identity` | every visible PID/TID/inode identity surface is normalized |
| 27 | `single_runnable_schedule` | no uncontrolled concurrent workload task exists |
| 28 | `limits_cpu_identity` | rlimits, affinity, CPU count/features, umask, and credentials are bound |
| 29 | `landlock` | the exact audited ruleset is installed and inherited |
| 30 | `cleanup` | mounts, branches, scratch state, and namespace tasks reach terminal state |
| 31 | `trace_integrity` | sequence numbers, counters, decoder, finalizer, and record encoding agree |

Eligibility is the mechanical predicate:

```text
complete == required
&& unsupported == 0
&& violation == 0
&& result capture is within limits
&& disposition is promoted
```

No aggregate `trace_complete=true` may be stored independently; it is derived
from those fields. Reason codes retain the first failure plus the full masks
and counters. Overflow, decoder disagreement, tracer restart, missing final
acknowledgement, or record/CAS corruption always fails closed.

## Two-invocation asynchronous promotion

On a miss, invocation A runs synchronously on branch A, streams to the caller,
and finalizes `EffectRecordV2(A)`. A is never immediately reusable. If A is
normally exited with status 0, within the fixed stream/branch limits, and has
complete zero-violation masks, the CLI hands a sealed snapshot handle plus an in-memory
invocation/environment envelope to a short-lived shadow worker. Raw
environment values are never written to SQLite or CAS. The CLI may return
after the worker acknowledges ownership; it does not wait for invocation B.
If A is signaled or exits nonzero, or if handoff fails, A remains a
nonreusable record; its foreground status and streams are still returned.

The worker creates a fresh namespace set, tmpfs root, and branch B from the
same sealed input and runs the exact argv again with no user-visible streams.
This is a second process-tree invocation, not a second pass inside A. The
worker has a bounded lease and lifetime and exits after terminal cleanup; a
crash or expired lease leaves no hit and is not retried without a new live
envelope.

Promotion requires exact equality of:

- profile, invocation, environment, sealed workspace, and runtime roots;
- stdout bytes, stderr bytes, and wait status;
- canonical observations, ambient transcript, and ordered effects after only
  documented logical PID normalization;
- completeness/unsupported/violation masks and trace-integrity counters; and
- final workspace Merkle root.

Duration, record UUID, outer host PIDs, and storage timestamps are excluded.
The comparison digest commits to both canonical records and the exclusion
rules. A mismatch atomically quarantines the candidate and its generalization
class (profile + Python/pytest/plugin/runtime closure + effect-shape digest).
No matching-output special case can override a dependency, ambient, effect,
or final-root mismatch.

A request arriving while the shadow is pending does not wait for or consume
the candidate; it executes normally and may supply a new candidate. A hit is
visible only after one transaction changes the pair to `promoted`. Before
replay, Again reconstructs and validates the recorded observation closure
against a fresh descriptor-stable snapshot, checks CAS bytes and current
runtime/executable authority, and runs the exact Python executable with fixed
internal capability-probe arguments inside the same no-network boundary. A
failed validation or probe becomes a miss, never a hit.

## Storage and code interfaces

EffectIR v2 uses new tables and immutable CAS objects. Existing v0/v1 rows are
neither migrated nor queried by this profile. The minimum SQLite interface is:

```text
pytest_snapshots(
  snapshot_id PRIMARY KEY, workspace_root, runtime_root, manifest_blob,
  profile_digest, state, ref_count, created_ns, expires_ns
)
pytest_effect_records(
  record_id PRIMARY KEY, shape_key, request_key, snapshot_id, record_blob,
  stdout_blob, stderr_blob, required_mask, complete_mask, unsupported_mask,
  violation_mask, disposition, created_ns
)
pytest_shadow_jobs(
  job_id PRIMARY KEY, shape_key, primary_record_id UNIQUE, state,
  lease_owner, lease_expires_ns, shadow_record_id, terminal_reason
)
pytest_promotions(
  request_key PRIMARY KEY, primary_record_id, shadow_record_id,
  comparison_digest, class_key, state, promoted_ns
)
pytest_quarantine_classes(
  class_key PRIMARY KEY, reason, first_record_id, created_ns
)
```

Foreign keys are immediate and state values are checked enums. A promotion
references two distinct immutable record ids and is valid only when both CAS
records decode as v2 and independently satisfy the bitmap predicate. Blob and
record bytes are written by private stage, fsync, digest verification, atomic
rename, and directory fsync before a transaction references them. Promotion
uses compare-and-swap from `pending_shadow`; crashes at every boundary leave
either an unreferenced GC candidate or a non-hit row. Quarantine is monotonic.
GC removes only expired, terminal, unreferenced snapshots/jobs/blobs and never
touches the workspace.

The implementation boundary is four narrow Rust interfaces:

```text
ProfileAdmission::parse(argv, cwd, stdio, env) -> AdmittedPytest | Refusal
SnapshotProvider::seal_full(admitted) -> SealedSnapshot
SnapshotProvider::seal_observation_closure(proof) -> ValidationSnapshot
SandboxTracer::execute(snapshot, admitted, mode) -> EffectRecordV2
PromotionStore::record_primary / claim_shadow / finish_shadow /
                lookup_promoted / quarantine / expire
```

`SandboxTracer` cannot accept raw arbitrary argv; it accepts only
`AdmittedPytest`, whose fields are private to the profile parser. The internal
fixed capability probe is a separate closed enum variant. `SealedSnapshot`
exposes immutable directory fds/ids rather than host path strings. All
cross-interface data structures have round-trip, unknown-version, unknown-bit,
and canonical-hash tests before integration.

## Parallel implementation plan

The integration owner first freezes `AdmittedPytest`, `SealedSnapshot`,
`EffectRecordV2`, bitmap constants, reason codes, and the four trait method
signatures. After that checkpoint, three implementers work in parallel without
sharing mutable modules.

### Implementer A — snapshot and isolation

Own the descriptor-relative snapshot copier/reflinker, runtime-closure builder,
tmpfs/pivot-root mount plan, user/mount/PID/net/UTS/IPC namespace setup,
minimal proc/dev/tmp layout, `close_range` audit, Landlock compiler/application,
and teardown. Deliver fake-exec fixtures proving immutable-source, no host
write, no network, fd hygiene, and zero leftover mounts/tasks. Expose only
`SnapshotProvider` and a pre-exec `IsolationPlan`; do not implement ptrace,
SQLite, CLI admission, or promotion.

### Implementer B — tracer and EffectIR v2

Own the x86_64 seccomp table, ptrace supervisor, descendant state machine,
dirfd/path/fd models, filesystem observations/effects, logical metadata,
time/random/PID brokers, scheduling classifier, canonical v2 codec, bitmap
finalizer, and A/B comparison digest. Deliver syscall-level fixtures for every
bitmap bit, including vDSO bypass and clone/clone3/fork/vfork/exec/exit. Expose
only `SandboxTracer`; do not create mounts, parse public argv, or write SQLite.

### Implementer C — admission, storage, worker, and measurement harness

Own the exact argv/selector parser, environment policy/digests, new SQLite
tables and migrations, CAS transaction ordering, shadow-worker handoff/lease,
promotion/quarantine state machine, GC, explain reason codes, generated-test
driver, and benchmark artifact schema. Use a fake snapshotter/tracer until the
interfaces land. Do not implement namespace or ptrace logic.

### Integration owner — composition and release decision

Own the profile feature gate and CLI dispatch, shared interface files, review
of each unsafe block and syscall table, conflict resolution, end-to-end fault
injection, Linux CI image/kernel pin, corpus selection before measurement,
and the final gate report. Integrate A and B behind C's fake interfaces, then
replace fakes one boundary at a time. The owner must keep all current Linux
profiles disabled until every correctness and product gate below passes; a
partial implementation may ship only as an unreachable probe/test module.

The merge sequence is explicit:

1. **Stage 0, contract freeze:** the integration owner lands only shared types,
   traits, fixtures, and fake implementations.
2. **Stage 1, parallel build:** A, B, and C implement against those fakes on
   separate modules; changing a frozen interface requires owner review and a
   coordinated fixture update.
3. **Stage 2, boundary tests:** each implementer passes its adversarial unit
   contract independently; the owner rejects any implementation that sets a
   completeness bit without a positive and negative fixture.
4. **Stage 3, integration:** compose snapshot/isolation, tracer, and storage in
   that order, fault-inject every handoff, and keep public dispatch disabled.
5. **Stage 4, gate run:** freeze the corpus/seeds, run all correctness gates
   before performance gates, publish raw artifacts, and enable the exact
   kernel/runtime tuple only if every gate passes.

## Adversarial test contract

The suite must include deterministic oracles for at least these classes:

- argv confusions: alternate Python paths, symlink escapes, reordered/missing
  `-I -m pytest`, pytest/Python flags, `--`, NUL/non-UTF-8 selectors, absolute
  paths, `..`, node-id path confusion, shell syntax, and TTY/stdin input;
- snapshot races: rename/unlink/recreate, symlink and mount swaps, hard links,
  concurrent writes with restored mtime, sparse files, xattrs, FIFOs, sockets,
  devices, unreadable entries, reflink failure, copy interruption, and a live
  overlay lower attempted by a test-only faulty backend;
- dependency invalidation: file bytes and metadata, directory membership and
  order, absent-path creation, symlink target, pytest config/conftest/plugin,
  imported Python source/bytecode, extension module, ELF loader/library,
  executable permission, environment, locale, and selector order;
- fd escape: low and very high inherited files/sockets, shared fd tables,
  `/proc/*/fd`, `pidfd_getfd`, SCM_RIGHTS, close-range failure, and supervisor
  descriptors without `CLOEXEC`;
- network escape: IPv4/IPv6/localhost, TCP/UDP/raw/packet/netlink, DNS,
  abstract and pathname Unix sockets, inherited connected sockets, interface
  creation/move, `setns`, and io_uring submission;
- descendant escape: daemon double-fork, clone flags, clone3, vfork, exec
  chains, thread exec, orphan/reparent, PID-1 exit, tracer crash,
  `CLONE_UNTRACED`, ptrace, process_vm, BPF/perf, signals during setup/run/
  drain, and a child holding stdout open;
- filesystem completeness: open/openat/openat2, cwd and dirfd changes,
  read/pread/readv, mmap, sendfile/splice/copy paths, stat/statx/access,
  partial getdents, negative lookup, magic links, rename/link/unlink,
  truncate/fallocate, xattrs, timestamps, chmod/chown, and writable shared mmap;
- ambient inputs: vDSO and direct time syscalls, all supported clocks/timers,
  getrandom and random devices, RDRAND/RDSEED/RDTSC fixtures, ASLR/address
  printing, PID/TID/procfs visibility, CPU count/affinity, threads, futex/rseq,
  racing subprocesses, asynchronous signals, and unsupported-interface
  execute-only behavior;
- output/result integrity: binary and invalid-UTF-8 streams, partial writes,
  nonempty stderr, nonzero exit, signal exit, capture limit, reader close,
  shadow-only output, and deliberately different A/B results/effects; and
- storage faults: crash or ENOSPC before/after every blob rename and SQLite
  transaction, stale worker leases, concurrent candidates, record/CAS bit
  flips, unknown schema/bits, forged complete masks, deleted blobs, and GC
  racing lookup without ever producing a hit from incomplete state.

An execute-only assertion must prove that no shadow job or promotion row was
created, not merely that the CLI printed a miss. A refusal assertion must prove
that Python never executed. Every divergence and incomplete bit becomes a
named regression fixture.

## Benchmarks and kill gates

All corpus definitions, seeds, hardware, exact kernel/configuration, filesystem,
Python/pytest/plugin locks, direct-command baselines, raw samples, and failures
must be written to versioned benchmark artifacts. Warm-cache measurements use
non-TTY streams and include CLI startup, validation, the fixed executable
capability probe, blob verification, and complete output replay. No paper's or
prototype's published number substitutes for an Again measurement.

The generated differential/adversarial campaign contains **100,000 completed
cases** from a committed seed schedule and covers every bitmap dimension and
fault class above. A false hit is any replay when the direct profile oracle for
the same sealed inputs would differ in either stream, wait status, canonical
observations/effects, or final root, or when any required bit is incomplete.

The profile remains disabled immediately if any one of these exact gates
fails:

- **0 false hits** across all 100,000 generated cases and the fixed regression
  corpus;
- **0 host mutations**: the workspace content/metadata/xattr/link manifest is
  identical before and after success, failure, SIGINT/SIGTERM/SIGHUP, tracer
  crash, worker crash, timeout, and ENOSPC fixtures;
- **0 network escapes**: the external canary receives zero connections,
  datagrams, DNS queries, or bytes, and packet/counter capture records zero
  sandbox-originated host packets in every network fixture;
- **0 leaked file descriptors** beyond 0/1/2 at exec, and no secret-marker
  file or socket is readable by any descendant;
- **0 leftovers** after each terminal run and bounded worker deadline: no
  namespace task, mount, execution branch, scratch object, live lease, or
  unreferenced non-GC state remains;
- **p95 sandbox startup at most 25 ms**, measured over at least 1,000 warm-page-
  cache misses from receipt of an already sealed snapshot through namespace/
  root setup, policy installation, fd audit, and release of Python's first
  instruction; end-to-end snapshot cost is still included in the trace-
  overhead gate rather than hidden from product measurement;
- **trace overhead at most 15% for pytest selectors taking more than 1 s**:
  for every qualifying corpus selector, the median execute-only traced wall
  time over 10 alternating runs is at most `1.15 *` its median direct wall
  time, with snapshot construction and cleanup included in traced time;
- **p95 promoted-hit latency at most 100 ms**, over at least 1,000 hits and
  including dependency/runtime validation, capability probe, CAS verification,
  and replay of fixtures whose combined streams are at most 1 MiB;
- **at least 3x median warm speedup**, computed per qualifying selector as
  `median direct wall / median promoted-hit wall` and then taking the median
  across selectors whose direct median is at least 500 ms; and
- **at least 8 of 10 preselected real repositories work with no repository,
  test, pytest configuration, or selector changes**: the exact admitted command
  completes, collects the same tests, and returns the same pass/fail outcome as
  direct pytest while preserving Again's documented virtual time/random and
  discarded-effect semantics.

Correctness gates are zero-tolerance and cannot be averaged against performance
or compatibility. Performance gates do not authorize reuse when a completeness
bit is missing. If a gate fails, the integration owner narrows or disables the
profile and records the failing fixture; no public Linux pytest-reuse claim is
made.

## Primary sources and design consequences

- Linux namespaces isolate specific global resources, rather than providing
  one complete sandbox abstraction; the required set and lifecycle follow the
  [namespaces overview](https://man7.org/linux/man-pages/man7/namespaces.7.html),
  [user namespace mapping rules](https://man7.org/linux/man-pages/man7/user_namespaces.7.html),
  [mount namespaces](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html),
  [PID namespaces](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html),
  and [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).
- A private mount propagation tree and detached old root are explicit because
  the [`pivot_root(2)` example](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
  makes both requirements visible. The new root uses the kernel's documented
  [tmpfs](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html).
- `FICLONE` supplies per-file copy-on-write separation and an atomic clone
  operation, but only on supporting filesystems; that is why full copy is the
  only fallback. See [`ioctl_ficlone(2)`](https://man7.org/linux/man-pages/man2/ioctl_ficlone.2.html).
  Descriptor-relative source walking uses the containment and magic-link
  controls in [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html).
- The exact fd scrub follows [`close_range(2)`](https://man7.org/linux/man-pages/man2/close_range.2.html),
  including `CLOSE_RANGE_UNSHARE`; Landlock's own documentation notes that
  pre-opened descriptors retain relevant rights, reinforcing the need to
  close them.
- Landlock is an unprivileged, stackable restriction layer inherited by future
  children, but its documented rights and limitations are narrower than this
  observation model. See the kernel's
  [Landlock userspace documentation](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html).
- Seccomp filters inherit across allowed fork/clone and persist across exec;
  `SECCOMP_RET_TRACE` integrates with a tracer, but vDSO calls can bypass
  syscall filters. These constraints come from [`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html)
  and the kernel's [seccomp-filter documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).
  Descendant capture and fail-closed tracer death use the fork/clone/vfork/
  exec/exit and `PTRACE_O_EXITKILL` semantics documented by
  [`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html).
- [Riker](https://www.usenix.org/conference/atc22/presentation/curtsinger)
  motivates treating directories and the wider POSIX filesystem as
  dependencies rather than recording file contents alone. It does not prove
  this profile correct.
- [DetTrace](https://doi.org/10.1145/3373376.3378519) demonstrates why time,
  random data, PIDs, and scheduling need deliberate reproducibility treatment
  for multiprocess Linux workloads. V1 adopts those categories as mandatory
  completeness dimensions, not DetTrace's empirical results.
- [Sandlock](https://arxiv.org/abs/2605.26298) motivates the split between
  static kernel-enforced restrictions and a narrow dynamic supervisor. Again
  does not inherit Sandlock's guarantees or performance measurements; every
  claim remains subject to the gates in this document.
