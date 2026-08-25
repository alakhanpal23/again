# Linux pytest trace profile v1

## Status and exact slice

This document is an implementation contract, not a statement that the profile
exists or has passed its gates. The profile identifier is
`linux-pytest-v1`. Its exact binary object registry, field tags, hash frame,
environment normalization, comparison exclusions, and manifest commitments
are frozen separately in [the v1 wire contract](LINUX_PYTEST_WIRE_V1.md).
The crate-private execution profile remains unreachable from the CLI and no
concrete profile implementation exists; pytest execution and reuse are not
implemented. A hidden, fixed, no-command diagnostic contains the implemented
private-root, layout, scratch, procfs, descriptor-scrub, capability-drop,
Landlock, and terminal seccomp slices described below. It remains non-
qualifying and grants no execution authority; stock hosted Ubuntu refuses at
UTS configuration before executing them, so they have no positive live runtime
evidence. Descriptor-stable source enumeration, regular-file copying,
connector-owned charged materialization, identity-checked atomic publication,
and one shared resource contract exist as internal leaves. A no-atime
source-view qualification path is also implemented as a crate-private leaf,
but the connector does not invoke it and its fixed local probe retries are
outside the shared resource ledger. The production and legacy test adapters
refuse every symlink before creating it because durable replay of
symlink xattrs and timestamps still requires a qualified dedicated staging
filesystem and a final bounded `syncfs`. Before any destination-tree
population, the materializer also requires a private-field cleanup envelope
read from the actual staged publisher to dominate its source depth, entry
count, basename, and retry limits. Mismatch refuses before materializer
population and delegates bounded, best-effort cleanup to the staged publisher.
The connector now joins the supported materialization and observation leaves
into an internal four-view comparison, charged canonical workspace-tree
compilation, atomic publication, and exact published-child binding. Its
`PublishedCanonicalTreeV1` result keeps the charged canonical bytes and root
digest live beside opaque descriptors for the durable publication and the
exact D2-committed child. This remains an internal evidence checkpoint: it
does not construct the full snapshot manifest or snapshot digest, choose a
content-addressed name, protect private state from the same host UID, or wire
the result to `SnapshotProvider`.

A static, allocation-free projection now returns a non-`Clone`, non-`Copy`
connector that owns the preflighted policy and one shared operation/heap
ledger. It refuses zero-valued classes and aggregate ceilings that current leaf
shapes cannot represent exactly rather than silently increasing them. Source
observation is connector-wired: it accepts an already-qualified source-view
authority, charges raw attempts through a connector-minted session, reserves
the full committed per-view ceiling before traversal, and returns the owned
plan beside a linear lease. The shared retained-view boundary permits at most
two such full-plan leases at once. One connector-owned materialization
operation reserves both ceilings for its enumerator plan and materializer
workspace before filesystem work, creates the sole charged private stage,
walks the already-qualified source, invokes the charged regular-copy leaf, and
returns the populated RAII-cleanup guard beside the retained copy-time source
plan, S1. The materializer-workspace lease is released while the source-plan
lease remains attached to that plan. The session binds the exact source,
destination, and copy policies to the shared ledger.

### Charged publication checkpoint

On Linux x86_64, the connector's atomic comparison path next observes an
independent source plan S2 and then two independent destination plans D1 and
D2. Destination observation uses a distinct connector-minted charged session;
directory and regular-file content reads use `O_NOATIME`, and a destination
symlink is refused after descriptor-selected type identification but before
xattr or target acquisition, including before `readlinkat`. The connector
compares S1/S2, S1/D1 with the stage's expected physical owner, and D1/D2, in
that order. It drops S2 before D1. After S1/D1 succeeds, the connector records
only the exact D1 fields omitted by the logical projection: 57 raw bytes per
entry for physical inode identity, directory size, ctime, and optional btime,
plus 24 raw inode-identity bytes per hard-link group. This `57N + 24G` buffer
is charged to the destination-observation transient heap through that exact
connector session; it is not a hash or a retained-view lease. D1 is then
dropped before D2. The D1/D2 comparator reconstructs the prior full-plan
field order from S1 plus the raw witness, preserving exact mismatch locations
while S1 remains available for logical-manifest projection. The witness is
dropped after D2. The verifier's stable S1/D2 projection then flows directly
into the charged compiler. It computes node and hard-link digests bottom-up,
uses source logical metadata, moves destination payload and xattr evidence
under the two retained-view leases, charges each new outer allocation to the
persistent-manifest ledger, and retains the exact canonical workspace-tree
bytes, root digest, and 102-byte D2 `SourceStatxV1` root commitment.

The D2-complete cleanup guard remains private. Before any irreversible
transition it escrows the exact published-child bind ceiling from its embedded
publication session. A non-forgeable prepared handoff borrows the live charged
manifest and owns that reservation. The sole production publication function
requires the stage and this handoff together. It then reserves finalization,
changes the top-level staging container to physical mode `0500`, revalidates
and fsyncs it, performs an adjacent pre-rename identity check, uses state-aware
`renameat2(..., RENAME_NOREPLACE)` reconciliation, fsyncs the parent, and
reopens the final name. Finally it opens the exact manifest root beneath that
durable publication and requires its `statx` commitment to equal D2. Success
returns an opaque physical binding paired with the still-charged canonical
tree evidence. Production exposes no raw physical-only seal and no clonable FD
borrow from that composite.

This manifest-bound publication checkpoint does not construct the full
canonical snapshot manifest, compute a snapshot digest, choose a
content-addressed name, or grant execution, Python, isolation, or reuse
authority. It makes no claim against a malicious same-UID process or host
root. The positive full-flow test remains ignored until both source and
destination filesystems are functionally qualified for no-atime access, so
stock hosted CI provides no positive qualified full-flow publication evidence.

Runtime qualification and retained evidence are tracked in
[STATUS.md](STATUS.md).

Within the wired source-observation, materialization, and staged-publication
slices, every explicitly modeled raw kernel operation attempt, including every
retry, is charged before invocation. Non-retryable RAII descriptor close is
the explicit release-only exception.
Before finalization, the session holds the exact child-bind reservation and
subtracts the complete finalization leaf ceiling in a second checked
reservation. Every charged attempt consumes its reservation before invocation,
and dropping either reservation refunds only unused attempts.
Forward and publisher-cleanup attempts use disjoint buckets, so forward
exhaustion cannot spend the cleanup reserve. The policy also pre-reserves a
separate leaf-local cleanup bucket consumed by the charged regular-copy leaf.
The retained 55-byte staging basename is charged to the forward heap stage;
each retained cleanup name is charged to the cleanup heap stage. For cleanup
depth `D`, entry limit `E`, and basename limit `N`, the exact maximum live
retained-name heap is
`55 + min(E, 2 * (D + 1)) * (N + 1)` bytes. Each active cleanup frame retains
one fixed two-slot name batch on the stack; those stack bytes and
allocator-private metadata are outside the transient-heap ledger. Maximum-depth
cleanup is retained as a required test on each supported build/target. Positive
qualified runtime evidence, canonical manifest/digest construction, isolation,
Python execution, and reuse remain required before this checkpoint can become
a release-qualified snapshot backend.

Each charged `Vec<u8>` precharges its requested capacity, observes capacity
after `try_reserve_exact`, and accepts only exact equality. Allocator
overcapacity drops the storage and returns a typed compatibility refusal. The
raw vector is never exposed, only byte buffers are admitted so nested owned
allocations cannot escape, and backing storage is dropped before its ledger
charge is released. A retained-view lease precharges the full committed
per-plan ceiling, but allocator-observed capacities inside source plans and the
materializer workspace, including boxed plan and xattr storage, are not
individually charged or proven exact. The leases therefore bound full-plan
coexistence without making this an exact whole-pipeline heap authority.

The intended next local product slice has exactly one public invocation
shape:

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
events, all six required namespace types, tmpfs, and Landlock ABI 6 or newer.
An exact kernel/configuration/runtime tuple is enabled only after that tuple
passes this document's gates. A missing or administratively disabled user
namespace, unsupported filesystem operation, untested architecture, old
Landlock ABI, or failed isolation probe is a typed refusal before Python
executes, never a best-effort unsandboxed fallback.

Stock GitHub-hosted Ubuntu is intentionally a negative, non-qualifying lane:
host policy prevents completion of the required rootless bootstrap. CI requires
the independent single-namespace route to refuse with `EACCES` and the fixed
combined diagnostic to verify its mapped child, fresh namespace ownership, and
effective `CAP_SYS_ADMIN` before an exact `EPERM` at UTS configuration. The
diagnostic accepts no command, must refuse before any workload surface, and
cannot supply positive isolation or profile evidence.

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
and policy all match both records referenced by the promoted pair. Cache
replay preserves each stream individually; it does not claim to reproduce the
timing or interleaving
between writes to stdout and stderr.

There are four outcomes:

1. **Refused:** admission or the mandatory isolation preflight fails. Python
   is not executed.
2. **Executed only:** the invocation safely finishes in the sandbox and its
   exact result is returned, but an unsupported effect, incomplete trace,
   nondeterministic interface, limit, or policy violation prevents both a
   shadow and reuse.
3. **Candidate:** a complete foreground result becomes an immutable primary
   candidate; a separate asynchronous invocation may produce an immutable
   shadow candidate.
4. **Promoted pair:** a separate promotion row may reference two distinct,
   complete candidate records whose canonical semantic-comparison views are
   byte-equal. Only that row grants reuse. Records themselves are never
   changed to a promoted disposition.

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

Admission is deliberately two phase. `parse_lexical` inspects only the public
argv/cwd/stdio/environment envelope and produces an in-memory draft; it cannot
claim that a selector, symlink chain, executable, or runtime object is safe.
`seal_full` then creates the immutable snapshot. Only
`finalize_against_snapshot` may resolve selector targets and the executable
chain against destination bytes and descriptor capabilities, finalize the
runtime closure, and create `PreparedPytest`. That value owns both the
admission result and live sealed-snapshot descriptor capabilities. Python
cannot execute between those phases.

Lexical admission parses `OsString` argv directly and never reparses a shell
string. The selector grammar is versioned with the profile. After snapshot
resolution, the canonical `ShapeV1` binds exactly:

- shape schema, profile ID, and profile digest;
- canonical workspace identity;
- the ordered argv byte strings, workspace-relative cwd (`.` in v1), ordered
  selectors, and stdin profile;
- the keyed environment binding, with no raw value persisted;
- the ordered resolved selector sandbox paths;
- the executable-chain digest, the complete canonical executable-chain
  witness, and the runtime-forest root; and
- architecture, kernel-capability digest, stable namespace-policy digest, and
  all ten component policy digests.

The embedded chain witness is bounded to 40 unique normalized sandbox paths,
starts at `/workspace/.venv/bin/python`, ends at a regular-file manifest node,
and binds every symlink target, normalized next hop, and node digest. Its
digest is recomputed and every hop is checked against the sealed manifest; a
digest without the witness has no authority. The pre-snapshot
`LexicalShapeV1` is also frozen: it commits schema, profile, workspace,
invocation, and keyed environment, but cannot grant lookup or execution.

The finalized shape deliberately excludes the full workspace root, snapshot and record
IDs, observations, results, effects, and raw per-run namespace inode IDs.
Observed content, metadata, symlink, directory-membership, and negative-path
inputs instead form a nonempty canonical `ObservationClosureV1`. Dependencies
are ordered by `(kind, sandbox_subject, operation_key)`; byte-identical repeats
merge, while the same identity with a different current blob value is
malformed rather than order-dependent.

The final request key is a domain-separated BLAKE3 identity over shape schema,
profile ID, profile digest, canonical shape key, and canonical observation-
closure digest. Host paths are represented by their fixed sandbox paths plus
workspace identity; raw home paths and raw environment values are not
serialized. A finalized-shape lookup is capped at exactly 64 rows. Each
candidate's closure and exact request identity must be recomputed against a
fresh validation snapshot before it can be selected. Hash equality is an
identity check, not proof of trace completeness.

`-I` is part of the admitted argv and is never inferred. Again still passes a
profile-defined environment. The exact name/value table and denylist are in
the [wire contract](LINUX_PYTEST_WIRE_V1.md#environment-normalization-and-key-lifecycle).
Caller entries are raw-byte validated and duplicate names are refused.
Profile-owned names are replaced first; loader/Python injection names not in
that owned table are then refused. Entries are sorted by raw name, and the
profile-owned table supplies deterministic home, path, locale, timezone,
Python, temp, and XDG values. Both the full name/value set and the names-only
set are locally keyed; records contain only key ID, keyed digests, entry count,
and environment-policy digest. Raw names and values are kept only in redacted,
zero-on-drop memory and are never serialized.

The 32-byte environment key is an owner-private persistent secret. Losing or
corrupting it disables admission until an explicit rotation/recovery action;
the implementation must never silently regenerate it. Rotation changes the
key ID and deliberately partitions all older entries. Its exact path is
`<private-state>/keys/linux-pytest-environment-v1`; creation, validation,
fsync, and rotation semantics are frozen in the wire contract. The keystore
implementation and explicit rotation command do not exist yet. Pytest
configuration or plugin discovery through the workspace or runtime is
permitted only when the corresponding file and directory observations are
complete.

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
`openat2` beneath/in-root resolution with magic links denied. Acquisition is
permitted only when it is proven not to mutate host atime or any other host
metadata. A functionally qualified no-atime acquisition view is the authority
for ordinary `O_RDONLY` regular-file and `O_RDONLY|O_DIRECTORY` directory
reads; source `O_NOATIME` is neither required nor sufficient, because Linux
also requires file ownership or `CAP_FOWNER`. Destination regular-file FDs
retain `O_NOATIME`. The raw copy leaf is unsafe and may be called safely only
from a callback scoped to that qualified source view. If the exact filesystem,
mount, credential, and source-type tuple cannot prove zero mutation,
construction refuses before Python.
It records
regular files, directories, symlinks, hard-link groups, modes, logical
uid/gid, size/link count, timestamps, all visible xattr names and values,
sparse data extents, and negative selector resolution.
FIFOs, sockets, devices, mount crossings, unreadable objects, sparse-file or
xattr loss, source mutation during copy, and an unrepresentable filename
refuse when encountered while constructing a required sealed root. They may
be execute-only only when discovered after a safely isolated foreground has
already run. A pre/post descriptor identity check and a second manifest pass
must agree. The immutable manifest and every file digest are computed from
destination bytes, never assumed from source metadata.

Manifest `ctime` and optional `btime` are logical stable-source metadata used
for identity and mutation detection; copied inodes are not required to have
the same physical creation/change timestamps. Destination verification is
physical for logical bytes, the destination-byte digest, mode/ownership and
atime/mtime where representable, visible xattrs, and the normalized sparse
extent sequence. That sequence is exactly the ordered nonempty ranges returned
by `SEEK_DATA` followed by `SEEK_HOLE`, clipped to logical size; an empty or
all-hole file has an empty sequence, and a filesystem may legally report the
whole file as data. Source and destination must expose the same sequence.
Physical snapshot ownership is the current effective UID, while logical
ownership and mode remain manifest metadata. Materialization uses private
`0600`/`0700` builder modes, replays exact xattrs, then performs one final chmod
from ordinary rwx bits only: strip `0o7000` and every write bit, add owner-read,
add owner-execute for directories, and add owner-execute for a regular file if
and only if any logical execute-class bit was set. Full logical mode, special
bits, uid, and gid remain in the manifest. Physical uid and gid are
creation-context metadata behind the private container and are excluded from
the logical projection. Final mode and xattrs are reverified; ACL/xattr sets
changed by that chmod refuse. No chmod of a manifest entry follows the verified
destination views. Charged publication separately changes the non-manifest
staging container to mode `0500`. Directory `st_size` is not an exact
projection.

The canonical manifest has one workspace tree at `/workspace` and a nonempty,
strictly mount-path-sorted forest of read-only runtime trees. Entries use raw
relative Linux paths in strict byte order; every nonroot entry is committed
exactly once by its parent. Per-kind node digests commit canonical metadata and
directory children, file content/extents, symlink target, or external-tree
root as applicable. Hard-link groups are scoped to one manifest tree. Their
identities commit the complete sorted member list and must agree with every
member's source link count; a link count larger than in-tree membership is an
external hardlink and refuses the tree. The workspace
Merkle summary commits the workspace-tree root. The runtime summary commits a
canonical sorted list of runtime `(mount_path, root_digest)` pairs. Every
workspace external-tree entry must correspond to exactly one runtime mount.
The full validation rules and domain strings are frozen in the
[wire contract](LINUX_PYTEST_WIRE_V1.md#snapshot-manifest-and-merkle-rules).

The mount namespace is made recursively private before any mount operation.
Its `/` is a new size-limited tmpfs with `nodev,nosuid`; fixed directories are
created there, the old root is detached after `pivot_root`, and no path to it
remains. The execution branch appears at `/workspace`. The sealed virtual
environment appears read-only at `/workspace/.venv`; runtime files are mounted
read-only at their fixed sandbox paths. `/tmp`, `/run`, and `/home/again` are
fresh bounded tmpfs directories. `/proc` is a new procfs for the new PID
namespace. `/dev` contains only profile-created `null`, `zero`, and controlled
stdio/random endpoints. `/sys`, host procfs, host home, and the Again state
directory are absent. The `/dev/null`, `/dev/zero`, and random paths are
profile-owned regular placeholders with completely brokered read, write,
stat, mmap, and ioctl behavior; v1 does not bind host device nodes into the
`nodev` root.

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

The launcher makes one `clone3` call containing `CLONE_NEWUSER` and the fresh
mount, PID, network, UTS, and IPC namespace flags. Linux creates the user
namespace first. Namespace PID 1 remains blocked while the parent writes and
verifies a one-entry uid map from namespace uid 0 to the caller's real uid,
writes and verifies `deny` in `setgroups`, and writes and verifies the
corresponding gid map. No host capability is requested or retained. The parent
pins all six namespace descriptors, verifies each namespace type and
device/inode identity, and proves through `NS_GET_USERNS` that every non-user
namespace is owned by the new user namespace.

The fixed bootstrap diagnostic first pins `/proc`, verifies `PROC_SUPER_MAGIC`,
requires the mount's exact `self` link to equal the caller's canonical decimal
`getpid()`, and then opens the numeric self and direct-child task directories
beneath that descriptor with `openat2`
`RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`. Its procfs
observations are descriptor-relative; only the authenticated `ns/*` magic-link
opens may cross into nsfs. The direct child remains unreaped and pidfd-bound
through validation, while the default `SIGCHLD` disposition preserves the
direct-child wait contract. `Completed` is minted only after terminal reap and
descriptor disposal; failures expose whether cleanup completed. Either result
is narrow bootstrap evidence only: it neither qualifies the profile nor grants
execution authority.

After the verified child configures its fixed UTS state, the diagnostic's
fixed no-command root slice makes the mount tree recursively private and uses
the pre-existing `/tmp` only as a descriptor-checked mountpoint. It mounts a
new 16 MiB/4096-inode `nodev,nosuid,noswap` tmpfs there, enters it by pinned
descriptor, pivots, detaches and removes the old-root pathname, reopens
absolute `/`, and verifies the exact mount identity, tmpfs type, mode,
ownership, flags, limits, and initial absence of `.oldroot`, `/proc`, `/dev`,
and `/sys`.

Before pivot, the child pins `/proc/self/ns/pid` and requires NSFS plus
`NS_GET_NSTYPE == CLONE_NEWPID`, retaining its exact device/inode identity.
Inside the new root, child-local umask is set to `0` while it creates the fixed
directories `/workspace` `0755`, `/tmp` `01777`, `/run` `0755`, `/home`
`0755`, `/home/again` `0700`, `/proc` `0555`, and `/dev` `0755`; it then
sets and verifies the final `0077` policy. `/tmp`, `/run`, and `/home/again`
are separate writable tmpfs mounts, each capped at 4 MiB and 1024 inodes, with
`nodev,nosuid,noexec,noswap`. Each must differ from its pre-mount target, and
all three must have distinct nonzero mount IDs and device tuples. The child
mounts a fresh read-only `nodev,nosuid,noexec` procfs with `subset=pid`,
requires its exact `self` link to be `1`, and verifies that `/proc/1/ns/pid` is
the same NSFS `CLONE_NEWPID` device/inode pinned before pivot. A final absolute
root reopen rechecks every constructed fixed path and mount, plus the absence
of `.oldroot` and `/sys`.

The exact success frame first added a combined layout/scratch/proc bit; stale
root-only success frames remain rejected. OS and invariant failures in that
slice reuse `mount_root_failed` at `child_mount_root`; there is no
caller-selected mount interface.

The next fixed no-command slice authenticates the nonblocking, close-on-exec
report FIFO, duplicates its write end to fd 0, and requires the duplicate to
retain the exact pipe identity, access mode, status flags, and descriptor
flags. One raw
`close_range(1, UINT_MAX, CLOSE_RANGE_UNSHARE)` call must then succeed, with no
numeric-close fallback. The child reauthenticates fd 0 and opens fixed relative
`proc/1/fd` beneath its already-verified `/`; the open must allocate fd 1 and
resolve without symlinks or magic links. The audit directory must be a
close-on-exec directory on the fixed read-only procfs. A bounded raw
`getdents64` loop accepts only one each of dot, dot-dot, `0`, and `1`, reaches
EOF, closes fd 1, proves fd 1 is `EBADF`, and reauthenticates fd 0 before the
new combined FD-success bit can be sent. The parent still requires the exact
nonce-bound frame, exact EOF, and exit-zero pidfd reap before constructing its
private completion marker.

`close_range` syscall failures have their own canonical
`close_range_unavailable` status. Only exact `ENOSYS`/`EINVAL` capability
failures and `EPERM`/`EACCES` administrative-policy failures are expected
unavailability; every other errno remains broken. All other FD handoff,
inventory, close, or identity failures are `isolation_preflight_failed` and
never expected-unavailable. Because the diagnostic child already owns a
private FD table, this proves flag-bearing syscall acceptance and its exact
terminal close postcondition, not the kernel's shared-table unshare path and
not the workload boundary specified below.

The following fixed no-command slice then eliminates namespace capabilities
without accepting a command or opening another descriptor. It scans
`PR_CAPBSET_READ` for every capability id 0 through 64 and requires exactly one
contiguous supported prefix whose last id is 40 through 63; id 64 must be
invalid. Exact v3 `capget` state must contain effective and permitted
`CAP_SETPCAP` and no effective, permitted, or inheritable bit above that
boundary. The child sets and immediately reads exact securebits `0xEF`: root
and setuid-fixup semantics are disabled and locked, `KEEP_CAPS` is locked off,
and ambient raises are disabled and locked. It then drops every supported
bounding capability in ascending order, clears the ambient set and scans it
again, writes all six v3 capability words to zero, and sets `no_new_privs`.
Before success it independently requires all six words zero, the same empty
bounding and ambient ranges, exact securebits `0xEF`, `no_new_privs == 1`, and
the original authenticated fd 0 identity.

Capability-drop OS and invariant failures share canonical status 9 with zero
flags and map to `isolation_preflight_failed` at `child_capability_drop`; none
is expected unavailability. The diagnostic then opens and authenticates fd 1
from its fresh procfs, reopens only `.`, `tmp`, `run`, and `proc`, and requires
their complete retained identities to match. Immediately before irreversible
Landlock enforcement it independently rereads the empty capability sets,
securebits, `no_new_privs`, and fd 0.

The VERSION query admits exactly ABI 6 or 7. ABI 1–5 and VERSION-query
`ENOSYS`/`EOPNOTSUPP` use canonical status 10 and map to expected
`landlock_unavailable`. ABI above 7 and every later syscall, policy, canary, or
cleanup failure use status 11 and map to non-expected
`isolation_preflight_failed` at `child_landlock`. The ruleset handles exact
filesystem, TCP, and scope masks `0xFFFF`, `0x3`, and `0x3`. It grants only
`tmp` access `0x77BE` and `run/restricted` access `0x17BE`; workspace and TCP
receive no rule. Fixed canaries require tmp create/write/truncate/rename
success, restricted `ftruncate` `EACCES` and rename `EXDEV`, workspace file and
directory read `EACCES`, and TCP bind/connect `EACCES`. ABI 6 uses restriction
flags zero; ABI 7 uses exactly `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`.

On success and every post-audit failure, cleanup attempts every tracked close
and then uses fd 1 to require the exact `{0,1}` inventory, close and prove fd 1
`EBADF`, and reauthenticate fd 0. Cleanup failure overrides an otherwise
expected refusal. This establishes one fixed Landlock policy's functional
filesystem/TCP behavior and ABI-7 flag acceptance. It does not functionally
prove signal or abstract-Unix scoping, inspect audit logs, or establish the
production tracer/workload split.

After Landlock has closed and audited its transient descriptors, the same
fixed no-command child reauthenticates fd 0, independently rereads
`no_new_privs == 1`, and requires inherited seccomp mode 0. It queries exact
availability of the bare `SECCOMP_RET_ERRNO` and
`SECCOMP_RET_KILL_PROCESS` actions, then makes one
`seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)` call for a
static 93-instruction x86_64 cBPF program and requires return 0. The child
requires post-install seccomp mode 2 and `no_new_privs == 1`. Unit tests pin
the program's exact byte fingerprint to `0x185859bbc1525aac`, prove every jump
terminates, and reject wrong architecture and the x32 syscall bit with
`KILL_PROCESS`.

The filter is deny-by-default with private errno marker `0x05A5`. Its entire
allowed terminal-report surface is:

- `write(0, pointer, 64)`;
- `poll(pointer, 1, timeout)` for `0 <= timeout <= 8000`;
- `clock_gettime(CLOCK_MONOTONIC, pointer)`;
- `prctl(PR_GET_SECCOMP, 0, 0, 0, 0)` or
  `prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)`;
- `close(0)`; and
- raw `exit(0)` or `exit(125)`.

The filter deliberately does not authenticate the pointer values, and for
`prctl` it does not inspect the unused sixth syscall slot
`seccomp_data.args[5]`. These are explicit nonclaims, not memory-integrity or
full-register proofs. The child calls six otherwise harmless canaries and
requires each to return the exact marker: `unshare(0)`,
`setns(-1,0)`, `clone3(NULL,0)`, `socket(-1,0,0)`, `ioctl(-1,0,0)`, and
`openat(AT_FDCWD,NULL,O_RDONLY|O_CLOEXEC,0)`.

Only `ENOSYS` or `EOPNOTSUPP` from either action-availability query uses
canonical status 12 and maps to expected `seccomp_unavailable` at
`ChildSeccomp` (serialized `child_seccomp`). An inherited filter, action
mutation, `EINVAL`, `EPERM`, `EACCES`, a positive `TSYNC` result,
install/readback mismatch, canary mismatch, or an unexpected syscall-result
shape uses status 13 and maps to non-expected `isolation_preflight_failed`;
malformed proof frames are rejected separately at `verify_child_proof`.
Protocol V2 encodes its version and flags as
little-endian `u16`; success requires exact mask `0x01FF`. The Landlock-only
`0x00FF` and capability-only `0x007F` frames are stale.

Stock hosted Ubuntu currently refuses at UTS configuration before reaching
the root, layout, FD, capability, Landlock, or seccomp code, so no positive
live evidence exists that those slices compose. The terminal diagnostic's
filter denies its six namespace/descriptor/network canaries, but it grants no
workload authority and is not the production tracer/workload filter. The
diagnostic makes no claim against malicious same-UID peers or host root. Its
fresh procfs still exposes PID 1's `exe`, `maps`, and `map_files`; inherited
executable mappings and potentially authoritative supplementary groups remain.
It has no descriptor-selected workspace/runtime attachment, populated `/dev`,
profile-owned stdio, tracer, command, Python, execution authority, or reuse
authority.

Permanently denying `setgroups` is required for the unprivileged gid map, but
does not clear the child's inherited supplementary groups. Before `clone3`,
the launcher captures a bounded canonical host-KGID vector; while PID 1 is
blocked, the parent verifies the child's exact vector through its pinned proc
view and commits the vector digest to the isolation/platform evidence. The
fixed diagnostic also requires the same bounded proc status to show effective
`CAP_SYS_ADMIN` before release. Only its dedicated post-release UTS status with
exact `EPERM` can then identify administrative policy; a missing capability,
different errno, malformed frame, or cleanup uncertainty remains broken. This
namespace proof does not claim inherited groups are non-authoritative.
Workload execution remains forbidden until a later outer proof has detached
the old root, admitted only profile-created or descriptor-selected trees,
closed every host descriptor above 2, denied namespace/descriptor/IPC escape
paths, and made the inherited group vector unable to reveal or mutate any
additional object.

- The mount namespace owns the tmpfs root and private mounts described above.
- Namespace PID 1 is the reaper and tracer. It launches pytest, forwards the
  foreground termination signals, reaps orphans, and kills the namespace when
  the invocation or outer watchdog ends. It remains outside the workload's
  Landlock/seccomp policy and uses only child-user-namespace capabilities for
  setup and exact seccomp-filter readback; no host capability is used.
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

This workload boundary is not implemented; the following text specifies
required behavior, not current behavior. The fixed diagnostic above has a
narrower terminal no-command proof that closes from fd 1 and uses fd 0 only as
its authenticated report channel. It does not establish profile-owned
descriptors 0/1/2, execute a workload, or exercise shared-table unsharing.

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

After the private root is complete and before Python execs, the workload sets
`no_new_privs` and installs a Landlock ruleset using every filesystem access
right supported and tested by the selected ABI. ABI 6 is the minimum positive
profile: it includes `REFER`, `TRUNCATE`, TCP bind/connect, device-ioctl
control, and abstract-Unix-socket/signal scoping. On ABI 7 the default commits
`LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`, so it does not emit host audit
records for the same executable. Audit emission and `NEW_EXEC_ON` are outside
the current proof and require an explicit operator opt-in. The ruleset
grants read/execute only to sealed runtime/input paths and write/create/remove
only to the execution branch and bounded scratch mounts. Device ioctls and
host-root traversal are not granted. No TCP allow rule exists, and abstract-
Unix-socket/signal scopes are mandatory. Rules are inherited by all
descendants.

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
  shape_key, request_key, invocation, workspace_identity,
  environment { key_id, digest, names_digest, entry_count, policy_digest },
  sealed_snapshot { snapshot_id, workspace_root, runtime_root, manifest_blob },
  platform {
    architecture, kernel_release, capability_digest, namespace_ids,
    namespace_policy_digest, policy_digests
  },
  trace { required, complete, unsupported, violation, counters, first_failure },
  observations[], ambient_events[], ordered_effects[], final_workspace_root,
  result { stdout, stderr, raw_linux_wait_status },
  disposition, disposition_reason?, primary_record_id?,
  reserved_comparison_digest_absent, created_monotonic_ns
}
```

Canonical encoding is the strict, dependency-free tagged binary format in the
[wire contract](LINUX_PYTEST_WIRE_V1.md#canonical-object-envelope). It has
fixed object IDs, versions, field tags, wire types, ordered lists, explicit
optionals, and closed enums; maps and unknown/default fields do not exist. A
decoder consumes every byte and rejects a value whose decoded form does not
re-encode identically. The maximum canonical size is 512 MiB. Records contain
no floats, raw environment values, host home path, or duration. Digests use
the frozen `AGNHSH01` tagged, length-prefixed, domain-separated BLAKE3 frame.
JSON diagnostics render each bitmap as exactly 16 lowercase hexadecimal
digits so JavaScript number precision cannot change it; SQLite stores the same
bitmap as an eight-byte big-endian BLOB.

The output streams are closed states: `complete { blob }`,
`exceeded { observed_bytes }`, or
`incomplete { observed_bytes, reason }`. The result stores the raw 32-bit
Linux wait word, not a lossy exit-code/signal enum. Only raw zero is successful
for candidate eligibility.

Record dispositions are immutable execution provenance:
`executed_only`, `primary_candidate`, or `shadow_candidate`. An execute-only
record requires an execute-only reason and cannot name a primary; a primary
candidate has neither; a shadow candidate names its primary and has no
execute-only reason. There is no promoted record disposition. The canonical
record reserves its comparison-digest optional field but requires it to be
absent. `comparison_digest` exists only in the separate promotion row that
references both immutable record CAS objects.

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
&& final_sequence == event_count
&& task_birth_count == task_exit_count == task_reap_count
&& denied_operation_count == unsupported_operation_count == 0
&& decoder_error_count == lost_event_count == 0
&& final_ack_count == 1
&& stdout and stderr are complete blob captures
&& raw_linux_wait_status == 0
&& disposition is primary_candidate or shadow_candidate
```

No aggregate `trace_complete=true` may be stored independently; it is derived
from those fields. Candidate eligibility still does not grant replay authority;
only a valid promotion row does. Reason codes retain the first failure plus
the full masks and counters. Overflow, decoder disagreement, tracer restart,
missing final acknowledgement, or record/CAS corruption always fails closed.

## Two-invocation asynchronous promotion

On a miss, invocation A runs synchronously on branch A, streams to the caller,
and finalizes an immutable primary-candidate `EffectRecordV2(A)`. A is never
immediately reusable and its disposition is never mutated. If A is
normally exited with status 0, within the fixed stream/branch limits, and has
complete zero-violation masks, the CLI hands a sealed snapshot handle plus an in-memory
invocation/environment envelope to a short-lived shadow worker. Raw
environment values are never written to SQLite or CAS. The CLI may return
after the worker acknowledges ownership; it does not wait for invocation B.
If A is signaled or exits nonzero, or if handoff fails, A remains a
nonreusable record; its foreground status and streams are still returned.

The durable shadow job commits the primary record, shape key, exact request
key, and complete sealed-snapshot identity. Those fields are derived only from
the verified primary record. Its live `ShadowEnvelopeV2` binds the job's shape
and exact snapshot identity to the same `PreparedPytest`; the primary record
and request key remain immutable durable-job bindings. Reconstructing an
envelope from host path strings or a merely equal snapshot digest is forbidden.
The worker creates a fresh namespace set, tmpfs root, and branch B from the
same sealed input and runs the exact argv again with no user-visible streams,
then writes a distinct immutable shadow-candidate record that names A.
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

Record UUID, snapshot UUID, raw per-run namespace inode IDs, disposition and
its reason/link, the reserved comparison-digest slot, creation monotonic time,
outer host PIDs, and duration are excluded. Stable namespace-policy identity
remains included. The comparison digest commits to the canonical exclusion
rules, the ordered primary and shadow immutable-record CAS digests, and both
semantic-view digests. The digest is stored only on the promotion row. A
mismatch atomically quarantines the exact request-scoped class committing
profile digest, workspace identity, shape key, and request key. `EffectShapeV1`
is a canonical analytics/future-policy identity only; it does not widen v1
quarantine or reuse authority.
No matching-output special case can override a dependency, ambient, effect,
or final-root mismatch.

A request arriving while the shadow is pending does not wait for or consume
the candidate; it executes normally and may supply a new candidate. A hit is
visible only after one transaction creates the authoritative promoted pair.
Lookup first returns at most 64 promoted rows for the finalized shape. For
each row, Again strictly decodes both records, reconstructs and validates the
recorded observation closure against a fresh descriptor-stable snapshot,
recomputes the exact request key, checks every referenced CAS object and
current runtime/executable authority, and runs the exact Python executable
with fixed internal capability-probe arguments inside the same no-network
boundary. Direct request-key lookup cannot bypass those checks. A failed
validation or probe becomes a miss, never a hit.

## Storage and code interfaces

EffectIR v2 uses new tables and immutable objects in a distinct hardened V2
CAS namespace/root. Existing v0/v1 rows and CAS aliases are neither migrated,
queried, nor garbage-collected by this profile. The legacy 16 MiB object limit
and legacy GC assumptions are incompatible with V2's 512 MiB canonical limit
and manifest/record reference graph. V2 therefore requires its own typed
object metadata, limits and quotas, staged-write/fsync protocol, digest
verification, corruption handling, reachability graph, and GC. The minimum
SQLite interface is:

```text
pytest_snapshots(
  snapshot_id PRIMARY KEY, workspace_root, runtime_root, manifest_blob,
  profile_digest, state, ref_count, created_ns, expires_ns
)
pytest_effect_records(
  record_id PRIMARY KEY, shape_key, request_key, snapshot_id, record_blob,
  stdout_blob, stderr_blob, required_mask, complete_mask, unsupported_mask,
  violation_mask, disposition, disposition_reason, primary_record_id,
  created_ns
)
pytest_shadow_jobs(
  job_id PRIMARY KEY, shape_key, request_key, snapshot_id,
  primary_record_id UNIQUE, state,
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
records strictly decode and re-encode as v2, independently satisfy candidate
eligibility, and have identical semantic comparison views. The four bitmap
columns are exactly eight-byte big-endian BLOBs, not signed SQLite integers or
text. Blob and record bytes are written by private V2 stage, fsync, digest
verification, atomic rename, and directory fsync before a transaction
references them. Promotion uses compare-and-swap from `pending_shadow`; it
inserts the comparison digest in `pytest_promotions` and never changes a
record disposition. `promoted_ns` is nonzero and no earlier than either
record's creation monotonic time. Shape lookup returns at most 64 pairs ordered
by descending `promoted_ns`, then ascending request key; request keys and every
primary/shadow record id are unique within the result, and malformed ordering
or duplication fails closed. Crashes at every boundary leave either an
unreferenced V2 GC candidate or a non-hit row. Quarantine is monotonic. V2 GC removes only
expired, terminal, unreachable V2 snapshots/jobs/records/blobs and never
touches legacy CAS or the workspace.

The implementation boundary is four narrow Rust interfaces:

```text
ProfileAdmission::parse_lexical(input) -> PytestAdmissionDraft | Refusal
SnapshotProvider::seal_full(draft) -> SealedSnapshot
ProfileAdmission::finalize_against_snapshot(draft, snapshot)
  -> PreparedPytest | Refusal
SnapshotProvider::seal_validation_snapshot(draft, expected_shape,
                                             expected_closure)
  -> RevalidatedObservationClosureV1
SandboxTracer::execute(prepared, mode) -> VerifiedExecutionRecordV2
SandboxTracer::capability_probe(validation_snapshot, isolated_import_pytest)
PromotionStore::record_primary / finish_shadow / fail_shadow /
                lookup_promoted_by_shape(shape) / quarantine / expire
```

`lookup_promoted_by_shape` has no caller-selected limit: the profile constant
requires the store to return at most 64 rows in newest-promotion order with
request-key tie breaking.

`SandboxTracer` cannot accept raw arbitrary argv; it accepts only
`PreparedPytest`, whose admission fields are private to the profile parser and
whose sealed descriptors are live capabilities. The internal
fixed capability probe is a separate closed enum variant. `SealedSnapshot`
owns immutable directory descriptor capabilities rather than serializable or
cloneable host path strings; diagnostic formatting redacts them. All
cross-interface data structures have round-trip, unknown-version, unknown-bit,
and canonical-hash tests before integration.

## Parallel implementation plan

The integration owner first freezes `PreparedPytest`, `SealedSnapshot`,
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
