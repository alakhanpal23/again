# Linux pytest v1 snapshot and isolation research

Status: implementation research for `linux-pytest-v1`. This note does not
change the normative profile or wire contracts. Where this note identifies a
conflict, the existing contract remains authoritative until deliberately
amended.

Normative inputs:

- [`LINUX_PYTEST_PROFILE_V1.md`](LINUX_PYTEST_PROFILE_V1.md)
- [`LINUX_PYTEST_WIRE_V1.md`](LINUX_PYTEST_WIRE_V1.md)
- the closed reason enums in [`src/linux_pytest.rs`](../src/linux_pytest.rs)

## Hosted Ubuntu result

Stock GitHub-hosted Ubuntu 24.04 cannot be the positive qualification target
for the rootless profile today.

[Actions run 32784270117](https://github.com/alakhanpal23/again/actions/runs/32784270117)
(repository authentication required) retained the decisive discovery tuple at
commit `df68613`:

- runner image `ubuntu24` version `20260816.277.1`;
- x86_64, kernel `6.17.0-1022-azure`, glibc 2.39;
- UID/GID 1001 with zero effective, permitted, inheritable, and ambient host
  capabilities;
- working `openat2` beneath/magic-link and
  `close_range(..., CLOSE_RANGE_UNSHARE)` semantics;
- Landlock ABI 7 from the version query, but no functional ruleset test;
- an independent `unshare(CLONE_NEWUSER)` returning `EACCES` while
  `kernel.unprivileged_userns_clone=1`,
  `kernel.apparmor_restrict_unprivileged_userns=1`, and the process is
  AppArmor `unconfined`; and
- Again's combined `clone3` route creating the child, writing the maps,
  validating the six namespace descriptors, and reaching its post-release
  proof, where the older protocol reported only a generic `EPERM`.

That failed run deliberately did not classify the generic `EPERM` as an
expected refusal: it could not prove which child operation failed. The fixed
diagnostic now checks effective `CAP_SYS_ADMIN` from the blocked child's pinned
proc view and assigns one closed proof status only at `sethostname` and
`setdomainname`. CI may classify only the exact status with `EPERM`, exact
identity and reserved fields, and completed cleanup as administrative policy.
Every other shape remains broken. This diagnostic accepts no command and
grants no execution or profile authority.

[Actions run 32786126330](https://github.com/alakhanpal23/again/actions/runs/32786126330)
then retained the exact fail-closed behavior of that rule at commit `948069e`:
two bootstrap attempts returned authenticated child `PROTOCOL`/`EPROTO`, not a
UTS-policy refusal. The child had drained the complete release frame before the
parent closed the last writer; the resulting HUP-only wake was incorrectly
treated as protocol failure. The correction accepts HUP only as a wake while
waiting for EOF after a complete frame, then loops back and still requires an
actual zero-byte read. Partial and extra frames remain rejected, with
deterministic 63/64/65-byte tests. The failed run is discovery evidence only.

[Actions run 32786996039](https://github.com/alakhanpal23/again/actions/runs/32786996039)
closed that race at commit `ca51b6a`. The retained product artifact contains
the exact closed UTS `EPERM` refusal, completed cleanup, empty stderr, and false
command/profile/execution-authority scope. The independent probe still records
`EACCES` at user-namespace creation. Both hosted OS jobs passed formatting,
pinned strict Clippy, locked tests, and the explicit 100,000-case gate; the
Linux library lane passed 615 tests with 7 ignored and zero failures. This is
positive evidence for the fixed negative-lane classifier and control framing,
not for a private root, command execution, profile qualification, or reuse.

The subsequent fixed child contains the first no-command private-root
implementation slice: after the namespace, identity, UTS, and parent-death
checks, it makes
mount propagation recursively private; mounts a fixed 16 MiB/4096-inode
`nodev,nosuid,noswap` tmpfs over descriptor-checked `/tmp`; pivots into it;
detaches the old-root pathname; reopens absolute `/`; and binds the final
tmpfs identity, flags, limits, ownership, mode, and reserved-path absence into
an exact new success bit. Dedicated canonical OS and invariant failures map to
`mount_root_failed` and are never expected-unavailable. This source compiles
for pinned x86_64 GNU production and test targets, but stock hosted Ubuntu
refuses earlier at UTS configuration. A provisioned qualifying runner must
exercise the branch before it becomes positive root-runtime evidence.

[Actions run 32788942118](https://github.com/alakhanpal23/again/actions/runs/32788942118)
passed that source checkpoint at commit `36f60f9`: Linux compiled and ran the
closed frame/policy tests and 617 library tests with 7 ignored, both hosted OS
jobs passed strict Clippy and the explicit 100,000-case gate, and the retained
product artifact remained the exact earlier UTS-policy refusal with empty
stderr. The run therefore confirms fail-closed compatibility while explicitly
showing that stock CI did not execute the mount/pivot branch.

Commit `883a0a6` extends that same fixed child through the layout frozen in the
normative profile without adding a command or authority surface. It uses
child-local umask `0` for construction, then sets and verifies final umask
`0077`. `/tmp`, `/run`, and `/home/again` become three independent writable
`nodev,nosuid,noexec,noswap` tmpfs mounts, each capped at 4 MiB and 1024
inodes. A fresh read-only `nodev,nosuid,noexec` procfs uses `subset=pid`,
reports exact `self -> 1`, and must expose `/proc/1/ns/pid` as the same NSFS
`CLONE_NEWPID` device/inode pinned from `/proc/self/ns/pid` before pivot. A
final absolute-root reopen revalidates every constructed fixed path and mount.
The success frame adds one combined layout/scratch/proc bit; OS and invariant
failures retain the existing `mount_root_failed` / `child_mount_root` mapping.

This is source-level implementation, not positive live runtime evidence:
stock hosted Ubuntu still stops at UTS configuration before the root code.
Malicious same-UID peers and host root remain outside the threat model. Fresh
procfs still exposes diagnostic PID 1's live `fd`, `exe`, `maps`, and
`map_files`; there is no workspace/runtime attachment, populated `/dev`, FD
scrub, capability drop, Landlock, seccomp, command, Python, execution, or reuse
authority.

[Actions run 32791466632](https://github.com/alakhanpal23/again/actions/runs/32791466632)
passed that source checkpoint: the Ubuntu library lane passed 621 tests with 7
ignored and zero failures, macOS passed 473 with 7 ignored, and both passed
strict Clippy plus the explicit 100,000-case gate. The retained product
artifact is still the exact UTS-policy `EPERM` refusal with completed cleanup,
empty stderr, and every command/profile/execution-authority scope false. The
run therefore validates source compilation, unit-policy checks, framing, and
negative-lane compatibility only; stock CI did not execute the root, scratch,
or procfs syscalls.

Ubuntu 24.04 intentionally restricts user namespaces and can deny capability
use inside a created namespace for unprivileged applications. Canonical
background is in the
[Ubuntu 24.04 release notes](https://documentation.ubuntu.com/release-notes/24.04/#unprivileged-user-namespace-restrictions)
and [AppArmor documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/).

The CI layout should therefore be:

1. Stock `ubuntu-24.04`: a negative lane requiring the exact independent
   `EACCES` plus combined-bootstrap UTS `EPERM` tuple. The fixed diagnostic
   accepts no command or workload surface.
2. Provisioned `ubuntu-24.04`: a positive integration lane only after an
   administrator supplies policy that permits every required user-namespace
   and namespaced-capability operation. Again itself still runs as the ordinary
   runner UID with zero host capabilities.
3. Pinned self-hosted VM/image: release qualification. GitHub GA images update
   weekly, and even a versioned runner label does not pin the image or kernel;
   see the [runner-images policy](https://github.com/actions/runner-images#available-images).

Again must not silently use `sudo`, disable AppArmor, fall back to a container,
or run Python directly.

## Required implementation order

### 1. Functional admission

Before snapshot work, require Linux/x86_64 and an enabled capability tuple,
then functionally test:

- `openat2` escape, magic-link, mount-crossing, and final-symlink-handle
  behavior;
- `xattrat` with `AT_EMPTY_PATH` on an `O_PATH` symlink;
- `SEEK_DATA` and `SEEK_HOLE` on the source and state filesystems;
- `close_range(..., CLOSE_RANGE_UNSHARE)` with a deliberately shared FD table;
- Landlock rule creation, enforcement, and ABI-specific allow/deny behavior;
- all six namespaces, UID/GID mapping, tmpfs, descriptor mount operations,
  `pivot_root`, and a new procfs; and
- seccomp TSYNC, ptrace fork/clone/exec/seccomp events, and exact filter
  readback.

A syscall or ABI version query alone is not a qualification.

### 2. Descriptor-stable tree walk

Create a fresh private staging directory and retain its directory FD. Never
concatenate untrusted source or destination path components.

For every directory:

1. Enumerate with `getdents64`, ignore `d_type`, and sort raw basename bytes.
2. Open each child relative to its parent FD with a zero-filled `open_how`:
   `O_PATH|O_NOFOLLOW|O_CLOEXEC` and
   `RESOLVE_BENEATH|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV`.
3. Call `statx(fd, "", AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW, ...)` and record
   mount ID, device, inode, type, metadata, and identity.
4. Within the still-live, functionally qualified no-atime source view, open an
   `O_RDONLY|O_NOFOLLOW` read FD for a regular file or an
   `O_RDONLY|O_DIRECTORY` FD for a directory. Do not add source `O_NOATIME`:
   [`open(2)`](https://man7.org/linux/man-pages/man2/open.2.html) requires file
   ownership or `CAP_FOWNER`, even on a no-atime mount, so that flag would
   incorrectly refuse qualified root-owned runtime files. The raw regular-copy
   boundary is unsafe; its caller must prove all source FDs came from the same
   still-live qualified view. Destination regular-file FDs keep `O_NOATIME`.
5. Create the destination only relative to a trusted destination-parent FD:
   regular files use `O_CREAT|O_EXCL|O_NOFOLLOW|O_NOATIME`; directories use `mkdirat`
   followed by reopen/verification; symlinks use `symlinkat` followed by an
   `O_PATH|O_NOFOLLOW` reopen.
6. Arm cleanup as soon as the exclusive destination name exists, then pin its
   device/inode identity. On failure, unlink only the still-matching private
   destination; never delete a replacement inode.
7. Reopen the original source parent/name after capture and compare identity
   to detect unlink/recreate races.

`RESOLVE_BENEATH` and `RESOLVE_IN_ROOT` are mutually exclusive. Use `BENEATH`
for the walk and separately use `IN_ROOT|NO_MAGICLINKS|NO_XDEV` for selector
resolution inside the completed snapshot. Linux rejects their combination;
see [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html) and
the [Linux 6.17 validation](https://github.com/torvalds/linux/blob/v6.17/fs/open.c#L1261-L1263).

Give scoped-resolution `EAGAIN` a fixed bounded retry count committed to the
profile. Exhaustion is source instability. Treat `EXDEV` as an escape or mount
crossing, never as permission to retry with ordinary pathname resolution.

### 3. Reflink and sparse-copy path

For the first member of each regular-file inode:

1. Create an empty destination.
2. Try whole-file `ioctl(dst, FICLONE, src)`. Reflink is atomic with concurrent
   writes and yields independent copy-on-write contents; see
   [`FICLONE(2const)`](https://man7.org/linux/man-pages/man2/FICLONERANGE.2const.html).
3. Fall back for validated capability-like failures such as `ENOTTY`,
   `EOPNOTSUPP`, `EXDEV`, or whole-file `EINVAL`. Recreate the destination
   before falling back. `EIO`, `ENOSPC`, and other construction failures are
   fatal.
4. In the fallback, `ftruncate` to the logical size, enumerate source data
   ranges with `SEEK_DATA`/`SEEK_HOLE`, and `pread`/`pwrite` only those ranges.
5. Enumerate destination ranges and require the same normalized API-visible
   data-extent sequence.
6. Hash destination logical bytes, including zero-filled holes.

Do not use a whole-file `copy_file_range`; Linux documents that it may expand
holes. See [`copy_file_range(2)`](https://man7.org/linux/man-pages/man2/copy_file_range.2.html)
and [`lseek(2)`](https://man7.org/linux/man-pages/man2/lseek.2.html). A nonempty
all-hole file has a nonzero size and an empty data-extent list.

### 4. Xattrs, symlinks, hardlinks, and metadata

"All visible xattrs" means every attribute returned under the snapshot
credential; Linux may omit inaccessible namespaces. Xattr lists are unordered
and size/value calls race. Use bounded `ERANGE` retries, sort raw names, read
all values, and repeat the complete list/value pass. See
[`listxattr(2)`](https://man7.org/linux/man-pages/man2/listxattr.2.html).

For the 6.17 x86_64 target, use raw syscalls 463 through 466 (`setxattrat`,
`getxattrat`, `listxattrat`, and `removexattrat`) with
`AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW` against stable `O_PATH` handles. The
primary definitions are the [x86_64 syscall table](https://github.com/torvalds/linux/blob/v6.17/arch/x86/entry/syscalls/syscall_64.tbl#L388-L391),
[`struct xattr_args`](https://github.com/torvalds/linux/blob/v6.17/include/uapi/linux/xattr.h#L23-L27),
and the [kernel implementation](https://github.com/torvalds/linux/blob/v6.17/fs/xattr.c#L863-L865).

Materialization order for each node is:

1. content and links under private builder modes (`0600` regular files and
   `0700` directories), physically owned by the current effective UID;
2. exact visible-xattr replay while those builder modes still permit access;
3. one final chmod to the physical sealed-mode projection from ordinary rwx
   bits only: strip `0o7000` and every write bit, add owner-read, add
   owner-execute for directories, and add owner-execute for a regular file if
   and only if any logical execute-class bit was set;
4. apply atime and mtime;
5. reverify the final mode, timestamps, and exact xattr set, refusing ACL/xattr
   combinations whose value changes under the final chmod; and
6. fsync the verified inode. Directories perform steps 2 through 6 only after
   their descendants and therefore finalize bottom-up.

Full logical source mode, special bits, uid, and gid remain in the manifest.
Physical uid and gid are creation-context metadata behind the private
container and are excluded from the logical projection. Directory `st_size`
is not an exact destination projection and is never compared as one.

Before the first destination-tree mutation, the materializer must read a
nonforgeable, allocation-free cleanup envelope from the actual staged
publisher. Its cleanup depth, entry count, basename limit, `openat2` attempts,
and generic syscall attempts must each dominate the source-derived
materialization policy. An independently configured or smaller cleanup guard
is a typed pre-population refusal. The current connector reserves both
simultaneously live plan ceilings before filesystem work, creates one private
charged stage, traverses the already-qualified source, populates supported
entries through the connector-bound regular-copy leaf, and returns the
populated guard beside the retained copy-time source plan. The source-plan
lease remains attached while the materializer-workspace lease is released.
Forward and cleanup raw
attempts, including retries, use disjoint buckets; the retained 55-byte staging
basename is forward-charged and retained cleanup names are cleanup-charged. For
cleanup depth `D`, entry limit `E`, and basename limit `N`, the exact maximum
live retained-name heap is `55 + min(E, 2 * (D + 1)) * (N + 1)` bytes. Each
active cleanup frame retains a fixed two-slot name batch on the stack; those
stack bytes are outside the transient-heap ledger. The materializer alone
returns a connector-private cleanup guard; production code does not expose
that guard after the subsequent D2 comparison.

The current Linux x86_64 connector continues from the copy-time source plan S1
with an independent source observation S2, followed by destination observations
D1 and D2 over the owner-private stage. Destination observation has its own
connector-minted charged session. Directory and regular-file reads use
`O_NOATIME`; a destination symlink is refused after descriptor-selected type
identification and before xattr or target acquisition, including before
`readlinkat`. The connector compares S1/S2, S1/D1 with the stage's expected
physical owner, and D1/D2, in that order. It drops retained plans between steps
so no more than two retained-view leases coexist. On success all plans and
leases are gone, and the D2-complete guard remains inside the connector. The
subsequent charged publication mechanics and authority limits are normative in
the [profile contract](LINUX_PYTEST_PROFILE_V1.md#charged-publication-checkpoint);
the isolation consequences are summarized in section 5 below.

Runtime qualification and retained evidence are tracked in
[STATUS.md](STATUS.md). The positive full-flow test remains ignored until both
source and destination filesystems are functionally qualified for no-atime
access, so hosted CI is not positive evidence for the qualified full flow.
The production-shaped charged compiler can now construct exact canonical tree
data from a verifier-minted S1/D2 projection. The connector keeps that charged
evidence live, escrows the exact child-bind work before sealing, durably
publishes, verifies the D2 root commitment against the reopened exact child,
and returns paired canonical evidence and opaque physical descriptors. Full
snapshot-manifest identity, content-addressed publication, the same-UID
boundary, and every later isolation step in this note remain research
requirements.

A regular file or directory can be made durable through its selected
descriptor. Linux does not provide the equivalent generic inode-`fsync`
boundary for a symlink after replaying its xattrs and timestamps. Therefore a
materializer without a nonforgeable authority for a functionally qualified,
dedicated staging filesystem refuses the symlink before `symlinkat`. With that
authority, it must finish all regular-file and bottom-up directory syncs, run
one bounded-`EINTR` `syncfs` on the dedicated filesystem, permit no later tree
mutation, and let the publisher revalidate and sync the staging root. Never
apply this fallback to an arbitrary shared filesystem: `syncfs` flushes the
whole filesystem and couples correctness, latency, and error reporting to
unrelated writers.

Read symlink targets with `readlinkat(symlink_fd, "", ...)`, using a growing
buffer and a second read. Identify hardlinks by `(mount-id, device, inode)`,
not inode alone. Enumerate all members before computing the group digest. Copy
the first destination member; create later members with `linkat` from the
first private destination name and without `AT_SYMLINK_FOLLOW`. If source
`nlink` exceeds membership inside that manifest tree, the group crosses the
copied boundary and cannot satisfy the current wire contract.

### 5. Stability and sealing

The current connector constructs and consumes the four views in this order:

- S1, the logical source manifest captured while copying;
- S2, an independent complete source walk/hash/xattr/extent manifest;
- D1, a complete destination manifest; and
- D2, an independent complete destination manifest.

It compares S1/S2, S1/D1, and D1/D2. Exact comparison makes the D2 match to S1
transitive rather than retaining a third plan for another direct comparison.
The final physical sealed-mode projection and post-chmod xattr verification of
every manifest entry are already part of both destination views. The current
materializer fsyncs each supported file and directory before destination
observation. After D2, the connector compiles the charged canonical
workspace-tree evidence. Charged publication separately changes the
non-manifest staging container to mode `0500`; the connector does not expose
the staging descriptor and follows the
[normative charged-publication sequence](LINUX_PYTEST_PROFILE_V1.md#charged-publication-checkpoint).
Before that irreversible transition it reserves the exact post-publication
binding work. It then reopens the durable publication, pins the exact child,
and verifies the D2 root commitment. The returned composite pairs those opaque
physical descriptors with the still-charged canonical tree bytes and root
digest. It grants no full snapshot manifest or digest, content-addressed name,
execution, Python, isolation, or reuse authority.

A complete backend must still combine this workspace tree with the runtime
forest, construct the full snapshot manifest and digest, choose a
content-addressed name, and mint the later isolation/execution authorities.
The malicious same-UID and host-root threat boundary also remains open. The
logical source mode remains in the future manifest and is restored only on the
private execution branch.

The per-run branch uses the same verified reflink/sparse-copy algorithm from
sealed input. Branch writes must not change either sealed input or the host
workspace.

### 6. Namespace creation and mapping

Run namespace setup in a fresh single-threaded worker. The outer launcher makes
one `clone3` call with:

```text
CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID |
CLONE_NEWNET  | CLONE_NEWUTS | CLONE_NEWIPC |
CLONE_PIDFD   | CLONE_CLEAR_SIGHAND
```

Set `exit_signal=SIGCHLD`. When `CLONE_NEWUSER` is combined with other
namespace flags, Linux guarantees creation of the user namespace first; see
[`user_namespaces(7)`](https://man7.org/linux/man-pages/man7/user_namespaces.7.html).

The new PID 1 blocks on a CLOEXEC control channel while the parent writes and
then reads back exactly:

```text
/proc/<pid>/uid_map:   0 <real_uid> 1\n
/proc/<pid>/setgroups: deny\n
/proc/<pid>/gid_map:   0 <real_gid> 1\n
```

PID 1 sets GID before UID and retains capabilities only for trusted namespace
setup. Record all six namespace device/inode identities, verify their types,
and use `NS_GET_USERNS` to verify that the non-user namespaces are owned by the
new user namespace. See [`ioctl_ns(2)`](https://man7.org/linux/man-pages/man2/ioctl_ns.2.html).

The required `setgroups=deny` transition does not clear supplementary groups
inherited across `clone3`. Capture a bounded canonical host-KGID vector before
the clone, verify the exact child vector from the pinned proc view while PID 1
is blocked, and commit its digest. Treat those groups as potentially
authoritative until the later private-root, mount, FD, network/IPC, and syscall
audits prove that they grant no additional object access. Namespace-bootstrap
evidence alone therefore cannot authorize a workload.

The workload later locks `SECBIT_NOROOT` and `SECBIT_NO_SETUID_FIXUP`, drops
every bounding, effective, permitted, inheritable, and ambient capability,
sets `no_new_privs`, and verifies the result before Python.

### 7. Mount root and namespace state

Inside the new mount namespace:

1. Make `/` recursively private with `MS_REC|MS_PRIVATE`.
2. Mount a new tmpfs root with explicit `size=`, `nr_inodes=`, `mode=0755`,
   `nodev,nosuid,noswap`.
3. Attach descriptor-selected trees with
   [`open_tree`](https://man7.org/linux/man-pages/man2/open_tree.2.html),
   [`mount_setattr`](https://man7.org/linux/man-pages/man2/mount_setattr.2.html),
   and [`move_mount`](https://man7.org/linux/man-pages/man2/move_mount.2.html),
   using `OPEN_TREE_CLONE|AT_EMPTY_PATH`:
   - branch at `/workspace`, read-write with `nodev,nosuid`;
   - sealed `.venv` and runtime forest, recursively read-only with
     `nodev,nosuid`;
   - `/tmp`, `/run`, and `/home/again`, separate bounded tmpfs mounts,
     preferably `noexec`.
4. Mount fresh procfs from PID 1 with `nodev,nosuid,noexec,ro,subset=pid`.
5. `chdir(newroot)`, create `.oldroot`, `pivot_root(".", ".oldroot")`,
   `chdir("/")`, detach `/.oldroot`, remove it, and close every old-root FD.
6. Verify root type, mount flags, and absence of host state, host home, `/sys`,
   and host procfs.

[`pivot_root(2)`](https://man7.org/linux/man-pages/man2/pivot_root.2.html)
requires a mountpoint new root and non-shared parents. Tmpfs defaults to half
of physical RAM, so size and inode ceilings must be explicit; see the
[tmpfs documentation](https://www.kernel.org/doc/html/latest/filesystems/tmpfs.html).

Set hostname `again` and an empty domain. Use rtnetlink to require only a down,
unconfigured loopback device, with no addresses, routes, or veth. Network
namespaces isolate devices, protocol stacks, routes, ports, and the abstract
Unix namespace; see [`network_namespaces(7)`](https://man7.org/linux/man-pages/man7/network_namespaces.7.html).

### 8. Landlock, FD scrub, and ptrace/seccomp handoff

Use namespace PID 1 as both reaper and tracer. It remains outside Landlock and
seccomp, forks the blocked workload, and attaches with `PTRACE_SEIZE`. This
satisfies Yama parent/child tracing and lets the tracer use `CAP_SYS_ADMIN` only
inside the child user namespace to call `PTRACE_SECCOMP_GET_FILTER`.

The workload order is strict:

1. drop namespace capabilities;
2. set `no_new_privs`;
3. install Landlock after the mount topology is final;
4. establish profile-owned FDs 0, 1, and 2;
5. close setup, path, mount, ruleset, namespace, and control FDs;
6. call `close_range(3, ~0U, CLOSE_RANGE_UNSHARE)`;
7. install exactly one classic-BPF filter using
   `seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, ...)`; and
8. invoke a dedicated syscall classified as `SECCOMP_RET_TRACE|COOKIE`, then
   remain stopped.

`CLOSE_RANGE_UNSHARE` separates a shared FD table before closing the range;
individual close errors are ignored, so an external `/proc/<outer-pid>/fd`
audit must still require exactly 0, 1, and 2. See
[`close_range(2)`](https://man7.org/linux/man-pages/man2/close_range.2.html).

At the tagged stop, the tracer must:

- observe `PTRACE_EVENT_SECCOMP` and the exact `PTRACE_GETEVENTMSG` cookie;
- use `PTRACE_GET_SYSCALL_INFO` to verify x86_64, syscall number, and arguments;
- dump filter index 0, hash the exact instructions, and match the frozen policy;
- require filter index 1 to be absent;
- verify seccomp mode, namespace IDs, zero capability sets, and exact FDs; and
- hold the workload until the outer watchdog acknowledges its independent
  audit.

Only then may it resume. Validate the following traced `execve` or `execveat`
against the sealed executable before allowing Python's first instruction.
`SECCOMP_RET_TRACE` stops before syscall execution and carries its data to
ptrace; TSYNC returns a positive TID when synchronization fails. See
[`seccomp(2)`](https://man7.org/linux/man-pages/man2/seccomp.2.html) and
[`ptrace(2)`](https://man7.org/linux/man-pages/man2/ptrace.2.html).

Landlock ABI 6 is the positive-profile floor:

- ABI 2 adds `REFER`;
- ABI 3 adds `TRUNCATE`;
- ABI 4 adds TCP bind/connect;
- ABI 5 adds device ioctl control;
- ABI 6 adds abstract-Unix-socket and signal scopes; and
- ABI 7 adds audit logging controls.

Handle every filesystem right through `TRUNCATE`, TCP bind/connect, device
ioctl, and both abstract-Unix-socket/signal scopes, with no TCP allow rules.
On the current ABI-7 target, also enable and commit the audited logging
controls. Grant read/execute to runtime, ordinary writable-tree rights to the
branch and scratch mounts, and no device-node creation. A read-only `.venv`
mount remains mandatory because a broad ancestor Landlock grant cannot be
narrowed by a descendant rule. See the
[Linux 6.17 Landlock documentation](https://github.com/torvalds/linux/blob/v6.17/Documentation/userspace-api/landlock.rst).

### 9. Cleanup

The tracer drains `waitpid(..., __WALL)` until every observed task has exited
and been reaped. PID 1 reaps orphans and exits last. On timeout, tracer failure,
or outer failure, signal PID 1 through its pidfd and wait for terminal state.
Linux sends `SIGKILL` to every remaining PID-namespace member when its init
process terminates; see [`pid_namespaces(7)`](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html).

After every namespace task is gone:

1. close namespace and mount handles;
2. atomically rename the execution branch to a private tombstone;
3. recursively delete only through descriptor-relative, no-follow operations;
4. fsync the state parent; and
5. verify no task, mount, branch, scratch object, or live lease remains.

## Exact failure mapping

| Failure | Existing reason |
|---|---|
| User-namespace creation or UID/GID-map setup is refused | `user_namespace_unavailable` |
| Required mount/PID/net/UTS/IPC namespace identity, child capability, or fixed UTS configuration fails | `required_namespace_failed` |
| tmpfs, descriptor mount, procfs, pivot, or old-root detach fails | `mount_root_failed` |
| `close_range` is absent or fails | `close_range_unavailable` |
| Seccomp query, install, TSYNC, or TRACE semantics fail | `seccomp_unavailable` |
| Ptrace attach, options, event, or exact filter readback fails | `ptrace_unavailable` |
| Landlock ABI is below 6 or functional enforcement fails | `landlock_unavailable` |
| Pre-exec FD, network, capability, namespace, or handoff audit differs | `isolation_preflight_failed` |
| Required FIFO, socket, device, unreadable object, or external hardlink group | `snapshot_required_object_unsupported` |
| Copy, hash, fsync, or atomic-publication construction failure | `snapshot_construction_failed` |
| A usable isolated copy exists but source passes differ | `source_mutated_during_snapshot` |
| Destination passes differ | `snapshot_manifest_unstable` |
| Destination sparse extents differ | `sparse_layout_loss` |
| Destination visible xattrs differ | `xattr_loss` |
| Unsupported object found only after a safely isolated foreground ran | `unsupported_snapshot_object` |
| Post-exec network, namespace, mount, or FD attempt | existing `network_attempt`, `namespace_escape_attempt`, `mount_escape_attempt`, or `fd_hygiene_violation` |
| Tracees remain unreaped | `descendant_unreaped` |
| Post-exec task, mount, branch, or scratch residue | `cleanup_incomplete` |

If sparse, xattr, or object loss makes root construction unsafe before Python,
use a refusal rather than inventing an execute-only foreground.

## Deterministic test matrix

| Area | Fixtures and required oracle |
|---|---|
| Stock hosted runner | `ubuntu-24.04`; exact independent `EACCES` plus combined-bootstrap UTS `EPERM`; the fixed diagnostic accepts no command |
| Provisioned hosted runner | administrator-approved user-namespace and namespaced-capability policy; ordinary UID, zero host caps, complete positive handoff |
| Path walk | Rename/unlink/recreate, symlink swap, bind crossing, magic link, `..`, non-UTF-8 names; no escape |
| Destination | Name/symlink replacement at each create/reopen boundary; FD-selected destination remains stable |
| Reflink | Success plus forced `EOPNOTSUPP`, `ENOTTY`, `EXDEV`, `EINVAL`, `EIO`, and `ENOSPC`; sealed/branch independence |
| Sparse | Empty, all-hole, leading/interior/trailing holes, written zeros, truncate race; exact bytes and extents |
| Xattrs | Empty/large values, unordered list, ACL, symlink attrs, list/value mutation, set failure, inherited attrs |
| Hardlinks | Regular and symlink groups, cross-directory, outside-tree link, unlink/relink, directory-link rejection |
| Metadata/host | Mode, logical IDs, timestamps, xattrs, links; host manifest identical after success, signal, crash, timeout, and ENOSPC |
| No-atime authority | Qualified view with current-UID workspace plus root-owned runtime objects; ordinary regular/directory reads succeed and the host manifest, including atime, remains identical. Run on the provisioned qualifying runner, not stock CI. |
| Namespace/root | Six fresh IDs and ownership, exact maps, fixed UTS, empty IPC/net, private mounts, bounded tmpfs, no old root |
| FD boundary | Low/high FDs, socket, secret marker, `CLONE_FILES`; exactly 0/1/2 at the tagged stop |
| Landlock | Runtime read, runtime/venv write denial, branch/scratch write, host denial, truncate/refer, TCP/ioctl/scope; ABI-7 audit controls |
| Seccomp/ptrace | Wrong arch/x32, absent tracer, wrong cookie/filter, TSYNC failure, all task events, tracer crash |
| Cleanup | Double fork, orphan, PID-1 exit, tracer/outer death, task holding FD/cwd; no leftovers |

Race tests must use explicit barriers or fault-injection hooks, never timing
sleeps.

## Resolved contract decisions

1. **Timestamps:** manifest `ctime` and optional `btime` are logical
   stable-source metadata. Destination validation is physical for bytes,
   digest, extents, visible xattrs, and representable metadata; copied physical
   creation/change timestamps are not compared for equality.
2. **Host atime:** snapshot acquisition must prove zero host-metadata mutation.
   A qualified no-atime acquisition view authorizes ordinary regular-file and
   directory reads plus symlink/xattr capture. Source `O_NOATIME` is deliberately
   absent because its ownership/`CAP_FOWNER` gate rejects otherwise qualified
   root-owned runtime objects. Destination regular-file FDs retain the flag. A
   tuple that cannot prove this property is refused rather than accepted with
   an atime side effect.
3. **Sparse semantics:** `data_extents` is the normalized, ordered
   `SEEK_DATA`/`SEEK_HOLE` sequence clipped to logical size. Linux may legally
   report an actually sparse file as entirely data; source and destination
   API-visible sequences must still match.
4. **Xattrs:** visible but unrepresentable attributes produce typed loss or a
   pre-exec refusal. No visible attribute is silently omitted.
5. **Hardlinks:** groups are scoped to one manifest tree. Source `nlink`
   greater than complete in-tree membership is an unsupported external link
   and refuses required root construction.
6. **`/dev`:** use profile-owned regular placeholders with completely brokered
   null, zero, random, stat, mmap, and ioctl behavior. V1 authorizes no host
   device bind.
7. **Landlock:** ABI 6 is mandatory so TCP, device-ioctl,
   abstract-Unix-socket, and signal controls are present. ABI 7 audit controls
   are enabled and committed when available.
8. **Tracer placement:** namespace PID 1 is the reaper/tracer and stays outside
   workload Landlock/seccomp. Child-user-namespace `CAP_SYS_ADMIN` permits
   `PTRACE_SECCOMP_GET_FILTER` without any host capability.
9. **Threat boundary:** double passes and hashes detect ordinary races,
   including restored-mtime fixtures, but not a malicious same-UID process that
   changes and restores content between every observation. Same-UID peer,
   state-store tampering, and host root are explicitly outside v1's boundary.
10. **Cleanup mapping:** use `isolation_preflight_failed` when cleanup is the
    first pre-Python failure and `cleanup_incomplete` after Python, retaining
    cleanup substage and errno as evidence.
