# Gate 3 Linux filesystem and supervisor reconciliation

This note reconciles two historical side-branch commits against source
`4d8869c828b745e0abfce10ff2fe541b43bb7fb0`. It is a source proof, not new
Linux qualification evidence. Portable tests below are behavior models only;
only checked kernel calls on the supported Linux tuple can produce live
diagnostic evidence.

## Historical patch disposition

| Historical commit | Disposition | Reason and retained replacement |
|---|---|---|
| `fbf52cf5b8d028390de5b02af425222c60c62b52` (`codex/gate3-filesystem-transaction`) | Rejected as an implementation; its fail-closed intent is reimplemented | Its `LinuxDescriptorOperations::perform` always returns `Unsupported`, so its successful scripted transaction is portable model evidence only. The base already contains the live child-only implementation from `2e1ce4d6af0d3e8a69f255f2419ec120d4847f35`, `8486104eb1df34fc3ca50d1fbd0fd3092cc975c1`, `41e6cd3d58ea24a49ecea2543665ca195208f4b8`, and `a829980045dafb18ccc74e413e00ba3b2a3e8777`. That implementation uses checked `openat2`, `statx`, `open_tree`, recursive `mount_setattr`, `move_mount`, reopen, `fstatfs`, and close operations inside the branded fork child. This reconciliation adds a distinct rebind fault coordinate and puts each final source validation immediately before that root's `open_tree` attachment. |
| `c8d6613ab13ab46992c24034a04bd7de71e4b0f1` (`codex/gate3-supervisor-handoff-v2`) | Rejected and superseded | It only moved the existing filesystem-ready checkpoint into another wrapper; it did not seize, stop, or authenticate a kernel tracee. `b5f6a7cf8f531b232231bf8fe35541328e02d96a` supersedes it with live `PTRACE_SEIZE`, `PTRACE_INTERRUPT`, exact stop checking, process/status reauthentication, terminal cleanup, and one opaque supervisor owner. This reconciliation additionally makes seize-to-release ownership a linear witness so the trace filter release cannot precede supervisor ownership. |

Neither historical commit is cherry-picked.

## Boundary proof

- The two published roots are independently rebound in the child's private
  mount namespace, revalidated at the last fallible source boundary before
  each attachment, recursively changed to `RDONLY|NOSUID|NODEV`, attached only
  at the fixed `/workspace` and `/runtime` targets, then both reopened and
  authenticated. A second final target pass authenticates both roots after
  both attachments exist.
- Recursive read-only is a property of the attached mount views. It does not
  prevent the host user or another same-UID writable alias from mutating the
  underlying filesystem; malicious same-UID peers and host root remain outside
  the v1 threat model.
- The filesystem-ready child stays blocked and command-free. The only public
  operation of the successive opaque owners is cancellation followed by
  terminal reap and bounded stream cleanup. No PID, descriptor, path,
  environment, command, resume, release, candidate, replay, hit, or reuse
  accessor crosses the crate-private boundary.
- The cleanup guard exists immediately after clone and before returned child
  fields are validated. The fixed supervisor tree likewise has a drop-safe
  guard before seize. Cleanup ownership moves once through non-`Clone`,
  non-`Copy` states; failure retains the first error while kill, wait, reap,
  final `ECHILD`, signal verification, and descriptor destruction continue.
- The fixed trace child is blocked on a private channel when `PTRACE_SEIZE`
  succeeds. Only the resulting non-forgeable ownership witness can send the
  release byte; only the consumed release witness can enter wait and filter
  readback. Therefore its `SECCOMP_RET_TRACE` program cannot be installed
  before supervisor ownership. Filter count and every native cBPF instruction
  are read back with `PTRACE_SECCOMP_GET_FILTER` and compared exactly.
- Parent-event-first and child-stop-first fork delivery remain separate
  accepted live classifications. A wait-returned uncorrelated child stop is
  retained as cleanup authority before event-message validation.
- Production issuer and cleanup permits have no test constructor. Pure
  supervisor tests enter a private modeled-state helper and are explicitly not
  Linux or cleanup evidence.
- Hidden, fixed, argument-free diagnostics remain non-authoritative. There is
  no public linux-pytest command or workload dispatch. Profile, command,
  EffectIR, execution, candidate, promotion, replay, hit, and reuse authority
  all remain false; command release is unavailable.

## Fault coordinates

The production leaves retain explicit fault coordinates for namespace and
credential operations; both source roles and every rebind, validation, mount,
target-authentication, final-revalidation, and descriptor-close operation;
the eight independently addressed normal descriptor-close leaves per root;
ptrace seize/event/message/syscall/filter operations; run and cleanup waits;
both resume modes; stopped-memory reads; signal-mask read/write/verification;
PID and pidfd kill; terminal reap/final `ECHILD`; and stdio cleanup. The fixed
supervisor now also has distinct post-seize ownership-transfer and child
seccomp-install coordinates. Injected forward failures must preserve their
typed primary error while cleanup attempts the complete child tree and reports
any independent uncertainty.

The provisioned-only post-seize fault test is ignored on ordinary hosts. A
green portable unit test for its plan is not positive Linux evidence.
