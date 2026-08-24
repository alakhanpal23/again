# Linux pytest v1 wire and identity contract

## Status

This is the frozen Stage 0 binary and identity contract for the future
`linux-pytest-v1` profile. It documents the crate-private contract in
`src/linux_pytest.rs`, `src/linux_pytest/canonical.rs`, and
`src/linux_pytest/identity.rs`. The module remains unreachable from the public
CLI, and its concrete admission, sealed-snapshot, sandbox, tracer, storage, and
worker implementations do not exist. The connector now wires source
observation through its shared ledger and precharges one full retained-view
ceiling before each walk; a linear lease held beside the resulting plan limits
coexisting full views to two. This is a structural ceiling, not exact
allocator-capacity accounting inside the plan. A no-atime source-view
qualification path exists but is not connector-wired; its fixed local probe
retries are outside the shared resource ledger, so callers cannot yet obtain
that authority through the charged pipeline. On Linux x86_64, one
connector-owned operation now reserves two full-plan ceilings, creates the
charged private stage, traverses the already-qualified source, invokes charged
regular copying, finalizes supported metadata and durability, and returns the
populated RAII-cleanup guard. Source-enumeration, materialization, and
regular-copy policies are bound into the same connector-minted session. The
populated guard exposes no ready, publish, execution, or reuse transition;
destination observation and complete four-view orchestration remain unwired.
Nothing in this document is evidence that pytest execution or reuse is
available.

Serde/JSON is diagnostic only. It is not a storage, comparison, or digest
format. Canonical bytes described here are the only bytes accepted for EffectIR
v2 record identities, comparison views, and snapshot-manifest identities.

## Canonical object envelope

All integers are big-endian. A top-level object is:

```text
8 bytes  magic = "AGNCAN01"
2 bytes  type_id
2 bytes  format_version = 1
2 bytes  field_count
...      fields
```

A nested object omits only the eight-byte magic. Each field is:

```text
2 bytes  nonzero field tag
1 byte   wire type
8 bytes  payload length
N bytes  payload
```

Field tags must be unique and strictly increasing. The decoder requires the
exact type, version, field count, tag sequence, and wire type defined for that
object. Missing, duplicate, reordered, or unknown fields; unknown wire types;
truncation; trailing bytes; noncanonical booleans or optionals; unknown enum
variants; and a decode/re-encode mismatch are errors. The maximum canonical
object size is 512 MiB. No map, float, platform-width integer, implicit
default, or unordered collection exists in the format.

| Code | Wire type | Canonical payload |
|---:|---|---|
| `0x01` | `u8` | exactly 1 byte |
| `0x02` | `u16` | exactly 2 bytes |
| `0x03` | `u32` | exactly 4 bytes |
| `0x04` | `u64` | exactly 8 bytes |
| `0x05` | `i32` | exactly 4 bytes; reserved by the codec |
| `0x06` | `i64` | exactly 8 bytes |
| `0x07` | `bool` | exactly `00` or `01` |
| `0x08` | bytes | uninterpreted bytes |
| `0x09` | UTF-8 | bytes that must decode as UTF-8 |
| `0x0a` | object | one nested object envelope |
| `0x0b` | list | `u64 count`, then `u64 length || item` for each item |
| `0x0c` | optional | `00`, or `01 || u64 length || value` |
| `0x0d` | enum | nonzero `u16 variant || u16 field_count || fields` |

Lists preserve order. Set-like inputs must be sorted before encoding. An enum
with no payload still carries a zero field count. An absent optional is always
the single byte `00`; an empty present value is `01` followed by an eight-byte
zero length. Raw Linux path and argv values use the bytes wire type, not UTF-8,
except the schema and profile identifiers. Any list count above 10,000,000 is
invalid. Decoders prove the minimum framing fits the remaining input before
allocating, use checked arithmetic and fallible reservations, and reject
impossible lengths before iterating; the 512 MiB object ceiling is not itself
permission for attacker-directed infallible allocation.

## Object registry

The current registry is fixed as follows.

| Type ID | Object | Tagged fields in order |
|---:|---|---|
| `0x0001` | Effect record | specified below |
| `0x0002` | Invocation | `1 list argv`, `2 bytes cwd`, `3 list selectors`, `4 enum stdin_profile` |
| `0x0003` | Selector | `1 bytes raw`, `2 bytes path`, `3 list node suffixes` |
| `0x0004` | Environment binding | `1 bytes key_id`, `2 bytes digest`, `3 bytes names_digest`, `4 u32 entry_count`, `5 bytes policy_digest` |
| `0x0005` | Sealed-snapshot identity | `1 bytes snapshot_id`, `2 bytes workspace_root`, `3 bytes runtime_root`, `4 object manifest_blob`, `5 bytes profile_digest` |
| `0x0006` | Platform identity | `1 enum architecture`, `2 bytes kernel_release`, `3 bytes capability_digest`, `4 object namespace_ids`, `5 bytes namespace_policy_digest`, `6 object policy_digests` |
| `0x0007` | Namespace IDs | `1..6 u64 user, mount, pid, network, uts, ipc` |
| `0x0008` | Policy digests | `1..10 bytes seccomp, landlock, namespace, tracer_runtime, ambient_broker, limits, environment, selector_grammar, runtime_closure, codec` |
| `0x0009` | Trace completeness | `1 u64 required`, `2 u64 complete`, `3 u64 unsupported`, `4 u64 violation`, `5 object counters`, `6 optional first_failure` |
| `0x000a` | Trace counters | `1..18 u64`, in the order listed below |
| `0x000b` | First failure | `1 u8 dimension`, `2 u16 reason`, `3 enum phase`, `4 optional u64 event_sequence`, `5 optional u32 logical_task_id` |
| `0x000c` | Observation | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum kind`, `4 bytes sandbox_subject`, `5 object canonical_detail` |
| `0x000d` | Ambient event | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum kind`, `4 object canonical_detail` |
| `0x000e` | Ordered effect | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum kind`, `4 bytes sandbox_subject`, `5 object canonical_detail` |
| `0x000f` | Blob reference | `1 bytes digest`, `2 u64 byte_count` |
| `0x0010` | Result | `1 enum stdout`, `2 enum stderr`, `3 u32 raw_linux_wait_status` |
| `0x0011` | Comparison view | specified below |
| `0x0012` | Shape | `1 UTF-8 schema`, `2 UTF-8 profile_id`, `3 bytes profile_digest`, `4 bytes workspace_identity`, `5 object invocation`, `6 object environment`, `7 list resolved_selector_targets`, `8 bytes executable_chain_digest`, `9 bytes runtime_root`, `10 enum architecture`, `11 bytes capability_digest`, `12 bytes namespace_policy_digest`, `13 object policy_digests`, `14 bytes complete canonical executable-chain witness` |
| `0x0013` | Observation closure | `1 list dependencies` |
| `0x0014` | Observation dependency | `1 bytes operation_key`, `2 enum observation_kind`, `3 bytes sandbox_subject`, `4 object current_value` |
| `0x0015` | Comparison snapshot | `1 bytes workspace_root`, `2 bytes runtime_root`, `3 object manifest_blob`, `4 bytes profile_digest` |
| `0x0016` | Comparison platform | `1 enum architecture`, `2 bytes kernel_release`, `3 bytes capability_digest`, `4 bytes namespace_policy_digest`, `5 object policy_digests` |
| `0x0017` | Comparison rules | `1 bytes rule_version`, `2 list excluded-field names` |
| `0x0018` | Observation detail | `1 enum detail` |
| `0x0020` | Snapshot manifest | specified below |
| `0x0021` | Tree manifest | `1 bytes mount_path`, `2 enum tree_role`, `3 list entries`, `4 bytes root_digest` |
| `0x0022` | Manifest entry | `1 bytes relative_path`, `2 enum entry_kind`, `3 object metadata`, `4 enum payload`, `5 optional hardlink_group`, `6 bytes node_digest` |
| `0x0023` | Metadata | `1 u32 mode`, `2 u32 logical_uid`, `3 u32 logical_gid`, `4 u64 size`, `5 u64 nlink`, `6..8 object atime, mtime, ctime`, `9 optional btime`, `10 list xattrs` |
| `0x0024` | Timespec | `1 i64 seconds`, `2 u32 nanoseconds` |
| `0x0025` | Xattr | `1 bytes name`, `2 bytes value` |
| `0x0026` | Extent | `1 u64 offset`, `2 u64 length` |
| `0x0027` | Child commitment | `1 bytes name`, `2 enum entry_kind`, `3 bytes node_digest` |
| `0x0028` | Runtime-mount commitment | `1 bytes mount_path`, `2 bytes root_digest` |
| `0x0030` | Profile commitment | `1 UTF-8 schema`, `2 UTF-8 profile_id`, `3 UTF-8 EffectIR schema`, `4 UTF-8 shape schema`, `5 u64 required_mask`, `6 bytes wire_magic`, `7 u16 wire_version`, `8 u64 max_canonical_bytes`, `9 u16 max_lookup_candidates`, `10 object policy_digests` |
| `0x0031` | Workspace-identity commitment | `1 UTF-8 schema`, `2 bytes stable_id` |
| `0x0032` | Lexical shape | `1 UTF-8 schema`, `2 UTF-8 profile_id`, `3 bytes profile_digest`, `4 bytes workspace_identity`, `5 object invocation`, `6 object environment` |
| `0x0033` | Executable chain | `1 UTF-8 schema`, `2 bytes requested_path`, `3 list executable_hops` |
| `0x0034` | Executable hop | `1 bytes sandbox_path`, `2 bytes node_digest`, `3 enum resolution` |
| `0x0035` | Effect shape | `1 UTF-8 schema`, `2 bytes profile_digest`, `3 list observation_layouts`, `4 list ambient_layouts`, `5 list ordered_effect_layouts`, `6 enum stdout_class`, `7 enum stderr_class`, `8 enum wait_class`, `9 bool final_workspace_changed` |
| `0x0036` | Observation layout | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum observation_kind`, `4 bytes sandbox_subject` |
| `0x0037` | Ambient layout | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum ambient_kind` |
| `0x0038` | Ordered-effect layout | `1 u64 sequence`, `2 u32 logical_task_id`, `3 enum effect_kind`, `4 bytes sandbox_subject` |
| `0x0039` | Quarantine class | `1 UTF-8 schema`, `2 bytes profile_digest`, `3 bytes workspace_identity`, `4 bytes shape_key`, `5 bytes request_key` |

Trace-counter tags 1 through 18 are, exactly: final sequence, event count,
syscall-event count, seccomp-trace count, ptrace-event count, encoded trace
bytes, task births, task execs, task exits, task reaps, observations, ambient
events, ordered effects, denied operations, unsupported operations, decoder
errors, lost events, and final acknowledgements.

Closed structural enum variants are:

```text
stdin_profile: 1 closed_eof; 2 empty_non_tty_eof
architecture: 1 x86_64
trace_phase: 1 snapshot; 2 isolation; 3 trace; 4 finalize; 5 capture; 6 cleanup
observation_kind: 1 file; 2 directory; 3 absent_path; 4 symlink;
                  5 executable; 6 mapping; 7 metadata
ambient_kind: 1 logical_time; 2 logical_random; 3 logical_pid; 4 sleep; 5 signal
effect_kind: 1 write; 2 truncate; 3 metadata; 4 link; 5 rename; 6 unlink;
             7 mkdir; 8 rmdir; 9 writable_mapping
tree_role: 1 workspace; 2 runtime
manifest_entry_kind: 1 directory; 2 regular; 3 symlink; 4 external_tree
stream_capture: 1 complete; 2 exceeded; 3 incomplete
record_disposition: 1 executed_only; 2 primary_candidate; 3 shadow_candidate
executable_hop_resolution:
  1 symlink { 1 bytes raw_target, 2 bytes normalized_next_path }
  2 terminal_regular {}
effect_shape_stream:
  1 complete {}; 2 exceeded {}; 3 incomplete { 1 u16 ExecuteOnlyCode }
effect_shape_wait:
  1 success {}; 2 exited { 1 u8 code };
  3 signaled { 1 u8 signal, 2 bool core_dumped }
observation_detail:
  1 file { 1 bytes content_digest, 2 u64 byte_count }
  2 directory { 1 bytes membership_digest, 2 u64 entry_count }
  3 absent_path { 1 bytes parent_membership_digest, 2 bytes missing_component }
  4 symlink { 1 bytes target }
  5 executable { 1 bytes node_digest, 2 bytes chain_digest }
  6 mapping { 1 bytes content_digest, 2 u64 offset, 3 u64 length,
              4 u32 protection, 5 u32 flags }
  7 metadata { 1 u64 field_mask, 2 bytes value_digest }
```

Reason enums are distinct closed `u16` namespaces; a code from one namespace
is never accepted as another. Their exact wire values are:

```text
RefusalCode
0001 profile_disabled                  0002 unsupported_os
0003 unsupported_architecture          0004 kernel_tuple_not_enabled
0005 required_kernel_capability_missing
0010 cwd_not_workspace_root            0011 argv0_not_exact
0012 pytest_prefix_not_exact            0013 selector_missing
0014 selector_non_utf8                 0015 selector_option_like
0016 selector_malformed                0017 selector_path_escape
0018 selector_target_missing           0019 selector_target_type
001a forbidden_argument                001b executable_symlink_escape
001c executable_runtime_mismatch       0020 stdin_tty
0021 stdin_nonempty                    0022 stdout_tty
0023 stderr_tty                        0030 environment_malformed
0031 loader_injection_environment      0040 snapshot_required_object_unsupported
0041 snapshot_construction_failed      0050 user_namespace_unavailable
0051 required_namespace_failed         0052 mount_root_failed
0053 close_range_unavailable           0054 seccomp_unavailable
0055 ptrace_unavailable                0056 landlock_unavailable
0057 isolation_preflight_failed

ExecuteOnlyCode
1001 source_mutated_during_snapshot    1002 snapshot_manifest_unstable
1003 unsupported_snapshot_object       1004 sparse_layout_loss
1005 xattr_loss                        1010 runtime_closure_incomplete
1011 descendant_exec_unsealed          1012 executable_mapping_unsupported
1020 syscall_unknown                   1021 trace_operation_unsupported
1022 path_resolution_unsupported       1023 metadata_surface_unsupported
1024 shared_writable_mapping           1025 splice_path_unsupported
1030 time_surface_unsupported          1031 entropy_surface_unsupported
1032 pid_identity_surface_unsupported  1033 concurrent_runnable_workload
1034 scheduling_surface_unsupported    1035 asynchronous_signal
2001 network_attempt                   2002 external_unix_socket_attempt
2003 external_fd_acquired              2004 forbidden_syscall_attempt
2005 namespace_escape_attempt          2006 mount_escape_attempt
2007 process_introspection_attempt     2008 runtime_closure_violation
2009 landlock_policy_violation         200a fd_hygiene_violation
3001 stdout_limit                      3002 stderr_limit
3003 descendant_task_limit             3004 trace_event_limit
3005 trace_encoding_limit              3006 wall_time_limit
3007 snapshot_limit                    3008 branch_limit
3009 scratch_limit                     300a memory_limit
300b open_file_limit                   300c per_file_limit
3010 foreground_nonzero_exit           3011 foreground_signaled
4001 trace_event_lost                  4002 trace_event_malformed
4003 trace_event_out_of_order          4004 trace_event_unknown
4005 counter_overflow                  4006 decoder_disagreement
4007 tracer_restart                    4008 missing_final_ack
4009 descendant_unreaped              400a effect_diff_mismatch
400b final_root_unstable               400c record_encoding_failure
400d capture_failure                   400e cleanup_incomplete
400f cas_corruption

ShadowTerminalCode
0001 handoff_failed                    0002 primary_ineligible
0003 lease_expired                     0004 worker_crashed
0005 shadow_launch_failed              0006 shadow_nonzero_exit
0007 shadow_signaled                   0008 shadow_incomplete
0009 semantic_mismatch                 000a durable_record_failed
000b promotion_compare_and_swap_lost   000c class_already_quarantined
000d superseded_by_promoted_pair

QuarantineCode
0001 comparison_view_mismatch          0002 profile_mismatch
0003 invocation_mismatch               0004 environment_mismatch
0005 snapshot_root_mismatch            0006 platform_policy_mismatch
0007 trace_mask_mismatch               0008 trace_counter_mismatch
0009 observation_mismatch              000a ambient_mismatch
000b ordered_effect_mismatch           000c final_workspace_root_mismatch
000d stdout_mismatch                   000e stderr_mismatch
000f wait_status_mismatch              0010 noncanonical_record
0011 unknown_schema                    0012 unknown_bitmap_bit
0013 forged_complete_mask              0014 record_cas_corruption
0015 stream_cas_corruption             0016 same_request_different_pair
```

## Effect record v2

The top-level EffectIR schema string is `again.effect_ir.v2`. The exact record
layout is:

| Tag | Wire | Field |
|---:|---|---|
| 1 | UTF-8 | schema |
| 2 | bytes | 16-byte record ID |
| 3 | UTF-8 | profile ID; exactly `linux-pytest-v1` |
| 4 | bytes | 32-byte profile digest |
| 5 | bytes | 32-byte shape key |
| 6 | bytes | 32-byte request key |
| 7 | object | invocation |
| 8 | bytes | 32-byte workspace identity |
| 9 | object | environment binding |
| 10 | object | sealed-snapshot identity |
| 11 | object | platform identity |
| 12 | object | trace completeness |
| 13 | list | observations |
| 14 | list | ambient events |
| 15 | list | ordered effects |
| 16 | bytes | 32-byte final workspace root |
| 17 | object | result |
| 18 | enum | immutable record disposition |
| 19 | optional | `u16` execute-only reason |
| 20 | optional | 16-byte primary record ID |
| 21 | optional | reserved comparison-digest slot; must be absent |
| 22 | u64 | creation monotonic nanoseconds |

Tag 21 is intentionally encoded as an absent optional for wire stability. An
EffectRecordV2 has no `comparison_digest` member and a decoder rejects a
present value. A comparison digest belongs only to a promotion row.

Record dispositions describe how an immutable execution record was produced;
they never grant reuse:

- `1 executed_only`: tag 19 must contain an `ExecuteOnlyCode`; tag 20 is
  absent.
- `2 primary_candidate`: tags 19 and 20 are absent.
- `3 shadow_candidate`: tag 19 is absent and tag 20 names its primary record.

Candidate records additionally require all 32 completeness bits, zero
unsupported and violation bits, final sequence equal to event count, balanced
birth/exit/reap counters, zero denied, unsupported, decoder-error, and
lost-event counters, exactly one final acknowledgement, complete stdout and
stderr blobs, and raw wait status zero.
There is no `promoted` record disposition. Promotion authority exists only in
an independently validated promotion row referencing two distinct immutable
candidate records.

Each stream is a closed enum: variant 1 contains a complete blob reference;
variant 2 contains the observed byte count after exceeding its limit; variant
3 contains observed byte count plus an execute-only reason. The process result
stores the raw 32-bit Linux wait word. It does not reduce it to an exit/signal
enum. Only raw value zero is a successful candidate; a stopped, continued, or
otherwise nonfinal wait word is invalid.

## Shape, observation closure, and request identity

The shape schema is exactly `again.linux-pytest.shape.v1`. Shape object
`0x0012` is a top-level object and must carry profile ID
`linux-pytest-v1`. It commits profile digest, workspace identity, the complete
invocation, keyed environment binding, one resolved sandbox target for each
selector in the same order, executable-chain digest, its complete canonical
witness bytes, runtime-forest root,
architecture, capability digest, stable namespace-policy digest, and all ten
policy digests. It deliberately excludes the full workspace root, snapshot and
record IDs, observations, results, effects, and raw namespace inode IDs.

The chain witness decodes as object `0x0033`, is bounded to 40 unique normalized
sandbox paths, starts at `/workspace/.venv/bin/python`, and ends in exactly one
terminal regular-file hop. Every symlink hop binds its raw target, normalized
next path, and manifest node digest. The shape decoder recomputes tag 8 from
tag 14 and prepared/candidate validation checks every hop against the exact
sealed manifest. A standalone digest cannot substitute for this witness.

`ShapeKey` is the tagged-field-1 digest of the complete canonical shape under
`again linux pytest shape v1`. `LexicalShapeKey` is the tagged-field-1 digest
of canonical object `0x0032` under `again linux pytest lexical shape v1`. It
commits the accepted profile and workspace identities, invocation, and keyed
environment before snapshot resolution, but cannot grant lookup, execution,
or reuse authority.

`ProfileDigest` is derived only from canonical profile-commitment object
`0x0030`; callers do not supply it independently. `WorkspaceIdentity` is
derived only from an enrolled nonzero 32-byte stable id in object `0x0031`.
Both commitments and their exact schemas are revalidated wherever they cross
an authority boundary.

An observation dependency commits an operation-specific raw key, closed
observation kind, absolute normalized sandbox subject, and current-value blob
reference. An observation closure is nonempty and strictly sorted by
`(kind as u16, subject bytes, key bytes)`. Byte-identical repeats are merged.
Equal identities with different values are malformed and may not be resolved
by input order. Trace sequence and logical task ID do not appear in this
closure.

`ObservationClosureDigest` is the tagged-field-1 digest of canonical closure
bytes under `again linux pytest observation closure v1`. `RequestKey` uses the
request domain and these exact tagged fields:

```text
1 shape schema bytes
2 profile ID bytes
3 profile digest
4 shape key
5 observation-closure digest
```

Changing a dependency value changes the request key without widening the
shape lookup class.

## Semantic comparison and pair attestation

The comparison view is a separate top-level `0x0011` object:

```text
1 schema, 2 profile_id, 3 profile_digest, 4 shape_key, 5 request_key,
6 invocation, 7 workspace_identity, 8 environment,
9 comparison_snapshot, 10 comparison_platform, 11 trace,
12 observations, 13 ambient_events, 14 ordered_effects,
15 final_workspace_root, 16 result
```

It intentionally excludes record ID, snapshot ID, the six raw per-run
namespace inode IDs, disposition, disposition reason, primary record ID, the
reserved comparison-digest field, creation monotonic time, outer host PIDs,
and duration. The stable namespace-policy digest remains included. No other
semantic field is excluded.

Primary and shadow comparison-view bytes must be exactly equal before pair
attestation. The comparison-rules object contains the literal version
`comparison-view-v1` and the ordered exclusion-name list. Its digest, both
immutable record-CAS blob digests, and both view digests are committed under
the pair-comparison domain. The ordered tagged fields are:

```text
1 rules_digest
2 primary_record_blob_digest
3 shadow_record_blob_digest
4 primary_view_digest
5 shadow_view_digest
```

The two view digests are equal by precondition, but both positions are
retained. Swapping primary and shadow record blobs changes the pair digest.

## Hash frame and domains

Every unkeyed typed digest uses BLAKE3 derive-key mode with a literal domain
string. Its input frame is:

```text
8 bytes  magic = "AGNHSH01"
4 bytes  field_count
repeat field_count times:
  2 bytes  strictly increasing field tag
  8 bytes  field length
  N bytes  field
```

The convenience form assigns tags starting at one. Keyed environment digests
first derive a 32-byte subkey from the domain and the owner-private 32-byte
master key, then apply keyed BLAKE3 to the same hash frame. The subkey is wiped
after use.

| Identity | Domain |
|---|---|
| pair comparison | `again linux pytest effect comparison v1` |
| comparison view | `again linux pytest effect comparison view v1` |
| comparison rules | `again linux pytest effect comparison rules v1` |
| profile digest | `again linux pytest profile v1` |
| workspace identity | `again linux pytest workspace identity v1` |
| full environment | `again linux pytest environment v1` |
| environment names | `again linux pytest environment names v1` |
| environment key ID | `again linux pytest environment key id v1` |
| lexical shape | `again linux pytest lexical shape v1` |
| finalized shape | `again linux pytest shape v1` |
| observation closure | `again linux pytest observation closure v1` |
| request | `again linux pytest request v1` |
| executable chain | `again linux pytest executable chain v1` |
| V2 CAS object | `again linux pytest cas object v1` |
| file content | `again linux pytest file content v1` |
| hard-link group | `again linux pytest hardlink group v1` |
| regular node | `again linux pytest regular node v1` |
| symlink node | `again linux pytest symlink node v1` |
| directory node | `again linux pytest directory node v1` |
| external-tree node | `again linux pytest external tree node v1` |
| workspace Merkle summary | `again linux pytest workspace merkle v1` |
| runtime-forest Merkle summary | `again linux pytest runtime merkle v1` |
| effect shape | `again linux pytest effect shape v1` |
| quarantine class | `again linux pytest quarantine class v1` |

Digest values are exactly 32 bytes. Diagnostic hexadecimal is exactly 64
lowercase characters. Typed IDs are exactly 16 bytes. JSON bitmaps are exactly
16 lowercase hexadecimal characters, while the canonical binary and SQLite
forms use the eight-byte big-endian bit pattern.

## Environment normalization and key lifecycle

Caller environment names and values are raw Unix bytes. Empty names, names
containing NUL or `=`, values containing NUL, and duplicate names are refused.
A caller value for a profile-owned name is wiped and replaced by the table
below. For every other name, the prefixes `LD_`, `DYLD_`, `PYTHON`, and
`PYTEST_` are refused. The following exact non-owned caller names are also
refused: `BASH_ENV`, `ENV`, `GCONV_PATH`, `GLIBC_TUNABLES`, `LOCPATH`,
`MALLOC_TRACE`, `NLSPATH`, and `TZDIR`.

After validation, the entries are sorted by raw name bytes and these exact
profile-owned values replace any same-name caller entry:

```text
COLUMNS=80
HOME=/home/again
LANG=C.UTF-8
LC_ALL=C.UTF-8
LINES=24
LOGNAME=again
NO_COLOR=1
PATH=/workspace/.venv/bin:/usr/bin:/bin
PWD=/workspace
PYTHONDONTWRITEBYTECODE=1
PYTHONHASHSEED=0
PYTHONIOENCODING=utf-8:surrogateescape
PYTHONPYCACHEPREFIX=/tmp/pycache
PYTHONUTF8=1
TEMP=/tmp
TMP=/tmp
TMPDIR=/tmp
TZ=UTC
USER=again
VIRTUAL_ENV=/workspace/.venv
XDG_CACHE_HOME=/tmp/xdg-cache
XDG_CONFIG_HOME=/home/again/.config
XDG_DATA_HOME=/home/again/.local/share
```

The keyed names digest commits to policy digest, entry count, and the sorted
length-prefixed names. The keyed full digest commits to policy digest, entry
count, and sorted length-prefixed name/value pairs. Only key ID, both digests,
entry count, and policy digest enter a record. Raw names, values, the master
key, and derived subkey never enter SQLite, CAS, diagnostic JSON, or debug
output; in-memory secret buffers are wiped on drop.

The owner-private key is a required 32-byte persistent secret at exactly
`<private-state>/keys/linux-pytest-environment-v1`. It is created
descriptor-relatively with `O_CREAT|O_EXCL|O_NOFOLLOW`, mode `0600`, current
uid ownership, and link count one; the file and keys directory are fsynced
before use. An existing key must be a nonsymlink regular file with those owner,
mode, link-count, and exact-length properties. It is never stored in SQLite,
CAS, logs, argv, or diagnostics. Its key ID is the unkeyed domain-separated
digest of the key.

Rotation atomically installs and fsyncs a new 32-byte key and deliberately
creates a new identity partition: old rows cannot match a new key ID. A
missing, unreadable, malformed, or corrupt key when V2 state exists must
disable admission until an explicit operator rotation/recovery action occurs.
Implementations must never silently generate a replacement and thereby make
existing entries look like ordinary misses. The keystore and explicit
rotation command remain implementation deliverables; they are not yet present
in the contract-only module.

## Snapshot manifest and Merkle rules

The top-level schema is
`again.linux-pytest.snapshot-manifest.v1`. Object `0x0020` contains:

```text
1 UTF-8 schema
2 bytes profile_digest
3 bytes workspace_identity
4 object workspace_tree
5 list runtime_trees
6 bytes workspace_root
7 bytes runtime_root
```

The workspace tree is mounted at exactly `/workspace` and has role 1. There
is at least one runtime tree, each has role 2, and runtime trees are strictly
sorted by raw mount-path bytes. Each tree has at least one entry. Entries are
strictly sorted by raw relative path; the first and only root entry has the
empty path and is a directory. Other paths are relative, contain no NUL, have
no empty, `.` or `..` component, and have no leading or trailing slash. Every
nonroot entry is named exactly once by its parent directory commitment.

Metadata commits the complete visible mode, logical uid/gid, size, link count,
atime, mtime, ctime, optional btime, and all visible xattrs. `ctime` and
optional `btime` are stable-source logical metadata: a copied inode's physical
creation/change timestamps need not equal them. Destination validation instead
proves logical bytes and digest, normalized sparse extents, visible xattrs, and
every representable mode/ownership/time field. Nanoseconds are
less than one billion. Xattrs are strictly sorted by raw nonempty NUL-free
name, and both xattr name and value are committed. File-type mode bits must
match the payload kind.

Node digests are recomputed, never trusted from the manifest:

- Directory: tagged fields `1 canonical_metadata`, `2 canonical_children`.
  Children are strictly sorted valid basenames and commit name, entry kind,
  and child node digest.
- Regular file: tagged fields `1 canonical_metadata`, `2 content_digest`,
  `3 canonical_extents`, `4 optional_hardlink_group`. Extents are the exact
  normalized API-visible sequence produced by alternating `SEEK_DATA` and
  `SEEK_HOLE`, clipped to logical size. Present ranges are nonempty, sorted,
  nonoverlapping, overflow-free, and within metadata size; empty/all-hole
  files use an empty list, and a filesystem may report an entire sparse file
  as data. Source and destination sequences must match exactly.
- Symlink: tagged fields `1 canonical_metadata`, `2 raw_target`,
  `3 optional_hardlink_group`. Target is nonempty, NUL-free, and its byte
  length equals metadata size.
- External tree: tagged fields `1 canonical_metadata`, `2 role`,
  `3 target_root`, `4 true`. It is allowed only in the workspace tree, is
  read-only, has runtime role, and has no hard-link group.

Directories and external trees cannot be hard links. Hardlink membership is
scoped to one tree; an observed source link count larger than membership in
that tree is unsupported and cannot be encoded as a valid group. A regular file or
symlink without a hard-link group has link count one. For a group, all member
paths are sorted, the group digest commits that path list, the number of
members equals each member's link count, and every member carries the same
group digest.

The tree root is the node digest of its root entry. The workspace summary is:

```text
derive("again linux pytest workspace merkle v1", workspace_tree.root_digest)
```

The runtime summary is the same derivation under the runtime-Merkle domain
over a canonical list of `(mount_path, root_digest)` commitments. Every
workspace external-tree entry must match exactly one runtime tree at its
joined sandbox mount path, role, and root digest. This sorted forest makes
runtime material part of identity without pretending it is a child of the
writable workspace tree.

The strict manifest encoder, decoder, canonical round-trip check, and
validators are contract code. The regular-file leaf now performs
descriptor-selected reflink or sparse-copy materialization, destination-byte
hashing, extent comparison, and source/destination reopen validation on Linux
x86_64. Full traversal, xattrs, hardlinks, metadata application, publication,
CAS persistence, and runtime mounting remain to be implemented and gated.

## Promotion lookup and V2 storage boundary

Reuse lookup starts with the finalized shape and returns at most 64
promotion rows. Rows are strictly ordered by descending nonzero promotion
monotonic time, then ascending request key. The promotion time cannot precede
either immutable record's creation time; request keys and all primary/shadow
record IDs are unique within the result. For every row, the caller must load and strictly decode both
immutable records, reconstruct the recorded observation closure against a
fresh validation snapshot, recompute the exact request identity, verify all
referenced CAS bytes, and pass the fixed isolated-Python capability probe. A
direct request-key lookup that skips this proof is forbidden. The 64-row cap
is part of v1 behavior, not a caller-selected tuning value.

V2 uses new SQLite tables and a distinct hardened CAS namespace/root. It does
not alias, migrate, query, or garbage-collect through v0/v1 storage. In
particular, the existing 16 MiB object ceiling and legacy GC assumptions are
incompatible with the 512 MiB canonical ceiling and manifest/record graph.
V2 must have its own object-type metadata, size limits, staged-write and fsync
protocol, digest verification, reference graph, quotas, corruption handling,
and reachability-based GC. A V2 database row may reference bytes only after
those bytes are durable in V2 CAS.

Each durable shadow job binds primary record ID, shape key, exact request key,
and complete sealed-snapshot identity, all derived from a verified primary
record. A live shadow envelope is accepted only when its shape and exact
snapshot identity equal the `PreparedPytest` admission and live capability;
the primary record and request key remain immutable job bindings. Host paths
or digest-only reconstruction are forbidden.

Completeness masks are stored as exactly eight-byte big-endian BLOBs, never a
SQLite signed integer or decimal text. Promotion is one compare-and-swap
transaction that references two distinct immutable candidate records and
stores the pair comparison digest. Record rows are never updated to a
promoted disposition. Quarantine is monotonic and exact-request scoped: object
`0x0039` commits profile digest, workspace identity, shape key, and request key.
Object `0x0035` is an effect-shape analytics/future-policy identity and grants
no v1 reuse or generalized-quarantine authority. Any missing, noncanonical, or
corrupt record/blob fails closed.
