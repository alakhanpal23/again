#!/bin/sh
set -eu

sample_count=100
binary=${AGAIN_SUPERVISOR_BINARY:-target/debug/again}
evidence_dir=${AGAIN_SUPERVISOR_EVIDENCE_DIR:-linux-supervisor-qualification}
source_commit=${GITHUB_SHA:-$(git rev-parse HEAD)}
kernel_release=$(uname -r)

if [ "$(uname -s)" != "Linux" ] || [ "$(uname -m)" != "x86_64" ]; then
  echo "error: the supervisor qualification requires Linux x86_64" >&2
  exit 1
fi
if [ ! -x "$binary" ]; then
  echo "error: qualification binary is not executable: $binary" >&2
  exit 1
fi
case "$source_commit" in
  *[!0-9a-f]*)
    echo "error: source commit must be exactly 40 lowercase hexadecimal characters" >&2
    exit 1
    ;;
esac
if [ "${#source_commit}" -ne 40 ]; then
  echo "error: source commit must be exactly 40 lowercase hexadecimal characters" >&2
  exit 1
fi
if [ -e "$evidence_dir" ]; then
  echo "error: refusing to replace existing evidence directory: $evidence_dir" >&2
  exit 1
fi

mkdir -m 700 "$evidence_dir"
: > "$evidence_dir/validated.jsonl"

iteration=1
failed_sample_count=0
while [ "$iteration" -le "$sample_count" ]; do
  sample_dir=$(printf '%s/sample-%03d' "$evidence_dir" "$iteration")
  mkdir -m 700 "$sample_dir"
  set +e
  "$binary" __linux-pytest-supervisor-tree-probe-v1 \
    > "$sample_dir/stdout.raw" \
    2> "$sample_dir/stderr.raw"
  probe_exit=$?
  set -e
  printf '%d\n' "$probe_exit" > "$sample_dir/exit-status.txt"
  validated_record="$sample_dir/validated.json"
  sample_valid=true
  if [ "$probe_exit" -ne 0 ] || [ -s "$sample_dir/stderr.raw" ]; then
    sample_valid=false
  elif ! jq -c -s -e --argjson iteration "$iteration" '
    select(
      length == 1
      and (.[0] |
        (keys == ["profile_id", "refusal", "result", "schema", "scope", "status"])
        and .schema == "again.linux-pytest-supervisor-tree-probe.v1"
        and .profile_id == "linux-pytest-v1"
        and .status == "completed"
        and .refusal == null
        and (.scope | keys == [
          "accepts_command", "effect_ir_authority", "execution_authority", "kind",
          "profile_qualification", "reuse_authority"
        ])
        and .scope.kind == "fixed_no_command_two_task_supervisor"
        and .scope.profile_qualification == false
        and .scope.accepts_command == false
        and .scope.effect_ir_authority == false
        and .scope.execution_authority == false
        and .scope.reuse_authority == false
        and (.result | keys == [
          "accepted_transition_count", "cleanup_complete", "fork_birth_count",
          "fork_delivery_order", "no_return_resolution_count", "ptrace_exit_event_count",
          "seccomp_entry_count", "syscall_exit_count", "task_count", "terminal_reap_count"
        ])
        and (.result.fork_delivery_order == "parent_event_first"
          or .result.fork_delivery_order == "child_stop_first")
        and .result.task_count == 2
        and .result.accepted_transition_count == 11
        and .result.fork_birth_count == 1
        and .result.seccomp_entry_count == 3
        and .result.syscall_exit_count == 1
        and .result.no_return_resolution_count == 2
        and .result.ptrace_exit_event_count == 2
        and .result.terminal_reap_count == 2
        and .result.cleanup_complete == true
      )
    )
    | .[0] + {iteration: $iteration}
  ' "$sample_dir/stdout.raw" > "$validated_record"; then
    sample_valid=false
  fi
  if [ "$sample_valid" = true ]; then
    cat "$validated_record" >> "$evidence_dir/validated.jsonl"
  else
    failed_sample_count=$((failed_sample_count + 1))
  fi
  rm -f "$validated_record"
  iteration=$((iteration + 1))
done

if [ "$failed_sample_count" -ne 0 ]; then
  printf 'error: %d of 100 supervisor samples failed validation; all raw samples were retained.\n' \
    "$failed_sample_count" >&2
  exit 1
fi

pending_report="$evidence_dir/report.json.pending"
if ! jq -s -e --arg source_commit "$source_commit" --arg kernel_release "$kernel_release" '
  select(
    length == 100
    and ([.[].iteration] == [range(1; 101)])
    and ([.[].result.fork_delivery_order] | unique | sort
      == ["child_stop_first", "parent_event_first"])
  )
  | {
      schema: "again.linux-pytest-supervisor-qualification.v1",
      validated_sample_count: length,
      source_commit: $source_commit,
      platform: {
        os: "linux",
        architecture: "x86_64",
        kernel_release: $kernel_release
      },
      first_iteration: .[0].iteration,
      last_iteration: .[-1].iteration,
      fork_delivery_orders: ([.[].result.fork_delivery_order] | unique | sort),
      scope: {
        kind: "fixed_no_command_two_task_supervisor_qualification",
        profile_qualification: false,
        accepts_command: false,
        effect_ir_authority: false,
        execution_authority: false,
        reuse_authority: false
      }
    }
' "$evidence_dir/validated.jsonl" > "$pending_report"; then
  rm -f "$pending_report"
  echo 'error: 100 validated samples did not contain both live fork-delivery orders.' >&2
  exit 1
fi
mv "$pending_report" "$evidence_dir/report.json"

printf 'Validated 100/100 fixed supervisor samples and both kernel fork-delivery orders.\n'
