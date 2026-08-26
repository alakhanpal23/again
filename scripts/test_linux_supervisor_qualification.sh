#!/bin/sh
set -eu

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/again-supervisor-qualification-test.XXXXXXXX")
trap 'rm -rf "$temporary_root"' EXIT HUP INT TERM
fake_binary="$temporary_root/again"
counter="$temporary_root/counter"

cat > "$fake_binary" <<'EOF'
#!/bin/sh
set -eu
test "$#" -eq 1
test "$1" = "__linux-pytest-supervisor-tree-probe-v1"
counter=${FAKE_SUPERVISOR_COUNTER:?}
iteration=1
if [ -f "$counter" ]; then
  iteration=$(( $(cat "$counter") + 1 ))
fi
printf '%d\n' "$iteration" > "$counter"
if [ "${FAKE_SINGLE_ORDER:-0}" = 1 ] || [ $((iteration % 2)) -eq 0 ]; then
  order=parent_event_first
else
  order=child_stop_first
fi
printf '%s\n' "{\"schema\":\"again.linux-pytest-supervisor-tree-probe.v1\",\"profile_id\":\"linux-pytest-v1\",\"scope\":{\"kind\":\"fixed_no_command_two_task_supervisor\",\"profile_qualification\":false,\"accepts_command\":false,\"effect_ir_authority\":false,\"execution_authority\":false,\"reuse_authority\":false},\"status\":\"completed\",\"result\":{\"fork_delivery_order\":\"$order\",\"task_count\":2,\"accepted_transition_count\":11,\"fork_birth_count\":1,\"seccomp_entry_count\":3,\"syscall_exit_count\":1,\"no_return_resolution_count\":2,\"ptrace_exit_event_count\":2,\"terminal_reap_count\":2,\"cleanup_complete\":true},\"refusal\":null}"
EOF
chmod 700 "$fake_binary"

FAKE_SUPERVISOR_COUNTER="$counter" \
AGAIN_SUPERVISOR_BINARY="$fake_binary" \
AGAIN_SUPERVISOR_EVIDENCE_DIR="$temporary_root/success" \
  scripts/qualify_linux_supervisor.sh > /dev/null
jq -e '
  .validated_sample_count == 100
  and (.source_commit | test("^[0-9a-f]{40}$"))
  and .platform.os == "linux"
  and .platform.architecture == "x86_64"
  and .fork_delivery_orders == ["child_stop_first", "parent_event_first"]
  and .scope.profile_qualification == false
  and .scope.execution_authority == false
  and .scope.reuse_authority == false
' "$temporary_root/success/report.json" > /dev/null

printf '0\n' > "$counter"
set +e
FAKE_SUPERVISOR_COUNTER="$counter" \
FAKE_SINGLE_ORDER=1 \
AGAIN_SUPERVISOR_BINARY="$fake_binary" \
AGAIN_SUPERVISOR_EVIDENCE_DIR="$temporary_root/one-order" \
  scripts/qualify_linux_supervisor.sh > /dev/null 2>&1
one_order_exit=$?
set -e
test "$one_order_exit" -ne 0

printf 'Linux supervisor qualification harness tests passed.\n'
