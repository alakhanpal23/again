#!/usr/bin/env bash

set -euo pipefail
set +x

script_dir=$(CDPATH= cd -P -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
repository=$(CDPATH= cd -P -- "$script_dir/.." && pwd -P)
production_wrapper="$repository/scripts/again-team-ci.sh"
production_action_runner="$repository/.github/actions/team-run/run.py"
action_metadata="$repository/.github/actions/team-run/action.yml"
workflow="$repository/.github/workflows/team-ci-integration.yml"

test_root=$(mktemp -d "${TMPDIR:-/tmp}/again-team-ci-tests.XXXXXXXX")
test_root=$(CDPATH= cd -P -- "$test_root" && pwd -P)

cleanup_tests() {
  local status=$?
  trap - EXIT
  set +e
  set +x
  if [[ -n ${test_root:-} && ! -L "$test_root" &&
        "$test_root" == */again-team-ci-tests.* ]]; then
    chmod -R u+rwX "$test_root" 2>/dev/null
    rm -rf -- "$test_root"
  fi
  exit "$status"
}
trap cleanup_tests EXIT

fail() {
  printf 'team CI test failure: %s\n' "$1" >&2
  exit 1
}

assert_contains() {
  local haystack=$1
  local needle=$2
  [[ "$haystack" == *"$needle"* ]] || fail "expected fixed output was absent: $needle"
}

assert_not_contains() {
  local haystack=$1
  local needle=$2
  [[ "$haystack" != *"$needle"* ]] || fail "sensitive or suppressed output was present"
}

assert_runner_empty() {
  if find "$runner_temp" -mindepth 1 -print -quit | grep -q .; then
    fail 'the private runner directory was not cleaned'
  fi
}

assert_no_poison() {
  [[ ! -s "$poison_log" ]] || fail 'a hostile PATH, startup, Python, or Cargo hook executed'
}

workspace="$test_root/workspace"
runner_temp="$test_root/runner-temp"
fake_bin="$test_root/fake-bin"
test_source="$test_root/action-source"
trusted_rustup="$test_root/trusted-rustup"
poison_log="$test_root/poison.log"
mkdir -p \
  "$workspace/.git" "$workspace/.cargo" \
  "$runner_temp" "$fake_bin" \
  "$test_source/.github/actions/team-run" \
  "$test_source/scripts" \
  "$test_source/service/src" \
  "$test_source/service/test/fixtures"
chmod 700 "$workspace" "$workspace/.cargo" "$runner_temp" "$fake_bin" "$test_source"
printf 'clean runner fixture\n' > "$workspace/README.md"

# Exercise a byte-identical wrapper except for one deterministic test seam:
# the account-owned rustup path points at the trusted fake below. This lets the
# boundary suite prove isolation without downloading and compiling the entire
# dependency graph for every negative case. Reversing that one substitution
# must recover the production file exactly.
cp "$repository/Cargo.toml" "$repository/Cargo.lock" "$repository/rust-toolchain.toml" "$test_source/"
cp -R "$repository/src" "$test_source/src"
cp "$repository/service/src/util.ts" "$test_source/service/src/util.ts"
for fixture in \
  manifest-v2-canonical-rust.json \
  lookup-bundle-v1-wire.json \
  trust-v1-canonical-rust.json; do
  cp "$repository/service/test/fixtures/$fixture" "$test_source/service/test/fixtures/$fixture"
done
cp "$production_wrapper" "$test_source/scripts/again-team-ci.sh"
cp "$repository/scripts/materialize-team-ci-bundle.py" "$test_source/scripts/"
cp "$production_action_runner" "$test_source/.github/actions/team-run/run.py"
/usr/bin/python3 -I - "$production_wrapper" "$test_source/scripts/again-team-ci.sh" "$trusted_rustup" <<'PY'
from pathlib import Path
import sys

production = Path(sys.argv[1]).read_text(encoding="utf-8")
fixture_path = Path(sys.argv[2])
trusted_rustup = sys.argv[3]
old = 'rustup_bin="$account_home/.cargo/bin/rustup"'
new = f'rustup_bin="{trusted_rustup}"'
if production.count(old) != 1:
    raise SystemExit("production rustup boundary changed")
fixture = production.replace(old, new, 1)
if fixture.replace(new, old, 1) != production:
    raise SystemExit("test wrapper differs by more than the rustup seam")
fixture_path.write_text(fixture, encoding="utf-8")
PY
chmod 700 "$test_source/scripts/again-team-ci.sh"
chmod 600 "$test_source/scripts/materialize-team-ci-bundle.py"
wrapper="$test_source/scripts/again-team-ci.sh"
action_runner="$test_source/.github/actions/team-run/run.py"

# A consumer-workspace Cargo config and inherited wrapper variables must not
# influence the isolated source snapshot or credential-consuming binary.
cat > "$workspace/.cargo/config.toml" <<EOF
[build]
rustc-wrapper = "$test_root/poison-rustc-wrapper"
rustc-workspace-wrapper = "$test_root/poison-rustc-workspace-wrapper"
EOF
for poison_wrapper in poison-rustc-wrapper poison-rustc-workspace-wrapper; do
  cat > "$test_root/$poison_wrapper" <<'SH'
#!/bin/bash -p
printf '%s\n' "$0" >> "$(/usr/bin/dirname "$0")/poison.log"
exit 97
SH
  chmod 700 "$test_root/$poison_wrapper"
done

secret_marker='CI_BUNDLE_SECRET_MUST_NEVER_APPEAR'
bundle_file="$test_root/bundle.json"
cat > "$bundle_file" <<EOF
{
  "schema_version": 1,
  "namespace": "again.team-ci-bundle.v1",
  "profile": {
    "schema_version": 1,
    "namespace": "again.team-profile.v1",
    "endpoint_origin": "https://cache.example.invalid",
    "tenant_id": "test-tenant",
    "repository_id": "test-repository",
    "generation_id": "0123456789abcdef0123456789abcdef",
    "pinned_root_key_id": "test-root-key",
    "pinned_root_public_key_hex": "fd1724385aa0c75b64fb78cd602fa1d991fdebf76b13c58ed702eac835e9f618",
    "lookup_protocol": "legacy_v2",
    "lookup_budget": {
      "max_requests": 5,
      "max_response_bytes": 1048576,
      "total_timeout_ms": 1000
    },
    "publisher": {
      "publish_budget": {
        "max_requests": 4,
        "max_transfer_bytes": 1048576,
        "total_timeout_ms": 1000
      }
    }
  },
  "files": {
    "read_token": "ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "repository_key": {
      "schema_version": 1,
      "namespace": "again.repository-encryption-key.v1",
      "key_id": "$secret_marker",
      "key_hex": "2222222222222222222222222222222222222222222222222222222222222222"
    },
    "sharing_policy": {
      "schema_version": 1,
      "namespace": "again.repository-sharing-policy.v1",
      "version": "ci-policy-v1",
      "include_prefixes": ["README.md"],
      "exclude_prefixes": [".env", ".git", "target"],
      "max_output_bytes": 1048576
    },
    "write_token": "ag1.writer.BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
    "producer_signing_key": {
      "schema_version": 1,
      "namespace": "again.producer-signing-key.v1",
      "key_id": "test-producer-key",
      "producer_id": "test-producer",
      "secret_key_hex": "3333333333333333333333333333333333333333333333333333333333333333"
    }
  }
}
EOF
chmod 600 "$bundle_file"

state_validator="$test_root/validate-state.py"
cat > "$state_validator" <<'PY'
import json
import os
import stat
import sys
from pathlib import Path

profile_path = Path(sys.argv[1])
mode = sys.argv[2]
argv = sys.argv[3:]
root = Path(__file__).resolve().parent
if (
    len(argv) != 5
    or argv[:3] != ["wc", "-c", "two words"]
    or not argv[3].startswith("$(touch ")
    or not argv[3].endswith(")")
    or argv[4] != "README.md"
):
    raise SystemExit("argv boundaries changed")
if "AGAIN_TEAM_CI_BUNDLE_JSON" in os.environ:
    raise SystemExit("bundle leaked to Again")
if "bundle_json" in os.environ:
    raise SystemExit("internal bundle copy leaked to Again")

profile = json.loads(profile_path.read_bytes())
state = profile_path.parent
workspace = (root / "workspace").resolve()
if state == workspace or workspace in state.parents or state in workspace.parents:
    raise SystemExit("state overlaps workspace")

expected_paths = {
    "read_token_file": state / "read.token",
    "repository_key_file": state / "repository-key.json",
    "sharing_policy_file": state / "sharing-policy.json",
    "checkpoint_file": state / "trust-checkpoint.json",
    "runtime_attestation_checkpoint_file": state / "runtime-checkpoint.json",
}
for key, path in expected_paths.items():
    if profile[key] != str(path):
        raise SystemExit(f"wrong rewritten path: {key}")
publisher_paths = {
    "write_token_file": state / "write.token",
    "producer_signing_key_file": state / "producer-signing-key.json",
}
for key, path in publisher_paths.items():
    if profile["publisher"][key] != str(path):
        raise SystemExit(f"wrong publisher path: {key}")

for path in [profile_path, *list(expected_paths.values())[:3], *publisher_paths.values()]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or path.resolve() != path
    ):
        raise SystemExit(f"unsafe materialized file: {path.name}")
for key in ("checkpoint_file", "runtime_attestation_checkpoint_file"):
    if Path(profile[key]).exists():
        raise SystemExit("checkpoint was not fresh")
metadata = state.lstat()
if stat.S_IMODE(metadata.st_mode) != 0o700 or metadata.st_uid != os.geteuid():
    raise SystemExit("state directory is not private")

if Path(profile["read_token_file"]).read_text() != "ag1.reader." + "A" * 32:
    raise SystemExit("read token changed")
if Path(profile["publisher"]["write_token_file"]).read_text() != "ag1.writer." + "B" * 32:
    raise SystemExit("write token changed")
repository_key = json.loads(Path(profile["repository_key_file"]).read_bytes())
if repository_key["key_id"] != "CI_BUNDLE_SECRET_MUST_NEVER_APPEAR":
    raise SystemExit("repository key changed")
policy = json.loads(Path(profile["sharing_policy_file"]).read_bytes())
if policy["include_prefixes"] != ["README.md"]:
    raise SystemExit("sharing policy changed")
producer = json.loads(Path(profile["publisher"]["producer_signing_key_file"]).read_bytes())
if producer["producer_id"] != "test-producer":
    raise SystemExit("producer key changed")

with open(root / "again.log", "a", encoding="utf-8") as output:
    output.write(f"{mode} {profile_path}\n")
PY
chmod 600 "$state_validator"

fake_again="$test_root/fake-again.sh"
cat > "$fake_again" <<'SH'
#!/bin/bash -p
set -euo pipefail
[[ ${AGAIN_TEAM_CI_BUNDLE_JSON+x} != x ]]
[[ ${bundle_json+x} != x ]]
! env | grep -Fq 'CI_BUNDLE_SECRET_MUST_NEVER_APPEAR'
[[ $1 == team ]]
mode=$2
[[ $3 == --profile ]]
profile=$4
private_dir=${profile%/state/profile.json}
runner_temp=${private_dir%/*}
test_root=${runner_temp%/*}
shift 4
case "$mode" in
  inspect)
    [[ $1 == --json && $2 == -- ]]
    shift 2
    /usr/bin/python3 -I "$test_root/validate-state.py" "$profile" inspect "$@"
    printf 'INSPECTION_DOCUMENT_MUST_BE_SUPPRESSED\n'
    if [[ -s "$test_root/inspect.status" ]]; then
      exit "$(<"$test_root/inspect.status")"
    fi
    exit 0
    ;;
  run)
    [[ $1 == -- ]]
    shift
    /usr/bin/python3 -I "$test_root/validate-state.py" "$profile" run "$@"
    printf 'mock-team-output\n'
    if [[ -s "$test_root/run.status" ]]; then
      exit "$(<"$test_root/run.status")"
    fi
    exit 0
    ;;
  *)
    exit 90
    ;;
esac
SH
chmod 700 "$fake_again"

cat > "$trusted_rustup" <<'SH'
#!/bin/bash -p
set -euo pipefail
[[ ${AGAIN_TEAM_CI_BUNDLE_JSON+x} != x ]]
[[ ${bundle_json+x} != x ]]
! env | grep -Fq 'CI_BUNDLE_SECRET_MUST_NEVER_APPEAR'
root=$(/usr/bin/dirname "$0")
case "$1" in
  toolchain)
    [[ $# == 5 ]]
    [[ $2 == install && $3 == 1.88.0 && $4 == --profile && $5 == minimal ]]
    printf 'rustup-ok\n' >> "$root/tool.log"
    ;;
  which)
    [[ $# == 4 ]]
    [[ $2 == --toolchain && $3 == 1.88.0 ]]
    case "$4" in
      cargo|rustc|rustdoc)
        printf '%s\n' "$root/trusted-toolchain/bin/$4"
        ;;
      *)
        exit 95
        ;;
    esac
    ;;
  *)
    exit 96
    ;;
esac
SH
chmod 700 "$trusted_rustup"

mkdir -p "$test_root/trusted-toolchain/bin"
cat > "$test_root/trusted-toolchain/bin/cargo" <<'SH'
#!/bin/bash -p
set -euo pipefail
root=$(CDPATH= cd -P -- "$(/usr/bin/dirname "$0")/../.." && pwd -P)
[[ ${AGAIN_TEAM_CI_BUNDLE_JSON+x} != x ]]
[[ ${bundle_json+x} != x ]]
! /usr/bin/env | /usr/bin/grep -Fq 'CI_BUNDLE_SECRET_MUST_NEVER_APPEAR'
[[ $# == 9 ]]
[[ $1 == build && $2 == --release && $3 == --locked ]]
[[ $4 == --manifest-path && $6 == --target-dir && $8 == --bin && $9 == again ]]
[[ $5 == "$PWD/Cargo.toml" ]]
[[ "$PWD" == "$root/runner-temp"/again-team-ci.*/source ]]
[[ $RUSTC == "$root/trusted-toolchain/bin/rustc" ]]
[[ $RUSTDOC == "$root/trusted-toolchain/bin/rustdoc" ]]
[[ -z ${RUSTC_WRAPPER:-} && -z ${RUSTC_WORKSPACE_WRAPPER:-} ]]
[[ -z ${RUSTFLAGS:-} && -z ${CARGO_ENCODED_RUSTFLAGS:-} ]]
[[ ! -e "$PWD/.cargo/config" && ! -e "$PWD/.cargo/config.toml" ]]
target_dir=$7
/bin/mkdir -p "$target_dir/release"
/bin/cp "$root/fake-again.sh" "$target_dir/release/again"
/bin/chmod 700 "$target_dir/release/again"
printf 'cargo-ok\n' >> "$root/tool.log"
SH
for trusted_tool in cargo rustc rustdoc; do
  if [[ $trusted_tool != cargo ]]; then
    cat > "$test_root/trusted-toolchain/bin/$trusted_tool" <<'SH'
#!/bin/bash -p
exit 99
SH
  fi
  chmod 700 "$test_root/trusted-toolchain/bin/$trusted_tool"
done

# Every name that previously crossed a PATH or interpreter boundary is poison.
# A successful run must leave this log absent/empty.
for poison_name in bash python3 wc cargo rustup; do
  cat > "$fake_bin/$poison_name" <<'SH'
#!/bin/bash -p
root=$(/usr/bin/dirname "$0")
printf '%s\n' "$0" >> "$root/../poison.log"
exit 98
SH
  chmod 700 "$fake_bin/$poison_name"
done

bash_env_poison="$test_root/bash-env-poison.sh"
cat > "$bash_env_poison" <<'SH'
printf 'BASH_ENV\n' >> "$(/usr/bin/dirname "${BASH_SOURCE[0]}")/poison.log"
SH
python_poison="$test_root/python-poison"
mkdir "$python_poison"
cat > "$python_poison/json.py" <<'PY'
from pathlib import Path
Path(__file__).resolve().parent.parent.joinpath("poison.log").write_text("PYTHONPATH\n")
raise RuntimeError("PYTHONPATH poison executed")
PY

tool_log="$test_root/tool.log"
again_log="$test_root/again.log"
literal_path="$test_root/SHOULD_NOT_EXIST"
literal_arg='$(touch '"$literal_path"')'
export TEST_TOOL_LOG="$tool_log"
export TEST_LITERAL_ARG="$literal_arg"
export GITHUB_WORKSPACE="$workspace"
export RUNNER_TEMP="$runner_temp"
export PATH="$fake_bin:$PATH"
export BASH_ENV="$bash_env_poison"
export PYTHONPATH="$python_poison"
export RUSTC_WRAPPER="$test_root/poison-rustc-wrapper"
export RUSTC_WORKSPACE_WRAPPER="$test_root/poison-rustc-workspace-wrapper"

run_direct() {
  export AGAIN_TEAM_CI_BUNDLE_JSON
  AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
  (
    cd "$workspace"
    "$wrapper" -- wc -c 'two words' "$literal_arg" README.md
  )
}

run_direct_with_inherited_allexport() {
  (
    set -a
    export SHELLOPTS
    AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
    cd "$workspace"
    "$wrapper" -- wc -c 'two words' "$literal_arg" README.md
  )
}

run_in_workspace() {
  (
    cd "$workspace"
    "$wrapper" "$@"
  )
}

set +e
output=$(run_direct 2>&1)
status=$?
set -e
if [[ $status != 0 ]]; then
  printf '%s\n' "${output//$secret_marker/[REDACTED]}" >&2
  fail 'clean-runner wrapper invocation failed'
fi
assert_contains "$output" 'mock-team-output'
assert_not_contains "$output" 'INSPECTION_DOCUMENT_MUST_BE_SUPPRESSED'
assert_not_contains "$output" "$secret_marker"
[[ ! -e "$literal_path" ]] || fail 'an argv element was evaluated by a shell'
[[ "$(cat "$tool_log")" == $'rustup-ok\ncargo-ok' ]] || fail 'pinned build commands changed'
[[ "$(cut -d' ' -f1 "$again_log")" == $'inspect\nrun' ]] || fail 'inspect did not precede run'
profile_used=$(head -n 1 "$again_log" | cut -d' ' -f2-)
[[ ! -e "$profile_used" ]] || fail 'the materialized profile survived successful exit'
assert_runner_empty
assert_no_poison

# An exported SHELLOPTS can enable `allexport` in the wrapper's Bash process.
# The copied secret must remain absent from every child environment even under
# that hostile inherited shell option.
: > "$tool_log"
: > "$again_log"
set +e
output=$(run_direct_with_inherited_allexport 2>&1)
status=$?
set -e
[[ $status == 0 ]] || fail 'inherited allexport invocation failed'
assert_contains "$output" 'mock-team-output'
assert_not_contains "$output" "$secret_marker"
[[ "$(cut -d' ' -f1 "$again_log")" == $'inspect\nrun' ]] ||
  fail 'inherited allexport changed the inspect/run boundary'
assert_runner_empty
assert_no_poison

# The action decoder must preserve the same exact argv without invoking a
# command string parser.
: > "$tool_log"
: > "$again_log"
export AGAIN_TEAM_CI_BUNDLE_JSON
AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
export AGAIN_TEAM_CI_ARGV_JSON
AGAIN_TEAM_CI_ARGV_JSON=$(/usr/bin/python3 -I -c 'import json, os; print(json.dumps(["wc", "-c", "two words", os.environ["TEST_LITERAL_ARG"], "README.md"]))')
output=$(
  cd "$workspace"
  /usr/bin/python3 -I "$action_runner" 2>&1
) || fail 'composite-action argv bridge failed'
assert_contains "$output" 'mock-team-output'
assert_not_contains "$output" "$secret_marker"
[[ ! -e "$literal_path" ]] || fail 'the action argv was evaluated by a shell'
assert_runner_empty
assert_no_poison

# On an explicitly selected audited host, exercise the real binary against the
# same clean-runner materialization. The default mock test remains portable to
# Linux and unknown macOS CI images that the production client must reject.
if [[ -n ${AGAIN_TEAM_CI_REAL_BINARY:-} ]]; then
  real_binary=$(CDPATH= cd -P -- "$(dirname -- "$AGAIN_TEAM_CI_REAL_BINARY")" && pwd -P)/$(basename -- "$AGAIN_TEAM_CI_REAL_BINARY")
  [[ -f "$real_binary" && -x "$real_binary" && ! -L "$real_binary" ]] ||
    fail 'AGAIN_TEAM_CI_REAL_BINARY is not a regular executable'
  real_private="$test_root/real-private"
  real_home="$test_root/real-home"
  real_again_home="$test_root/real-again-home"
  mkdir "$real_private" "$real_home" "$real_again_home"
  chmod 700 "$real_private" "$real_home" "$real_again_home"
  /usr/bin/python3 -I "$repository/scripts/materialize-team-ci-bundle.py" "$real_private" < "$bundle_file"
  real_stdout="$test_root/real-inspect.stdout"
  real_stderr="$test_root/real-inspect.stderr"
  set +e
  (
    cd "$repository"
    env -i \
      PATH=/usr/bin:/bin \
      HOME="$real_home" \
      AGAIN_HOME="$real_again_home" \
      "$real_binary" team inspect \
        --profile "$real_private/state/profile.json" \
        --json -- cat README.md
  ) > "$real_stdout" 2> "$real_stderr"
  status=$?
  set -e
  if [[ $status != 0 ]]; then
    output=$(<"$real_stderr")
    printf '%s\n' "${output//$secret_marker/[REDACTED]}" >&2
    fail 'real clean-runner offline inspection failed'
  fi
  output=$(<"$real_stdout")
  assert_contains "$output" '"namespace":"again.team-inspection.v1"'
  assert_not_contains "$output" "$secret_marker"
  [[ ! -s "$real_stderr" ]] || fail 'real offline inspection wrote stderr'
fi

# A failed offline inspection must prevent team run, preserve its nonzero
# status, and clean every materialized file.
: > "$tool_log"
: > "$again_log"
printf '23\n' > "$test_root/inspect.status"
set +e
output=$(run_direct 2>&1)
status=$?
set -e
: > "$test_root/inspect.status"
[[ $status == 23 ]] || fail 'offline inspection status was not preserved'
[[ "$(cut -d' ' -f1 "$again_log")" == 'inspect' ]] || fail 'run occurred after failed inspection'
assert_not_contains "$output" "$secret_marker"
assert_runner_empty

# A team-run failure is the wrapper result, with cleanup still guaranteed.
: > "$again_log"
printf '37\n' > "$test_root/run.status"
set +e
output=$(run_direct 2>&1)
status=$?
set -e
: > "$test_root/run.status"
[[ $status == 37 ]] || fail 'team run status was not preserved'
[[ "$(cut -d' ' -f1 "$again_log")" == $'inspect\nrun' ]] || fail 'run boundary was skipped'
assert_runner_empty

expect_early_failure() {
  local expected=$1
  shift
  : > "$tool_log"
  set +e
  output=$("$@" 2>&1)
  status=$?
  set -e
  [[ $status == 2 ]] || fail 'invalid input did not fail with the wrapper usage status'
  assert_contains "$output" "$expected"
  [[ ! -s "$tool_log" ]] || fail 'invalid input reached the toolchain'
  assert_not_contains "$output" "$secret_marker"
  assert_runner_empty
}

export AGAIN_TEAM_CI_BUNDLE_JSON
AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
expect_early_failure 'literal -- delimiter' "$wrapper" wc -c README.md
export AGAIN_TEAM_CI_BUNDLE_JSON
AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
expect_early_failure 'supported bare executable' "$wrapper" -- /usr/bin/wc -c README.md
export AGAIN_TEAM_CI_BUNDLE_JSON=''
expect_early_failure 'must not be empty' "$wrapper" -- wc -c README.md

# Temp state inside the active workspace is rejected and removed before any
# child tool is launched.
inside_temp="$workspace/runner-temp"
mkdir "$inside_temp"
chmod 700 "$inside_temp"
old_runner_temp=$RUNNER_TEMP
export RUNNER_TEMP="$inside_temp"
export AGAIN_TEAM_CI_BUNDLE_JSON
AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
expect_early_failure 'external to the workspace' run_in_workspace -- wc -c README.md
export RUNNER_TEMP=$old_runner_temp
rmdir "$inside_temp"

# Malformed and path-injecting bundles reach the strict materializer but never
# offline inspection. Mocked build calls are expected; Again calls are not.
expect_bundle_failure() {
  local candidate=$1
  : > "$again_log"
  export AGAIN_TEAM_CI_BUNDLE_JSON
  AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$candidate")
  set +e
  output=$(
    cd "$workspace"
    "$wrapper" -- wc -c 'two words' "$literal_arg" README.md 2>&1
  )
  status=$?
  set -e
  [[ $status == 2 ]] || fail 'invalid bundle did not fail closed'
  [[ ! -s "$again_log" ]] || fail 'invalid bundle reached offline inspection'
  assert_not_contains "$output" "$secret_marker"
  assert_runner_empty
}

malformed="$test_root/malformed.json"
printf '{not-json' > "$malformed"
expect_bundle_failure "$malformed"

path_injection="$test_root/path-injection.json"
/usr/bin/python3 -I - "$bundle_file" "$path_injection" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["profile"]["read_token_file"] = "/tmp/attacker-selected"
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"))
PY
expect_bundle_failure "$path_injection"

unknown_field="$test_root/unknown-field.json"
/usr/bin/python3 -I - "$bundle_file" "$unknown_field" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["files"]["unexpected"] = "value"
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"))
PY
expect_bundle_failure "$unknown_field"

# Python's default JSON decoder accepts duplicate object keys and non-finite
# numeric constants. The bundle decoder must reject both before materializing
# ambiguous state or reaching inspection.
/usr/bin/python3 -I - "$bundle_file" "$test_root" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
root = Path(sys.argv[2])
variants = {
    "duplicate-top.json": source.replace(
        '  "namespace": "again.team-ci-bundle.v1",',
        '  "namespace": "again.team-ci-bundle.v1",\n'
        '  "namespace": "again.team-ci-bundle.v1",',
        1,
    ),
    "duplicate-profile.json": source.replace(
        '    "endpoint_origin": "https://cache.example.invalid",',
        '    "endpoint_origin": "https://cache.example.invalid",\n'
        '    "endpoint_origin": "https://cache.example.invalid",',
        1,
    ),
    "duplicate-files.json": source.replace(
        '    "read_token": "ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",',
        '    "read_token": "ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",\n'
        '    "read_token": "ag1.reader.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",',
        1,
    ),
    "duplicate-nested-key.json": source.replace(
        '      "key_hex": "2222222222222222222222222222222222222222222222222222222222222222"',
        '      "key_hex": "2222222222222222222222222222222222222222222222222222222222222222",\n'
        '      "key_hex": "2222222222222222222222222222222222222222222222222222222222222222"',
        1,
    ),
    "nan.json": source.replace('"max_response_bytes": 1048576', '"max_response_bytes": NaN', 1),
    "infinity.json": source.replace('"max_response_bytes": 1048576', '"max_response_bytes": Infinity', 1),
    "negative-infinity.json": source.replace(
        '"max_response_bytes": 1048576', '"max_response_bytes": -Infinity', 1
    ),
}
for name, payload in variants.items():
    (root / name).write_text(payload, encoding="utf-8")
PY

for strict_json_failure in \
  duplicate-top.json \
  duplicate-profile.json \
  duplicate-files.json \
  duplicate-nested-key.json \
  nan.json \
  infinity.json \
  negative-infinity.json; do
  expect_bundle_failure "$test_root/$strict_json_failure"
done

oversized="$test_root/oversized.json"
/usr/bin/python3 -I - "$oversized" <<'PY'
import sys
open(sys.argv[1], "wb").write(b"x" * 65537)
PY
: > "$tool_log"
export AGAIN_TEAM_CI_BUNDLE_JSON
AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$oversized")
set +e
output=$("$wrapper" -- wc -c README.md 2>&1)
status=$?
set -e
[[ $status == 2 ]] || fail 'oversized bundle did not fail closed'
[[ ! -s "$tool_log" ]] || fail 'oversized bundle reached the toolchain'
assert_not_contains "$output" "$secret_marker"

# The action rejects malformed argv JSON before starting the wrapper.
for invalid_argv in '' '{}' '[]' '["/usr/bin/wc"]' '["wc", 1]' '["wc", "nul\u0000byte"]'; do
  : > "$tool_log"
  export AGAIN_TEAM_CI_BUNDLE_JSON
  AGAIN_TEAM_CI_BUNDLE_JSON=$(<"$bundle_file")
  export AGAIN_TEAM_CI_ARGV_JSON="$invalid_argv"
  set +e
  output=$(/usr/bin/python3 -I "$action_runner" 2>&1)
  status=$?
  set -e
  [[ $status == 2 ]] || fail 'malformed action argv did not fail closed'
  [[ ! -s "$tool_log" ]] || fail 'malformed action argv reached the wrapper'
  assert_not_contains "$output" "$secret_marker"
done

# Static assertions guard against accidentally interpolating secrets into the
# composite run script or weakening workflow permissions.
/usr/bin/python3 -I - \
  "$action_metadata" "$workflow" "$production_wrapper" \
  "$production_action_runner" "$repository/docs/TEAM_CI.md" <<'PY'
from pathlib import Path
import sys

action = Path(sys.argv[1]).read_text(encoding="utf-8")
workflow = Path(sys.argv[2]).read_text(encoding="utf-8")
wrapper = Path(sys.argv[3]).read_text(encoding="utf-8")
action_runner = Path(sys.argv[4]).read_text(encoding="utf-8")
team_ci_docs = Path(sys.argv[5]).read_text(encoding="utf-8")
if "AGAIN_TEAM_CI_BUNDLE_JSON: ${{ inputs.bundle }}" not in action:
    raise SystemExit("action does not pass the masked bundle through env")
run_block = action.split("run: |", 1)[1]
if "inputs.bundle" in run_block or "inputs.argv" in run_block:
    raise SystemExit("action interpolates an input into shell source")
if "permissions:\n  contents: read" not in workflow:
    raise SystemExit("workflow permissions are not read-only")
if "shell: /bin/bash --noprofile --norc -p -euo pipefail {0}" not in action:
    raise SystemExit("action shell is not fixed privileged system Bash")
if 'exec /usr/bin/python3 -I "$GITHUB_ACTION_PATH/run.py"' not in action:
    raise SystemExit("action bridge does not use isolated system Python")
for warning in (
    "immutable, reviewed Again",
    "pull-request-controlled",
    "remote composite action pinned to a reviewed full commit SHA",
    "fresh ephemeral runner",
):
    if warning not in team_ci_docs:
        raise SystemExit(f"team CI trust-boundary warning is missing: {warning}")
if "eval" in wrapper or "base64" in wrapper:
    raise SystemExit("wrapper contains a forbidden command parser/encoding path")
if not wrapper.startswith("#!/bin/bash -p\n"):
    raise SystemExit("wrapper does not use the fixed privileged Bash interpreter")
if 'bundle_bytes=${#bundle_json}' not in wrapper or '| wc -c' in wrapper:
    raise SystemExit("bundle byte length can cross a child-process boundary")
if '"$SYSTEM_PYTHON" -I "$materializer"' not in wrapper:
    raise SystemExit("materializer does not use isolated system Python")
if 'rustup_bin="$account_home/.cargo/bin/rustup"' not in wrapper:
    raise SystemExit("production wrapper does not pin the account rustup path")
if '"$SYSTEM_ENV" -i' not in wrapper or 'RUSTC_WORKSPACE_WRAPPER=' not in wrapper:
    raise SystemExit("Cargo build environment is not isolated")
if '"$SYSTEM_CP" -R "$source_dir/src/." "$build_source/src/"' not in wrapper:
    raise SystemExit("Cargo no longer builds the isolated source snapshot")
if 'os.execve(\n        "/bin/bash"' not in action_runner or '"-p"' not in action_runner:
    raise SystemExit("action bridge no longer pins privileged system Bash")
if '"$again_binary" team inspect --profile "$profile_path" --json -- "$@"' not in wrapper:
    raise SystemExit("offline inspect lost exact delimiter semantics")
if '"$again_binary" team run --profile "$profile_path" -- "$@"' not in wrapper:
    raise SystemExit("team run lost exact delimiter semantics")
PY

/bin/bash -n "$production_wrapper" "$wrapper" "$repository/scripts/test_team_ci.sh"
PYTHONPYCACHEPREFIX="$test_root/pycache" \
  /usr/bin/python3 -I -m py_compile \
    "$production_action_runner" "$action_runner" \
    "$repository/scripts/materialize-team-ci-bundle.py"

printf 'team CI integration tests passed\n'
