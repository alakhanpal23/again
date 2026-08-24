#!/bin/bash -p

# Run one explicitly delimited argv through the manually provisioned Again
# team alpha. The self-contained CI bundle is accepted only through an
# environment variable so no profile or credential becomes a command-line
# argument.

set +x
set +a
set -euo pipefail
unset BASH_ENV ENV CDPATH GLOBIGNORE
for injected_name in ${!DYLD_@} ${!LD_@}; do
  unset "$injected_name"
done
export LANG=C
export LC_ALL=C

readonly TOOLCHAIN="1.88.0"
readonly MAX_BUNDLE_BYTES=65536
readonly MAX_WIPE_BYTES=8388608
readonly PRIVATE_DIR_PREFIX="again-team-ci."
readonly SYSTEM_PYTHON="/usr/bin/python3"
readonly SYSTEM_ENV="/usr/bin/env"
readonly SYSTEM_GIT="/usr/bin/git"
readonly SYSTEM_STAT="/usr/bin/stat"
readonly SYSTEM_UNAME="/usr/bin/uname"
readonly SYSTEM_ID="/usr/bin/id"
readonly SYSTEM_MKTEMP="/usr/bin/mktemp"
readonly SYSTEM_WC="/usr/bin/wc"
readonly SYSTEM_CHMOD="/bin/chmod"
readonly SYSTEM_CP="/bin/cp"
readonly SYSTEM_DD="/bin/dd"
readonly SYSTEM_MKDIR="/bin/mkdir"
readonly SYSTEM_RM="/bin/rm"

private_dir=""
profile_path=""
state_dir=""
temp_root=""
private_dir_stem=""

fail() {
  printf 'again-team-ci: %s\n' "$1" >&2
  exit 2
}

canonical_directory() {
  (CDPATH= cd -P -- "$1" 2>/dev/null && pwd -P)
}

paths_overlap() {
  local left=$1
  local right=$2
  [[ "$left" == "$right" || "$left" == "$right/"* || "$right" == "$left/"* ]]
}

file_metadata() {
  local path=$1
  case "$("$SYSTEM_UNAME" -s)" in
    Darwin)
      "$SYSTEM_STAT" -f '%Lp %l %u' "$path"
      ;;
    Linux)
      "$SYSTEM_STAT" -c '%a %h %u' -- "$path"
      ;;
    *)
      return 1
      ;;
  esac
}

directory_metadata() {
  local path=$1
  case "$("$SYSTEM_UNAME" -s)" in
    Darwin)
      "$SYSTEM_STAT" -f '%Lp %u' "$path"
      ;;
    Linux)
      "$SYSTEM_STAT" -c '%a %u' -- "$path"
      ;;
    *)
      return 1
      ;;
  esac
}

cleanup() {
  local status=$?
  local byte_count blocks path

  trap - EXIT HUP INT TERM
  set +e
  set +x

  if [[ -n "$state_dir" && "$state_dir" == "$private_dir/state" && ! -L "$state_dir" ]]; then
    for path in \
      "$state_dir/read.token" \
      "$state_dir/repository-key.json" \
      "$state_dir/sharing-policy.json" \
      "$state_dir/write.token" \
      "$state_dir/producer-signing-key.json" \
      "$state_dir/profile.json" \
      "$state_dir/trust-checkpoint.json" \
      "$state_dir/runtime-checkpoint.json"; do
      if [[ -f "$path" && ! -L "$path" ]]; then
        "$SYSTEM_CHMOD" 600 "$path" 2>/dev/null
        byte_count=$("$SYSTEM_WC" -c < "$path" 2>/dev/null)
        if [[ "$byte_count" =~ ^[0-9]+$ && "$byte_count" -gt 0 && "$byte_count" -le "$MAX_WIPE_BYTES" ]]; then
          blocks=$(( (byte_count + 1023) / 1024 ))
          "$SYSTEM_DD" if=/dev/zero of="$path" bs=1024 count="$blocks" conv=notrunc 2>/dev/null
          : > "$path"
        fi
        "$SYSTEM_RM" -f -- "$path" 2>/dev/null
      fi
    done
  fi

  # Only remove the exact directory created by mktemp under the resolved
  # temporary root. Refuse to follow a substituted symlink.
  if [[ -n "$private_dir" && -n "$private_dir_stem" && ! -L "$private_dir" &&
        "$private_dir" == "$private_dir_stem"* &&
        "$private_dir" != "$temp_root" ]]; then
    "$SYSTEM_RM" -rf -- "$private_dir" 2>/dev/null
  fi

  exit "$status"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ ${AGAIN_TEAM_CI_BUNDLE_JSON+x} != x ]]; then
  fail 'AGAIN_TEAM_CI_BUNDLE_JSON must be set from a masked CI secret'
fi

# Keep the value only in a non-exported shell variable. In particular, Rustup,
# Cargo, build scripts, Again, and the requested command do not inherit it.
# `allexport` can be inherited through an exported `SHELLOPTS`, and an
# attacker-controlled environment could also pre-export our internal name.
# Clear both cases before the secret is copied.
unset bundle_json
bundle_json=$AGAIN_TEAM_CI_BUNDLE_JSON
export -n bundle_json
unset AGAIN_TEAM_CI_BUNDLE_JSON

if [[ -z "$bundle_json" ]]; then
  fail 'the team CI bundle secret must not be empty'
fi

bundle_bytes=${#bundle_json}
if (( bundle_bytes == 0 || bundle_bytes > MAX_BUNDLE_BYTES )); then
  fail 'the team CI bundle secret must contain between 1 and 65536 bytes'
fi

if (( $# == 0 )) || [[ "$1" != "--" ]]; then
  fail 'a literal -- delimiter is required before the command argv'
fi
shift
if (( $# == 0 )); then
  fail 'the command argv must not be empty'
fi
if (( $# > 256 )); then
  fail 'the command argv has too many arguments'
fi

case "$1" in
  cat|head|tail|wc|grep|rg)
    ;;
  */*|''|.|..)
    fail 'argv[0] must be a supported bare executable name'
    ;;
  *)
    fail 'argv[0] is outside the current team-alpha command subset'
    ;;
esac

script_dir=$(canonical_directory "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")") ||
  fail 'could not resolve the integration script directory'
source_dir=$(canonical_directory "$script_dir/..") ||
  fail 'could not resolve the Again source directory'
if [[ ! -f "$source_dir/Cargo.toml" || ! -f "$source_dir/Cargo.lock" ]]; then
  fail 'the integration script is not inside a complete Again source tree'
fi

cwd=$(canonical_directory "$PWD") || fail 'the current working directory must exist'
if [[ -n ${GITHUB_WORKSPACE:-} ]]; then
  workspace=$(canonical_directory "$GITHUB_WORKSPACE") ||
    fail 'GITHUB_WORKSPACE must name an existing directory'
else
  [[ -x "$SYSTEM_GIT" ]] || fail 'system Git is required to locate the active workspace'
  workspace_hint=$("$SYSTEM_GIT" -C "$cwd" rev-parse --show-toplevel 2>/dev/null) ||
    fail 'the current working directory must be inside a Git workspace'
  workspace=$(canonical_directory "$workspace_hint") ||
    fail 'could not resolve the active Git workspace'
fi
if [[ "$cwd" != "$workspace" && "$cwd" != "$workspace/"* ]]; then
  fail 'the current working directory must be inside the active workspace'
fi

temp_hint=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
temp_root=$(canonical_directory "$temp_hint") ||
  fail 'the CI temporary root must be an existing directory'
private_dir_stem="${temp_root%/}/$PRIVATE_DIR_PREFIX"

umask 077
private_dir_candidate=$("$SYSTEM_MKTEMP" -d "$private_dir_stem"XXXXXXXX) ||
  fail 'could not create an owner-private temporary directory'
private_dir=$private_dir_candidate
resolved_private_dir=$(canonical_directory "$private_dir_candidate") ||
  fail 'could not resolve the owner-private temporary directory'
if [[ "$resolved_private_dir" != "$private_dir_candidate" ]]; then
  fail 'the owner-private temporary directory must be canonical'
fi
private_dir=$resolved_private_dir
"$SYSTEM_CHMOD" 700 "$private_dir"

if paths_overlap "$private_dir" "$workspace"; then
  fail 'the owner-private temporary directory must be external to the workspace'
fi

current_uid=$("$SYSTEM_ID" -u)
if [[ -L "$private_dir" || ! -d "$private_dir" || ! -O "$private_dir" ||
      "$(directory_metadata "$private_dir")" != "700 $current_uid" ]]; then
  fail 'the temporary directory is not an owner-private canonical directory'
fi

[[ -x "$SYSTEM_PYTHON" ]] || fail 'the system Python 3 interpreter is required'
account_home=$("$SYSTEM_PYTHON" -I -c \
  'import os, pwd; print(pwd.getpwuid(os.geteuid()).pw_dir)') ||
  fail 'could not resolve the runner account home'
if [[ -z "$account_home" || "$account_home" != /* ]]; then
  fail 'the runner account home is not absolute'
fi
rustup_bin="$account_home/.cargo/bin/rustup"
if [[ -L "$rustup_bin" || ! -f "$rustup_bin" || ! -x "$rustup_bin" || ! -O "$rustup_bin" ]]; then
  fail 'rustup must be the runner-owned regular executable at $HOME/.cargo/bin/rustup'
fi
rustup_home="$account_home/.rustup"
if [[ -L "$rustup_home" || ! -d "$rustup_home" || ! -O "$rustup_home" ]]; then
  fail 'the default runner-owned Rustup home is required'
fi

printf 'again-team-ci: installing pinned Rust %s\n' "$TOOLCHAIN" >&2
"$SYSTEM_ENV" -i \
  HOME="$account_home" \
  RUSTUP_HOME="$rustup_home" \
  PATH=/usr/bin:/bin \
  "$rustup_bin" toolchain install "$TOOLCHAIN" --profile minimal

resolve_toolchain_binary() {
  local tool=$1
  local resolved
  resolved=$("$SYSTEM_ENV" -i \
    HOME="$account_home" \
    RUSTUP_HOME="$rustup_home" \
    PATH=/usr/bin:/bin \
    "$rustup_bin" which --toolchain "$TOOLCHAIN" "$tool") ||
    fail "could not resolve pinned $tool"
  if [[ "$resolved" != /* || -L "$resolved" || ! -f "$resolved" ||
        ! -x "$resolved" || ! -O "$resolved" ]]; then
    fail "pinned $tool is not a runner-owned regular executable"
  fi
  printf '%s\n' "$resolved"
}

cargo_bin=$(resolve_toolchain_binary cargo)
rustc_bin=$(resolve_toolchain_binary rustc)
rustdoc_bin=$(resolve_toolchain_binary rustdoc)
toolchain_bin=${cargo_bin%/*}
if [[ "$rustc_bin" != "$toolchain_bin/rustc" ||
      "$rustdoc_bin" != "$toolchain_bin/rustdoc" ]]; then
  fail 'the pinned Rust toolchain executables do not share one directory'
fi

target_dir="$private_dir/target"
build_source="$private_dir/source"
build_home="$private_dir/build-home"
cargo_home="$private_dir/cargo-home"
runtime_home="$private_dir/runtime-home"
runtime_tmp="$private_dir/runtime-tmp"
again_home="$private_dir/again-home"
"$SYSTEM_MKDIR" -m 700 \
  "$build_source" "$build_source/src" \
  "$build_source/service" "$build_source/service/src" \
  "$build_source/service/test" "$build_source/service/test/fixtures" \
  "$build_home" "$cargo_home" \
  "$runtime_home" "$runtime_tmp" "$again_home"

# Build a minimal reviewed source snapshot. In particular, never build from
# the consumer workspace or copy its `.cargo` directory: either would let a
# caller-controlled Cargo config replace rustc or inject a wrapper that emits
# a credential-reading binary.
for source_file in Cargo.toml Cargo.lock rust-toolchain.toml; do
  if [[ -L "$source_dir/$source_file" || ! -f "$source_dir/$source_file" ]]; then
    fail "the trusted source tree is missing $source_file"
  fi
  "$SYSTEM_CP" "$source_dir/$source_file" "$build_source/$source_file"
done
"$SYSTEM_CP" -R "$source_dir/src/." "$build_source/src/"
"$SYSTEM_CP" "$source_dir/service/src/util.ts" "$build_source/service/src/util.ts"
for fixture in \
  manifest-v2-canonical-rust.json \
  lookup-bundle-v1-wire.json \
  trust-v1-canonical-rust.json; do
  "$SYSTEM_CP" \
    "$source_dir/service/test/fixtures/$fixture" \
    "$build_source/service/test/fixtures/$fixture"
done

# Cargo discovers `.cargo/config{,.toml}` in every ancestor of its cwd. The
# fresh snapshot excludes one locally, and this walk prevents a runner-temp or
# account-level ancestor from silently reintroducing one. Same-UID/root races
# after this check remain outside the documented alpha host boundary.
cargo_config_cursor=$build_source
while :; do
  for cargo_config in \
    "$cargo_config_cursor/.cargo/config" \
    "$cargo_config_cursor/.cargo/config.toml"; do
    if [[ -e "$cargo_config" || -L "$cargo_config" ]]; then
      fail 'a Cargo config exists in the isolated build path ancestry'
    fi
  done
  [[ "$cargo_config_cursor" == / ]] && break
  cargo_config_cursor=${cargo_config_cursor%/*}
  [[ -n "$cargo_config_cursor" ]] || cargo_config_cursor=/
done

printf 'again-team-ci: building Again from the locked source tree\n' >&2
(
  cd "$build_source"
  "$SYSTEM_ENV" -i \
    HOME="$build_home" \
    CARGO_HOME="$cargo_home" \
    CARGO_TARGET_DIR="$target_dir" \
    CARGO_INCREMENTAL=0 \
    CARGO_TERM_COLOR=never \
    RUSTUP_HOME="$rustup_home" \
    PATH="$toolchain_bin:/usr/bin:/bin" \
    RUSTC="$rustc_bin" \
    RUSTDOC="$rustdoc_bin" \
    RUSTC_WRAPPER= \
    RUSTC_WORKSPACE_WRAPPER= \
    RUSTFLAGS= \
    CARGO_ENCODED_RUSTFLAGS= \
    "$cargo_bin" build \
      --release \
      --locked \
      --manifest-path "$build_source/Cargo.toml" \
      --target-dir "$target_dir" \
      --bin again
)

again_binary="$target_dir/release/again"
if [[ -L "$again_binary" || ! -f "$again_binary" || ! -x "$again_binary" ]]; then
  fail 'the pinned build did not produce a regular executable'
fi

materializer="$source_dir/scripts/materialize-team-ci-bundle.py"
if [[ -L "$materializer" || ! -f "$materializer" ]]; then
  fail 'the strict CI bundle materializer is missing from the source tree'
fi
printf 'again-team-ci: materializing the owner-private team state\n' >&2
state_dir="$private_dir/state"
printf '%s' "$bundle_json" | "$SYSTEM_PYTHON" -I "$materializer" "$private_dir"
bundle_json=''
unset bundle_json

profile_path="$state_dir/profile.json"

if [[ -L "$profile_path" || ! -f "$profile_path" || ! -O "$profile_path" ||
      "$(file_metadata "$profile_path")" != "600 1 $current_uid" ]]; then
  fail 'the materialized profile is not an owner-private single-link file'
fi

# Apple read-only system tools are resolved only from their fixed system
# directories. The audited Codex-bundled `rg` has a versioned installation
# path, so it retains the caller's search path and relies on Again's exact
# canonical-path and BLAKE3 verifier; an unreviewed candidate fails closed.
execution_path=/usr/bin:/bin
if [[ $1 == rg ]]; then
  execution_path=${PATH:-/usr/bin:/bin}
fi

printf 'again-team-ci: validating the exact request offline\n' >&2
"$SYSTEM_ENV" -i \
  HOME="$runtime_home" \
  TMPDIR="$runtime_tmp" \
  AGAIN_HOME="$again_home" \
  PATH="$execution_path" \
  LANG=C \
  LC_ALL=C \
  "$again_binary" team inspect --profile "$profile_path" --json -- "$@" >/dev/null

printf 'again-team-ci: running the exact validated request\n' >&2
"$SYSTEM_ENV" -i \
  HOME="$runtime_home" \
  TMPDIR="$runtime_tmp" \
  AGAIN_HOME="$again_home" \
  PATH="$execution_path" \
  LANG=C \
  LC_ALL=C \
  "$again_binary" team run --profile "$profile_path" -- "$@"
