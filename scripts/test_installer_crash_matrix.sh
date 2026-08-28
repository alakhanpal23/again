#!/bin/sh
# Catchable-signal and one-shot command-fault coverage only. This harness does
# not claim SIGKILL, power-loss, storage-durability, or persistent-fault safety.
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/again-installer-crash-matrix.XXXXXXXX")
fixture=$(CDPATH= cd -- "$fixture" && pwd -P)
socket_fixture=
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ]; then
        echo "error: installer crash matrix failed in ${CURRENT_CASE:-setup} (command status ${RUN_STATUS:-n/a})" >&2
        if [ -n "${CURRENT_CASE:-}" ] && [ -f "$CURRENT_CASE/stderr" ]; then
            sed 's/^/  /' "$CURRENT_CASE/stderr" >&2
        fi
    fi
    rm -rf "$fixture"
    [ -z "$socket_fixture" ] || rm -rf "$socket_fixture"
    exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM
socket_fixture=$(mktemp -d /tmp/ai.XXXXXXXX)

case "$(uname -s):$(uname -m)" in
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    Darwin:x86_64|Darwin:amd64) target=x86_64-apple-darwin ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
    *) exit 0 ;;
esac

write_payload() {
    path=$1
    label=$2
    printf '#!/bin/sh\nprintf "%%s\\n" "%s"\n' "$label" > "$path"
    chmod 0755 "$path"
}

file_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

make_release() {
    release_version=$1
    payload=$2
    release_dir=$fixture/releases/$release_version
    release_asset="again-${release_version}-${target}.tar.gz"
    mkdir -p "$release_dir"
    python3 "$repository/scripts/package_release.py" \
        --binary "$payload" \
        --output "$release_dir/$release_asset" \
        --source-date-epoch 1700000000
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$release_dir" && sha256sum "$release_asset" > SHA256SUMS)
    else
        (cd "$release_dir" && shasum -a 256 "$release_asset" > SHA256SUMS)
    fi
}

mkdir -p "$fixture/releases"
write_payload "$fixture/payload-one" payload-one
write_payload "$fixture/payload-two" payload-two
write_payload "$fixture/user-payload" original-user-file
make_release v0.1.0 "$fixture/payload-one"
make_release v0.1.1 "$fixture/payload-two"

real_cp=$(command -v cp)
real_mv=$(command -v mv)
real_mkdir=$(command -v mkdir)
real_rmdir=$(command -v rmdir)
real_install=$(command -v install)
real_chmod=$(command -v chmod)
real_rm=$(command -v rm)
real_mktemp=$(command -v mktemp)
fake_bin=$fixture/fake-bin
mkdir "$fake_bin"

cat > "$fake_bin/fault-command" <<'EOF'
#!/bin/sh
set -u

tool=${0##*/}
last=
previous=
for value do
    previous=$last
    last=$value
done
point=
case "$tool" in
    cp)
        source_path=$previous
        destination_path=$last
        case "$source_path:$destination_path" in
            */managed-binary:*) point=rollback-binary-copy ;;
            */managed-metadata:*.again-install) point=rollback-marker-copy ;;
            *.again-install:*/managed-metadata) point=snapshot-marker-copy ;;
            *:*/managed-binary) point=snapshot-binary-copy ;;
            */SHA256SUMS:*/SHA256SUMS) point=input-manifest-copy ;;
            *.tar.gz:*.tar.gz) point=input-archive-copy ;;
        esac
        real=$REAL_CP
        ;;
    mv)
        source_path=$previous
        destination_path=$last
        case "$source_path:$destination_path" in
            */.again-marker-remove.*:*.again-install) point=marker-restore-rename ;;
            *.again-install:*/.again-marker-remove.*) point=marker-stage-rename ;;
            */.again-marker.*:*.again-install) point=marker-commit-rename ;;
            */.again-bin.*:*) point=binary-commit-rename ;;
            *:*/.again-remove.*) point=binary-stage-rename ;;
            */.again-remove.*:*) point=binary-restore-rename ;;
            *.previous:*) point=backup-to-destination-rename ;;
            *:*.previous) point=destination-to-backup-rename ;;
        esac
        real=$REAL_MV
        ;;
    mkdir)
        case "$last" in
            *.again-lock) point=lock-mkdir ;;
            */unpack) point=unpack-mkdir ;;
        esac
        real=$REAL_MKDIR
        ;;
    rmdir)
        case "$last" in *.again-lock) point=lock-release ;; esac
        real=$REAL_RMDIR
        ;;
    install)
        case "$last" in */.again-bin.*) point=prepared-binary-install ;; esac
        real=$REAL_INSTALL
        ;;
    chmod)
        case "$last" in
            *.again-lock/owner) point=lock-owner-chmod ;;
            */.again-marker.*) point=prepared-marker-chmod ;;
        esac
        real=$REAL_CHMOD
        ;;
    rm)
        case "$last" in
            */.again-remove.*) point=removed-binary-delete ;;
            */.again-marker-remove.*)
                if [ -s "$last" ]; then
                    point=removed-marker-delete
                else
                    point=staging-placeholders-remove
                fi
                ;;
            */.again-bin.*) point=prepared-binary-remove ;;
            */.again-marker.*) point=prepared-marker-remove ;;
            */again-install.*) point=temp-tree-remove ;;
            "${TEST_DEST:-__unset__}") point=rollback-new-binary-remove ;;
            "${TEST_DEST:-__unset__}.again-install") point=rollback-new-marker-remove ;;
        esac
        real=$REAL_RM
        ;;
    mktemp)
        case "$last" in
            */.again-bin.*) point=binary-temp-create ;;
            */.again-marker-remove.*) point=marker-remove-temp-create ;;
            */.again-marker.*) point=marker-temp-create ;;
            */.again-remove.*) point=remove-temp-create ;;
        esac
        real=$REAL_MKTEMP
        ;;
    *)
        echo "error: unsupported fault command: $tool" >&2
        exit 125
        ;;
esac

if [ -n "$point" ]; then
    printf '%s\n' "$point" >> "$FAULT_LOG"
fi
if [ -n "${FAULT_POINT:-}" ] && [ "$point" = "$FAULT_POINT" ] && \
    [ ! -e "$FAULT_STATE_DIR/fail-$point" ]; then
    : > "$FAULT_STATE_DIR/fail-$point"
    exit 97
fi

status=0
"$real" "$@" || status=$?
[ "$status" -eq 0 ] || exit "$status"

if [ "$point" = lock-mkdir ] && [ -n "${HOLD_LOCK_GATE:-}" ]; then
    : > "$HOLD_LOCK_READY"
    while [ ! -e "$HOLD_LOCK_GATE" ]; do
        sleep 0.01
    done
fi
if [ "$point" = lock-owner-chmod ] && [ "${REPLACE_LOCK:-0}" -eq 1 ] && \
    [ ! -e "$FAULT_STATE_DIR/replaced-lock" ]; then
    : > "$FAULT_STATE_DIR/replaced-lock"
    lock_path=${last%/owner}
    "$REAL_RM" -f "$last"
    "$REAL_RMDIR" "$lock_path"
    "$REAL_MKDIR" "$lock_path"
    : > "$SIGNAL_READY"
    while [ ! -e "$SIGNAL_GATE" ]; do
        sleep 0.01
    done
fi
if [ -n "${SIGNAL_POINT:-}" ] && [ "$point" = "$SIGNAL_POINT" ] && \
    [ ! -e "$FAULT_STATE_DIR/signal-$point" ]; then
    : > "$FAULT_STATE_DIR/signal-$point"
    : > "$SIGNAL_READY"
    while [ ! -e "$SIGNAL_GATE" ]; do
        sleep 0.01
    done
fi
exit 0
EOF
chmod 0755 "$fake_bin/fault-command"
for command_name in cp mv mkdir rmdir install chmod rm mktemp; do
    ln -s fault-command "$fake_bin/$command_name"
done

coverage_log=$fixture/coverage.log
: > "$coverage_log"
case_count=0

run_faulted() {
    script=$1
    destination=$2
    case_dir=$3
    fault_point=$4
    signal_point=$5
    shift 5
    CURRENT_CASE=$case_dir
    mkdir -p "$case_dir/fault-state" "$case_dir/tmp" "$case_dir/home"
    signal_ready=$case_dir/signal-ready
    signal_gate=$case_dir/signal-gate
    status=0
    if [ -n "$signal_point" ]; then
        env \
            REAL_CP="$real_cp" REAL_MV="$real_mv" REAL_MKDIR="$real_mkdir" \
            REAL_RMDIR="$real_rmdir" REAL_INSTALL="$real_install" \
            REAL_CHMOD="$real_chmod" REAL_RM="$real_rm" REAL_MKTEMP="$real_mktemp" \
            FAULT_POINT="$fault_point" SIGNAL_POINT="$signal_point" \
            SIGNAL_READY="$signal_ready" SIGNAL_GATE="$signal_gate" \
            FAULT_STATE_DIR="$case_dir/fault-state" FAULT_LOG="$coverage_log" \
            TEST_DEST="$destination" TMPDIR="$case_dir/tmp" HOME="$case_dir/home" \
            PATH="$fake_bin:$PATH" \
            sh "$script" "$@" > "$case_dir/stdout" 2> "$case_dir/stderr" &
        command_pid=$!
        attempt=0
        while [ ! -e "$signal_ready" ] && [ "$attempt" -lt 1000 ]; do
            if ! kill -0 "$command_pid" 2>/dev/null; then
                break
            fi
            sleep 0.01
            attempt=$((attempt + 1))
        done
        if [ ! -e "$signal_ready" ]; then
            : > "$signal_gate"
            wait "$command_pid" || status=$?
            echo "error: signal point $signal_point was not reached" >&2
            RUN_STATUS=$status
            return 1
        fi
        kill -TERM "$command_pid"
        : > "$signal_gate"
        wait "$command_pid" || status=$?
    else
        env \
            REAL_CP="$real_cp" REAL_MV="$real_mv" REAL_MKDIR="$real_mkdir" \
            REAL_RMDIR="$real_rmdir" REAL_INSTALL="$real_install" \
            REAL_CHMOD="$real_chmod" REAL_RM="$real_rm" REAL_MKTEMP="$real_mktemp" \
            FAULT_POINT="$fault_point" SIGNAL_POINT= \
            SIGNAL_READY="$signal_ready" SIGNAL_GATE="$signal_gate" \
            FAULT_STATE_DIR="$case_dir/fault-state" FAULT_LOG="$coverage_log" \
            TEST_DEST="$destination" TMPDIR="$case_dir/tmp" HOME="$case_dir/home" \
            PATH="$fake_bin:$PATH" \
            sh "$script" "$@" > "$case_dir/stdout" 2> "$case_dir/stderr" || status=$?
    fi
    RUN_STATUS=$status
}

assert_no_ephemeral_state() {
    destination=$1
    case_dir=$2
    [ ! -e "${destination}.again-lock" ] && [ ! -L "${destination}.again-lock" ]
    if find "$case_dir/tmp" -mindepth 1 -print -quit | grep . >/dev/null; then
        echo "error: temporary installer state leaked for $case_dir" >&2
        exit 1
    fi
    if find "$case_dir/home" -mindepth 1 -print -quit | grep . >/dev/null; then
        echo "error: installer wrote unsupported setup state for $case_dir" >&2
        exit 1
    fi
}

prepare_initial_case() {
    case_dir=$1
    destination=$case_dir/bin/again
    mkdir -p "$(dirname "$destination")"
    cp "$fixture/user-payload" "$destination"
    INITIAL_DESTINATION=$destination
    INITIAL_HASH=$(file_hash "$destination")
}

assert_initial_unchanged() {
    destination=$1
    case_dir=$2
    [ -f "$destination" ] && [ ! -L "$destination" ]
    [ "$(file_hash "$destination")" = "$INITIAL_HASH" ]
    [ "$($destination)" = original-user-file ]
    [ ! -e "${destination}.again-install" ] && [ ! -L "${destination}.again-install" ]
    [ ! -e "${destination}.previous" ] && [ ! -L "${destination}.previous" ]
    assert_no_ephemeral_state "$destination" "$case_dir"
}

prepare_managed_case() {
    case_dir=$1
    destination=$case_dir/bin/again
    mkdir -p "$(dirname "$destination")" "$case_dir/tmp" "$case_dir/home"
    cp "$fixture/user-payload" "$destination"
    TMPDIR="$case_dir/tmp" HOME="$case_dir/home" \
        sh "$repository/scripts/install.sh" \
        --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
        --dest "$destination" > /dev/null
    MANAGED_DESTINATION=$destination
    MANAGED_BINARY_HASH=$(file_hash "$destination")
    MANAGED_MARKER_HASH=$(file_hash "${destination}.again-install")
    MANAGED_BACKUP_HASH=$(file_hash "${destination}.previous")
}

assert_managed_unchanged() {
    destination=$1
    case_dir=$2
    [ "$(file_hash "$destination")" = "$MANAGED_BINARY_HASH" ]
    [ "$(file_hash "${destination}.again-install")" = "$MANAGED_MARKER_HASH" ]
    [ "$(file_hash "${destination}.previous")" = "$MANAGED_BACKUP_HASH" ]
    [ "$($destination)" = payload-one ]
    [ "$("${destination}.previous")" = original-user-file ]
    assert_no_ephemeral_state "$destination" "$case_dir"
}

run_initial_matrix_case() {
    mode=$1
    point=$2
    case_dir=$fixture/cases/initial-$mode-$point
    prepare_initial_case "$case_dir"
    if [ "$mode" = failure ]; then
        fault=$point
        signal=
    else
        fault=
        signal=$point
    fi
    run_faulted "$repository/scripts/install.sh" "$INITIAL_DESTINATION" "$case_dir" \
        "$fault" "$signal" \
        --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
        --dest "$INITIAL_DESTINATION"
    [ "$RUN_STATUS" -ne 0 ]
    assert_initial_unchanged "$INITIAL_DESTINATION" "$case_dir"
    case_count=$((case_count + 1))
}

run_managed_matrix_case() {
    mode=$1
    point=$2
    case_dir=$fixture/cases/managed-$mode-$point
    prepare_managed_case "$case_dir"
    if [ "$mode" = failure ]; then
        fault=$point
        signal=
    else
        fault=
        signal=$point
    fi
    run_faulted "$repository/scripts/install.sh" "$MANAGED_DESTINATION" "$case_dir" \
        "$fault" "$signal" \
        --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
        --dest "$MANAGED_DESTINATION"
    [ "$RUN_STATUS" -ne 0 ]
    assert_managed_unchanged "$MANAGED_DESTINATION" "$case_dir"
    case_count=$((case_count + 1))
}

run_uninstall_matrix_case() {
    mode=$1
    point=$2
    case_dir=$fixture/cases/uninstall-$mode-$point
    prepare_managed_case "$case_dir"
    if [ "$mode" = failure ]; then
        fault=$point
        signal=
    else
        fault=
        signal=$point
    fi
    run_faulted "$repository/scripts/uninstall.sh" "$MANAGED_DESTINATION" "$case_dir" \
        "$fault" "$signal" --dest "$MANAGED_DESTINATION"
    [ "$RUN_STATUS" -ne 0 ]
    assert_managed_unchanged "$MANAGED_DESTINATION" "$case_dir"
    case_count=$((case_count + 1))
}

mkdir -p "$fixture/cases"
for mode in failure signal; do
    for point in \
        input-archive-copy input-manifest-copy binary-temp-create \
        marker-temp-create prepared-binary-install prepared-marker-chmod \
        lock-mkdir destination-to-backup-rename binary-commit-rename \
        marker-commit-rename
    do
        run_initial_matrix_case "$mode" "$point"
    done
    for point in \
        input-archive-copy input-manifest-copy binary-temp-create \
        marker-temp-create prepared-binary-install prepared-marker-chmod \
        lock-mkdir snapshot-binary-copy snapshot-marker-copy \
        binary-commit-rename marker-commit-rename
    do
        run_managed_matrix_case "$mode" "$point"
    done
    for point in \
        lock-mkdir remove-temp-create marker-remove-temp-create \
        staging-placeholders-remove binary-stage-rename \
        backup-to-destination-rename marker-stage-rename
    do
        run_uninstall_matrix_case "$mode" "$point"
    done
done

# Rollback commands are faulted independently after a signal enters rollback.
run_nested_installer_case() {
    state_kind=$1
    trigger=$2
    rollback_fault=$3
    case_dir=$fixture/cases/nested-install-$state_kind-$rollback_fault
    if [ "$state_kind" = initial ]; then
        prepare_initial_case "$case_dir"
        destination=$INITIAL_DESTINATION
        version=v0.1.0
        release=v0.1.0
    else
        prepare_managed_case "$case_dir"
        destination=$MANAGED_DESTINATION
        version=v0.1.1
        release=v0.1.1
    fi
    run_faulted "$repository/scripts/install.sh" "$destination" "$case_dir" \
        "$rollback_fault" "$trigger" \
        --version "$version" --artifact-dir "$fixture/releases/$release" \
        --dest "$destination"
    [ "$RUN_STATUS" -ne 0 ]
    if [ "$state_kind" = initial ]; then
        assert_initial_unchanged "$destination" "$case_dir"
    else
        assert_managed_unchanged "$destination" "$case_dir"
    fi
    case_count=$((case_count + 1))
}

run_nested_installer_case initial marker-commit-rename backup-to-destination-rename
run_nested_installer_case initial marker-commit-rename rollback-new-binary-remove
run_nested_installer_case initial marker-commit-rename rollback-new-marker-remove
for rollback_point in \
    rollback-new-binary-remove rollback-binary-copy \
    rollback-new-marker-remove rollback-marker-copy lock-release
do
    run_nested_installer_case managed marker-commit-rename "$rollback_point"
done

run_nested_uninstall_case() {
    rollback_fault=$1
    case_dir=$fixture/cases/nested-uninstall-$rollback_fault
    prepare_managed_case "$case_dir"
    run_faulted "$repository/scripts/uninstall.sh" "$MANAGED_DESTINATION" "$case_dir" \
        "$rollback_fault" marker-stage-rename --dest "$MANAGED_DESTINATION"
    [ "$RUN_STATUS" -ne 0 ]
    assert_managed_unchanged "$MANAGED_DESTINATION" "$case_dir"
    case_count=$((case_count + 1))
}

for rollback_point in \
    marker-restore-rename destination-to-backup-rename \
    binary-restore-rename lock-release
do
    run_nested_uninstall_case "$rollback_point"
done

# Final cleanup failures are retried after a complete commit and therefore do
# not turn a consistent successful operation into a reported failure.
for mode in failure signal; do
    for point in temp-tree-remove lock-release; do
        case_dir=$fixture/cases/install-final-$mode-$point
        prepare_initial_case "$case_dir"
        if [ "$mode" = failure ]; then
            fault=$point
            signal=
        else
            fault=
            signal=$point
        fi
        run_faulted "$repository/scripts/install.sh" "$INITIAL_DESTINATION" "$case_dir" \
            "$fault" "$signal" \
            --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
            --dest "$INITIAL_DESTINATION"
        [ "$RUN_STATUS" -eq 0 ]
        [ "$($INITIAL_DESTINATION)" = payload-one ]
        [ -f "${INITIAL_DESTINATION}.again-install" ]
        [ "$("${INITIAL_DESTINATION}.previous")" = original-user-file ]
        assert_no_ephemeral_state "$INITIAL_DESTINATION" "$case_dir"
        case_count=$((case_count + 1))
    done
done

for mode in failure signal; do
    for point in removed-binary-delete removed-marker-delete lock-release; do
        case_dir=$fixture/cases/uninstall-final-$mode-$point
        prepare_managed_case "$case_dir"
        if [ "$mode" = failure ]; then
            fault=$point
            signal=
        else
            fault=
            signal=$point
        fi
        run_faulted "$repository/scripts/uninstall.sh" "$MANAGED_DESTINATION" "$case_dir" \
            "$fault" "$signal" --dest "$MANAGED_DESTINATION"
        [ "$RUN_STATUS" -eq 0 ]
        [ "$($MANAGED_DESTINATION)" = original-user-file ]
        [ ! -e "${MANAGED_DESTINATION}.again-install" ]
        [ ! -e "${MANAGED_DESTINATION}.previous" ]
        assert_no_ephemeral_state "$MANAGED_DESTINATION" "$case_dir"
        case_count=$((case_count + 1))
    done
done

# Replacing the fully recorded owned lock with an empty foreign directory
# before termination must never let cleanup remove the replacement.
case_dir=$fixture/cases/replaced-lock
CURRENT_CASE=$case_dir
prepare_initial_case "$case_dir"
mkdir -p "$case_dir/fault-state" "$case_dir/tmp" "$case_dir/home"
signal_ready=$case_dir/signal-ready
signal_gate=$case_dir/signal-gate
env REAL_CP="$real_cp" REAL_MV="$real_mv" REAL_MKDIR="$real_mkdir" \
    REAL_RMDIR="$real_rmdir" REAL_INSTALL="$real_install" \
    REAL_CHMOD="$real_chmod" REAL_RM="$real_rm" REAL_MKTEMP="$real_mktemp" \
    FAULT_POINT= SIGNAL_POINT= REPLACE_LOCK=1 \
    SIGNAL_READY="$signal_ready" SIGNAL_GATE="$signal_gate" \
    FAULT_STATE_DIR="$case_dir/fault-state" FAULT_LOG="$coverage_log" \
    TEST_DEST="$INITIAL_DESTINATION" TMPDIR="$case_dir/tmp" HOME="$case_dir/home" \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
    --dest "$INITIAL_DESTINATION" > "$case_dir/stdout" 2> "$case_dir/stderr" &
command_pid=$!
attempt=0
while [ ! -e "$signal_ready" ] && [ "$attempt" -lt 1000 ]; do
    kill -0 "$command_pid" 2>/dev/null || break
    sleep 0.01
    attempt=$((attempt + 1))
done
test -e "$signal_ready"
kill -TERM "$command_pid"
: > "$signal_gate"
status=0
wait "$command_pid" || status=$?
[ "$status" -ne 0 ]
[ "$(file_hash "$INITIAL_DESTINATION")" = "$INITIAL_HASH" ]
[ "$($INITIAL_DESTINATION)" = original-user-file ]
[ ! -e "${INITIAL_DESTINATION}.again-install" ]
[ ! -e "${INITIAL_DESTINATION}.previous" ]
test -d "${INITIAL_DESTINATION}.again-lock"
rmdir "${INITIAL_DESTINATION}.again-lock"
case_count=$((case_count + 1))

# Hostile destination, marker, backup, and lock shapes fail closed. Hard links
# are exercised separately to prove no operation mutates the other link.
make_socket() {
    python3 - "$1" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_UNIX)
sock.bind(sys.argv[1])
sock.close()
PY
}

make_shape() {
    shape=$1
    path=$2
    case "$shape" in
        symlink) ln -s "$fixture/user-payload" "$path" ;;
        directory) mkdir "$path" ;;
        fifo) mkfifo "$path" ;;
        socket) make_socket "$path" ;;
    esac
}

for shape in symlink directory fifo socket; do
    if [ "$shape" = socket ]; then
        case_dir=$socket_fixture/hostile-destination
    else
        case_dir=$fixture/cases/hostile-destination-$shape
    fi
    CURRENT_CASE=$case_dir
    destination=$case_dir/bin/again
    mkdir -p "$(dirname "$destination")"
    make_shape "$shape" "$destination"
    status=0
    sh "$repository/scripts/install.sh" \
        --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
        --dest "$destination" > /dev/null 2>&1 || status=$?
    [ "$status" -ne 0 ]
    [ -e "$destination" ] || [ -L "$destination" ]
    [ ! -e "${destination}.again-install" ]
    [ ! -e "${destination}.previous" ]
    [ ! -e "${destination}.again-lock" ]
    case_count=$((case_count + 1))
done

for location in marker backup; do
    for shape in symlink directory fifo socket; do
        if [ "$shape" = socket ]; then
            case_dir=$socket_fixture/hostile-$location
        else
            case_dir=$fixture/cases/hostile-$location-$shape
        fi
        CURRENT_CASE=$case_dir
        prepare_managed_case "$case_dir"
        if [ "$location" = marker ]; then
            hostile_path=${MANAGED_DESTINATION}.again-install
        else
            hostile_path=${MANAGED_DESTINATION}.previous
        fi
        mv "$hostile_path" "$case_dir/original-$location"
        make_shape "$shape" "$hostile_path"
        binary_before=$(file_hash "$MANAGED_DESTINATION")
        status=0
        sh "$repository/scripts/install.sh" \
            --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
            --dest "$MANAGED_DESTINATION" > /dev/null 2>&1 || status=$?
        [ "$status" -ne 0 ]
        [ "$(file_hash "$MANAGED_DESTINATION")" = "$binary_before" ]
        [ -e "$hostile_path" ] || [ -L "$hostile_path" ]
        [ ! -e "${MANAGED_DESTINATION}.again-lock" ]
        case_count=$((case_count + 1))
    done
done

for marker_mutation in duplicate wrong-hash missing-field; do
    case_dir=$fixture/cases/changed-marker-$marker_mutation
    CURRENT_CASE=$case_dir
    prepare_managed_case "$case_dir"
    marker=${MANAGED_DESTINATION}.again-install
    case "$marker_mutation" in
        duplicate) printf 'installed_sha256=%s\n' "$MANAGED_BINARY_HASH" >> "$marker" ;;
        wrong-hash) sed '5s/=.*/=0000000000000000000000000000000000000000000000000000000000000000/' \
            "$marker" > "$case_dir/marker" && mv "$case_dir/marker" "$marker" ;;
        missing-field) sed '$d' "$marker" > "$case_dir/marker" && mv "$case_dir/marker" "$marker" ;;
    esac
    binary_before=$(file_hash "$MANAGED_DESTINATION")
    backup_before=$(file_hash "${MANAGED_DESTINATION}.previous")
    for script in install uninstall; do
        status=0
        if [ "$script" = install ]; then
            sh "$repository/scripts/install.sh" \
                --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
                --dest "$MANAGED_DESTINATION" > /dev/null 2>&1 || status=$?
        else
            sh "$repository/scripts/uninstall.sh" --dest "$MANAGED_DESTINATION" \
                > /dev/null 2>&1 || status=$?
        fi
        [ "$status" -ne 0 ]
        [ "$(file_hash "$MANAGED_DESTINATION")" = "$binary_before" ]
        [ "$(file_hash "${MANAGED_DESTINATION}.previous")" = "$backup_before" ]
        [ ! -e "${MANAGED_DESTINATION}.again-lock" ]
    done
    case_count=$((case_count + 1))
done

case_dir=$fixture/cases/hard-links
CURRENT_CASE=$case_dir
destination=$case_dir/bin/again
external=$case_dir/external-user-file
mkdir -p "$(dirname "$destination")"
cp "$fixture/user-payload" "$external"
ln "$external" "$destination"
external_before=$(file_hash "$external")
sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
    --dest "$destination" > /dev/null
[ "$(file_hash "$external")" = "$external_before" ]
[ "$(file_hash "${destination}.previous")" = "$external_before" ]
cp "${destination}.again-install" "$case_dir/marker-external"
rm "${destination}.again-install"
ln "$case_dir/marker-external" "${destination}.again-install"
marker_external_before=$(file_hash "$case_dir/marker-external")
sh "$repository/scripts/uninstall.sh" --dest "$destination" > /dev/null
[ "$(file_hash "$external")" = "$external_before" ]
[ "$(file_hash "$case_dir/marker-external")" = "$marker_external_before" ]
[ "$($destination)" = original-user-file ]
case_count=$((case_count + 1))

for shape in directory symlink fifo socket; do
    if [ "$shape" = socket ]; then
        case_dir=$socket_fixture/foreign-lock
    else
        case_dir=$fixture/cases/foreign-lock-$shape
    fi
    CURRENT_CASE=$case_dir
    prepare_managed_case "$case_dir"
    lock=${MANAGED_DESTINATION}.again-lock
    if [ "$shape" = directory ]; then
        mkdir "$lock"
        : > "$lock/foreign-owner"
    else
        make_shape "$shape" "$lock"
    fi
    for script in install uninstall; do
        status=0
        if [ "$script" = install ]; then
            sh "$repository/scripts/install.sh" \
                --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
                --dest "$MANAGED_DESTINATION" > /dev/null 2>&1 || status=$?
        else
            sh "$repository/scripts/uninstall.sh" --dest "$MANAGED_DESTINATION" \
                > /dev/null 2>&1 || status=$?
        fi
        [ "$status" -ne 0 ]
        [ -e "$lock" ] || [ -L "$lock" ]
    done
    case_count=$((case_count + 1))
done

# One held atomic lock excludes both a competing installer and uninstaller;
# after release, the winner alone commits. Repeat with uninstall as the owner.
case_dir=$fixture/cases/concurrent-install
CURRENT_CASE=$case_dir
prepare_initial_case "$case_dir"
mkdir -p "$case_dir/fault-state" "$case_dir/tmp" "$case_dir/home"
gate=$case_dir/release-gate
ready=$case_dir/lock-ready
env REAL_CP="$real_cp" REAL_MV="$real_mv" REAL_MKDIR="$real_mkdir" \
    REAL_RMDIR="$real_rmdir" REAL_INSTALL="$real_install" \
    REAL_CHMOD="$real_chmod" REAL_RM="$real_rm" REAL_MKTEMP="$real_mktemp" \
    FAULT_POINT= SIGNAL_POINT= FAULT_STATE_DIR="$case_dir/fault-state" \
    FAULT_LOG="$coverage_log" TEST_DEST="$INITIAL_DESTINATION" \
    TMPDIR="$case_dir/tmp" HOME="$case_dir/home" PATH="$fake_bin:$PATH" \
    HOLD_LOCK_GATE="$gate" HOLD_LOCK_READY="$ready" \
    sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/releases/v0.1.0" \
    --dest "$INITIAL_DESTINATION" > "$case_dir/winner.out" 2> "$case_dir/winner.err" &
winner_pid=$!
attempt=0
while [ ! -e "$ready" ] && [ "$attempt" -lt 500 ]; do
    sleep 0.01
    attempt=$((attempt + 1))
done
[ -e "$ready" ] && [ -d "${INITIAL_DESTINATION}.again-lock" ]
status=0
sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
    --dest "$INITIAL_DESTINATION" > /dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && [ -d "${INITIAL_DESTINATION}.again-lock" ]
status=0
sh "$repository/scripts/uninstall.sh" --dest "$INITIAL_DESTINATION" \
    > /dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && [ -d "${INITIAL_DESTINATION}.again-lock" ]
: > "$gate"
wait "$winner_pid"
[ "$($INITIAL_DESTINATION)" = payload-one ]
[ ! -e "${INITIAL_DESTINATION}.again-lock" ]
case_count=$((case_count + 1))

case_dir=$fixture/cases/concurrent-uninstall
CURRENT_CASE=$case_dir
prepare_managed_case "$case_dir"
mkdir -p "$case_dir/fault-state"
gate=$case_dir/release-gate
ready=$case_dir/lock-ready
env REAL_CP="$real_cp" REAL_MV="$real_mv" REAL_MKDIR="$real_mkdir" \
    REAL_RMDIR="$real_rmdir" REAL_INSTALL="$real_install" \
    REAL_CHMOD="$real_chmod" REAL_RM="$real_rm" REAL_MKTEMP="$real_mktemp" \
    FAULT_POINT= SIGNAL_POINT= FAULT_STATE_DIR="$case_dir/fault-state" \
    FAULT_LOG="$coverage_log" TEST_DEST="$MANAGED_DESTINATION" \
    TMPDIR="$case_dir/tmp" HOME="$case_dir/home" PATH="$fake_bin:$PATH" \
    HOLD_LOCK_GATE="$gate" HOLD_LOCK_READY="$ready" \
    sh "$repository/scripts/uninstall.sh" --dest "$MANAGED_DESTINATION" \
    > "$case_dir/winner.out" 2> "$case_dir/winner.err" &
winner_pid=$!
attempt=0
while [ ! -e "$ready" ] && [ "$attempt" -lt 500 ]; do
    sleep 0.01
    attempt=$((attempt + 1))
done
[ -e "$ready" ] && [ -d "${MANAGED_DESTINATION}.again-lock" ]
status=0
sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/releases/v0.1.1" \
    --dest "$MANAGED_DESTINATION" > /dev/null 2>&1 || status=$?
[ "$status" -ne 0 ] && [ -d "${MANAGED_DESTINATION}.again-lock" ]
: > "$gate"
wait "$winner_pid"
[ "$($MANAGED_DESTINATION)" = original-user-file ]
[ ! -e "${MANAGED_DESTINATION}.again-install" ]
[ ! -e "${MANAGED_DESTINATION}.previous" ]
[ ! -e "${MANAGED_DESTINATION}.again-lock" ]
case_count=$((case_count + 1))

for required_point in \
    input-archive-copy input-manifest-copy binary-temp-create marker-temp-create \
    prepared-binary-install prepared-marker-chmod lock-mkdir lock-owner-chmod \
    destination-to-backup-rename backup-to-destination-rename \
    snapshot-binary-copy snapshot-marker-copy binary-commit-rename \
    marker-commit-rename rollback-new-binary-remove rollback-binary-copy \
    rollback-new-marker-remove rollback-marker-copy remove-temp-create \
    marker-remove-temp-create staging-placeholders-remove \
    binary-stage-rename marker-stage-rename \
    marker-restore-rename binary-restore-rename removed-binary-delete \
    removed-marker-delete temp-tree-remove lock-release
do
    grep -Fx "$required_point" "$coverage_log" >/dev/null || {
        echo "error: fault matrix did not reach $required_point" >&2
        exit 1
    }
done

printf 'installer catchable-signal/command-fault matrix: %s cases passed\n' "$case_count"
trap - EXIT HUP INT TERM
rm -rf "$fixture"
rm -rf "$socket_fixture"
