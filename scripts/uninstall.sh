#!/bin/sh
# Remove only an unmodified binary managed by scripts/install.sh.

set -eu

usage() {
    cat >&2 <<'EOF'
Usage: uninstall.sh --dest PATH

PATH must be the exact destination passed to scripts/install.sh.
EOF
    exit 2
}

destination=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dest)
            [ "$#" -ge 2 ] || usage
            destination=$2
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done
[ -n "$destination" ] || usage
case "$destination" in
    /*) ;;
    *) destination="$(pwd)/$destination" ;;
esac

destination_dir=$(dirname "$destination")
destination_name=$(basename "$destination")
case "$destination_name" in
    ''|.|..)
        echo "error: destination must name one binary file" >&2
        exit 2
        ;;
esac
[ -d "$destination_dir" ] && [ ! -L "$destination_dir" ] || {
    echo "error: destination parent is not a directory" >&2
    exit 1
}
destination_dir=$(CDPATH= cd -- "$destination_dir" && pwd -P)
destination="$destination_dir/$destination_name"
metadata=${destination}.again-install
backup=${destination}.previous
lock=${destination}.again-lock

removed_tmp=
marker_tmp=
lock_held=0
backup_restored=0
committed=0
had_backup=0

retry_remove_file() {
    retry_path=$1
    retry_description=$2
    if ! rm -f "$retry_path" && ! rm -f "$retry_path"; then
        echo "warning: could not $retry_description: $retry_path" >&2
        return 1
    fi
}

retry_move() {
    retry_source=$1
    retry_destination=$2
    retry_description=$3
    if ! mv "$retry_source" "$retry_destination" && \
        ! mv "$retry_source" "$retry_destination"; then
        echo "warning: could not $retry_description" >&2
        return 1
    fi
}

release_owned_lock() {
    if [ ! -d "$lock" ]; then
        lock_held=0
        return 0
    fi
    if rmdir "$lock" 2>/dev/null || rmdir "$lock" 2>/dev/null; then
        lock_held=0
        return 0
    fi
    echo "warning: could not remove install lock; inspect and remove it manually: $lock" >&2
    return 1
}

rollback() {
    status=$1
    trap '' HUP INT TERM
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$committed" -eq 0 ]; then
        if [ ! -e "$metadata" ] && [ -n "$marker_tmp" ] && [ -e "$marker_tmp" ]; then
            retry_move "$marker_tmp" "$metadata" \
                "restore the install marker" || :
        fi
        if [ "$had_backup" -eq 1 ] && [ -n "$removed_tmp" ] && [ -e "$removed_tmp" ] \
            && { [ -e "$destination" ] || [ -L "$destination" ]; } \
            && { [ ! -e "$backup" ] && [ ! -L "$backup" ]; }; then
            retry_move "$destination" "$backup" \
                "restore the managed backup" || :
        fi
        if [ -n "$removed_tmp" ] && [ -e "$removed_tmp" ] \
            && { [ ! -e "$destination" ] && [ ! -L "$destination" ]; }; then
            retry_move "$removed_tmp" "$destination" \
                "restore the managed binary" || :
        fi
    fi
    if [ "$lock_held" -eq 1 ]; then
        release_owned_lock || :
    fi
    exit "$status"
}

arm_signal_traps() {
    trap 'rollback 129' HUP
    trap 'rollback 130' INT
    trap 'rollback 143' TERM
}

acquire_lock() {
    # Defer catchable signals just long enough to record whether this process
    # won the atomic mkdir. This prevents both a leaked owned lock and removal
    # of a lock that belongs to another process.
    pending_signal=0
    lock_acquired=0
    trap 'pending_signal=129' HUP
    trap 'pending_signal=130' INT
    trap 'pending_signal=143' TERM
    if mkdir "$lock" 2>/dev/null; then
        lock_held=1
        lock_acquired=1
    fi
    arm_signal_traps
    if [ "$pending_signal" -ne 0 ]; then
        rollback "$pending_signal"
    fi
    if [ "$lock_acquired" -eq 1 ]; then
        return
    fi
    echo "error: another Again install or uninstall is active, or a stale lock exists: $lock" >&2
    exit 1
}

trap 'rollback "$?"' EXIT
arm_signal_traps
acquire_lock

[ ! -L "$metadata" ] && [ -f "$metadata" ] || {
    echo "error: no regular Again install marker for $destination" >&2
    exit 1
}
[ ! -L "$destination" ] && [ -f "$destination" ] || {
    echo "error: managed destination is missing or not a regular file" >&2
    exit 1
}
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
validate_marker() {
    marker=$1
    [ "$(wc -l < "$marker" | tr -d ' ')" -eq 5 ] &&
        awk -F= '
            NF != 2 { exit 1 }
            NR == 1 && $1 != "version" { exit 1 }
            NR == 2 && $1 != "target" { exit 1 }
            NR == 3 && $1 != "source_commit" { exit 1 }
            NR == 4 && $1 != "archive_sha256" { exit 1 }
            NR == 5 && $1 != "installed_sha256" { exit 1 }
            END { if (NR != 5) exit 1 }
        ' "$marker" &&
        sed -n '1s/^version=//p' "$marker" | grep -Eq "$semver_re" &&
        sed -n '2s/^target=//p' "$marker" | grep -Eq '^(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu)$' &&
        sed -n '3s/^source_commit=//p' "$marker" | grep -Eq '^(local-unattested|[0-9a-f]{40})$' &&
        sed -n '4s/^archive_sha256=//p' "$marker" | grep -Eq '^[0-9a-f]{64}$' &&
        sed -n '5s/^installed_sha256=//p' "$marker" | grep -Eq '^[0-9a-f]{64}$'
}
validate_marker "$metadata" || {
    echo "error: invalid Again install marker" >&2
    exit 1
}
recorded=$(sed -n '5s/^installed_sha256=//p' "$metadata")
if command -v sha256sum >/dev/null 2>&1; then
    current=$(sha256sum "$destination" | awk '{ print tolower($1) }')
else
    current=$(shasum -a 256 "$destination" | awk '{ print tolower($1) }')
fi
[ "$current" = "$recorded" ] || {
    echo "error: destination changed after installation; refusing removal" >&2
    exit 1
}
if [ -e "$backup" ] || [ -L "$backup" ]; then
    [ ! -L "$backup" ] && [ -f "$backup" ] || {
        echo "error: managed backup is not a regular non-symlink file" >&2
        exit 1
    }
fi

removed_tmp=$(mktemp "$destination_dir/.again-remove.XXXXXXXX")
marker_tmp=$(mktemp "$destination_dir/.again-marker-remove.XXXXXXXX")
rm -f "$removed_tmp" "$marker_tmp"
if [ -e "$backup" ] || [ -L "$backup" ]; then
    had_backup=1
fi

mv "$destination" "$removed_tmp"
if [ -e "$backup" ] || [ -L "$backup" ]; then
    mv "$backup" "$destination"
    backup_restored=1
fi
mv "$metadata" "$marker_tmp"
# The staged paths still permit rollback until all three renames complete.
# Publish the commit decision with catchable signals ignored so no signal can
# report failure after the old state has become intentionally unreachable.
trap '' HUP INT TERM
committed=1

retry_remove_file "$removed_tmp" "remove the staged managed binary" || :
retry_remove_file "$marker_tmp" "remove the staged install marker" || :
release_owned_lock || :
trap - EXIT HUP INT TERM
if [ "$backup_restored" -eq 1 ]; then
    echo "Restored the previous file at $destination"
else
    echo "Removed Again from $destination"
fi
