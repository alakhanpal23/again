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
metadata=${destination}.again-install
backup=${destination}.previous
lock=${destination}.again-lock
[ -d "$destination_dir" ] || {
    echo "error: destination parent is not a directory" >&2
    exit 1
}

removed_tmp=
marker_tmp=
lock_held=0
backup_restored=0
committed=0
had_backup=0

rollback() {
    status=$1
    trap '' HUP INT TERM
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$committed" -eq 0 ]; then
        if [ ! -e "$metadata" ] && [ -n "$marker_tmp" ] && [ -e "$marker_tmp" ]; then
            mv "$marker_tmp" "$metadata"
        fi
        if [ "$had_backup" -eq 1 ] && [ -n "$removed_tmp" ] && [ -e "$removed_tmp" ] \
            && { [ -e "$destination" ] || [ -L "$destination" ]; } \
            && { [ ! -e "$backup" ] && [ ! -L "$backup" ]; }; then
            mv "$destination" "$backup"
        fi
        if [ -n "$removed_tmp" ] && [ -e "$removed_tmp" ] \
            && { [ ! -e "$destination" ] && [ ! -L "$destination" ]; }; then
            mv "$removed_tmp" "$destination"
        fi
    fi
    if [ "$lock_held" -eq 1 ]; then
        if [ -d "$lock" ] && ! rmdir "$lock" 2>/dev/null; then
            echo "warning: could not remove install lock; inspect and remove it manually: $lock" >&2
        fi
        lock_held=0
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
recorded=$(awk -F= '$1 == "installed_sha256" { print $2; exit }' "$metadata")
[ -n "$recorded" ] || {
    echo "error: invalid Again install marker" >&2
    exit 1
}
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
committed=1

rm -f "$removed_tmp" "$marker_tmp"
rmdir "$lock"
lock_held=0
trap - EXIT HUP INT TERM
if [ "$backup_restored" -eq 1 ]; then
    echo "Restored the previous file at $destination"
else
    echo "Removed Again from $destination"
fi
