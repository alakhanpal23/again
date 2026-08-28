#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/again-package-test.XXXXXXXX")
fixture=$(CDPATH= cd -- "$fixture" && pwd -P)
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    rm -rf "$fixture"
    exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

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

checksum_manifest() {
    directory=$1
    asset=$2
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$directory" && sha256sum "$asset" > SHA256SUMS)
    else
        (cd "$directory" && shasum -a 256 "$asset" > SHA256SUMS)
    fi
}

file_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

make_release() {
    version=$1
    payload=$2
    directory="$fixture/$version"
    asset="again-${version}-${target}.tar.gz"
    mkdir "$directory"
    python3 "$repository/scripts/package_release.py" \
        --binary "$payload" \
        --output "$directory/$asset" \
        --source-date-epoch 1700000000
    checksum_manifest "$directory" "$asset"
}

write_payload "$fixture/payload-one" payload-one
write_payload "$fixture/payload-two" payload-two
make_release v0.1.0 "$fixture/payload-one"
make_release v0.1.1 "$fixture/payload-two"

# Normalized packaging is byte-stable for identical inputs and metadata.
python3 "$repository/scripts/package_release.py" \
    --binary "$fixture/payload-one" \
    --output "$fixture/repeat.tar.gz" \
    --source-date-epoch 1700000000
cmp "$fixture/v0.1.0/again-v0.1.0-${target}.tar.gz" "$fixture/repeat.tar.gz"
test "$(tar -tzf "$fixture/repeat.tar.gz")" = again

# Local development inputs remain explicitly unauthenticated, but malformed
# filesystem and archive shapes are still rejected before destination mutation.
artifact_symlink=$fixture/artifact-directory-symlink
ln -s "$fixture/v0.1.0" "$artifact_symlink"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$artifact_symlink" \
    --dest "$fixture/rejected-artifact-directory/again"; then
    echo "error: installer accepted a symlinked artifact directory" >&2
    exit 1
fi

symlink_input=$fixture/symlink-input
mkdir "$symlink_input"
ln -s "$fixture/v0.1.0/again-v0.1.0-${target}.tar.gz" \
    "$symlink_input/again-v0.1.0-${target}.tar.gz"
ln -s "$fixture/v0.1.0/SHA256SUMS" "$symlink_input/SHA256SUMS"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$symlink_input" \
    --dest "$fixture/rejected-symlink-input/again"; then
    echo "error: installer accepted symlinked release inputs" >&2
    exit 1
fi

duplicate_manifest=$fixture/duplicate-manifest
mkdir "$duplicate_manifest"
cp "$fixture/v0.1.0/again-v0.1.0-${target}.tar.gz" "$duplicate_manifest/"
cp "$fixture/v0.1.0/SHA256SUMS" "$duplicate_manifest/SHA256SUMS"
head -n 1 "$duplicate_manifest/SHA256SUMS" >> "$duplicate_manifest/SHA256SUMS"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$duplicate_manifest" \
    --dest "$fixture/rejected-duplicate-manifest/again"; then
    echo "error: installer accepted a duplicate checksum entry" >&2
    exit 1
fi

trailing_archive=$fixture/trailing-archive
mkdir "$trailing_archive"
cp "$fixture/v0.1.0/again-v0.1.0-${target}.tar.gz" \
    "$trailing_archive/again-v0.1.0-${target}.tar.gz"
printf 'trailing payload\n' >> "$trailing_archive/again-v0.1.0-${target}.tar.gz"
checksum_manifest "$trailing_archive" "again-v0.1.0-${target}.tar.gz"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$trailing_archive" \
    --dest "$fixture/rejected-trailing-archive/again"; then
    echo "error: installer accepted an archive with trailing payload" >&2
    exit 1
fi

symlink_archive=$fixture/symlink-archive
symlink_archive_source=$fixture/symlink-archive-source
mkdir "$symlink_archive" "$symlink_archive_source"
ln -s outside "$symlink_archive_source/again"
tar -czf "$symlink_archive/again-v0.1.0-${target}.tar.gz" \
    -C "$symlink_archive_source" again
checksum_manifest "$symlink_archive" "again-v0.1.0-${target}.tar.gz"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$symlink_archive" \
    --dest "$fixture/rejected-symlink-archive/again"; then
    echo "error: installer accepted a symbolic-link archive member" >&2
    exit 1
fi

real_destination_parent=$fixture/real-destination-parent
symlink_destination_parent=$fixture/symlink-destination-parent
mkdir "$real_destination_parent"
ln -s "$real_destination_parent" "$symlink_destination_parent"
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/v0.1.0" \
    --dest "$symlink_destination_parent/again"; then
    echo "error: installer accepted a symlinked destination parent" >&2
    exit 1
fi
test ! -e "$real_destination_parent/again"

# A destination typo must not rename and replace an existing directory tree.
directory_destination="$fixture/directory-destination"
mkdir "$directory_destination"
write_payload "$directory_destination/user-file" must-remain
if sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/v0.1.0" --dest "$directory_destination"; then
    echo "error: installer unexpectedly replaced a directory destination" >&2
    exit 1
fi
test -d "$directory_destination"
test "$("$directory_destination/user-file")" = must-remain
test ! -e "${directory_destination}.previous"
test ! -e "${directory_destination}.again-install"
test ! -e "${directory_destination}.again-lock"

real_mv=$(command -v mv)
mkdir "$fixture/fake-bin"

# TERM after an initial user's file is renamed to .previous must restore that
# file even when the shell has not yet advanced to its next command.
initial_signal_destination="$fixture/initial-signal/again"
mkdir -p "$(dirname "$initial_signal_destination")"
write_payload "$initial_signal_destination" initial-user-file
signal_sentinel="$fixture/initial-install-signal-fired"
printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    '"$REAL_MV" "$@"' \
    'if [ "$last" = "$SIGNAL_AFTER_DEST" ] && [ ! -e "$SIGNAL_SENTINEL" ]; then' \
    '    : > "$SIGNAL_SENTINEL"' \
    '    kill -TERM "$PPID"' \
    '    sleep 1' \
    'fi' > "$fixture/fake-bin/mv"
chmod 0755 "$fixture/fake-bin/mv"
signal_status=0
REAL_MV="$real_mv" SIGNAL_AFTER_DEST="${initial_signal_destination}.previous" \
    SIGNAL_SENTINEL="$signal_sentinel" PATH="$fixture/fake-bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/v0.1.0" \
    --dest "$initial_signal_destination" || signal_status=$?
test "$signal_status" -eq 143
test -e "$signal_sentinel"
test "$("$initial_signal_destination")" = initial-user-file
test ! -e "${initial_signal_destination}.previous"
test ! -e "${initial_signal_destination}.again-install"
test ! -e "${initial_signal_destination}.again-lock"

# A signal delivered by the mkdir that wins the lock must be deferred until
# ownership is recorded, then cleanly release the owned lock.
lock_signal_destination="$fixture/lock-signal/again"
mkdir -p "$(dirname "$lock_signal_destination")"
write_payload "$lock_signal_destination" lock-signal-user-file
real_mkdir=$(command -v mkdir)
mkdir "$fixture/fake-lock-bin"
signal_sentinel="$fixture/lock-acquire-signal-fired"
printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    '"$REAL_MKDIR" "$@"' \
    'case "$last" in' \
    '    *.again-lock)' \
    '        if [ ! -e "$SIGNAL_SENTINEL" ]; then' \
    '            : > "$SIGNAL_SENTINEL"' \
    '            kill -TERM "$PPID"' \
    '            sleep 1' \
    '        fi' \
    '        ;;' \
    'esac' > "$fixture/fake-lock-bin/mkdir"
chmod 0755 "$fixture/fake-lock-bin/mkdir"
signal_status=0
REAL_MKDIR="$real_mkdir" SIGNAL_SENTINEL="$signal_sentinel" \
    PATH="$fixture/fake-lock-bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/v0.1.0" \
    --dest "$lock_signal_destination" || signal_status=$?
test "$signal_status" -eq 143
test -e "$signal_sentinel"
test "$("$lock_signal_destination")" = lock-signal-user-file
test ! -e "${lock_signal_destination}.previous"
test ! -e "${lock_signal_destination}.again-install"
test ! -e "${lock_signal_destination}.again-lock"

destination="$fixture/bin/again"
mkdir -p "$(dirname "$destination")"
write_payload "$destination" original-user-file
sh "$repository/scripts/install.sh" \
    --version v0.1.0 --artifact-dir "$fixture/v0.1.0" --dest "$destination"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file

# A managed upgrade whose marker commit fails must restore the old binary and
# old marker while preserving the user's original backup.
old_binary_hash=$(file_hash "$destination")
old_marker_hash=$(file_hash "${destination}.again-install")

# Install-marker authority is an exact five-field record. Duplicate or
# appended fields cannot authorize upgrade or uninstall.
cp "${destination}.again-install" "$fixture/valid-install-marker"
printf 'installed_sha256=%s\n' "$old_binary_hash" >> "${destination}.again-install"
if sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/v0.1.1" --dest "$destination"; then
    echo "error: installer accepted a duplicate ownership field" >&2
    exit 1
fi
if sh "$repository/scripts/uninstall.sh" --dest "$destination"; then
    echo "error: uninstaller accepted a duplicate ownership field" >&2
    exit 1
fi
cp "$fixture/valid-install-marker" "${destination}.again-install"
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$($destination)" = payload-one

printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    'case "$last" in *.again-install) exit 73 ;; esac' \
    "exec \"$real_mv\" \"\$@\"" > "$fixture/fake-bin/mv"
chmod 0755 "$fixture/fake-bin/mv"
if PATH="$fixture/fake-bin:$PATH" sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/v0.1.1" --dest "$destination"; then
    echo "error: injected marker failure unexpectedly succeeded" >&2
    exit 1
fi
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file

# A live or stale adjacent lock must make both mutation paths fail closed
# without removing another process's lock or changing managed state.
mkdir "${destination}.again-lock"
if sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/v0.1.1" --dest "$destination"; then
    echo "error: installer unexpectedly ignored an existing lock" >&2
    exit 1
fi
test -d "${destination}.again-lock"
if sh "$repository/scripts/uninstall.sh" --dest "$destination"; then
    echo "error: uninstaller unexpectedly ignored an existing lock" >&2
    exit 1
fi
test -d "${destination}.again-lock"
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file
rmdir "${destination}.again-lock"

# A backup that was replaced with a directory must never be moved into the
# executable destination by upgrade or uninstall rollback logic.
backup_saved="$fixture/original-backup-saved"
mv "${destination}.previous" "$backup_saved"
mkdir "${destination}.previous"
if sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/v0.1.1" --dest "$destination"; then
    echo "error: installer unexpectedly accepted a non-regular backup" >&2
    exit 1
fi
if sh "$repository/scripts/uninstall.sh" --dest "$destination"; then
    echo "error: uninstaller unexpectedly accepted a non-regular backup" >&2
    exit 1
fi
test -d "${destination}.previous"
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test ! -e "${destination}.again-lock"
rmdir "${destination}.previous"
mv "$backup_saved" "${destination}.previous"

# TERM immediately after the replacement binary rename must take the explicit
# nonzero signal path, restore all old state, and release the lock.
signal_sentinel="$fixture/install-signal-fired"
printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    '"$REAL_MV" "$@"' \
    'if [ "$last" = "$SIGNAL_AFTER_DEST" ] && [ ! -e "$SIGNAL_SENTINEL" ]; then' \
    '    : > "$SIGNAL_SENTINEL"' \
    '    kill -TERM "$PPID"' \
    '    sleep 1' \
    'fi' > "$fixture/fake-bin/mv"
chmod 0755 "$fixture/fake-bin/mv"
signal_status=0
REAL_MV="$real_mv" SIGNAL_AFTER_DEST="$destination" \
    SIGNAL_SENTINEL="$signal_sentinel" PATH="$fixture/fake-bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version v0.1.1 --artifact-dir "$fixture/v0.1.1" --dest "$destination" \
    || signal_status=$?
test "$signal_status" -eq 143
test -e "$signal_sentinel"
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file
test ! -e "${destination}.again-lock"

# TERM immediately after uninstall stages the managed binary must likewise
# restore it, preserve the original backup and marker, and release the lock.
signal_sentinel="$fixture/uninstall-signal-fired"
printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    '"$REAL_MV" "$@"' \
    'case "$last" in' \
    '    *.again-remove.*)' \
    '        if [ ! -e "$SIGNAL_SENTINEL" ]; then' \
    '            : > "$SIGNAL_SENTINEL"' \
    '            kill -TERM "$PPID"' \
    '            sleep 1' \
    '        fi' \
    '        ;;' \
    'esac' > "$fixture/fake-bin/mv"
chmod 0755 "$fixture/fake-bin/mv"
signal_status=0
REAL_MV="$real_mv" SIGNAL_SENTINEL="$signal_sentinel" \
    PATH="$fixture/fake-bin:$PATH" \
    sh "$repository/scripts/uninstall.sh" --dest "$destination" \
    || signal_status=$?
test "$signal_status" -eq 143
test -e "$signal_sentinel"
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file
test ! -e "${destination}.again-lock"

# A failed marker move during uninstall must put both the managed binary and
# the original-user backup back in their pre-uninstall locations.
printf '%s\n' '#!/bin/sh' 'last=' 'for value do last=$value; done' \
    'case "$last" in *.again-marker-remove.*) exit 74 ;; esac' \
    "exec \"$real_mv\" \"\$@\"" > "$fixture/fake-bin/mv"
chmod 0755 "$fixture/fake-bin/mv"
if PATH="$fixture/fake-bin:$PATH" sh "$repository/scripts/uninstall.sh" --dest "$destination"; then
    echo "error: injected uninstall failure unexpectedly succeeded" >&2
    exit 1
fi
test "$(file_hash "$destination")" = "$old_binary_hash"
test "$(file_hash "${destination}.again-install")" = "$old_marker_hash"
test "$($destination)" = payload-one
test "$("${destination}.previous")" = original-user-file

sh "$repository/scripts/uninstall.sh" --dest "$destination"
test "$($destination)" = original-user-file
test ! -e "${destination}.again-install"
test ! -e "${destination}.previous"
test ! -e "${destination}.again-lock"

trap - EXIT HUP INT TERM
rm -rf "$fixture"
