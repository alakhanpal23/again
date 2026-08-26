#!/bin/sh
# Verify and install an Again release without executing downloaded bytes.

set -eu

MAX_ARCHIVE_BYTES=67108864
MAX_CHECKSUM_BYTES=1048576

usage() {
    cat >&2 <<'EOF'
Usage: install.sh --version TAG --dest PATH [--base-url URL | --artifact-dir DIR]

TAG must be a release tag such as v0.1.0. PATH is the exact binary destination.
With --artifact-dir, a local development directory must contain the archive and
SHA256SUMS. Without it, assets are downloaded from the Again GitHub release URL
and the GitHub CLI authenticates their release-workflow provenance.
EOF
    exit 2
}

version=
destination=
base_url=${AGAIN_RELEASE_BASE_URL:-https://github.com/alakhanpal23/again/releases/download}
artifact_dir=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift 2
            ;;
        --dest)
            [ "$#" -ge 2 ] || usage
            destination=$2
            shift 2
            ;;
        --base-url)
            [ "$#" -ge 2 ] || usage
            base_url=$2
            shift 2
            ;;
        --artifact-dir)
            [ "$#" -ge 2 ] || usage
            artifact_dir=$2
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

[ -n "$version" ] && [ -n "$destination" ] || usage
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
printf '%s\n' "$version" | grep -Eq "$semver_re" || {
    echo "error: invalid release tag" >&2
    exit 2
}
if [ -z "$artifact_dir" ]; then
    case "$base_url" in
        https://*) ;;
        *)
            echo "error: remote release base URL must use HTTPS" >&2
            exit 2
            ;;
    esac
    command -v gh >/dev/null 2>&1 || {
        echo "error: GitHub CLI with attestation support is required for remote installation" >&2
        exit 1
    }
fi

host_os=$(uname -s)
host_arch=$(uname -m)
case "$host_os:$host_arch" in
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    Darwin:x86_64|Darwin:amd64) target=x86_64-apple-darwin ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
    *)
        echo "error: unsupported host $host_os/$host_arch" >&2
        exit 1
        ;;
esac
if [ "$host_os" = Linux ]; then
    command -v ldd >/dev/null 2>&1 || {
        echo "error: the current Linux release requires glibc; no ldd was found" >&2
        exit 1
    }
    ldd_version=$(ldd --version 2>&1 || true)
    case "$ldd_version" in
        *musl*|*MUSL*)
            echo "error: musl Linux is not supported by the current GNU release" >&2
            exit 1
            ;;
    esac
fi

case "$destination" in
    /*) ;;
    *) destination="$(pwd)/$destination" ;;
esac
destination_dir=$(dirname "$destination")
mkdir -p "$destination_dir"
[ -d "$destination_dir" ] || {
    echo "error: destination parent is not a directory" >&2
    exit 1
}

metadata=${destination}.again-install
backup=${destination}.previous
lock=${destination}.again-lock
asset="again-${version}-${target}.tar.gz"
tmp=$(mktemp -d "${TMPDIR:-/tmp}/again-install.XXXXXXXX")
installed_tmp=
metadata_tmp=
lock_held=0
managed_upgrade=0
moved_backup=0
prepared_binary=0
prepared_metadata=0
committed=0

cleanup() {
    status=$1
    trap '' HUP INT TERM
    trap - EXIT
    if [ "$status" -ne 0 ] && [ "$committed" -eq 0 ]; then
        binary_was_replaced=0
        metadata_was_replaced=0
        if [ "$prepared_binary" -eq 1 ] && [ -n "$installed_tmp" ] && [ ! -e "$installed_tmp" ]; then
            binary_was_replaced=1
        fi
        if [ "$prepared_metadata" -eq 1 ] && [ -n "$metadata_tmp" ] && [ ! -e "$metadata_tmp" ]; then
            metadata_was_replaced=1
        fi
        if [ "$binary_was_replaced" -eq 1 ]; then
            rm -f "$destination"
            if [ "$managed_upgrade" -eq 1 ] && [ -f "$tmp/managed-binary" ]; then
                cp -p "$tmp/managed-binary" "$destination"
            elif [ "$moved_backup" -eq 1 ] && { [ -e "$backup" ] || [ -L "$backup" ]; }; then
                mv "$backup" "$destination"
            fi
        elif [ "$moved_backup" -eq 1 ] && { [ -e "$backup" ] || [ -L "$backup" ]; }; then
            mv "$backup" "$destination"
        fi
        if [ "$metadata_was_replaced" -eq 1 ]; then
            rm -f "$metadata"
            if [ "$managed_upgrade" -eq 1 ] && [ -f "$tmp/managed-metadata" ]; then
                cp -p "$tmp/managed-metadata" "$metadata"
            fi
        fi
    fi
    [ -z "$installed_tmp" ] || rm -f "$installed_tmp"
    [ -z "$metadata_tmp" ] || rm -f "$metadata_tmp"
    rm -rf "$tmp"
    if [ "$lock_held" -eq 1 ]; then
        if [ -d "$lock" ] && ! rmdir "$lock" 2>/dev/null; then
            echo "warning: could not remove install lock; inspect and remove it manually: $lock" >&2
        fi
        lock_held=0
    fi
    exit "$status"
}
arm_signal_traps() {
    trap 'cleanup 129' HUP
    trap 'cleanup 130' INT
    trap 'cleanup 143' TERM
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
        cleanup "$pending_signal"
    fi
    if [ "$lock_acquired" -eq 1 ]; then
        return
    fi
    echo "error: another Again install or uninstall is active, or a stale lock exists: $lock" >&2
    exit 1
}

trap 'cleanup "$?"' EXIT
arm_signal_traps

download() {
    url=$1
    output=$2
    if command -v curl >/dev/null 2>&1; then
        curl --fail --location --proto '=https' --proto-redir '=https' \
            --connect-timeout 10 --max-time 120 --silent --show-error \
            --output "$output" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --https-only --timeout=30 --tries=2 --quiet --output-document="$output" "$url"
    else
        echo "error: curl or wget is required for remote installation" >&2
        exit 1
    fi
}

bounded_file() {
    path=$1
    maximum=$2
    description=$3
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "error: $description is not a regular file" >&2
        exit 1
    }
    size=$(wc -c < "$path" | tr -d ' ')
    [ "$size" -le "$maximum" ] || {
        echo "error: $description exceeds the size limit" >&2
        exit 1
    }
}

if [ -n "$artifact_dir" ]; then
    cp "$artifact_dir/$asset" "$tmp/$asset"
    cp "$artifact_dir/SHA256SUMS" "$tmp/SHA256SUMS"
else
    download "${base_url%/}/${version}/${asset}" "$tmp/$asset"
    download "${base_url%/}/${version}/SHA256SUMS" "$tmp/SHA256SUMS"
fi
bounded_file "$tmp/$asset" "$MAX_ARCHIVE_BYTES" "release archive"
bounded_file "$tmp/SHA256SUMS" "$MAX_CHECKSUM_BYTES" "checksum manifest"

if [ -z "$artifact_dir" ]; then
    verify_attestation() {
        subject=$1
        description=$2
        gh attestation verify "$subject" \
            --repo alakhanpal23/again \
            --signer-workflow alakhanpal23/again/.github/workflows/release.yml \
            --source-ref "refs/tags/$version" \
            --deny-self-hosted-runners >/dev/null || {
            echo "error: publisher attestation verification failed for $description" >&2
            exit 1
        }
    }
    verify_attestation "$tmp/SHA256SUMS" "checksum manifest"
    verify_attestation "$tmp/$asset" "release archive"
fi

expected=$(awk -v file="$asset" '
    length($1) == 64 && tolower($1) !~ /[^0-9a-f]/ && ($2 == file || $2 == "*" file) {
        print tolower($1); exit
    }
' "$tmp/SHA256SUMS")
[ -n "$expected" ] || {
    echo "error: SHA256SUMS has no valid entry for $asset" >&2
    exit 1
}
if command -v sha256sum >/dev/null 2>&1; then
    actual=$(sha256sum "$tmp/$asset" | awk '{ print tolower($1) }')
else
    actual=$(shasum -a 256 "$tmp/$asset" | awk '{ print tolower($1) }')
fi
[ "$actual" = "$expected" ] || {
    echo "error: checksum mismatch for $asset" >&2
    exit 1
}

members=$(tar -tzf "$tmp/$asset")
[ "$members" = "again" ] || {
    echo "error: archive must contain exactly one top-level member named again" >&2
    exit 1
}
mkdir "$tmp/unpack"
(ulimit -f 131072; tar -xzf "$tmp/$asset" -C "$tmp/unpack")
[ ! -L "$tmp/unpack/again" ] && [ -f "$tmp/unpack/again" ] && [ -x "$tmp/unpack/again" ] || {
    echo "error: archive does not contain a regular executable named again" >&2
    exit 1
}

installed_tmp=$(mktemp "$destination_dir/.again-bin.XXXXXXXX")
metadata_tmp=$(mktemp "$destination_dir/.again-marker.XXXXXXXX")
install -m 0755 "$tmp/unpack/again" "$installed_tmp"
prepared_binary=1
if command -v sha256sum >/dev/null 2>&1; then
    installed_hash=$(sha256sum "$installed_tmp" | awk '{ print tolower($1) }')
else
    installed_hash=$(shasum -a 256 "$installed_tmp" | awk '{ print tolower($1) }')
fi
{
    printf 'version=%s\n' "$version"
    printf 'target=%s\n' "$target"
    printf 'installed_sha256=%s\n' "$installed_hash"
} > "$metadata_tmp"
chmod 0600 "$metadata_tmp"
prepared_metadata=1

acquire_lock

if [ -L "$metadata" ]; then
    echo "error: refusing a symbolic-link install marker" >&2
    exit 1
fi
if [ -e "$metadata" ]; then
    [ -f "$metadata" ] && [ ! -L "$destination" ] && [ -f "$destination" ] || {
        echo "error: managed installation shape is invalid" >&2
        exit 1
    }
    recorded=$(awk -F= '$1 == "installed_sha256" { print $2; exit }' "$metadata")
    [ -n "$recorded" ] || {
        echo "error: refusing to replace an invalid install marker" >&2
        exit 1
    }
    if command -v sha256sum >/dev/null 2>&1; then
        current=$(sha256sum "$destination" | awk '{ print tolower($1) }')
    else
        current=$(shasum -a 256 "$destination" | awk '{ print tolower($1) }')
    fi
    [ "$current" = "$recorded" ] || {
        echo "error: destination changed after installation; refusing replacement" >&2
        exit 1
    }
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        [ ! -L "$backup" ] && [ -f "$backup" ] || {
            echo "error: managed backup is not a regular non-symlink file" >&2
            exit 1
        }
    fi
    cp -p "$destination" "$tmp/managed-binary"
    cp -p "$metadata" "$tmp/managed-metadata"
    managed_upgrade=1
else
    if [ -e "$backup" ] || [ -L "$backup" ]; then
        echo "error: stale backup exists; run uninstall or remove it deliberately: $backup" >&2
        exit 1
    fi
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        [ ! -L "$destination" ] && [ -f "$destination" ] || {
            echo "error: refusing to replace a destination that is not a regular non-symlink file" >&2
            exit 1
        }
        moved_backup=1
        mv "$destination" "$backup"
    fi
fi

mv "$installed_tmp" "$destination"
mv "$metadata_tmp" "$metadata"
committed=1

rm -rf "$tmp"
rmdir "$lock"
lock_held=0
trap - EXIT HUP INT TERM
echo "Installed Again $version ($target) at $destination"
