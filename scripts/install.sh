#!/bin/sh
# Verify and install an Again release without executing downloaded bytes.

set -eu

MAX_ARCHIVE_BYTES=67108864
MAX_CHECKSUM_BYTES=1048576

usage() {
    cat >&2 <<'EOF'
Usage: install.sh --version TAG --dest PATH [--source-commit SHA]
       [--base-url URL | --artifact-dir DIR]

TAG must be a release tag such as v0.1.0. PATH is the exact binary destination.
With --artifact-dir, a local development directory must contain the archive and
SHA256SUMS. Without it, assets are downloaded from the Again GitHub release URL
and --source-commit is required so the GitHub CLI can authenticate the immutable
release, tag, and release-workflow provenance.
EOF
    exit 2
}

version=
destination=
source_commit=
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
        --source-commit)
            [ "$#" -ge 2 ] || usage
            source_commit=$2
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
    printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40}$' || {
        echo "error: remote installation requires a 40-character lowercase source commit" >&2
        exit 2
    }
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
elif [ -n "$source_commit" ]; then
    printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40}$' || {
        echo "error: source commit must be 40 lowercase hexadecimal characters" >&2
        exit 2
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
destination_name=$(basename "$destination")
case "$destination_name" in
    ''|.|..)
        echo "error: destination must name one binary file" >&2
        exit 2
        ;;
esac
mkdir -p "$destination_dir"
[ -d "$destination_dir" ] && [ ! -L "$destination_dir" ] || {
    echo "error: destination parent is not a directory" >&2
    exit 1
}
destination_dir=$(CDPATH= cd -- "$destination_dir" && pwd -P)
destination="$destination_dir/$destination_name"

metadata=${destination}.again-install
backup=${destination}.previous
lock=${destination}.again-lock
lock_owner=${lock}/owner
lock_token=install-$$
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

retry_remove_file() {
    retry_path=$1
    retry_description=$2
    if ! rm -f "$retry_path" && ! rm -f "$retry_path"; then
        echo "warning: could not $retry_description: $retry_path" >&2
        return 1
    fi
}

retry_remove_tree() {
    retry_path=$1
    if ! rm -rf "$retry_path" && ! rm -rf "$retry_path"; then
        echo "warning: could not remove installer temporary directory: $retry_path" >&2
        return 1
    fi
}

retry_copy() {
    retry_source=$1
    retry_destination=$2
    retry_description=$3
    if ! cp -p "$retry_source" "$retry_destination" && \
        ! cp -p "$retry_source" "$retry_destination"; then
        echo "warning: could not $retry_description" >&2
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
    observed_token=
    if [ -d "$lock" ] && [ ! -L "$lock" ] && \
        [ -f "$lock_owner" ] && [ ! -L "$lock_owner" ]; then
        IFS= read -r observed_token < "$lock_owner" || observed_token=
    fi
    if [ "$observed_token" != "$lock_token" ]; then
        echo "warning: install lock ownership changed; preserving it for inspection: $lock" >&2
        return 1
    fi
    retry_remove_file "$lock_owner" "remove the install lock owner record" || return 1
    if rmdir "$lock" 2>/dev/null || rmdir "$lock" 2>/dev/null; then
        lock_held=0
        return 0
    fi
    echo "warning: could not remove install lock; inspect and remove it manually: $lock" >&2
    return 1
}

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
            retry_remove_file "$destination" "remove the uncommitted binary" || :
            if [ "$managed_upgrade" -eq 1 ] && [ -f "$tmp/managed-binary" ]; then
                retry_copy "$tmp/managed-binary" "$destination" \
                    "restore the previous managed binary" || :
            elif [ "$moved_backup" -eq 1 ] && { [ -e "$backup" ] || [ -L "$backup" ]; }; then
                retry_move "$backup" "$destination" \
                    "restore the original destination" || :
            fi
        elif [ "$moved_backup" -eq 1 ] && { [ -e "$backup" ] || [ -L "$backup" ]; }; then
            retry_move "$backup" "$destination" \
                "restore the original destination" || :
        fi
        if [ "$metadata_was_replaced" -eq 1 ]; then
            retry_remove_file "$metadata" "remove the uncommitted install marker" || :
            if [ "$managed_upgrade" -eq 1 ] && [ -f "$tmp/managed-metadata" ]; then
                retry_copy "$tmp/managed-metadata" "$metadata" \
                    "restore the previous install marker" || :
            fi
        fi
    fi
    [ -z "$installed_tmp" ] || \
        retry_remove_file "$installed_tmp" "remove the prepared binary" || :
    [ -z "$metadata_tmp" ] || \
        retry_remove_file "$metadata_tmp" "remove the prepared marker" || :
    retry_remove_tree "$tmp" || :
    if [ "$lock_held" -eq 1 ]; then
        release_owned_lock || :
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
        if (umask 077; printf '%s\n' "$lock_token" > "$lock_owner") && \
            chmod 0600 "$lock_owner"; then
            lock_acquired=1
        fi
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
    [ "$size" -gt 0 ] && [ "$size" -le "$maximum" ] || {
        echo "error: $description is empty or exceeds the size limit" >&2
        exit 1
    }
}

if [ -n "$artifact_dir" ]; then
    [ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] || {
        echo "error: artifact directory is missing or is a symlink" >&2
        exit 1
    }
    bounded_file "$artifact_dir/$asset" "$MAX_ARCHIVE_BYTES" "local release archive"
    bounded_file "$artifact_dir/SHA256SUMS" "$MAX_CHECKSUM_BYTES" "local checksum manifest"
    cp "$artifact_dir/$asset" "$tmp/$asset"
    cp "$artifact_dir/SHA256SUMS" "$tmp/SHA256SUMS"
else
    expected_prerelease=false
    case "$version" in *-*) expected_prerelease=true ;; esac
    expected_release=$tmp/expected-release
    observed_release=$tmp/observed-release
    {
        printf '%s\n' "$version" false true "$expected_prerelease"
        printf '%s\n' \
            SHA256SUMS \
            again-alpha.rb \
            "again-${version}-aarch64-apple-darwin.tar.gz" \
            "again-${version}-aarch64-unknown-linux-gnu.tar.gz" \
            "again-${version}-source.cdx.json" \
            "again-${version}-x86_64-apple-darwin.tar.gz" \
            "again-${version}-x86_64-unknown-linux-gnu.tar.gz"
    } > "$expected_release"
    gh release view "$version" \
        --repo alakhanpal23/again \
        --json assets,isDraft,isImmutable,isPrerelease,tagName \
        --jq '[.tagName,(.isDraft|tostring),(.isImmutable|tostring),(.isPrerelease|tostring)] + ([.assets[].name] | sort) | .[]' \
        > "$observed_release"
    cmp "$expected_release" "$observed_release" >/dev/null 2>&1 || {
        echo "error: remote release identity, immutability, kind, or inventory is invalid" >&2
        exit 1
    }
    current_sha=$(gh api "repos/alakhanpal23/again/commits/${version}" --jq .sha)
    [ "$current_sha" = "$source_commit" ] || {
        echo "error: release tag does not resolve to the requested source commit" >&2
        exit 1
    }
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
            --signer-digest "$source_commit" \
            --source-ref "refs/tags/$version" \
            --source-digest "$source_commit" \
            --cert-oidc-issuer https://token.actions.githubusercontent.com \
            --predicate-type https://slsa.dev/provenance/v1 \
            --deny-self-hosted-runners >/dev/null || {
            echo "error: publisher attestation verification failed for $description" >&2
            exit 1
        }
    }
    verify_attestation "$tmp/SHA256SUMS" "checksum manifest"
    verify_attestation "$tmp/$asset" "release archive"
fi

parsed_manifest=$tmp/parsed-manifest
manifest_names=$tmp/manifest-names
awk '
    NF != 2 || length($1) != 64 || tolower($1) ~ /[^0-9a-f]/ { exit 1 }
    {
        name=$2
        sub(/^\*/, "", name)
        if (name !~ /^again-v[0-9A-Za-z.-]+-(aarch64-apple-darwin|aarch64-unknown-linux-gnu|x86_64-apple-darwin|x86_64-unknown-linux-gnu)\.tar\.gz$/ &&
            name !~ /^again-v[0-9A-Za-z.-]+-source\.cdx\.json$/) { exit 1 }
        print tolower($1), name
    }
' "$tmp/SHA256SUMS" > "$parsed_manifest" || {
    echo "error: checksum manifest contains a malformed or unsafe entry" >&2
    exit 1
}
awk '{ print $2 }' "$parsed_manifest" | LC_ALL=C sort > "$manifest_names"
if [ -z "$artifact_dir" ]; then
    sed '1,6d' "$expected_release" > "$tmp/expected-checksum-names"
    cmp "$tmp/expected-checksum-names" "$manifest_names" >/dev/null 2>&1 || {
        echo "error: checksum manifest does not contain the exact release assets" >&2
        exit 1
    }
else
    printf '%s\n' "$asset" > "$tmp/local-checksum-name"
    cmp "$tmp/local-checksum-name" "$manifest_names" >/dev/null 2>&1 || {
        echo "error: local checksum manifest must contain exactly the selected archive" >&2
        exit 1
    }
fi
expected=$(awk -v file="$asset" '$2 == file { print $1 }' "$parsed_manifest")
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

gzip -t "$tmp/$asset" 2>/dev/null || {
    echo "error: archive is not a complete gzip stream" >&2
    exit 1
}

members=$(tar -tzf "$tmp/$asset")
[ "$members" = "again" ] || {
    echo "error: archive must contain exactly one top-level member named again" >&2
    exit 1
}
archive_mode=$(tar -tvzf "$tmp/$asset" | awk 'NR == 1 { print $1 }')
[ "$archive_mode" = "-rwxr-xr-x" ] || {
    echo "error: archive member must be a normalized regular executable" >&2
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
    if [ -n "$source_commit" ]; then
        printf 'source_commit=%s\n' "$source_commit"
    else
        printf 'source_commit=local-unattested\n'
    fi
    printf 'archive_sha256=%s\n' "$actual"
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
        echo "error: refusing to replace an invalid install marker" >&2
        exit 1
    }
    recorded=$(sed -n '5s/^installed_sha256=//p' "$metadata")
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
# Both destination records are now consistent. Ignore catchable termination
# during the few shell-builtins that publish the commit decision; a signal
# delivered by either rename is still handled by rollback before this point.
trap '' HUP INT TERM
committed=1

retry_remove_tree "$tmp" || :
release_owned_lock || :
trap - EXIT HUP INT TERM
echo "Installed Again $version ($target) at $destination"
