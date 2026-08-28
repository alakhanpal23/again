#!/bin/sh
# Authenticate and hash-check one complete Again release asset set.

set -eu

MAX_ASSET_BYTES=67108864
MAX_CHECKSUM_BYTES=1048576

usage() {
    cat >&2 <<'EOF'
Usage: verify_release.sh --version TAG --source-commit SHA --artifact-dir DIR
       [--repository OWNER/REPO]

DIR must contain SHA256SUMS, all four native archives, and the source SBOM.
The GitHub CLI must be authenticated or otherwise able to read public
attestations. Verification pins the Again release workflow, tag ref, repository,
and GitHub-hosted runner provenance.
EOF
    exit 2
}

version=
source_commit=
artifact_dir=
repository=alakhanpal23/again

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift 2
            ;;
        --artifact-dir)
            [ "$#" -ge 2 ] || usage
            artifact_dir=$2
            shift 2
            ;;
        --source-commit)
            [ "$#" -ge 2 ] || usage
            source_commit=$2
            shift 2
            ;;
        --repository)
            [ "$#" -ge 2 ] || usage
            repository=$2
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

[ -n "$version" ] && [ -n "$source_commit" ] && [ -n "$artifact_dir" ] || usage
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
printf '%s\n' "$version" | grep -Eq "$semver_re" || {
    echo "error: invalid release tag" >&2
    exit 2
}
printf '%s\n' "$repository" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || {
    echo "error: invalid GitHub repository" >&2
    exit 2
}
printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40}$' || {
    echo "error: source commit must be 40 lowercase hexadecimal characters" >&2
    exit 2
}
[ -d "$artifact_dir" ] && [ ! -L "$artifact_dir" ] || {
    echo "error: artifact directory is missing or is a symlink" >&2
    exit 1
}
artifact_dir=$(CDPATH= cd -- "$artifact_dir" && pwd -P) || {
    echo "error: artifact directory cannot be resolved" >&2
    exit 1
}
command -v gh >/dev/null 2>&1 || {
    echo "error: GitHub CLI with attestation support is required" >&2
    exit 1
}
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)

bounded_regular_file() {
    path=$1
    maximum=$2
    description=$3
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "error: $description is not a regular non-symlink file" >&2
        exit 1
    }
    size=$(wc -c < "$path" | tr -d ' ')
    [ "$size" -gt 0 ] && [ "$size" -le "$maximum" ] || {
        echo "error: $description is empty or exceeds the size limit" >&2
        exit 1
    }
}

file_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print tolower($1) }'
    else
        shasum -a 256 "$1" | awk '{ print tolower($1) }'
    fi
}

verify_attestation() {
    gh attestation verify "$1" \
        --repo "$repository" \
        --signer-workflow "$repository/.github/workflows/release.yml" \
        --signer-digest "$source_commit" \
        --source-ref "refs/tags/$version" \
        --source-digest "$source_commit" \
        --cert-oidc-issuer https://token.actions.githubusercontent.com \
        --predicate-type https://slsa.dev/provenance/v1 \
        --deny-self-hosted-runners >/dev/null
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/again-release-verify.XXXXXXXX")
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    rm -rf "$temporary"
    exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

manifest=$artifact_dir/SHA256SUMS
bounded_regular_file "$manifest" "$MAX_CHECKSUM_BYTES" "checksum manifest"
verify_attestation "$manifest"

expected=$temporary/expected
expected_inventory=$temporary/expected-inventory
parsed=$temporary/parsed
actual=$temporary/actual
observed_inventory=$temporary/observed-inventory
cat > "$expected" <<EOF
again-${version}-aarch64-apple-darwin.tar.gz
again-${version}-aarch64-unknown-linux-gnu.tar.gz
again-${version}-source.cdx.json
again-${version}-x86_64-apple-darwin.tar.gz
again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF
{
    printf '%s\n' SHA256SUMS
    cat "$expected"
} > "$expected_inventory"

find "$artifact_dir" -mindepth 1 -maxdepth 1 -print | while IFS= read -r path; do
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "error: artifact directory contains a non-regular member" >&2
        exit 1
    }
    basename "$path"
done | LC_ALL=C sort > "$observed_inventory" || exit 1
cmp "$expected_inventory" "$observed_inventory" >/dev/null || {
    echo "error: artifact directory does not contain the exact release asset set" >&2
    exit 1
}

awk '
    NF != 2 || length($1) != 64 || tolower($1) ~ /[^0-9a-f]/ { exit 1 }
    {
        name = $2
        sub(/^\*/, "", name)
        if (name == "" || name ~ /\// || name == "." || name == "..") { exit 1 }
        print name
    }
' "$manifest" > "$parsed" || {
    echo "error: malformed checksum manifest" >&2
    exit 1
}
LC_ALL=C sort "$parsed" > "$actual"
cmp "$expected" "$actual" >/dev/null || {
    echo "error: checksum manifest does not name the exact release asset set" >&2
    exit 1
}

while IFS= read -r asset; do
    path=$artifact_dir/$asset
    bounded_regular_file "$path" "$MAX_ASSET_BYTES" "release asset $asset"
    expected_hash=$(awk -v file="$asset" '
        {
            name = $2
            sub(/^\*/, "", name)
            if (name == file) { print tolower($1); exit }
        }
    ' "$manifest")
    actual_hash=$(file_hash "$path")
    [ "$actual_hash" = "$expected_hash" ] || {
        echo "error: checksum mismatch for $asset" >&2
        exit 1
    }
    case "$asset" in
        *.tar.gz)
            python3 "$script_dir/package_release.py" --verify-archive "$path"
            ;;
        *.cdx.json)
            python3 "$script_dir/package_release.py" \
                --verify-sbom "$path" --version "$version"
            ;;
        *)
            echo "error: unsupported release asset type: $asset" >&2
            exit 1
            ;;
    esac
    verify_attestation "$path"
done < "$expected"

trap - EXIT HUP INT TERM
rm -rf "$temporary"
echo "Verified authenticated Again release $version from $repository"
