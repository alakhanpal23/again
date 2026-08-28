#!/bin/sh
# Authenticate and hash-check one complete Again release asset set.

set -eu

MAX_ASSET_BYTES=67108864
MAX_CHECKSUM_BYTES=1048576
MAX_FORMULA_BYTES=131072

usage() {
    cat >&2 <<'EOF'
Usage: verify_release.sh --version TAG --source-commit SHA --artifact-dir DIR
       [--repository OWNER/REPO] [--attestation-summary-dir DIR]

DIR must contain SHA256SUMS, all four native archives, the source SBOM, and the
deterministically generated again-alpha.rb formula.
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
attestation_summary_dir=

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
        --attestation-summary-dir)
            [ "$#" -ge 2 ] || usage
            attestation_summary_dir=$2
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
evidence_tool=$script_dir/export_release_evidence.py

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
    subject=$1
    subject_name=$2
    subject_digest=$3
    if [ "$collect_attestation_summaries" -eq 0 ]; then
        gh attestation verify "$subject" \
            --repo "$repository" \
            --signer-workflow "$repository/.github/workflows/release.yml" \
            --signer-digest "$source_commit" \
            --source-ref "refs/tags/$version" \
            --source-digest "$source_commit" \
            --cert-oidc-issuer https://token.actions.githubusercontent.com \
            --predicate-type https://slsa.dev/provenance/v1 \
            --deny-self-hosted-runners \
            >/dev/null
        attestation_index=$((attestation_index + 1))
        return
    fi
    summary_name=$(printf '%03d.json' "$attestation_index")
    raw_result=$temporary/attestation-result.json
    (ulimit -f 8192; gh attestation verify "$subject" \
        --repo "$repository" \
        --signer-workflow "$repository/.github/workflows/release.yml" \
        --signer-digest "$source_commit" \
        --source-ref "refs/tags/$version" \
        --source-digest "$source_commit" \
        --cert-oidc-issuer https://token.actions.githubusercontent.com \
        --predicate-type https://slsa.dev/provenance/v1 \
        --deny-self-hosted-runners \
        --format json > "$raw_result")
    python3 "$evidence_tool" attestation \
        --input "$raw_result" \
        --subject-name "$subject_name" \
        --subject-digest "$subject_digest" \
        --repository "$repository" \
        --tag "$version" \
        --source-commit "$source_commit" \
        --output "$attestation_summary_dir/$summary_name"
    rm -f "$raw_result"
    attestation_index=$((attestation_index + 1))
}

temporary=$(mktemp -d "${TMPDIR:-/tmp}/again-release-verify.XXXXXXXX")
attestation_summary_external=0
cleanup() {
    status=$1
    trap - EXIT HUP INT TERM
    if [ "$status" -ne 0 ] && [ "$attestation_summary_external" -eq 1 ]; then
        rm -rf "$attestation_summary_dir"
    fi
    rm -rf "$temporary"
    exit "$status"
}
trap 'cleanup "$?"' EXIT
trap 'cleanup 129' HUP
trap 'cleanup 130' INT
trap 'cleanup 143' TERM

if [ -n "$attestation_summary_dir" ]; then
    case "$attestation_summary_dir" in
        /*) ;;
        *)
            echo "error: attestation summary directory must be absolute" >&2
            exit 2
            ;;
    esac
    if [ -e "$attestation_summary_dir" ] || [ -L "$attestation_summary_dir" ]; then
        echo "error: attestation summary directory already exists" >&2
        exit 1
    fi
    mkdir "$attestation_summary_dir"
    attestation_summary_external=1
    collect_attestation_summaries=1
else
    collect_attestation_summaries=0
fi
attestation_index=0

manifest=$artifact_dir/SHA256SUMS
bounded_regular_file "$manifest" "$MAX_CHECKSUM_BYTES" "checksum manifest"
manifest_digest=$(file_hash "$manifest")
verify_attestation "$manifest" SHA256SUMS "$manifest_digest"

expected=$temporary/expected
expected_inventory=$temporary/expected-inventory
parsed=$temporary/parsed
actual=$temporary/actual
observed_inventory_unsorted=$temporary/observed-inventory-unsorted
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
    printf '%s\n' again-alpha.rb
    cat "$expected"
} > "$expected_inventory"

: > "$observed_inventory_unsorted"
for path in "$artifact_dir"/* "$artifact_dir"/.[!.]* "$artifact_dir"/..?*; do
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then
        continue
    fi
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "error: artifact directory contains a non-regular member" >&2
        exit 1
    }
    name=$(basename "$path")
    case "$name" in
        SHA256SUMS|again-alpha.rb|again-"${version}"-aarch64-apple-darwin.tar.gz|again-"${version}"-aarch64-unknown-linux-gnu.tar.gz|again-"${version}"-source.cdx.json|again-"${version}"-x86_64-apple-darwin.tar.gz|again-"${version}"-x86_64-unknown-linux-gnu.tar.gz) ;;
        *)
            echo "error: artifact directory contains an unexpected member" >&2
            exit 1
            ;;
    esac
    printf '%s\n' "$name" >> "$observed_inventory_unsorted"
done
LC_ALL=C sort "$observed_inventory_unsorted" > "$observed_inventory"
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

formula=$artifact_dir/again-alpha.rb
bounded_regular_file "$formula" "$MAX_FORMULA_BYTES" "Homebrew alpha formula"
python3 "$script_dir/../packaging/homebrew/generate_formula.py" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$manifest" \
    --verify "$formula"
formula_digest=$(file_hash "$formula")
verify_attestation "$formula" again-alpha.rb "$formula_digest"

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
    verify_attestation "$path" "$asset" "$actual_hash"
done < "$expected"
[ "$attestation_index" -eq 7 ] || {
    echo "error: attestation verification count is inconsistent" >&2
    exit 1
}

trap - EXIT HUP INT TERM
rm -rf "$temporary"
echo "Verified authenticated Again release $version from $repository"
