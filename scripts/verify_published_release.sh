#!/bin/sh
# Download and authenticate the exact asset inventory of one published release.

set -eu

usage() {
    cat >&2 <<'EOF'
Usage: verify_published_release.sh --version TAG --source-commit SHA
       [--repository OWNER/REPO]
       [--evidence-output FILE [--verified-at YYYY-MM-DDTHH:MM:SSZ]]

The GitHub CLI must be able to read the release and its GitHub attestations.
The release must contain exactly the four native archives, source SBOM,
SHA256SUMS, and deterministic alpha formula expected for TAG.
EOF
    exit 2
}

version=
source_commit=
repository=alakhanpal23/again
evidence_output=
verified_at=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --version)
            [ "$#" -ge 2 ] || usage
            version=$2
            shift 2
            ;;
        --repository)
            [ "$#" -ge 2 ] || usage
            repository=$2
            shift 2
            ;;
        --source-commit)
            [ "$#" -ge 2 ] || usage
            source_commit=$2
            shift 2
            ;;
        --evidence-output)
            [ "$#" -ge 2 ] || usage
            evidence_output=$2
            shift 2
            ;;
        --verified-at)
            [ "$#" -ge 2 ] || usage
            verified_at=$2
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

[ -n "$version" ] && [ -n "$source_commit" ] || usage
if [ -z "$evidence_output" ] && [ -n "$verified_at" ]; then
    usage
fi
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
command -v gh >/dev/null 2>&1 || {
    echo "error: GitHub CLI with attestation support is required" >&2
    exit 1
}

script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd -P)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/again-published-release.XXXXXXXX")
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

expected=$temporary/expected
observed=$temporary/observed
published=$temporary/published
assets=$temporary/assets
downloaded=$temporary/downloaded
downloaded_sorted=$temporary/downloaded-sorted
attestation_summaries=$temporary/attestation-summaries
cat > "$expected" <<EOF
SHA256SUMS
again-alpha.rb
again-${version}-aarch64-apple-darwin.tar.gz
again-${version}-aarch64-unknown-linux-gnu.tar.gz
again-${version}-source.cdx.json
again-${version}-x86_64-apple-darwin.tar.gz
again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF

case "$version" in
    *-*) expected_prerelease=true ;;
    *) expected_prerelease=false ;;
esac
{
    printf '%s\n' "$version" false true "$expected_prerelease"
    cat "$expected"
} > "$published"
gh release view "$version" \
    --repo "$repository" \
    --json assets,isDraft,isImmutable,isPrerelease,tagName \
    --jq '[.tagName,(.isDraft|tostring),(.isImmutable|tostring),(.isPrerelease|tostring)] + ([.assets[].name] | sort) | .[]' \
    > "$observed"
cmp "$published" "$observed" >/dev/null || {
    echo "error: published release identity, immutability, kind, or inventory is invalid" >&2
    exit 1
}
current_sha=$(gh api "repos/${repository}/commits/${version}" --jq .sha)
[ "$current_sha" = "$source_commit" ] || {
    echo "error: published release tag does not resolve to the expected source commit" >&2
    exit 1
}

mkdir "$assets"
gh release download "$version" \
    --repo "$repository" \
    --dir "$assets"
: > "$downloaded"
for path in "$assets"/*; do
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "error: downloaded release inventory contains a non-regular asset" >&2
        exit 1
    }
    basename "$path" >> "$downloaded"
done
LC_ALL=C sort "$downloaded" > "$downloaded_sorted"
cmp "$expected" "$downloaded_sorted" >/dev/null || {
    echo "error: downloaded release does not contain the exact expected asset inventory" >&2
    exit 1
}
if [ -n "$evidence_output" ]; then
    sh "$script_dir/verify_release.sh" \
        --version "$version" \
        --source-commit "$source_commit" \
        --artifact-dir "$assets" \
        --repository "$repository" \
        --attestation-summary-dir "$attestation_summaries"
    release_metadata=$temporary/release-metadata.json
    gh_version_output=$temporary/gh-version
    (ulimit -f 2048; gh release view "$version" \
        --repo "$repository" \
        --json assets,isDraft,isImmutable,isPrerelease,tagName \
        > "$release_metadata")
    (ulimit -f 16; gh --version > "$gh_version_output")
    IFS= read -r github_cli_version < "$gh_version_output"
    if [ -z "$verified_at" ]; then
        verified_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
    fi
    python3 "$script_dir/export_release_evidence.py" evidence \
        --release-metadata "$release_metadata" \
        --attestation-dir "$attestation_summaries" \
        --artifact-dir "$assets" \
        --repository "$repository" \
        --tag "$version" \
        --source-commit "$source_commit" \
        --verified-at "$verified_at" \
        --github-cli-version "$github_cli_version" \
        --output "$evidence_output"
else
    sh "$script_dir/verify_release.sh" \
        --version "$version" \
        --source-commit "$source_commit" \
        --artifact-dir "$assets" \
        --repository "$repository"
fi

trap - EXIT HUP INT TERM
rm -rf "$temporary"
echo "Verified exact published Again release $version from $repository"
