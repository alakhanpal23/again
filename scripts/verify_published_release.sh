#!/bin/sh
# Download and authenticate the exact asset inventory of one published release.

set -eu

usage() {
    cat >&2 <<'EOF'
Usage: verify_published_release.sh --version TAG [--repository OWNER/REPO]

The GitHub CLI must be able to read the release and its public attestations.
The release must contain exactly the four native archives, source SBOM, and
SHA256SUMS expected for TAG.
EOF
    exit 2
}

version=
repository=alakhanpal23/again

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
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$version" ] || usage
semver_re='^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)(\.(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?$'
printf '%s\n' "$version" | grep -Eq "$semver_re" || {
    echo "error: invalid release tag" >&2
    exit 2
}
printf '%s\n' "$repository" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || {
    echo "error: invalid GitHub repository" >&2
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
sorted=$temporary/sorted
assets=$temporary/assets
downloaded=$temporary/downloaded
downloaded_sorted=$temporary/downloaded-sorted
cat > "$expected" <<EOF
SHA256SUMS
again-${version}-aarch64-apple-darwin.tar.gz
again-${version}-aarch64-unknown-linux-gnu.tar.gz
again-${version}-source.cdx.json
again-${version}-x86_64-apple-darwin.tar.gz
again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF

gh release view "$version" \
    --repo "$repository" \
    --json assets \
    --jq '.assets[].name' > "$observed"
LC_ALL=C sort "$observed" > "$sorted"
cmp "$expected" "$sorted" >/dev/null || {
    echo "error: published release does not contain the exact expected asset inventory" >&2
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
sh "$script_dir/verify_release.sh" \
    --version "$version" \
    --artifact-dir "$assets" \
    --repository "$repository"

trap - EXIT HUP INT TERM
rm -rf "$temporary"
echo "Verified exact published Again release $version from $repository"
