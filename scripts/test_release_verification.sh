#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/again-release-verification-test.XXXXXXXX")
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

version=v0.1.0-alpha.1
source_commit=0123456789abcdef0123456789abcdef01234567
assets=$fixture/assets
fake_bin=$fixture/bin
mkdir "$assets" "$fake_bin"

case "$(uname -s):$(uname -m)" in
    Darwin:arm64|Darwin:aarch64) target=aarch64-apple-darwin ;;
    Darwin:x86_64|Darwin:amd64) target=x86_64-apple-darwin ;;
    Linux:aarch64|Linux:arm64) target=aarch64-unknown-linux-gnu ;;
    Linux:x86_64|Linux:amd64) target=x86_64-unknown-linux-gnu ;;
    *) exit 0 ;;
esac

for asset in \
    "again-${version}-aarch64-apple-darwin.tar.gz" \
    "again-${version}-aarch64-unknown-linux-gnu.tar.gz" \
    "again-${version}-source.cdx.json" \
    "again-${version}-x86_64-apple-darwin.tar.gz" \
    "again-${version}-x86_64-unknown-linux-gnu.tar.gz"
do
    printf 'fixture:%s\n' "$asset" > "$assets/$asset"
done
cat > "$assets/again-${version}-source.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"again-cli","version":"0.1.0"}}}
EOF

printf '%s\n' '#!/bin/sh' 'printf "%s\n" authenticated-release' > "$fixture/again"
chmod 0755 "$fixture/again"
rm "$assets/again-${version}-${target}.tar.gz"
python3 "$repository/scripts/package_release.py" \
    --binary "$fixture/again" \
    --output "$assets/again-${version}-${target}.tar.gz" \
    --source-date-epoch 1700000000
for archive_target in \
    aarch64-apple-darwin \
    aarch64-unknown-linux-gnu \
    x86_64-apple-darwin \
    x86_64-unknown-linux-gnu
do
    [ "$archive_target" = "$target" ] || \
        cp "$assets/again-${version}-${target}.tar.gz" \
            "$assets/again-${version}-${archive_target}.tar.gz"
done

checksum_manifest() {
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$assets" && sha256sum "again-${version}-"* > SHA256SUMS)
    else
        (cd "$assets" && shasum -a 256 "again-${version}-"* > SHA256SUMS)
    fi
}
checksum_manifest
python3 "$repository/packaging/homebrew/generate_formula.py" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$assets/SHA256SUMS" \
    --output "$assets/again-alpha.rb"

cat > "$fake_bin/gh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_CALL_LOG"
[ "${GH_FAIL:-0}" -eq 0 ] || {
    [ "$1:$2" != attestation:verify ] || exit 1
}
case "$1:$2" in
    release:view)
        cat "$PUBLISHED_VIEW"
        ;;
    release:download)
        destination=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --dir)
                    destination=$2
                    shift 2
                    ;;
                *)
                    shift
                    ;;
            esac
        done
        [ -n "$destination" ]
        while IFS= read -r asset; do
            cp "$REMOTE_ASSETS/$asset" "$destination/$asset"
        done < "$PUBLISHED_INVENTORY"
        ;;
    api:*)
        printf '%s\n' "$SOURCE_COMMIT"
        ;;
esac
EOF
chmod 0755 "$fake_bin/gh"

cat > "$fake_bin/curl" <<'EOF'
#!/bin/sh
set -eu
output=
url=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --output)
            output=$2
            shift 2
            ;;
        *)
            url=$1
            shift
            ;;
    esac
done
[ -n "$output" ] && [ -n "$url" ]
cp "$REMOTE_ASSETS/${url##*/}" "$output"
EOF
chmod 0755 "$fake_bin/curl"

call_log=$fixture/gh-calls
GH_CALL_LOG=$call_log PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > "$fixture/success.out"
grep -Fx "Verified authenticated Again release $version from alakhanpal23/again" \
    "$fixture/success.out" >/dev/null
test "$(wc -l < "$call_log" | tr -d ' ')" -eq 7
while IFS= read -r call; do
    for required in \
        "--repo alakhanpal23/again" \
        "--signer-workflow alakhanpal23/again/.github/workflows/release.yml" \
        "--signer-digest $source_commit" \
        "--source-ref refs/tags/$version" \
        "--source-digest $source_commit" \
        "--cert-oidc-issuer https://token.actions.githubusercontent.com" \
        "--predicate-type https://slsa.dev/provenance/v1" \
        "--deny-self-hosted-runners"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: verifier did not pin the complete provenance policy: $call" >&2
            exit 1
        }
    done
done < "$call_log"

# The published-release verifier refuses additions or omissions in GitHub's
# live asset inventory before downloading and authenticating the exact set.
published_inventory=$fixture/published-inventory
cat > "$published_inventory" <<EOF
SHA256SUMS
again-alpha.rb
again-${version}-aarch64-apple-darwin.tar.gz
again-${version}-aarch64-unknown-linux-gnu.tar.gz
again-${version}-source.cdx.json
again-${version}-x86_64-apple-darwin.tar.gz
again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF
published_view=$fixture/published-view
{
    printf '%s\n' "$version" false true true
    cat "$published_inventory"
} > "$published_view"
published_call_log=$fixture/published-gh-calls
GH_CALL_LOG=$published_call_log PUBLISHED_VIEW=$published_view \
    PUBLISHED_INVENTORY=$published_inventory SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    > "$fixture/published.out"
grep -Fx "Verified exact published Again release $version from alakhanpal23/again" \
    "$fixture/published.out" >/dev/null
test "$(wc -l < "$published_call_log" | tr -d ' ')" -eq 10
test "$(grep -c '^attestation verify ' "$published_call_log")" -eq 7
grep -F "release view $version --repo alakhanpal23/again --json assets,isDraft,isImmutable,isPrerelease,tagName" \
    "$published_call_log" >/dev/null
grep -F "api repos/alakhanpal23/again/commits/$version --jq .sha" \
    "$published_call_log" >/dev/null
grep -F "release download $version --repo alakhanpal23/again --dir " \
    "$published_call_log" >/dev/null

printf '%s\n' unexpected-asset >> "$published_inventory"
if GH_CALL_LOG=$fixture/published-inventory-failure-calls \
    PUBLISHED_VIEW=$published_view PUBLISHED_INVENTORY=$published_inventory \
    SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: published-release verifier accepted an unexpected asset" >&2
    exit 1
fi
sed '$d' "$published_inventory" > "$fixture/published-inventory-restored"
mv "$fixture/published-inventory-restored" "$published_inventory"
{
    printf '%s\n' "$version" false true true
    cat "$published_inventory"
} > "$published_view"

sed '$d' "$published_inventory" > "$fixture/published-inventory-missing"
{
    printf '%s\n' "$version" false true true
    cat "$fixture/published-inventory-missing"
} > "$fixture/published-view-missing"
if GH_CALL_LOG=$fixture/published-inventory-missing-calls \
    PUBLISHED_VIEW=$fixture/published-view-missing \
    PUBLISHED_INVENTORY=$fixture/published-inventory-missing \
    SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: published-release verifier accepted a missing asset" >&2
    exit 1
fi

# The public installer authenticates both downloaded inputs with the same
# pinned provenance policy before it extracts or installs the archive.
sed '3s/true/false/' "$published_view" > "$fixture/mutable-published-view"
install_call_log=$fixture/install-gh-calls
install_destination=$fixture/installed/again
GH_CALL_LOG=$install_call_log PUBLISHED_VIEW=$published_view \
    SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version "$version" \
    --source-commit "$source_commit" \
    --base-url https://releases.example.invalid/download \
    --dest "$install_destination" \
    > "$fixture/install.out"
test "$("$install_destination")" = authenticated-release
test "$(wc -l < "$install_call_log" | tr -d ' ')" -eq 4
grep -F "release view $version --repo alakhanpal23/again --json assets,isDraft,isImmutable,isPrerelease,tagName" \
    "$install_call_log" >/dev/null
grep -F "api repos/alakhanpal23/again/commits/$version --jq .sha" \
    "$install_call_log" >/dev/null
grep -F "/SHA256SUMS --repo alakhanpal23/again" "$install_call_log" >/dev/null
grep -F "/again-${version}-${target}.tar.gz --repo alakhanpal23/again" \
    "$install_call_log" >/dev/null
grep '^attestation verify ' "$install_call_log" > "$fixture/install-attestation-calls"
while IFS= read -r call; do
    for required in \
        "--repo alakhanpal23/again" \
        "--signer-workflow alakhanpal23/again/.github/workflows/release.yml" \
        "--signer-digest $source_commit" \
        "--source-ref refs/tags/$version" \
        "--source-digest $source_commit" \
        "--cert-oidc-issuer https://token.actions.githubusercontent.com" \
        "--predicate-type https://slsa.dev/provenance/v1" \
        "--deny-self-hosted-runners"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: installer did not pin the complete provenance policy: $call" >&2
            exit 1
        }
    done
done < "$fixture/install-attestation-calls"

failed_install_destination=$fixture/failed-install/again
if GH_FAIL=1 GH_CALL_LOG=$fixture/failed-install-calls \
    PUBLISHED_VIEW=$published_view SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/install.sh" \
    --version "$version" \
    --source-commit "$source_commit" \
    --base-url https://releases.example.invalid/download \
    --dest "$failed_install_destination" \
    > /dev/null 2>&1; then
    echo "error: installer accepted failed provenance authentication" >&2
    exit 1
fi
test ! -e "$failed_install_destination"

cp "$assets/again-alpha.rb" "$fixture/formula-original.rb"
printf '\n# untrusted mutation\n' >> "$assets/again-alpha.rb"
if GH_CALL_LOG=$fixture/mutated-formula-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted mutated Homebrew formula bytes" >&2
    exit 1
fi
cp "$fixture/formula-original.rb" "$assets/again-alpha.rb"

if GH_CALL_LOG=$fixture/missing-source-install-calls \
    PUBLISHED_VIEW=$published_view SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/install.sh" \
    --version "$version" \
    --base-url https://releases.example.invalid/download \
    --dest "$fixture/missing-source-install/again" > /dev/null 2>&1; then
    echo "error: remote installer accepted a missing source commit" >&2
    exit 1
fi

if GH_CALL_LOG=$fixture/mutable-install-calls \
    PUBLISHED_VIEW=$fixture/mutable-published-view SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version "$version" --source-commit "$source_commit" \
    --base-url https://releases.example.invalid/download \
    --dest "$fixture/mutable-install/again" > /dev/null 2>&1; then
    echo "error: remote installer accepted a mutable release" >&2
    exit 1
fi

tampered=$assets/again-${version}-aarch64-apple-darwin.tar.gz
cp "$tampered" "$fixture/tampered-original"
printf 'tampered\n' >> "$tampered"
if GH_CALL_LOG=$fixture/tampered-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a checksum mismatch" >&2
    exit 1
fi
cp "$fixture/tampered-original" "$tampered"

printf 'unexpected\n' > "$assets/unexpected"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$assets" && sha256sum unexpected >> SHA256SUMS)
else
    (cd "$assets" && shasum -a 256 unexpected >> SHA256SUMS)
fi
if GH_CALL_LOG=$fixture/inventory-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted an unexpected manifest entry" >&2
    exit 1
fi
rm "$assets/unexpected"
checksum_manifest

printf '%s\n' 'not-a-checksum malformed' >> "$assets/SHA256SUMS"
if GH_CALL_LOG=$fixture/malformed-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a malformed manifest line" >&2
    exit 1
fi
checksum_manifest

if GH_FAIL=1 GH_CALL_LOG=$fixture/failed-attestation-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted failed provenance authentication" >&2
    exit 1
fi

# A source digest is mandatory and is part of every publisher identity check.
if GH_CALL_LOG=$fixture/malformed-source-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit not-a-commit \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a malformed source commit" >&2
    exit 1
fi

# An unlisted file, duplicate manifest row, or unsafe archive shape is a hard
# failure even if all expected checksums remain present.
printf 'unlisted\n' > "$assets/unlisted"
if GH_CALL_LOG=$fixture/unlisted-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted an unlisted artifact" >&2
    exit 1
fi
rm "$assets/unlisted"

head -n 1 "$assets/SHA256SUMS" >> "$assets/SHA256SUMS"
if GH_CALL_LOG=$fixture/duplicate-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a duplicate checksum entry" >&2
    exit 1
fi
checksum_manifest

cp "$assets/again-${version}-${target}.tar.gz" "$fixture/trailing.tar.gz"
printf 'not-padding\n' >> "$fixture/trailing.tar.gz"
if python3 "$repository/scripts/package_release.py" \
    --verify-archive "$fixture/trailing.tar.gz" > /dev/null 2>&1; then
    echo "error: archive verifier accepted trailing payload" >&2
    exit 1
fi

mkdir "$fixture/symlink-archive"
ln -s outside "$fixture/symlink-archive/again"
tar -czf "$fixture/symlink.tar.gz" -C "$fixture/symlink-archive" again
if python3 "$repository/scripts/package_release.py" \
    --verify-archive "$fixture/symlink.tar.gz" > /dev/null 2>&1; then
    echo "error: archive verifier accepted a symbolic-link member" >&2
    exit 1
fi

cp "$assets/again-${version}-source.cdx.json" "$fixture/wrong-version.cdx.json"
sed 's/"version":"0.1.0"/"version":"9.9.9"/' \
    "$fixture/wrong-version.cdx.json" > "$fixture/wrong-version-new.cdx.json"
mv "$fixture/wrong-version-new.cdx.json" "$fixture/wrong-version.cdx.json"
if python3 "$repository/scripts/package_release.py" \
    --verify-sbom "$fixture/wrong-version.cdx.json" --version "$version" \
    > /dev/null 2>&1; then
    echo "error: SBOM verifier accepted an inconsistent package version" >&2
    exit 1
fi

sed '3s/true/false/' "$published_view" > "$fixture/mutable-published-view"
if GH_CALL_LOG=$fixture/mutable-release-calls \
    PUBLISHED_VIEW=$fixture/mutable-published-view \
    PUBLISHED_INVENTORY=$published_inventory SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again > /dev/null 2>&1; then
    echo "error: published verifier accepted a mutable release" >&2
    exit 1
fi

if GH_CALL_LOG=$fixture/moved-tag-calls PUBLISHED_VIEW=$published_view \
    PUBLISHED_INVENTORY=$published_inventory \
    SOURCE_COMMIT=ffffffffffffffffffffffffffffffffffffffff \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again > /dev/null 2>&1; then
    echo "error: published verifier accepted a moved release tag" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
rm -rf "$fixture"
