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
assets=$fixture/assets
fake_bin=$fixture/bin
mkdir "$assets" "$fake_bin"

for asset in \
    "again-${version}-aarch64-apple-darwin.tar.gz" \
    "again-${version}-aarch64-unknown-linux-gnu.tar.gz" \
    "again-${version}-source.cdx.json" \
    "again-${version}-x86_64-apple-darwin.tar.gz" \
    "again-${version}-x86_64-unknown-linux-gnu.tar.gz"
do
    printf 'fixture:%s\n' "$asset" > "$assets/$asset"
done

checksum_manifest() {
    if command -v sha256sum >/dev/null 2>&1; then
        (cd "$assets" && sha256sum again-* > SHA256SUMS)
    else
        (cd "$assets" && shasum -a 256 again-* > SHA256SUMS)
    fi
}
checksum_manifest

cat > "$fake_bin/gh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_CALL_LOG"
[ "${GH_FAIL:-0}" -eq 0 ]
EOF
chmod 0755 "$fake_bin/gh"

call_log=$fixture/gh-calls
GH_CALL_LOG=$call_log PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
    > "$fixture/success.out"
grep -Fx "Verified authenticated Again release $version from alakhanpal23/again" \
    "$fixture/success.out" >/dev/null
test "$(wc -l < "$call_log" | tr -d ' ')" -eq 6
while IFS= read -r call; do
    for required in \
        "--repo alakhanpal23/again" \
        "--signer-workflow alakhanpal23/again/.github/workflows/release.yml" \
        "--source-ref refs/tags/$version" \
        "--deny-self-hosted-runners"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: verifier did not pin the complete provenance policy: $call" >&2
            exit 1
        }
    done
done < "$call_log"

tampered=$assets/again-${version}-aarch64-apple-darwin.tar.gz
printf 'tampered\n' >> "$tampered"
if GH_CALL_LOG=$fixture/tampered-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a checksum mismatch" >&2
    exit 1
fi
printf 'fixture:%s\n' "$(basename "$tampered")" > "$tampered"

printf 'unexpected\n' > "$assets/unexpected"
if command -v sha256sum >/dev/null 2>&1; then
    (cd "$assets" && sha256sum unexpected >> SHA256SUMS)
else
    (cd "$assets" && shasum -a 256 unexpected >> SHA256SUMS)
fi
if GH_CALL_LOG=$fixture/inventory-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted an unexpected manifest entry" >&2
    exit 1
fi
rm "$assets/unexpected"
checksum_manifest

printf '%s\n' 'not-a-checksum malformed' >> "$assets/SHA256SUMS"
if GH_CALL_LOG=$fixture/malformed-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted a malformed manifest line" >&2
    exit 1
fi
checksum_manifest

if GH_FAIL=1 GH_CALL_LOG=$fixture/failed-attestation-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
    > /dev/null 2>&1; then
    echo "error: verifier accepted failed provenance authentication" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
rm -rf "$fixture"
