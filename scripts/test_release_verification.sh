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

printf '%s\n' '#!/bin/sh' 'printf "%s\n" authenticated-release' > "$fixture/again"
chmod 0755 "$fixture/again"
python3 "$repository/scripts/package_release.py" \
    --binary "$fixture/again" \
    --output "$assets/again-${version}-${target}.tar.gz" \
    --source-date-epoch 1700000000

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

# The public installer authenticates both downloaded inputs with the same
# pinned provenance policy before it extracts or installs the archive.
install_call_log=$fixture/install-gh-calls
install_destination=$fixture/installed/again
GH_CALL_LOG=$install_call_log REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/install.sh" \
    --version "$version" \
    --base-url https://releases.example.invalid/download \
    --dest "$install_destination" \
    > "$fixture/install.out"
test "$("$install_destination")" = authenticated-release
test "$(wc -l < "$install_call_log" | tr -d ' ')" -eq 2
grep -F "/SHA256SUMS --repo alakhanpal23/again" "$install_call_log" >/dev/null
grep -F "/again-${version}-${target}.tar.gz --repo alakhanpal23/again" \
    "$install_call_log" >/dev/null
while IFS= read -r call; do
    for required in \
        "--repo alakhanpal23/again" \
        "--signer-workflow alakhanpal23/again/.github/workflows/release.yml" \
        "--source-ref refs/tags/$version" \
        "--deny-self-hosted-runners"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: installer did not pin the complete provenance policy: $call" >&2
            exit 1
        }
    done
done < "$install_call_log"

failed_install_destination=$fixture/failed-install/again
if GH_FAIL=1 GH_CALL_LOG=$fixture/failed-install-calls REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" sh "$repository/scripts/install.sh" \
    --version "$version" \
    --base-url https://releases.example.invalid/download \
    --dest "$failed_install_destination" \
    > /dev/null 2>&1; then
    echo "error: installer accepted failed provenance authentication" >&2
    exit 1
fi
test ! -e "$failed_install_destination"

tampered=$assets/again-${version}-aarch64-apple-darwin.tar.gz
cp "$tampered" "$fixture/tampered-original"
printf 'tampered\n' >> "$tampered"
if GH_CALL_LOG=$fixture/tampered-calls PATH="$fake_bin:$PATH" \
    sh "$repository/scripts/verify_release.sh" \
    --version "$version" --artifact-dir "$assets" --repository alakhanpal23/again \
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
