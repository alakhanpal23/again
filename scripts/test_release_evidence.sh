#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
exporter=$repository_root/scripts/export_release_evidence.py
workflow=$repository_root/.github/workflows/release.yml
fixture=$(mktemp -d "${TMPDIR:-/tmp}/again-release-evidence-test.XXXXXXXX")
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
verified_at=2026-08-27T20:30:00Z
assets=$fixture/assets
summaries=$fixture/summaries
fake_bin=$fixture/bin
mkdir "$assets" "$summaries" "$fake_bin"

cat > "$fixture/names" <<EOF
SHA256SUMS
again-alpha.rb
again-${version}-aarch64-apple-darwin.tar.gz
again-${version}-aarch64-unknown-linux-gnu.tar.gz
again-${version}-source.cdx.json
again-${version}-x86_64-apple-darwin.tar.gz
again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF
printf '%s\n' '#!/bin/sh' 'printf "%s\n" private-source-sentinel' \
    > "$fixture/again"
chmod 0755 "$fixture/again"
python3 "$repository_root/scripts/package_release.py" \
    --binary "$fixture/again" \
    --output "$assets/again-${version}-aarch64-apple-darwin.tar.gz" \
    --source-date-epoch 1700000000
for target in \
    aarch64-unknown-linux-gnu \
    x86_64-apple-darwin \
    x86_64-unknown-linux-gnu
do
    cp "$assets/again-${version}-aarch64-apple-darwin.tar.gz" \
        "$assets/again-${version}-${target}.tar.gz"
done
cat > "$assets/again-${version}-source.cdx.json" <<'EOF'
{"bomFormat":"CycloneDX","specVersion":"1.5","metadata":{"component":{"name":"again-cli","version":"0.1.0"}}}
EOF

file_hash() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{ print $1 }'
    else
        shasum -a 256 "$1" | awk '{ print $1 }'
    fi
}

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$assets" && sha256sum "again-${version}-"* > SHA256SUMS)
else
    (cd "$assets" && shasum -a 256 "again-${version}-"* > SHA256SUMS)
fi
python3 "$repository_root/packaging/homebrew/generate_formula.py" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$assets/SHA256SUMS" \
    --output "$assets/again-alpha.rb"

metadata=$fixture/release-metadata.json
cat > "$metadata" <<EOF
{"assets":[{"name":"SHA256SUMS"},{"name":"again-alpha.rb"},{"name":"again-${version}-aarch64-apple-darwin.tar.gz"},{"name":"again-${version}-aarch64-unknown-linux-gnu.tar.gz"},{"name":"again-${version}-source.cdx.json"},{"name":"again-${version}-x86_64-apple-darwin.tar.gz"},{"name":"again-${version}-x86_64-unknown-linux-gnu.tar.gz"}],"isDraft":false,"isImmutable":true,"isPrerelease":true,"tagName":"${version}"}
EOF

index=0
while IFS= read -r name; do
    digest=$(file_hash "$assets/$name")
    cat > "$fixture/attestation.json" <<EOF
[{"attestation":{"bundle":"intentionally-discarded"},"verificationResult":{"signature":{"certificate":{"issuer":"fixture"}},"verifiedTimestamps":[{"type":"transparency-log"}],"statement":{"subject":[{"name":"$name","digest":{"sha256":"$digest"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"untrusted":"not-retained"}}}}]
EOF
    summary=$(printf '%s/%03d.json' "$summaries" "$index")
    python3 "$exporter" attestation \
        --input "$fixture/attestation.json" \
        --subject-name "$name" \
        --subject-digest "$digest" \
        --output "$summary"
    index=$((index + 1))
done < "$fixture/names"
test "$index" -eq 7

run_export() {
    input_metadata=$1
    input_summaries=$2
    input_assets=$3
    output=$4
    tag=${5:-$version}
    commit=${6:-$source_commit}
    python3 "$exporter" evidence \
        --release-metadata "$input_metadata" \
        --attestation-dir "$input_summaries" \
        --artifact-dir "$input_assets" \
        --repository alakhanpal23/again \
        --tag "$tag" \
        --source-commit "$commit" \
        --verified-at "$verified_at" \
        --github-cli-version 'gh version 2.92.0 (2026-06-18)' \
        --output "$output"
}

expect_export_failure() {
    label=$1
    shift
    if run_export "$@" > /dev/null 2>&1; then
        echo "error: evidence exporter accepted $label" >&2
        exit 1
    fi
}

evidence=$fixture/release-evidence.json
evidence_repeat=$fixture/release-evidence-repeat.json
run_export "$metadata" "$summaries" "$assets" "$evidence"
run_export "$metadata" "$summaries" "$assets" "$evidence_repeat"
cmp "$evidence" "$evidence_repeat"
python3 - "$evidence" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert document["schema"] == "again.release-verification-summary.v1"
assert document["authority"] == {
    "independent_release_verification": False,
    "requires_enclosing_github_actions_run": True,
}
assert document["release"]["immutable"] is True
assert document["release"]["draft"] is False
assert document["release"]["source_commit"] == "0123456789abcdef0123456789abcdef01234567"
assert len(document["artifacts"]) == 7
assert all(item["attestation"]["status"] == "verified" for item in document["artifacts"])
assert document["verification"]["github_cli"].startswith("gh version 2.92.0")
PY
if grep -F 'private-source-sentinel' "$evidence" >/dev/null || \
    grep -F 'intentionally-discarded' "$evidence" >/dev/null || \
    grep -F 'untrusted' "$evidence" >/dev/null; then
    echo "error: evidence retained repository or raw attestation content" >&2
    exit 1
fi
grep -F 'scripts/test_release_evidence.sh' "$workflow" >/dev/null
grep -F -- '--evidence-output "$GITHUB_WORKSPACE/release-evidence.json"' "$workflow" >/dev/null
if grep -F -- '--verified-at "$verified_at"' "$workflow" >/dev/null; then
    echo "error: workflow timestamps verification before it completes" >&2
    exit 1
fi
grep -F 'name: release-evidence-${{ github.ref_name }}' "$workflow" >/dev/null

# Exercise the complete published verifier with offline GitHub metadata and
# official-shaped `gh attestation verify --format json` results. The evidence
# file is created only after all seven publisher-authenticated checks succeed.
published_view=$fixture/published-view
{
    printf '%s\n' "$version" false true true
    cat "$fixture/names"
} > "$published_view"
call_log=$fixture/gh-calls
cat > "$fake_bin/gh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_CALL_LOG"
first=${1:-}
second=${2:-}
case "$first:$second" in
    release:view)
        line_output=0
        for argument do
            [ "$argument" != --jq ] || line_output=1
        done
        if [ "$line_output" -eq 1 ]; then
            cat "$PUBLISHED_VIEW"
        else
            cat "$PUBLISHED_JSON"
        fi
        ;;
    release:download)
        destination=
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --dir)
                    destination=$2
                    shift 2
                    ;;
                *) shift ;;
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
    attestation:verify)
        [ "${GH_FAIL:-0}" -eq 0 ] || exit 1
        subject=$3
        name=${subject##*/}
        if command -v sha256sum >/dev/null 2>&1; then
            digest=$(sha256sum "$subject" | awk '{ print $1 }')
        else
            digest=$(shasum -a 256 "$subject" | awk '{ print $1 }')
        fi
        printf '[{"attestation":{"fixture":true},"verificationResult":{"signature":{"certificate":{"issuer":"fixture"}},"verifiedTimestamps":[{"type":"transparency-log"}],"statement":{"subject":[{"name":"%s","digest":{"sha256":"%s"}}],"predicateType":"https://slsa.dev/provenance/v1"}}}]\n' \
            "$name" "$digest"
        ;;
    --version:)
        printf '%s\n' 'gh version 2.92.0 (2026-06-18)'
        ;;
    *)
        echo "error: unexpected gh command: $*" >&2
        exit 1
        ;;
esac
EOF
chmod 0755 "$fake_bin/gh"

integrated_evidence=$fixture/integrated-evidence.json
GH_CALL_LOG=$call_log PUBLISHED_VIEW=$published_view \
    PUBLISHED_JSON=$metadata PUBLISHED_INVENTORY=$fixture/names \
    SOURCE_COMMIT=$source_commit REMOTE_ASSETS=$assets \
    PATH="$fake_bin:$PATH" \
    sh "$repository_root/scripts/verify_published_release.sh" \
    --version "$version" \
    --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    --verified-at "$verified_at" \
    --evidence-output "$integrated_evidence" \
    > "$fixture/integrated.out"
test -f "$integrated_evidence" && cmp "$evidence" "$integrated_evidence"
test "$(wc -l < "$call_log" | tr -d ' ')" -eq 12
test "$(grep -c '^attestation verify ' "$call_log")" -eq 7
grep '^attestation verify ' "$call_log" > "$fixture/attestation-calls"
while IFS= read -r call; do
    for required in \
        "--repo alakhanpal23/again" \
        "--signer-workflow alakhanpal23/again/.github/workflows/release.yml" \
        "--signer-digest $source_commit" \
        "--source-ref refs/tags/$version" \
        "--source-digest $source_commit" \
        "--cert-oidc-issuer https://token.actions.githubusercontent.com" \
        "--predicate-type https://slsa.dev/provenance/v1" \
        "--deny-self-hosted-runners" \
        "--format json"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: evidence verification omitted publisher policy: $call" >&2
            exit 1
        }
    done
done < "$fixture/attestation-calls"

failed_evidence=$fixture/failed-evidence.json
if GH_FAIL=1 GH_CALL_LOG=$fixture/failed-gh-calls \
    PUBLISHED_VIEW=$published_view PUBLISHED_JSON=$metadata \
    PUBLISHED_INVENTORY=$fixture/names SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository_root/scripts/verify_published_release.sh" \
    --version "$version" \
    --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    --verified-at "$verified_at" \
    --evidence-output "$failed_evidence" > /dev/null 2>&1; then
    echo "error: failed attestation produced release evidence" >&2
    exit 1
fi
test ! -e "$failed_evidence"

expect_export_failure "an existing output" \
    "$metadata" "$summaries" "$assets" "$evidence"
expect_export_failure "output path traversal" \
    "$metadata" "$summaries" "$assets" "$fixture/subdirectory/../traversed.json"
ln -s "$fixture" "$fixture/output-parent-link"
expect_export_failure "a symlinked output directory" \
    "$metadata" "$summaries" "$assets" "$fixture/output-parent-link/evidence.json"

sed 's/"tagName"/"tagName":"duplicate","tagName"/' "$metadata" \
    > "$fixture/duplicate-key.json"
expect_export_failure "duplicate JSON keys" \
    "$fixture/duplicate-key.json" "$summaries" "$assets" "$fixture/duplicate-key-output.json"

sed 's/"isImmutable":true/"isImmutable":false/' "$metadata" \
    > "$fixture/mutable.json"
expect_export_failure "a mutable release" \
    "$fixture/mutable.json" "$summaries" "$assets" "$fixture/mutable-output.json"

expect_export_failure "a mismatched tag identity" \
    "$metadata" "$summaries" "$assets" "$fixture/tag-output.json" v0.1.0-alpha.2
expect_export_failure "a malformed source identity" \
    "$metadata" "$summaries" "$assets" "$fixture/source-output.json" "$version" not-a-commit

dd if=/dev/zero of="$fixture/oversized.json" bs=1048576 count=5 2>/dev/null
expect_export_failure "oversized metadata" \
    "$fixture/oversized.json" "$summaries" "$assets" "$fixture/oversized-output.json"

ln -s "$metadata" "$fixture/symlink-metadata.json"
expect_export_failure "symlinked metadata" \
    "$fixture/symlink-metadata.json" "$summaries" "$assets" "$fixture/symlink-output.json"

sed 's#"SHA256SUMS"#"../escape"#' "$metadata" > "$fixture/traversal.json"
expect_export_failure "an unsafe artifact name" \
    "$fixture/traversal.json" "$summaries" "$assets" "$fixture/traversal-output.json"

cp -R "$summaries" "$fixture/bad-summaries"
first_summary=$fixture/bad-summaries/000.json
sed 's/"sha256": "[0-9a-f]*"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$first_summary" > "$fixture/bad-summary.json"
mv "$fixture/bad-summary.json" "$first_summary"
expect_export_failure "a mismatched attestation digest" \
    "$metadata" "$fixture/bad-summaries" "$assets" "$fixture/bad-summary-output.json"

cp -R "$summaries" "$fixture/duplicate-summaries"
first_summary=$fixture/duplicate-summaries/000.json
sed 's/"schema":/"schema":"duplicate","schema":/' "$first_summary" \
    > "$fixture/duplicate-summary.json"
mv "$fixture/duplicate-summary.json" "$first_summary"
expect_export_failure "duplicate attestation summary keys" \
    "$metadata" "$fixture/duplicate-summaries" "$assets" "$fixture/duplicate-summary-output.json"

cp -R "$assets" "$fixture/symlink-assets"
rm "$fixture/symlink-assets/SHA256SUMS"
ln -s "$assets/SHA256SUMS" "$fixture/symlink-assets/SHA256SUMS"
expect_export_failure "a symlinked release artifact" \
    "$metadata" "$summaries" "$fixture/symlink-assets" "$fixture/symlink-asset-output.json"

cat > "$fixture/duplicate-attestation.json" <<EOF
[{"verificationResult":{},"verificationResult":{}}]
EOF
if python3 "$exporter" attestation \
    --input "$fixture/duplicate-attestation.json" \
    --subject-name SHA256SUMS \
    --subject-digest "$(file_hash "$assets/SHA256SUMS")" \
    --output "$fixture/duplicate-attestation-summary.json" > /dev/null 2>&1; then
    echo "error: attestation summarizer accepted duplicate JSON keys" >&2
    exit 1
fi

dd if=/dev/zero of="$fixture/oversized-attestation.json" bs=1048576 count=5 2>/dev/null
if python3 "$exporter" attestation \
    --input "$fixture/oversized-attestation.json" \
    --subject-name SHA256SUMS \
    --subject-digest "$(file_hash "$assets/SHA256SUMS")" \
    --output "$fixture/oversized-attestation-summary.json" > /dev/null 2>&1; then
    echo "error: attestation summarizer accepted oversized input" >&2
    exit 1
fi

last_name=$(tail -n 1 "$fixture/names")
digest=$(file_hash "$assets/$last_name")
sed 's#https://slsa.dev/provenance/v1#https://example.invalid/wrong#' \
    "$fixture/attestation.json" > "$fixture/wrong-predicate.json"
if python3 "$exporter" attestation \
    --input "$fixture/wrong-predicate.json" --subject-name "$last_name" \
    --subject-digest "$digest" --output "$fixture/wrong-predicate-summary.json" \
    > /dev/null 2>&1; then
    echo "error: attestation summarizer accepted a mismatched predicate" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
rm -rf "$fixture"
