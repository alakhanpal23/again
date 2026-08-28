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
workflow_run_id=123456789
workflow_run_attempt=2
assets=$fixture/assets
summaries=$fixture/summaries
fake_bin=$fixture/bin
mkdir "$assets" "$summaries" "$fake_bin"

cat > "$fixture/subjects" <<EOF
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

# Build standardized bundle-shaped fixtures. Cryptographic validation belongs
# to the pinned Cosign invocation; this parser test independently validates the
# exact signed statement and required certificate, timestamp, and tlog material.
python3 - "$assets" "$fixture/subjects" "$version" "$source_commit" \
    "$workflow_run_id" "$workflow_run_attempt" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

assets = pathlib.Path(sys.argv[1])
names = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8").splitlines()
tag, commit, run_id, attempt = sys.argv[3:]
repository = "alakhanpal23/again"
source_ref = f"refs/tags/{tag}"
workflow = ".github/workflows/release.yml"
predicate = {
    "buildDefinition": {
        "buildType": "https://github.com/Attestations/GitHubActionsWorkflow@v1",
        "externalParameters": {
            "repository": repository,
            "sourceRef": source_ref,
            "workflow": workflow,
        },
        "internalParameters": {},
        "resolvedDependencies": [{
            "digest": {"gitCommit": commit},
            "uri": f"git+https://github.com/{repository}@{source_ref}",
        }],
    },
    "runDetails": {
        "builder": {"id": f"https://github.com/{repository}/{workflow}@{source_ref}"},
        "metadata": {
            "invocationId": (
                f"https://github.com/{repository}/actions/runs/{run_id}/attempts/{attempt}"
            )
        },
    },
}
for name in names:
    digest = hashlib.sha256((assets / name).read_bytes()).hexdigest()
    statement = {
        "_type": "https://in-toto.io/Statement/v0.1",
        "predicate": predicate,
        "predicateType": "https://slsa.dev/provenance/v1",
        "subject": [{"digest": {"sha256": digest}, "name": name}],
    }
    payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
    bundle = {
        "dsseEnvelope": {
            "payload": base64.b64encode(payload).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(b"fixture-signature").decode()}],
        },
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": base64.b64encode(b"fixture-fulcio-certificate").decode()
            },
            "timestampVerificationData": {
                "rfc3161Timestamps": [{
                    "signedTimestamp": base64.b64encode(b"fixture-timestamp").decode()
                }]
            },
            "tlogEntries": [{"fixture": "rekor-entry"}],
        },
    }
    (assets / f"{name}.sigstore.json").write_text(
        json.dumps(bundle, separators=(",", ":"), sort_keys=True) + "\n",
        encoding="utf-8",
    )
PY

metadata=$fixture/release-metadata.json
python3 - "$assets" "$version" "$metadata" <<'PY'
import json
import pathlib
import sys

assets = pathlib.Path(sys.argv[1])
tag = sys.argv[2]
output = pathlib.Path(sys.argv[3])
document = {
    "assets": [{"name": path.name} for path in sorted(assets.iterdir())],
    "isDraft": False,
    "isImmutable": True,
    "isPrerelease": True,
    "tagName": tag,
}
output.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
PY

index=0
while IFS= read -r name; do
    digest=$(file_hash "$assets/$name")
    summary=$(printf '%s/%03d.json' "$summaries" "$index")
    python3 "$exporter" attestation \
        --input "$assets/$name.sigstore.json" \
        --subject-name "$name" \
        --subject-digest "$digest" \
        --repository alakhanpal23/again \
        --tag "$version" \
        --source-commit "$source_commit" \
        --output "$summary"
    index=$((index + 1))
done < "$fixture/subjects"
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
        --cosign-version 'cosign v3.1.3 (11926fa5bbbbde47e88fc006b625a17769b743b2)' \
        --harness-root "$repository_root" \
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
assert document["schema"] == "again.release-verification-summary.v2"
assert document["authority"] == {
    "cryptographic_proof_embedded": False,
    "independent_release_verification_available": True,
    "requires_release_sigstore_bundles": True,
}
assert document["release"]["immutable"] is True
assert document["release"]["source_commit"] == "0123456789abcdef0123456789abcdef01234567"
assert len(document["artifacts"]) == 7
assert all(item["attestation"]["status"] == "verified" for item in document["artifacts"])
assert all(item["attestation"]["signed_timestamps"] == 1 for item in document["artifacts"])
assert all(item["attestation"]["transparency_log_entries"] == 1 for item in document["artifacts"])
archives = [item for item in document["artifacts"] if item["name"].endswith(".tar.gz")]
assert len(archives) == 4
assert all(item["binary_sha256"] == item["members"][0]["sha256"] for item in archives)
assert document["publisher"]["status"] == "authenticated"
assert document["publisher"]["workflow_run"] == {
    "attempt": 2,
    "id": 123456789,
    "url": "https://github.com/alakhanpal23/again/actions/runs/123456789/attempts/2",
}
assert document["publisher_policy"]["cosign_version"] == "v3.1.3"
assert document["publisher_policy"]["trusted_timestamp_required"] is True
assert document["publisher_policy"]["transparency_log_required"] is True
assert document["verification"]["cosign"].startswith("cosign v3.1.3")
assert len(document["verification"]["harness"]["components"]) == 7
assert len(document["verification"]["harness"]["sha256"]) == 64
PY
if grep -F 'private-source-sentinel' "$evidence" >/dev/null || \
    grep -F 'fixture-signature' "$evidence" >/dev/null || \
    grep -F 'rekor-entry' "$evidence" >/dev/null; then
    echo "error: evidence retained release payload or raw proof content" >&2
    exit 1
fi
grep -F 'scripts/test_release_evidence.sh' "$workflow" >/dev/null
grep -F -- '--evidence-output "$GITHUB_WORKSPACE/release-evidence.json"' "$workflow" >/dev/null
grep -F 'name: release-evidence-${{ github.ref_name }}' "$workflow" >/dev/null

published_view=$fixture/published-view
all_assets=$fixture/all-assets
(cd "$assets" && printf '%s\n' *) > "$all_assets"
{
    printf '%s\n' "$version" false true true
    cat "$all_assets"
} > "$published_view"
call_log=$fixture/gh-calls
cosign_log=$fixture/cosign-calls
cat > "$fake_bin/gh" <<'EOF'
#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$GH_CALL_LOG"
case "${1:-}:${2:-}" in
    release:view)
        line_output=0
        for argument do [ "$argument" != --jq ] || line_output=1; done
        if [ "$line_output" -eq 1 ]; then cat "$PUBLISHED_VIEW"; else cat "$PUBLISHED_JSON"; fi
        ;;
    release:download)
        destination=
        while [ "$#" -gt 0 ]; do
            case "$1" in --dir) destination=$2; shift 2 ;; *) shift ;; esac
        done
        [ -n "$destination" ]
        while IFS= read -r asset; do cp "$REMOTE_ASSETS/$asset" "$destination/$asset"; done \
            < "$PUBLISHED_INVENTORY"
        ;;
    api:*) printf '%s\n' "$SOURCE_COMMIT" ;;
    --version:) printf '%s\n' 'gh version 2.92.0 (2026-06-18)' ;;
    *) echo "error: unexpected gh command: $*" >&2; exit 1 ;;
esac
EOF
chmod 0755 "$fake_bin/gh"
cat > "$fake_bin/cosign" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
    version)
        cat <<'JSON'
{
  "gitVersion": "v3.1.3",
  "gitCommit": "11926fa5bbbbde47e88fc006b625a17769b743b2",
  "gitTreeState": "clean"
}
JSON
        ;;
    verify-blob-attestation)
        printf '%s\n' "$*" >> "${COSIGN_CALL_LOG:-/dev/null}"
        [ "${COSIGN_FAIL:-0}" -eq 0 ]
        ;;
    *) echo "error: unexpected cosign command: $*" >&2; exit 1 ;;
esac
EOF
chmod 0755 "$fake_bin/cosign"

integrated_evidence=$fixture/integrated-evidence.json
GH_CALL_LOG=$call_log COSIGN_CALL_LOG=$cosign_log \
    PUBLISHED_VIEW=$published_view PUBLISHED_JSON=$metadata \
    PUBLISHED_INVENTORY=$all_assets SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository_root/scripts/verify_published_release.sh" \
    --version "$version" \
    --source-commit "$source_commit" \
    --repository alakhanpal23/again \
    --verified-at "$verified_at" \
    --evidence-output "$integrated_evidence" \
    > "$fixture/integrated.out"
cmp "$evidence" "$integrated_evidence"
test "$(wc -l < "$call_log" | tr -d ' ')" -eq 5
test "$(wc -l < "$cosign_log" | tr -d ' ')" -eq 7
while IFS= read -r call; do
    for required in \
        "--certificate-identity https://github.com/alakhanpal23/again/.github/workflows/release.yml@refs/tags/$version" \
        "--certificate-oidc-issuer https://token.actions.githubusercontent.com" \
        "--certificate-github-workflow-ref refs/tags/$version" \
        "--certificate-github-workflow-repository alakhanpal23/again" \
        "--certificate-github-workflow-sha $source_commit" \
        "--certificate-github-workflow-trigger push" \
        "--type slsaprovenance1" \
        "--check-claims=true" \
        "--use-signed-timestamps"
    do
        printf '%s\n' "$call" | grep -F -- "$required" >/dev/null || {
            echo "error: evidence verification omitted publisher policy: $call" >&2
            exit 1
        }
    done
done < "$cosign_log"

failed_evidence=$fixture/failed-evidence.json
if COSIGN_FAIL=1 GH_CALL_LOG=$fixture/failed-gh-calls \
    COSIGN_CALL_LOG=$fixture/failed-cosign-calls \
    PUBLISHED_VIEW=$published_view PUBLISHED_JSON=$metadata \
    PUBLISHED_INVENTORY=$all_assets SOURCE_COMMIT=$source_commit \
    REMOTE_ASSETS=$assets PATH="$fake_bin:$PATH" \
    sh "$repository_root/scripts/verify_published_release.sh" \
    --version "$version" --source-commit "$source_commit" \
    --repository alakhanpal23/again --verified-at "$verified_at" \
    --evidence-output "$failed_evidence" > /dev/null 2>&1; then
    echo "error: failed Sigstore verification produced release evidence" >&2
    exit 1
fi
test ! -e "$failed_evidence"

expect_export_failure "an existing output" \
    "$metadata" "$summaries" "$assets" "$evidence"
sed 's/"isImmutable":true/"isImmutable":false/' "$metadata" > "$fixture/mutable.json"
expect_export_failure "a mutable release" \
    "$fixture/mutable.json" "$summaries" "$assets" "$fixture/mutable-output.json"
expect_export_failure "a mismatched tag identity" \
    "$metadata" "$summaries" "$assets" "$fixture/tag-output.json" v0.1.0-alpha.2
expect_export_failure "a malformed source identity" \
    "$metadata" "$summaries" "$assets" "$fixture/source-output.json" "$version" not-a-commit

cp -R "$summaries" "$fixture/bad-summaries"
first_summary=$fixture/bad-summaries/000.json
sed 's/"sha256": "[0-9a-f]*"/"sha256": "0000000000000000000000000000000000000000000000000000000000000000"/' \
    "$first_summary" > "$fixture/bad-summary.json"
mv "$fixture/bad-summary.json" "$first_summary"
expect_export_failure "a mismatched attestation digest" \
    "$metadata" "$fixture/bad-summaries" "$assets" "$fixture/bad-summary-output.json"

cp -R "$assets" "$fixture/symlink-assets"
rm "$fixture/symlink-assets/SHA256SUMS"
ln -s "$assets/SHA256SUMS" "$fixture/symlink-assets/SHA256SUMS"
expect_export_failure "a symlinked release artifact" \
    "$metadata" "$summaries" "$fixture/symlink-assets" "$fixture/symlink-output.json"

last_name=$(tail -n 1 "$fixture/subjects")
last_bundle=$assets/$last_name.sigstore.json
digest=$(file_hash "$assets/$last_name")
sed 's/"mediaType":"application\/vnd.dev.sigstore.bundle.v0.3+json"/"mediaType":"wrong","mediaType":"application\/vnd.dev.sigstore.bundle.v0.3+json"/' \
    "$last_bundle" > "$fixture/duplicate-bundle.json"
if python3 "$exporter" attestation --input "$fixture/duplicate-bundle.json" \
    --subject-name "$last_name" --subject-digest "$digest" \
    --repository alakhanpal23/again --tag "$version" \
    --source-commit "$source_commit" --output "$fixture/duplicate-summary.json" \
    > /dev/null 2>&1; then
    echo "error: attestation parser accepted duplicate bundle keys" >&2
    exit 1
fi
python3 - "$last_bundle" "$fixture/wrong-predicate.json" <<'PY'
import base64
import json
import pathlib
import sys

bundle = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
statement["predicateType"] = "https://example.invalid/wrong"
payload = json.dumps(statement, separators=(",", ":"), sort_keys=True).encode()
bundle["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode()
pathlib.Path(sys.argv[2]).write_text(
    json.dumps(bundle, separators=(",", ":"), sort_keys=True) + "\n",
    encoding="utf-8",
)
PY
if python3 "$exporter" attestation --input "$fixture/wrong-predicate.json" \
    --subject-name "$last_name" --subject-digest "$digest" \
    --repository alakhanpal23/again --tag "$version" \
    --source-commit "$source_commit" --output "$fixture/wrong-predicate-summary.json" \
    > /dev/null 2>&1; then
    echo "error: attestation parser accepted a mismatched predicate" >&2
    exit 1
fi
dd if=/dev/zero of="$fixture/oversized-bundle.json" bs=1048576 count=5 2>/dev/null
if python3 "$exporter" attestation --input "$fixture/oversized-bundle.json" \
    --subject-name "$last_name" --subject-digest "$digest" \
    --repository alakhanpal23/again --tag "$version" \
    --source-commit "$source_commit" --output "$fixture/oversized-summary.json" \
    > /dev/null 2>&1; then
    echo "error: attestation parser accepted an oversized bundle" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
rm -rf "$fixture"
