#!/bin/sh
set -eu

repository=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd -P)
generator=$repository/packaging/homebrew/generate_formula.py
workflow=$repository/.github/workflows/release.yml
fixture=$(mktemp -d "${TMPDIR:-/tmp}/again-homebrew-formula-test.XXXXXXXX")
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
checksums=$fixture/SHA256SUMS
cat > "$checksums" <<EOF
1111111111111111111111111111111111111111111111111111111111111111  again-${version}-aarch64-apple-darwin.tar.gz
2222222222222222222222222222222222222222222222222222222222222222  again-${version}-aarch64-unknown-linux-gnu.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  again-${version}-source.cdx.json
4444444444444444444444444444444444444444444444444444444444444444  again-${version}-x86_64-apple-darwin.tar.gz
5555555555555555555555555555555555555555555555555555555555555555  again-${version}-x86_64-unknown-linux-gnu.tar.gz
EOF

formula=$fixture/again-alpha.rb
formula_repeat=$fixture/again-alpha-repeat.rb
python3 "$generator" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$checksums" \
    --output "$formula"
python3 "$generator" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$checksums" \
    --output "$formula_repeat"
cmp "$formula" "$formula_repeat"
python3 "$generator" \
    --version "$version" \
    --source-commit "$source_commit" \
    --checksums "$checksums" \
    --verify "$formula"
ruby -c "$formula" >/dev/null

grep -Fx '  version "0.1.0-alpha.1"' "$formula" >/dev/null
grep -Fx "  SOURCE_COMMIT = \"$source_commit\"" "$formula" >/dev/null
grep -Fx '  CORE_VERSION = "0.1.0"' "$formula" >/dev/null
test "$(grep -c '^      url "https://github.com/alakhanpal23/again/releases/download/' "$formula")" -eq 4
test "$(grep -c '^      sha256 "[0-9a-f][0-9a-f]*"$' "$formula")" -eq 4
grep -F 'doctor --json' "$formula" >/dev/null
grep -F "'\"trace_backed_replay\": false'" "$formula" >/dev/null
grep -F "'\"seatbelt_used_for_profile\": false'" "$formula" >/dev/null
grep -F -- '--output dist/again-alpha.rb' "$workflow" >/dev/null
grep -F 'subject-path: dist/again-alpha.rb' "$workflow" >/dev/null
grep -F 'dist/again-alpha.rb \' "$workflow" >/dev/null
if grep -Eq 'setup|config enable|reuse authority' "$formula"; then
    echo "error: formula contains an unsupported authority-enabling action" >&2
    exit 1
fi

if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$checksums" --output "$formula" > /dev/null 2>&1; then
    echo "error: formula generator overwrote an existing output" >&2
    exit 1
fi

cp "$checksums" "$fixture/duplicate-checksums"
head -n 1 "$checksums" >> "$fixture/duplicate-checksums"
if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$fixture/duplicate-checksums" \
    --output "$fixture/duplicate.rb" > /dev/null 2>&1; then
    echo "error: formula generator accepted a duplicate checksum" >&2
    exit 1
fi

sed '$d' "$checksums" > "$fixture/missing-checksums"
if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$fixture/missing-checksums" \
    --output "$fixture/missing.rb" > /dev/null 2>&1; then
    echo "error: formula generator accepted a missing checksum" >&2
    exit 1
fi

cp "$checksums" "$fixture/traversal-checksums"
printf '%064d  ../outside\n' 0 >> "$fixture/traversal-checksums"
if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$fixture/traversal-checksums" \
    --output "$fixture/traversal.rb" > /dev/null 2>&1; then
    echo "error: formula generator accepted path traversal" >&2
    exit 1
fi

ln -s "$checksums" "$fixture/symlink-checksums"
if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$fixture/symlink-checksums" \
    --output "$fixture/symlink.rb" > /dev/null 2>&1; then
    echo "error: formula generator accepted a symlinked manifest" >&2
    exit 1
fi

if python3 "$generator" \
    --version v0.1.0 --source-commit "$source_commit" \
    --checksums "$checksums" --output "$fixture/stable.rb" > /dev/null 2>&1; then
    echo "error: alpha formula generator accepted a stable tag" >&2
    exit 1
fi

if python3 "$generator" \
    --version "$version" --source-commit not-a-commit \
    --checksums "$checksums" --output "$fixture/commit.rb" > /dev/null 2>&1; then
    echo "error: formula generator accepted a malformed source commit" >&2
    exit 1
fi

printf '\n# mutation\n' >> "$formula_repeat"
if python3 "$generator" \
    --version "$version" --source-commit "$source_commit" \
    --checksums "$checksums" --verify "$formula_repeat" > /dev/null 2>&1; then
    echo "error: formula verifier accepted mutated formula bytes" >&2
    exit 1
fi

trap - EXIT HUP INT TERM
rm -rf "$fixture"
