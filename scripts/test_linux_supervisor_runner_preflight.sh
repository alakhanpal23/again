#!/bin/bash
set -euo pipefail

temporary_root=$(mktemp -d "${TMPDIR:-/tmp}/again-supervisor-preflight-test.XXXXXXXX")
trap 'chmod -R u+rwX "$temporary_root" 2>/dev/null || true; rm -rf "$temporary_root"' EXIT HUP INT TERM
preflight=scripts/preflight_linux_supervisor_runner.sh

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

new_fixture() {
  local name=$1
  local root=$temporary_root/$name
  mkdir -p "$root/proc/self" "$root/boot"
  printf 'Linux\n' > "$root/uname-s"
  printf 'x86_64\n' > "$root/uname-m"
  printf '6.17.0-again\n' > "$root/uname-r"
  printf 'Name:\ttest\nCapEff:\t0000000000200000\n' > "$root/proc/self/status"
  printf '%s\n' "$root"
}

write_gzip_config() {
  local root=$1
  printf 'CONFIG_SECCOMP_FILTER=y\nCONFIG_CHECKPOINT_RESTORE=y\n' |
    gzip -c > "$root/proc/config.gz"
}

write_boot_config() {
  local root=$1
  printf 'CONFIG_SECCOMP_FILTER=y\nCONFIG_CHECKPOINT_RESTORE=y\n' \
    > "$root/boot/config-6.17.0-again"
}

expect_failure() {
  local root=$1
  local expected=$2
  local output=$temporary_root/failure-output
  if "$preflight" --test-fixture-root "$root" > "$output" 2>&1; then
    fail "preflight unexpectedly accepted fixture $root"
  fi
  grep -Fq "$expected" "$output" || fail "preflight did not report: $expected"
}

proc_fixture=$(new_fixture proc-config)
write_gzip_config "$proc_fixture"
proc_output=$("$preflight" --test-fixture-root "$proc_fixture")
[[ "$proc_output" == *'/proc/config.gz, effective CAP_SYS_ADMIN.' ]] ||
  fail 'proc-config success output was not canonical'

large_proc_fixture=$(new_fixture large-proc-config)
{
  printf 'CONFIG_SECCOMP_FILTER=y\nCONFIG_CHECKPOINT_RESTORE=y\n'
  awk 'BEGIN { for (i = 0; i < 20000; i += 1) print "CONFIG_AGAIN_FILLER_" i "=n" }'
} | gzip -c > "$large_proc_fixture/proc/config.gz"
"$preflight" --test-fixture-root "$large_proc_fixture" > /dev/null

boot_fixture=$(new_fixture boot-config)
write_boot_config "$boot_fixture"
boot_output=$("$preflight" --test-fixture-root "$boot_fixture")
[[ "$boot_output" == *'/boot/config-6.17.0-again, effective CAP_SYS_ADMIN.' ]] ||
  fail 'boot-config success output was not canonical'

readonly_fixture=$(new_fixture read-only)
write_gzip_config "$readonly_fixture"
chmod -R a-w "$readonly_fixture"
"$preflight" --test-fixture-root "$readonly_fixture" > /dev/null

wrong_os=$(new_fixture wrong-os)
write_gzip_config "$wrong_os"
printf 'Darwin\n' > "$wrong_os/uname-s"
expect_failure "$wrong_os" 'requires Linux'

wrong_arch=$(new_fixture wrong-arch)
write_gzip_config "$wrong_arch"
printf 'aarch64\n' > "$wrong_arch/uname-m"
expect_failure "$wrong_arch" 'requires x86_64'

missing_config=$(new_fixture missing-config)
expect_failure "$missing_config" 'configuration is not readable'

missing_seccomp=$(new_fixture missing-seccomp)
printf 'CONFIG_CHECKPOINT_RESTORE=y\n' | gzip -c > "$missing_seccomp/proc/config.gz"
expect_failure "$missing_seccomp" 'CONFIG_SECCOMP_FILTER=y'

missing_checkpoint=$(new_fixture missing-checkpoint)
printf 'CONFIG_SECCOMP_FILTER=y\n' > "$missing_checkpoint/boot/config-6.17.0-again"
expect_failure "$missing_checkpoint" 'CONFIG_CHECKPOINT_RESTORE=y'

duplicate_seccomp=$(new_fixture duplicate-seccomp)
printf 'CONFIG_SECCOMP_FILTER=y\nCONFIG_SECCOMP_FILTER=n\nCONFIG_CHECKPOINT_RESTORE=y\n' |
  gzip -c > "$duplicate_seccomp/proc/config.gz"
expect_failure "$duplicate_seccomp" 'CONFIG_SECCOMP_FILTER=y'

duplicate_checkpoint=$(new_fixture duplicate-checkpoint)
printf 'CONFIG_SECCOMP_FILTER=y\nCONFIG_CHECKPOINT_RESTORE=y\nCONFIG_CHECKPOINT_RESTORE=y\n' \
  > "$duplicate_checkpoint/boot/config-6.17.0-again"
expect_failure "$duplicate_checkpoint" 'CONFIG_CHECKPOINT_RESTORE=y'

missing_capability=$(new_fixture missing-capability)
write_gzip_config "$missing_capability"
printf 'Name:\ttest\nCapEff:\t0000000000000000\n' > "$missing_capability/proc/self/status"
expect_failure "$missing_capability" 'lacks effective CAP_SYS_ADMIN'

duplicate_capability=$(new_fixture duplicate-capability)
write_gzip_config "$duplicate_capability"
printf 'CapEff:\t0000000000200000\nCapEff:\t0000000000200000\n' \
  > "$duplicate_capability/proc/self/status"
expect_failure "$duplicate_capability" 'no canonical CapEff row'

malformed_capability=$(new_fixture malformed-capability)
write_gzip_config "$malformed_capability"
printf 'CapEff:\tnot-hex\n' > "$malformed_capability/proc/self/status"
expect_failure "$malformed_capability" 'CapEff value is malformed'

trailing_capability=$(new_fixture trailing-capability)
write_gzip_config "$trailing_capability"
printf 'CapEff:\t0000000000200000 trailing\n' > "$trailing_capability/proc/self/status"
expect_failure "$trailing_capability" 'no canonical CapEff row'

wide_capability=$(new_fixture wide-capability)
write_gzip_config "$wide_capability"
printf 'CapEff:\tffffffffffffffff\n' > "$wide_capability/proc/self/status"
"$preflight" --test-fixture-root "$wide_capability" > /dev/null

if "$preflight" --test-fixture-root relative/path > /dev/null 2>&1; then
  fail 'preflight accepted a relative fixture path'
fi

workflow=.github/workflows/linux-supervisor-qualification.yml
grep -Fqx '  workflow_dispatch:' "$workflow" ||
  fail 'qualification workflow is no longer manual dispatch only'
grep -Fqx '  contents: read' "$workflow" ||
  fail 'qualification workflow no longer has contents-read authority'
grep -Fqx '    runs-on: [self-hosted, linux, x64, again-linux-pytest-v1]' "$workflow" ||
  fail 'qualification workflow runner labels changed'
grep -Fqx '        run: scripts/preflight_linux_supervisor_runner.sh' "$workflow" ||
  fail 'qualification workflow does not invoke the production preflight'
grep -Fqx '        run: cargo +1.88.0 build --locked --features linux-pytest --bin again' "$workflow" ||
  fail 'qualification workflow does not build the hidden diagnostic surface'
if grep -Eq 'CapEff:|CONFIG_SECCOMP_FILTER|CONFIG_CHECKPOINT_RESTORE|uname -[sm]' "$workflow"; then
  fail 'qualification workflow still duplicates the extracted host contract'
fi

printf 'Linux supervisor runner preflight tests passed.\n'
