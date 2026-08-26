#!/bin/bash
set -euo pipefail

fail() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

has_one_exact_enabled_option() {
  local option=$1
  awk -v option="$option" '
    $0 == option "=y" {
      enabled += 1
      declarations += 1
      next
    }
    index($0, option "=") == 1 || $0 == "# " option " is not set" {
      declarations += 1
    }
    END {
      exit !(enabled == 1 && declarations == 1)
    }
  '
}

kernel_name=
kernel_machine=
kernel_release=
proc_config=/proc/config.gz
proc_status=/proc/self/status
boot_root=/boot

case "$#" in
  0)
    kernel_name=$(uname -s) || fail 'could not read the kernel name'
    kernel_machine=$(uname -m) || fail 'could not read the machine architecture'
    kernel_release=$(uname -r) || fail 'could not read the kernel release'
    ;;
  2)
    if [[ "$1" != "--test-fixture-root" || "$2" != /* ]]; then
      fail 'usage: preflight_linux_supervisor_runner.sh [--test-fixture-root /absolute/path]'
    fi
    fixture_root=$2
    [[ -d "$fixture_root" ]] || fail 'test fixture root is not a directory'
    IFS= read -r kernel_name < "$fixture_root/uname-s" ||
      fail 'could not read the fixture kernel name'
    IFS= read -r kernel_machine < "$fixture_root/uname-m" ||
      fail 'could not read the fixture machine architecture'
    IFS= read -r kernel_release < "$fixture_root/uname-r" ||
      fail 'could not read the fixture kernel release'
    proc_config=$fixture_root/proc/config.gz
    proc_status=$fixture_root/proc/self/status
    boot_root=$fixture_root/boot
    ;;
  *)
    fail 'usage: preflight_linux_supervisor_runner.sh [--test-fixture-root /absolute/path]'
    ;;
esac

[[ "$kernel_name" == Linux ]] || fail 'the supervisor qualification requires Linux'
[[ "$kernel_machine" == x86_64 ]] ||
  fail 'the supervisor qualification requires x86_64'
[[ "$kernel_release" =~ ^[0-9A-Za-z._+-]+$ ]] || fail 'kernel release is malformed'

required_kernel_options=(CONFIG_SECCOMP_FILTER CONFIG_CHECKPOINT_RESTORE)
if [[ -r "$proc_config" ]]; then
  for option in "${required_kernel_options[@]}"; do
    if ! gzip -cd -- "$proc_config" | has_one_exact_enabled_option "$option"; then
      fail "the running kernel does not expose ${option}=y in /proc/config.gz"
    fi
  done
  config_source=/proc/config.gz
else
  boot_config=$boot_root/config-$kernel_release
  [[ -r "$boot_config" ]] ||
    fail 'the running kernel configuration is not readable from procfs or /boot'
  for option in "${required_kernel_options[@]}"; do
    if ! has_one_exact_enabled_option "$option" < "$boot_config"; then
      fail "the running kernel does not expose ${option}=y in its /boot configuration"
    fi
  done
  config_source=/boot/config-$kernel_release
fi

[[ -r "$proc_status" ]] || fail 'the runner process status is not readable'
cap_eff=$(awk '
  $1 == "CapEff:" {
    count += 1
    if (NF != 2) {
      malformed = 1
    } else {
      value = $2
    }
  }
  END {
    if (count != 1 || malformed) {
      exit 1
    }
    print value
  }
' "$proc_status") || fail 'the runner process has no canonical CapEff row'
[[ "$cap_eff" =~ ^[0-9A-Fa-f]{1,16}$ ]] || fail 'the runner CapEff value is malformed'

# CAP_SYS_ADMIN is capability 21, i.e. bit 0x200000. The runner must hold it in
# the user namespace governing the diagnostic tracees; this script never adds it.
if (( (16#$cap_eff & 16#200000) == 0 )); then
  fail 'the runner process lacks effective CAP_SYS_ADMIN'
fi

printf 'Linux supervisor runner preflight passed: Linux x86_64 kernel %s, %s, effective CAP_SYS_ADMIN.\n' \
  "$kernel_release" "$config_source"
