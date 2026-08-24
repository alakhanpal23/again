#!/usr/bin/python3
"""Decode the action's argv without invoking a shell parser."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


MAX_ARGV_JSON_BYTES = 64 * 1024
MAX_ARGUMENTS = 256
ARGV_ENV = "AGAIN_TEAM_CI_ARGV_JSON"


def fail(message: str) -> "None":
    print(f"again-team-action: {message}", file=sys.stderr)
    raise SystemExit(2)


def decode_argv(raw: str) -> list[str]:
    try:
        size = len(raw.encode("utf-8"))
    except UnicodeEncodeError:
        fail("argv JSON must be valid UTF-8")
    if size == 0 or size > MAX_ARGV_JSON_BYTES:
        fail("argv JSON must contain between 1 and 65536 bytes")

    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, RecursionError):
        fail("argv must be a valid JSON string array")

    if not isinstance(value, list) or not value:
        fail("argv must be a non-empty JSON array")
    if len(value) > MAX_ARGUMENTS:
        fail("argv has too many arguments")
    if any(type(argument) is not str for argument in value):
        fail("every argv element must be a string")
    if any("\0" in argument for argument in value):
        fail("argv elements must not contain NUL bytes")

    command = value[0]
    if not command or "/" in command or command in {".", ".."}:
        fail("argv[0] must be a bare executable name")
    return value


def main() -> None:
    raw = os.environ.pop(ARGV_ENV, None)
    if raw is None:
        fail("the argv input is required")
    argv = decode_argv(raw)

    repository = Path(__file__).resolve().parents[3]
    wrapper = repository / "scripts" / "again-team-ci.sh"
    if not wrapper.is_file():
        fail("the Again CI wrapper is missing from the action source")

    # execve preserves the decoded argument boundaries and inserts the
    # wrapper's mandatory delimiter without eval, word splitting, or globbing.
    # Use the system shell directly in privileged mode. This prevents PATH,
    # BASH_ENV, exported functions, SHELLOPTS, and startup files controlled by
    # an earlier CI step from running while the bundle is still in the child
    # environment.
    environment = os.environ.copy()
    for name in tuple(environment):
        if name in {"BASH_ENV", "ENV", "CDPATH", "GLOBIGNORE"} or name.startswith(
            ("DYLD_", "LD_")
        ):
            environment.pop(name, None)
    os.execve(
        "/bin/bash",
        [
            "/bin/bash",
            "--noprofile",
            "--norc",
            "-p",
            str(wrapper),
            "--",
            *argv,
        ],
        environment,
    )


if __name__ == "__main__":
    main()
