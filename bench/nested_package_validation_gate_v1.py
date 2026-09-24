#!/usr/bin/env python3
"""Check source-backed nested package test guidance through the released CLI."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile

from agent_gateway_codex_live_probe_v1 import source_state


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = "export const total = (a, b) => a + b;\n"
TEST = (
    "import test from 'node:test';\n"
    "import assert from 'node:assert/strict';\n"
    "import { total } from '../src/total.mjs';\n"
    "test('sum', () => assert.equal(total(2, 3), 5));\n"
)


def brief(binary: pathlib.Path, workspace: pathlib.Path, environment: dict[str, str],
          task_id: str, package: str) -> dict:
    result = subprocess.run(
        [str(binary), "mcp", "brief", "--workspace", str(workspace),
         "--task-id", task_id,
         "--task", f"Fix packages/{package}/src/total.mjs and run its project tests"],
        cwd=workspace, env=environment, capture_output=True, text=True,
        check=True, timeout=45,
    )
    return json.loads(result.stdout)


def selector(value: dict) -> dict | None:
    selectors = value.get("validationPreview", {}).get("selectors", [])
    return selectors[0] if selectors else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = source_state(ROOT, binary)
    if source["binarySourceBindingVerified"] is not True:
        raise RuntimeError(f"gate requires a clean source-bound binary: {source}")
    with tempfile.TemporaryDirectory(prefix="again-nested-package-gate-") as scratch:
        temporary = pathlib.Path(scratch)
        workspace = temporary / "workspace"
        for name, manager in (("alpha", "npm"), ("beta", "pnpm")):
            package = workspace / "packages" / name
            (package / "src").mkdir(parents=True)
            (package / "test").mkdir()
            (package / "src/total.mjs").write_text(SOURCE)
            (package / "test/total.spec.mjs").write_text(TEST)
            (package / "package.json").write_text(json.dumps({
                "name": f"again-{name}", "private": True, "type": "module",
                "packageManager": f"{manager}@9.0.0",
                "scripts": {"test": "node --test test/total.spec.mjs"},
            }))
        (workspace / "package.json").write_text(
            '{"scripts":{"test":"echo root test does not cover packages"}}'
        )
        subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
        environment = dict(os.environ, AGAIN_HOME=str(temporary / "state"))
        alpha = selector(brief(binary, workspace, environment, "alpha", "alpha"))
        beta = selector(brief(binary, workspace, environment, "beta", "beta"))
        ran_test = subprocess.run(
            ["npm", "test"], cwd=workspace / "packages/alpha",
            capture_output=True, text=True, timeout=30,
        )
        (workspace / "packages/alpha/package.json").write_text(
            '{"packageManager":"npm@9.0.0","scripts":{"test":"echo no test specified && exit 1"}}'
        )
        stale = selector(brief(binary, workspace, environment, "alpha-stale", "alpha"))
        accepted = (
            alpha is not None
            and alpha["command"] == "npm test"
            and alpha["workingDirectory"] == "packages/alpha"
            and alpha["source"]["path"] == "packages/alpha/package.json"
            and alpha["verified"] is False
            and beta is not None
            and beta["command"] == "pnpm test"
            and beta["workingDirectory"] == "packages/beta"
            and beta["source"]["path"] == "packages/beta/package.json"
            and ran_test.returncode == 0
            and stale is None
        )
        report = {
            "schema": "again.nested-package-validation-gate.v1",
            "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": source,
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "alphaSelector": alpha,
            "betaSelector": beta,
            "alphaTestExitCode": ran_test.returncode,
            "staleSelector": stale,
            "accepted": accepted,
            "evidenceScope": "source-backed nested package test guidance; the separate npm test is not an agent-run validation",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
