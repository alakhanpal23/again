#!/usr/bin/env python3
"""Check package-script guidance and successful-test Brain handoff across tasks."""

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
SOURCE = "export const total = (a: number, b: number) => a + b;\n"
PACKAGE = '{"packageManager":"pnpm@9.0.0","scripts":{"test":"vitest run"}}'


def run_json(command: list[str], *, cwd: pathlib.Path, env: dict[str, str]) -> dict:
    result = subprocess.run(command, cwd=cwd, env=env, capture_output=True,
                            text=True, check=True, timeout=45)
    return json.loads(result.stdout)


def brief(binary: pathlib.Path, workspace: pathlib.Path, env: dict[str, str],
          task_id: str) -> dict:
    return run_json([str(binary), "mcp", "brief", "--workspace", str(workspace),
                     "--task-id", task_id,
                     "--task", "Fix ledger total and run the project tests"],
                    cwd=workspace, env=env)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    source = source_state(ROOT, binary)
    if source["binarySourceBindingVerified"] is not True:
        raise RuntimeError(f"gate requires a clean source-bound binary: {source}")
    with tempfile.TemporaryDirectory(prefix="again-package-test-brain-") as scratch:
        temporary = pathlib.Path(scratch)
        workspace = temporary / "workspace"
        (workspace / "src").mkdir(parents=True)
        (workspace / "src/ledger.ts").write_text(SOURCE)
        (workspace / "package.json").write_text(PACKAGE)
        (workspace / "pnpm-lock.yaml").write_text("lockfileVersion: 9\n")
        subprocess.run(["git", "init", "--quiet", str(workspace)], check=True)
        environment = dict(os.environ, AGAIN_HOME=str(temporary / "state"))
        before = brief(binary, workspace, environment, "before-test")

        fake_bin = temporary / "bin"
        fake_bin.mkdir()
        fake_codex = fake_bin / "codex"
        read_event = {
            "type": "item.completed",
            "item": {"id": "observed_read", "type": "command_execution",
                     "command": "cat src/ledger.ts", "exit_code": 0,
                     "aggregated_output": SOURCE},
        }
        fake_codex.write_text(
            "#!/usr/bin/env python3\n"
            "import json\n"
            + "print(json.dumps(" + repr(read_event) + "))\n"
            "print(json.dumps({'type':'item.completed','item':{'id':'observed_test',"
            "'type':'command_execution','command':'pnpm test','exit_code':0,"
            "'aggregated_output':'test passed'}}))\n"
            "print(json.dumps({'type':'item.completed','item':{'id':'done',"
            "'type':'agent_message','text':'Validation completed'}}))\n"
        )
        fake_codex.chmod(0o700)
        launch_env = dict(environment, PATH=str(fake_bin) + os.pathsep + environment["PATH"])
        launched = subprocess.run(
            [str(binary), "codex", "--workspace", str(workspace),
             "--task-id", "prior-validation", "--task", "Validate ledger total with pnpm test",
             "--", "--ephemeral"], cwd=workspace, env=launch_env,
            capture_output=True, text=True, timeout=45,
        )
        after = brief(binary, workspace, environment, "after-test")
        (workspace / "package.json").write_text(
            '{"packageManager":"pnpm@9.0.0","scripts":{"test":"echo no test specified && exit 1"}}'
        )
        stale = brief(binary, workspace, environment, "after-manifest-change")

        def selector(value: dict) -> dict | None:
            selectors = value.get("validationPreview", {}).get("selectors", [])
            return selectors[0] if selectors else None

        def hint(value: dict) -> str | None:
            return (value.get("againBrain") or {}).get("previousSuccessfulTestCommand")

        accepted = (
            launched.returncode == 0
            and selector(before) is not None
            and selector(before)["command"] == "pnpm test"
            and selector(before)["source"]["testScript"] == "vitest run"
            and selector(before)["verified"] is False
            and hint(before) is None
            and selector(after) is not None
            and selector(after)["command"] == "pnpm test"
            and after["relevantCode"]["unknowns"][0]["kind"] == "index_skipped_for_current_brain_preview"
            and hint(after) == "pnpm test"
            and selector(stale) is None
            and hint(stale) is None
        )
        report = {
            "schema": "again.package-test-brain-gate.v1",
            "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": source,
            "binarySha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "fixtureSha256": hashlib.sha256((SOURCE + PACKAGE).encode()).hexdigest(),
            "launcherExitCode": launched.returncode,
            "beforeTestSelector": selector(before),
            "beforeTestBrainHint": hint(before),
            "afterTestSelector": selector(after),
            "afterTestIndexStatus": after["relevantCode"]["unknowns"],
            "afterTestBrainHint": hint(after),
            "afterManifestChangeSelector": selector(stale),
            "afterManifestChangeBrainHint": hint(stale),
            "accepted": accepted,
            "evidenceScope": "fixed fake-Codex completed test event; no test execution or reuse claim",
        }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"accepted": accepted, "output": str(args.output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
