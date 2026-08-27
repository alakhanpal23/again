#!/usr/bin/env python3
"""Offline unit tests for the retained real-agent evaluation harness."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import pathlib
import sys
import tempfile
import unittest
from typing import Any


MODULE_PATH = pathlib.Path(__file__).with_name("agent_gateway_real_agent_eval.py")
SPEC = importlib.util.spec_from_file_location("agent_gateway_real_agent_eval", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
real_eval = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = real_eval
SPEC.loader.exec_module(real_eval)


def codex_template(executable: str = "/usr/bin/true") -> str:
    return json.dumps(
        [
            executable,
            "exec",
            "--json",
            "--ephemeral",
            "--color",
            "never",
            "--sandbox",
            "read-only",
            "--ask-for-approval",
            "never",
            "-C",
            "{workspace}",
            "--model",
            "{model}",
            "{prompt}",
        ]
    )


def claude_template(executable: str = "/usr/bin/true") -> str:
    return json.dumps(
        [
            executable,
            "--print",
            "--output-format",
            "stream-json",
            "--bare",
            "--strict-mcp-config",
            "--mcp-config",
            "{mcp_config}",
            "--no-session-persistence",
            "--no-chrome",
            "--verbose",
            "--permission-mode",
            "plan",
            "--add-dir",
            "{workspace}",
            "--allowedTools",
            real_eval.CLAUDE_ALLOWED_TOOLS,
            "--disallowedTools",
            real_eval.CLAUDE_DISALLOWED_TOOLS,
            "--model",
            "{model}",
            "{prompt}",
        ]
    )


def run_observation(
    *,
    calls: int = 0,
    outcome: str = "pass",
    mismatch: int = 0,
    observed_results: int = 0,
    environment_refusal: bool = False,
) -> dict[str, Any]:
    return {
        "task_outcome": outcome,
        "metrics": {"again_tool_calls_requested": calls},
        "observations": {
            "again_tool_result_mismatches": mismatch,
            "again_tool_results_observed": observed_results,
            "environment_network_or_model_refusal": environment_refusal,
        },
    }


def gateway_delta(**updates: int) -> dict[str, int]:
    value = {name: 0 for name in real_eval.STATS_FIELDS}
    value.update(updates)
    return value


class RealAgentEvalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-real-agent-eval-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.environment = {
            "HOME": str(self.root),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin",
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_command_template_validation_accepts_only_safe_client_shapes(self) -> None:
        codex = real_eval.parse_command_template("codex", codex_template())
        claude = real_eval.parse_command_template("claude", claude_template())
        self.assertEqual(codex.arguments[-1], "{prompt}")
        self.assertIn("{mcp_config}", claude.arguments)

        missing = json.loads(codex_template())
        missing.remove("--ephemeral")
        with self.assertRaises(real_eval.HarnessRefusal) as unsafe:
            real_eval.parse_command_template("codex", json.dumps(missing))
        self.assertEqual(unsafe.exception.code, "template_safety")

        shell = json.loads(codex_template())
        shell[0] = "/bin/sh"
        with self.assertRaises(real_eval.HarnessRefusal) as shell_refusal:
            real_eval.parse_command_template("codex", json.dumps(shell))
        self.assertEqual(shell_refusal.exception.code, "template_shell")

        credential_literal = json.loads(codex_template())
        credential_literal.insert(-1, "opaque-credential-material")
        with self.assertRaises(real_eval.HarnessRefusal) as credential_refusal:
            real_eval.parse_command_template("codex", json.dumps(credential_literal))
        self.assertEqual(credential_refusal.exception.code, "template_token")

    def test_no_shell_interpolation_in_templates_or_execution(self) -> None:
        malicious = json.loads(codex_template())
        malicious.insert(-1, "$(touch SHOULD_NOT_EXIST)")
        with self.assertRaises(real_eval.HarnessRefusal) as refused:
            real_eval.parse_command_template("codex", json.dumps(malicious))
        self.assertEqual(refused.exception.code, "template_interpolation")

        sentinel = self.root / "interpolated"
        result = real_eval.run_bounded_command(
            ("/bin/echo", f"$(touch {sentinel})"),
            cwd=self.root,
            environment=self.environment,
            timeout_seconds=2,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"$(touch", result.stdout)
        self.assertFalse(sentinel.exists())

    def test_live_mode_requires_explicit_network_authorization(self) -> None:
        with self.assertRaises(real_eval.HarnessRefusal) as live:
            real_eval.evaluate(
                mode="live",
                allow_network=False,
                again_binary=self.root / "absent-again",
                templates={},
                models={},
                settings_ids={},
                credential_names={},
                maximum_runs=16,
                timeout_seconds=10,
            )
        self.assertEqual(live.exception.code, "network_authorization")
        with self.assertRaises(real_eval.HarnessRefusal) as dry:
            real_eval.evaluate(
                mode="dry-run",
                allow_network=True,
                again_binary=self.root / "absent-again",
                templates={},
                models={},
                settings_ids={},
                credential_names={},
                maximum_runs=16,
                timeout_seconds=10,
            )
        self.assertEqual(dry.exception.code, "network_authorization")

    def test_credential_redaction_and_persistence_guard(self) -> None:
        secret = b"sk-unit-test-credential-123456"
        raw = b'{"authorization":"Bearer ' + secret + b'","api_key":"another-secret"}'
        redacted = real_eval.redact_sensitive_bytes(raw, (secret,))
        self.assertNotIn(secret, redacted)
        self.assertNotIn(b"another-secret", redacted)

        safe_output = self.root / "safe.json"
        real_eval.write_json_exclusive(safe_output, {"diagnostic": redacted.decode()}, (secret,))
        encoded = safe_output.read_bytes()
        self.assertNotIn(secret, encoded)
        self.assertNotIn(hashlib.sha256(secret).hexdigest().encode(), encoded)

        with self.assertRaises(real_eval.HarnessRefusal) as raw_refusal:
            real_eval.write_json_exclusive(
                self.root / "raw.json", {"credential": secret.decode()}, (secret,)
            )
        self.assertEqual(raw_refusal.exception.code, "credential_persistence")
        with self.assertRaises(real_eval.HarnessRefusal) as hash_refusal:
            real_eval.write_json_exclusive(
                self.root / "hash.json",
                {"credential_hash": hashlib.sha256(secret).hexdigest()},
                (secret,),
            )
        self.assertEqual(hash_refusal.exception.code, "credential_persistence")

    def test_paired_run_reconciliation_separates_gateway_events(self) -> None:
        baseline = [run_observation()]
        enabled = [run_observation(calls=3, observed_results=3)]
        classified = real_eval.classify_paired_run(
            baseline,
            enabled,
            gateway_delta(requested=3, executed=1, inflight_joins=1, exact_hits=1),
        )
        self.assertEqual(classified["classification"], "end_to_end_again_observed")
        self.assertTrue(classified["gateway_provider_executed"])
        self.assertTrue(classified["gateway_joined_inflight"])
        self.assertTrue(classified["gateway_reused_exact"])
        self.assertEqual(classified["tool_call_reconciliation"], "exact")

        with self.assertRaises(real_eval.HarnessRefusal) as contaminated:
            real_eval.classify_paired_run(
                [run_observation(calls=1)], enabled, gateway_delta(requested=3)
            )
        self.assertEqual(contaminated.exception.code, "baseline_contaminated")

    def test_unsupported_client_versions_are_refused(self) -> None:
        codex_help = "Codex CLI --version"
        exec_help = "Run Codex non-interactively --ephemeral --json --sandbox"
        with self.assertRaises(real_eval.HarnessRefusal) as old_codex:
            real_eval.validate_client_capabilities(
                "codex", "codex-cli 0.149.9", codex_help, exec_help
            )
        self.assertEqual(old_codex.exception.code, "client_version")

        claude_help = (
            "Claude Code --bare --strict-mcp-config --no-session-persistence "
            "stream-json --permission-mode --allowedTools --disallowedTools"
        )
        with self.assertRaises(real_eval.HarnessRefusal) as future_claude:
            real_eval.validate_client_capabilities(
                "claude", "3.0.0 (Claude Code)", claude_help
            )
        self.assertEqual(future_claude.exception.code, "client_version")

    def test_timeout_is_bounded_and_classified(self) -> None:
        result = real_eval.run_bounded_command(
            (sys.executable, "-c", "import time; time.sleep(5)"),
            cwd=self.root,
            environment={**self.environment, "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout_seconds=0.1,
        )
        self.assertTrue(result.timed_out)
        analysis = real_eval.AgentOutputAnalysis(
            malformed=True,
            malformed_reason="no output",
            final_text=None,
            oracle_passed=False,
            tool_call_count=0,
            again_tool_calls_requested=0,
            again_discovered=False,
            again_tool_response_bytes=0,
            again_tool_results_observed=0,
            again_tool_result_mismatches=0,
            client_reported_tokens={},
            client_reported_model=None,
            client_reported_error=False,
        )
        record = real_eval.build_agent_run_record(
            "codex", "baseline", 0, result, b"", b"", analysis
        )
        self.assertEqual(record["classification"], "timeout")

    def test_nonzero_exit_is_retained_without_becoming_success(self) -> None:
        result = real_eval.run_bounded_command(
            (sys.executable, "-c", "raise SystemExit(7)"),
            cwd=self.root,
            environment={**self.environment, "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
            timeout_seconds=2,
        )
        self.assertEqual(result.returncode, 7)
        analysis = real_eval.analyze_agent_output(
            "codex", b'{"type":"item.completed","item":{"type":"agent_message","text":"{}"}}\n', real_eval.TASKS[0]
        )
        record = real_eval.build_agent_run_record(
            "codex", "again_enabled", 0, result, result.stdout, result.stderr, analysis
        )
        self.assertEqual(record["classification"], "client_nonzero_exit")
        self.assertEqual(record["task_outcome"], "fail")

    def test_malformed_agent_output_is_detected(self) -> None:
        analysis = real_eval.analyze_agent_output(
            "claude", b"not-json\n", real_eval.TASKS[0]
        )
        self.assertTrue(analysis.malformed)
        self.assertFalse(analysis.oracle_passed)

        wrong_final = real_eval.analyze_agent_output(
            "claude",
            b'{"type":"result","result":"```json\\n{}\\n```"}\n',
            real_eval.TASKS[0],
        )
        self.assertTrue(wrong_final.malformed)

    def test_no_tool_use_classification_is_not_e2e_success(self) -> None:
        classified = real_eval.classify_paired_run(
            [run_observation()], [run_observation()], gateway_delta()
        )
        self.assertEqual(classified["classification"], "agent_did_not_use_again")
        self.assertTrue(classified["agent_did_not_use_tool"])
        self.assertFalse(classified["gateway_provider_executed"])

    def test_false_hit_classification_requires_observed_bad_reuse(self) -> None:
        classified = real_eval.classify_paired_run(
            [run_observation()],
            [run_observation(calls=2, mismatch=1, observed_results=2)],
            gateway_delta(requested=2, exact_hits=2),
        )
        self.assertEqual(classified["false_hit_count"], 1)
        self.assertEqual(
            classified["false_hit_observability"], "complete_reuse_only_cohort"
        )

        ambiguous = real_eval.classify_paired_run(
            [run_observation()],
            [run_observation(calls=2, mismatch=1, observed_results=2)],
            gateway_delta(requested=2, exact_hits=1, executed=1),
        )
        self.assertEqual(ambiguous["false_hit_count"], 0)
        self.assertEqual(
            ambiguous["false_hit_observability"], "ambiguous_mixed_dispositions"
        )

        unobserved = real_eval.classify_paired_run(
            [run_observation()],
            [run_observation(calls=2, mismatch=0, observed_results=0)],
            gateway_delta(requested=2, exact_hits=1),
        )
        self.assertEqual(unobserved["false_hit_count"], 0)
        self.assertEqual(
            unobserved["false_hit_observability"], "partial_response_capture"
        )

    def test_real_client_stream_shape_extracts_calls_results_and_direct_tokens(self) -> None:
        task = real_eval.TASKS[0]
        final = json.dumps(dict(task.expected), separators=(",", ":"))
        lines = [
            {
                "type": "system",
                "subtype": "init",
                "model": "claude-test",
                "mcp_servers": [{"name": "again", "status": "connected"}],
            },
            {
                "type": "assistant",
                "message": {
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "call-1",
                            "name": "mcp__again__repo__read",
                            "input": {"path": "facts/concurrent.txt"},
                        }
                    ]
                },
            },
            {
                "type": "user",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "call-1",
                            "content": "CONCURRENT-CHECKSUM-91E2: 91E2-A77C",
                        }
                    ]
                },
            },
            {
                "type": "result",
                "result": final,
                "usage": {"input_tokens": 120, "output_tokens": 20},
            },
        ]
        encoded = b"\n".join(real_eval.canonical_json_bytes(line) for line in lines) + b"\n"
        analysis = real_eval.analyze_agent_output("claude", encoded, task)
        self.assertFalse(analysis.malformed)
        self.assertTrue(analysis.oracle_passed)
        self.assertTrue(analysis.again_discovered)
        self.assertEqual(analysis.again_tool_calls_requested, 1)
        self.assertEqual(analysis.again_tool_results_observed, 1)
        self.assertEqual(analysis.again_tool_result_mismatches, 0)
        self.assertEqual(analysis.client_reported_tokens["input_tokens"], 120)

    def test_stable_canonical_json_and_overwrite_refusal(self) -> None:
        left = {"z": [3, 2, 1], "a": {"two": 2, "one": 1}}
        right = {"a": {"one": 1, "two": 2}, "z": [3, 2, 1]}
        self.assertEqual(real_eval.canonical_json_bytes(left), real_eval.canonical_json_bytes(right))

        first = self.root / "first.json"
        second = self.root / "second.json"
        real_eval.write_json_exclusive(first, left)
        real_eval.write_json_exclusive(second, right)
        self.assertEqual(first.read_bytes(), second.read_bytes())
        with self.assertRaises(real_eval.HarnessRefusal) as overwrite:
            real_eval.write_json_exclusive(first, left)
        self.assertEqual(overwrite.exception.code, "evidence_exists")


if __name__ == "__main__":
    unittest.main()
