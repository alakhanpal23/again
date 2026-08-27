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
                runtime_pins={},
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
                runtime_pins={},
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

    def test_matrix_is_exactly_16_runs_with_balanced_alternation(self) -> None:
        self.assertEqual(real_eval.planned_agent_runs(2), 16)
        orders = [
            real_eval.treatment_order(client_index, task_index)
            for client_index in range(2)
            for task_index in range(len(real_eval.TASKS))
        ]
        self.assertEqual(orders.count(("baseline", "again_enabled")), 3)
        self.assertEqual(orders.count(("again_enabled", "baseline")), 3)
        self.assertTrue(any(task.concurrency == 2 for task in real_eval.TASKS))

    def test_runtime_identity_pins_are_exact(self) -> None:
        digest = "a" * 64
        real_eval.validate_runtime_pin(
            real_eval.RuntimePin("codex-cli 0.150.1", digest),
            "codex-cli 0.150.1",
            digest,
        )
        with self.assertRaises(real_eval.HarnessRefusal) as mismatch:
            real_eval.validate_runtime_pin(
                real_eval.RuntimePin("codex-cli 0.150.1", digest),
                "codex-cli 0.150.2",
                digest,
            )
        self.assertEqual(mismatch.exception.code, "runtime_pin_mismatch")
        with self.assertRaises(real_eval.HarnessRefusal) as malformed:
            real_eval.validate_runtime_pin(
                real_eval.RuntimePin("codex-cli 0.150.1", "not-a-digest"),
                "codex-cli 0.150.1",
                "not-a-digest",
            )
        self.assertEqual(malformed.exception.code, "runtime_pin")

    def test_repository_snapshot_detects_dirty_fixture_contents(self) -> None:
        repository = self.root / "snapshot-repository"
        repository.mkdir()
        expected: dict[str, str] = {}
        for relative, contents in real_eval.FIXTURE_FILES.items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
            path.chmod(0o600)
            expected[relative] = hashlib.sha256(contents.encode()).hexdigest()
        clean = real_eval.repository_diff(
            expected, real_eval.snapshot_repository_contents(repository)
        )
        self.assertTrue(clean["clean"])

        changed_path = repository / "facts" / "primary.txt"
        changed_path.write_text("unexpected mutation\n")
        changed_path.chmod(0o600)
        added_path = repository / "unexpected.txt"
        added_path.write_text("unexpected addition\n")
        added_path.chmod(0o600)
        dirty = real_eval.repository_diff(
            expected, real_eval.snapshot_repository_contents(repository)
        )
        self.assertFalse(dirty["clean"])
        self.assertEqual(dirty["changed"], ["facts/primary.txt"])
        self.assertEqual(dirty["added"], ["unexpected.txt"])

        symlink = repository / "unsafe-link"
        symlink.symlink_to(changed_path)
        with self.assertRaises(real_eval.HarnessRefusal) as unsafe:
            real_eval.snapshot_repository_contents(repository)
        self.assertEqual(unsafe.exception.code, "repository_unsafe")

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

    def test_mcp_crash_is_a_typed_command_failure(self) -> None:
        crash = real_eval.CommandResult(
            returncode=70,
            stdout=b'{"partial":true}\n',
            stderr=b"MCP server exited\n",
            elapsed_ms=3.0,
            timed_out=False,
            output_limited=False,
        )
        with self.assertRaises(real_eval.HarnessRefusal) as failed:
            real_eval.require_checked_command(crash, "Again stats after agent cohort")
        self.assertEqual(failed.exception.code, "command_failed")

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

    def test_partial_result_and_missing_token_accounting_are_explicit(self) -> None:
        task = real_eval.TASKS[0]
        partial = real_eval.analyze_agent_output(
            "claude",
            b'{"type":"tool_use","id":"one","name":"mcp__again__repo.read"}\n',
            task,
        )
        self.assertTrue(partial.malformed)
        self.assertEqual(partial.malformed_reason, "agent output contained no final response")
        self.assertEqual(partial.client_reported_tokens, {})

        final = json.dumps(dict(task.expected), separators=(",", ":"))
        complete = real_eval.analyze_agent_output(
            "claude",
            real_eval.canonical_json_bytes({"type": "result", "result": final}) + b"\n",
            task,
        )
        self.assertFalse(complete.malformed)
        self.assertTrue(complete.oracle_passed)
        self.assertEqual(complete.client_reported_tokens, {})

    def test_duplicate_json_keys_are_never_silently_accepted(self) -> None:
        with self.assertRaises(real_eval.HarnessRefusal) as duplicate:
            real_eval.strict_json_loads(b'{"value":1,"value":2}')
        self.assertEqual(duplicate.exception.code, "duplicate_json_key")

        analysis = real_eval.analyze_agent_output(
            "codex",
            b'{"type":"result","type":"result","result":"{}"}\n',
            real_eval.TASKS[0],
        )
        self.assertTrue(analysis.malformed)
        self.assertEqual(analysis.malformed_reason, "agent emitted malformed JSONL")

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

    def test_interrupted_pairs_are_excluded_and_completed_pairs_resume(self) -> None:
        journal_root = self.root / "run-state"
        identity = {"source": "a" * 40, "harness": "b" * 64}
        journal = real_eval.RunJournal.open(journal_root, identity)
        first = journal.start_attempt("codex--later_checksum_v1", 2)
        self.assertIsNone(journal.load_completed(first.pair_id))

        resumed = real_eval.RunJournal.open(journal_root, identity)
        second = resumed.start_attempt(first.pair_id, 2)
        abandoned = journal_root / "attempts" / (
            f"{first.pair_id}.{first.number:04d}.abandoned.json"
        )
        self.assertFalse(real_eval.read_bounded_json_object(abandoned)["comparison_eligible"])
        self.assertIsNone(resumed.load_completed(first.pair_id))
        resumed.fail_attempt(second, "agent_crash")

        third = resumed.start_attempt(first.pair_id, 2)
        complete_pair = {
            "client": "codex",
            "task_id": "later_checksum_v1",
            "baseline": {"runs": [{"task_outcome": "pass"}]},
            "again_enabled": {"runs": [{"task_outcome": "pass"}]},
        }
        resumed.complete_attempt(third, complete_pair)
        pair_path = journal_root / "pairs" / f"{first.pair_id}.complete.json"
        retained_bytes = pair_path.read_bytes()

        reopened = real_eval.RunJournal.open(journal_root, identity)
        self.assertEqual(reopened.load_completed(first.pair_id), complete_pair)
        self.assertEqual(pair_path.read_bytes(), retained_bytes)
        self.assertEqual(reopened.summary()["completed_pairs"], 1)
        self.assertEqual(reopened.summary()["abandoned_attempts"], 1)
        self.assertEqual(reopened.summary()["failed_attempts"], 1)
        with self.assertRaises(real_eval.HarnessRefusal) as rerun:
            reopened.start_attempt(first.pair_id, 2)
        self.assertEqual(rerun.exception.code, "journal_pair_complete")
        self.assertEqual(pair_path.read_bytes(), retained_bytes)

    def test_run_journal_refuses_identity_changes_and_secret_material(self) -> None:
        journal_root = self.root / "identity-state"
        journal = real_eval.RunJournal.open(journal_root, {"identity": "one"})
        attempt = journal.start_attempt("claude--marker_locations_v1", 2)
        secret = b"unit-test-live-secret"
        with self.assertRaises(real_eval.HarnessRefusal) as secret_refusal:
            journal.complete_attempt(attempt, {"leak": secret.decode()}, (secret,))
        self.assertEqual(secret_refusal.exception.code, "credential_persistence")
        self.assertIsNone(journal.load_completed(attempt.pair_id))

        with self.assertRaises(real_eval.HarnessRefusal) as mismatch:
            real_eval.RunJournal.open(journal_root, {"identity": "two"})
        self.assertEqual(mismatch.exception.code, "journal_identity_mismatch")

    def test_statistics_review_never_turns_estimates_into_savings_claims(self) -> None:
        review = real_eval.review_statistical_claims("dry-run", [], [])
        self.assertFalse(review["comparison_matrix_complete"])
        self.assertFalse(review["token_savings_claim_permitted"])
        self.assertFalse(review["time_savings_claim_permitted"])
        self.assertFalse(review["quality_improvement_claim_permitted"])
        self.assertFalse(review["dry_run_is_live_evidence"])


if __name__ == "__main__":
    unittest.main()
