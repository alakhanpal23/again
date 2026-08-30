from __future__ import annotations

import contextlib
import io
import json
import pathlib
import stat
import tempfile
import unittest

from bench import local_beta_gate as gate


SOURCE = "1" * 40
INITIAL = "2" * 64
UPGRADED = "3" * 64


def step(name: str, evidence: dict[str, object]) -> dict[str, object]:
    return {"name": name, "status": "pass", "evidence": evidence}


def scenario_report() -> dict[str, object]:
    steps = [
        step(
            "isolated_install",
            {
                "archive_sha256": "4" * 64,
                "installed_binary_sha256": INITIAL,
                "installer_verified": True,
                "isolated_home": True,
                "private_permissions": True,
            },
        ),
        step(
            "client_setup",
            {
                "clients": {
                    name: {
                        "fake_probe": True,
                        "real_probe": True,
                        "applied": True,
                        "verified": True,
                    }
                    for name in ("claude", "codex")
                },
                "direct_config_edits": 0,
            },
        ),
        step(
            "automatic_daemon_clients",
            {
                "automatic_start": True,
                "client_count": 2,
                "daemon_process_count": 1,
                "authenticated_handshakes": 2,
            },
        ),
        step(
            "task_alias_convergence",
            {
                "alias_count": 2,
                "canonical_definition_count": 1,
                "definition_digest": "5" * 64,
                "leader_count": 1,
            },
        ),
        step(
            "task_graph_readiness",
            {
                "dependent_waiting": True,
                "incomplete_dependency_claim_refused": True,
                "completed_dependency_ready": True,
                "failed_cancelled_blockers_explicit": True,
            },
        ),
        step(
            "context_exchange",
            {
                "kinds": [
                    "verified_fact",
                    "unknown",
                    "failure",
                    "reference",
                    "in_flight",
                ],
                "cross_scope_deliveries": 0,
                "unauthorized_retrievals": 0,
            },
        ),
        step(
            "leader_takeover",
            {
                "leader_generation_before": 1,
                "leader_generation_after": 2,
                "takeover_succeeded": True,
                "stale_leader_transition_refused": True,
            },
        ),
        step(
            "lifecycle_completion",
            {
                "dependency_completed": True,
                "parent_completed": True,
                "terminal_immutable": True,
                "transition_history_count": 5,
            },
        ),
        step(
            "daemon_restart_recovery",
            {
                "daemon_identity_changed": True,
                "complete_history_recovered": True,
                "history_digest_before": "6" * 64,
                "history_digest_after": "6" * 64,
            },
        ),
        step(
            "repository_mutations",
            {
                "relevant_task_delivery_retired": True,
                "relevant_leases_retired": True,
                "unrelated_verified_facts_preserved": True,
            },
        ),
        step(
            "quota_maintenance",
            {
                "maintenance_mode": True,
                "new_durable_write_refused": True,
                "export_private_0600": True,
                "export_no_overwrite": True,
                "automatic_evictions": 0,
                "maintenance_operations": {
                    name: True
                    for name in (
                        "delete",
                        "doctor",
                        "export",
                        "gc",
                        "inspect",
                        "prune",
                        "stats",
                    )
                },
            },
        ),
        step(
            "upgrade_remove_uninstall",
            {
                "binary_mismatch_refused_or_drained": True,
                "active_sessions_silently_killed": 0,
                "codex_removed_exact": True,
                "claude_removed_exact": True,
                "uninstalled": True,
                "upgraded_binary_sha256": UPGRADED,
            },
        ),
    ]
    return {
        "schema": gate.SCENARIO_SCHEMA,
        "classification": {"type": "pass", "code": "all_beta_scenarios_passed"},
        "provenance": {
            "source_git_sha": SOURCE,
            "initial_binary_sha256": INITIAL,
            "upgraded_binary_sha256": UPGRADED,
            "target": "aarch64-apple-darwin",
        },
        "privacy": {
            "deterministic_screening": True,
            "raw_payloads_retained": False,
            "diagnostic_content_scan_passed": True,
        },
        "steps": steps,
        "adversarial": {
            "concurrent_clients": 100,
            "repository_count": 2,
            "retained_soak_seconds": 3_600,
            "probes": {name: True for name in gate.ADVERSARIAL_PROBES},
            "safety_counters": {name: 0 for name in gate.ZERO_SAFETY_COUNTERS},
        },
    }


def chaos_report() -> dict[str, object]:
    return {
        "schema": gate.CHAOS_SCHEMA,
        "classification": {"type": "pass", "code": "all_exact_scenarios_reconciled"},
        "source_git_sha": SOURCE,
        "binary": {"sha256": INITIAL},
        "mode": "beta",
        "concurrency": 100,
        "false_hit_count": 0,
        "exact_probe": {
            "automatic_daemon": True,
            "sessions": 100,
            "daemon_stop": {"absent_after_stop": True},
        },
        "resource_observation": {
            "new_or_changed_open_fds": 0,
            "all_owned_process_groups_absent": True,
            "temporary_state_absent": True,
            "resource_leaks": [],
        },
    }


def metrics(score: int) -> dict[str, int]:
    return {
        "cost_usd_micros": 100_000,
        "duplicate_investigations": 1,
        "duplicate_reads": 2,
        "first_correct_edit_ms": 1_000,
        "input_tokens": 2_000,
        "output_tokens": 300,
        "patch_quality_score": score,
        "response_bytes": 4_000,
        "tool_calls": 8,
        "validated_completion_ms": 2_000,
    }


def real_agent_report() -> dict[str, object]:
    return {
        "schema": gate.REAL_AGENT_SCHEMA,
        "classification": {"type": "pass", "code": "outside_user_pairs_passed"},
        "source_git_sha": SOURCE,
        "binary_sha256": INITIAL,
        "outside_user": True,
        "outside_user_count": 5,
        "accepted_attempts": 50,
        "repository_count": 5,
        "deterministic_harness_only": False,
        "methodology": {
            "balanced_order": True,
            "fixed_acceptance_tests": True,
            "identical_worktrees": True,
            "models_pinned": True,
            "provider_usage_retained": True,
            "settings_pinned": True,
        },
        "quality": {
            "incorrect_hits": 0,
            "quality_regressions": 0,
            "stale_or_incorrect_facts": 0,
            "patches_independently_reviewed": True,
        },
        "clients": {
            client: {
                "paired_runs": 25,
                "baseline": metrics(90),
                "again_enabled": metrics(90),
            }
            for client in ("claude", "codex")
        },
    }


def release_report() -> dict[str, object]:
    artifacts = []
    names = sorted(gate._release_subjects("v1.0.0-beta.1"))
    for index, name in enumerate(names):
        detail: dict[str, object] = {
            "name": name,
            "sha256": f"{index + 1:x}" * 64,
            "attestation": {
                "status": "verified",
                "certificate_present": True,
                "bundle_name": f"{name}.sigstore.json",
                "bundle_sha256": f"{index + 8:x}" * 64,
            },
        }
        if name.endswith(".tar.gz"):
            detail["target"] = name[len("again-v1.0.0-beta.1-") : -len(".tar.gz")]
            detail["binary_sha256"] = (
                INITIAL if detail["target"] == "aarch64-apple-darwin" else "d" * 64
            )
        artifacts.append(
            detail
        )
    return {
        "schema": gate.RELEASE_SCHEMA,
        "release": {
            "source_commit": SOURCE,
            "tag": "v1.0.0-beta.1",
            "draft": False,
            "immutable": True,
        },
        "artifacts": artifacts,
        "publisher": {"status": "authenticated"},
    }


def native_reports() -> list[dict[str, object]]:
    release = release_report()
    artifacts = release["artifacts"]
    assert isinstance(artifacts, list)
    archives = {
        item["target"]: item
        for item in artifacts
        if isinstance(item, dict) and item.get("target") in gate.TARGETS
    }
    return [
        {
            "schema": gate.NATIVE_SCHEMA,
            "classification": {"type": "pass", "code": "native_smoke_passed"},
            "target": target,
            "source_git_sha": SOURCE,
            "archive_sha256": archives[target]["sha256"],
            "installed_binary_sha256": archives[target]["binary_sha256"],
            "checks": {
                "authenticated_mcp": True,
                "automatic_daemon_start": True,
                "client_setup_plans": True,
                "daemon_started": True,
                "doctor_passed": True,
                "exact_tool_catalog": True,
                "installed": True,
                "uninstalled": True,
            },
        }
        for index, target in enumerate(gate.TARGETS)
    ]


class LocalBetaGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-local-beta-gate-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def build(self) -> dict[str, object]:
        return gate.build_gate(
            scenario=scenario_report(),
            chaos=chaos_report(),
            real_agent=real_agent_report(),
            release=release_report(),
            native=native_reports(),
        )

    def test_complete_gate_is_bound_and_compact(self) -> None:
        report = self.build()
        self.assertEqual(report["classification"]["type"], "pass")  # type: ignore[index]
        self.assertEqual(report["source_git_sha"], SOURCE)
        self.assertEqual(report["coverage"]["native_targets"], list(gate.TARGETS))  # type: ignore[index]
        self.assertEqual(report["coverage"]["release_asset_count"], 14)  # type: ignore[index]
        self.assertTrue(gate._digest(report["report_sha256"]))
        self.assertLess(len(gate.canonical_json(report)), gate.MAX_OUTPUT_BYTES)

    def test_all_twelve_scenario_steps_are_mandatory_and_ordered(self) -> None:
        for mutation in ("missing", "reordered", "failed"):
            report = scenario_report()
            steps = report["steps"]
            assert isinstance(steps, list)
            if mutation == "missing":
                steps.pop()
            elif mutation == "reordered":
                steps[0], steps[1] = steps[1], steps[0]
            else:
                steps[4]["status"] = "failure"
            with self.subTest(mutation=mutation), self.assertRaises(gate.GateRefusal):
                gate.validate_scenario(report)

    def test_scenario_invariants_fail_closed(self) -> None:
        cases = (
            ("daemon", "automatic_daemon_clients", "daemon_process_count", 2),
            ("aliases", "task_alias_convergence", "canonical_definition_count", 2),
            ("takeover", "leader_takeover", "leader_generation_after", 1),
            ("restart", "daemon_restart_recovery", "history_digest_after", "7" * 64),
            ("quota", "quota_maintenance", "automatic_evictions", 1),
            ("upgrade", "upgrade_remove_uninstall", "active_sessions_silently_killed", 1),
        )
        for label, step_name, field, value in cases:
            report = scenario_report()
            steps = report["steps"]
            assert isinstance(steps, list)
            item = next(step for step in steps if step["name"] == step_name)
            item["evidence"][field] = value
            with self.subTest(label=label), self.assertRaises(gate.GateRefusal):
                gate.validate_scenario(report)

    def test_diagnostics_refuse_content_and_credential_shapes(self) -> None:
        for field, value in (
            ("prompt", "harmless content"),
            ("note", "AKIA" + "A" * 16),
            ("result_content", "raw result"),
        ):
            report = scenario_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateRefusal) as refused:
                gate.validate_scenario(report)
            self.assertIn(refused.exception.code, {"diagnostic_content", "diagnostic_sensitive_text"})

    def test_adversarial_matrix_requires_100_clients_and_zero_safety_events(self) -> None:
        report = scenario_report()
        report["adversarial"]["concurrent_clients"] = 99  # type: ignore[index]
        with self.assertRaises(gate.GateRefusal) as clients:
            gate.validate_scenario(report)
        self.assertEqual(clients.exception.code, "adversarial")

        report = scenario_report()
        report["adversarial"]["safety_counters"]["false_hits"] = 1  # type: ignore[index]
        with self.assertRaises(gate.GateRefusal) as false_hit:
            gate.validate_scenario(report)
        self.assertEqual(false_hit.exception.code, "adversarial")

    def test_chaos_must_be_retained_100_client_beta_mode(self) -> None:
        for field, value in (("mode", "soak"), ("concurrency", 32), ("false_hit_count", 1)):
            report = chaos_report()
            report[field] = value
            with self.subTest(field=field), self.assertRaises(gate.GateRefusal) as refused:
                gate.validate_chaos(report)
            self.assertEqual(refused.exception.code, "chaos_scope")

    def test_real_agent_gate_requires_outside_user_and_no_quality_regression(self) -> None:
        report = real_agent_report()
        report["outside_user"] = False
        with self.assertRaises(gate.GateRefusal) as outside:
            gate.validate_real_agent(report)
        self.assertEqual(outside.exception.code, "outside_user")

        report = real_agent_report()
        report["clients"]["codex"]["again_enabled"]["patch_quality_score"] = 89  # type: ignore[index]
        with self.assertRaises(gate.GateRefusal) as quality:
            gate.validate_real_agent(report)
        self.assertEqual(quality.exception.code, "agent_metrics")

        report = real_agent_report()
        report["accepted_attempts"] = 49
        with self.assertRaises(gate.GateRefusal) as sample:
            gate.validate_real_agent(report)
        self.assertEqual(sample.exception.code, "agent_sample")

        report = real_agent_report()
        report["methodology"]["balanced_order"] = False  # type: ignore[index]
        with self.assertRaises(gate.GateRefusal) as methodology:
            gate.validate_real_agent(report)
        self.assertEqual(methodology.exception.code, "agent_methodology")

    def test_exact_native_target_matrix_and_source_binding_are_required(self) -> None:
        duplicate = native_reports()
        duplicate[-1]["target"] = duplicate[0]["target"]
        with self.assertRaises(gate.GateRefusal) as matrix:
            gate.build_gate(
                scenario=scenario_report(),
                chaos=chaos_report(),
                real_agent=real_agent_report(),
                release=release_report(),
                native=duplicate,
            )
        self.assertEqual(matrix.exception.code, "native_matrix")

        wrong_source = native_reports()
        wrong_source[0]["source_git_sha"] = "f" * 40
        with self.assertRaises(gate.GateRefusal) as source:
            gate.build_gate(
                scenario=scenario_report(),
                chaos=chaos_report(),
                real_agent=real_agent_report(),
                release=release_report(),
                native=wrong_source,
            )
        self.assertEqual(source.exception.code, "source_mismatch")

    def test_release_requires_exact_subject_and_bundle_inventory(self) -> None:
        report = release_report()
        report["artifacts"].pop()  # type: ignore[union-attr]
        with self.assertRaises(gate.GateRefusal) as refused:
            gate.validate_release(report)
        self.assertEqual(refused.exception.code, "release_assets")

    def test_strict_reader_rejects_duplicates_and_symlinks(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"one","schema":"two"}\n', encoding="utf-8")
        with self.assertRaises(gate.GateRefusal) as refused:
            gate.read_json(duplicate)
        self.assertEqual(refused.exception.code, "duplicate_json_key")

        target = self.root / "target.json"
        target.write_text("{}\n", encoding="utf-8")
        link = self.root / "link.json"
        link.symlink_to(target)
        with self.assertRaises(gate.GateRefusal) as unsafe:
            gate.read_json(link)
        self.assertEqual(unsafe.exception.code, "evidence_unsafe")

        argv = [
            "--scenario-evidence",
            str(link),
            "--chaos-evidence",
            str(target),
            "--real-agent-evidence",
            str(target),
            "--release-evidence",
            str(target),
        ]
        for _ in range(4):
            argv.extend(("--native-evidence", str(target)))
        argv.extend(("--output", str(self.root / "must-not-exist.json")))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(gate.main(argv), 3)
        self.assertEqual(
            json.loads(stream.getvalue())["classification"]["code"],
            "evidence_unsafe",
        )

    def test_output_is_private_exclusive_and_never_overwritten(self) -> None:
        output = self.root / "gate.json"
        report = self.build()
        gate.write_exclusive(output, report)
        before = output.read_bytes()
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaises(gate.GateRefusal) as refused:
            gate.write_exclusive(output, {"replacement": True})
        self.assertEqual(refused.exception.code, "output_exists")
        self.assertEqual(output.read_bytes(), before)

    def test_cli_aggregates_retained_files_without_overwrite(self) -> None:
        inputs = {
            "scenario": scenario_report(),
            "chaos": chaos_report(),
            "agent": real_agent_report(),
            "release": release_report(),
        }
        paths: dict[str, pathlib.Path] = {}
        for name, value in inputs.items():
            path = self.root / f"{name}.json"
            path.write_bytes(gate.canonical_json(value))
            paths[name] = path
        native_paths = []
        for index, value in enumerate(native_reports()):
            path = self.root / f"native-{index}.json"
            path.write_bytes(gate.canonical_json(value))
            native_paths.append(path)
        output = self.root / "result.json"
        argv = [
            "--scenario-evidence",
            str(paths["scenario"]),
            "--chaos-evidence",
            str(paths["chaos"]),
            "--real-agent-evidence",
            str(paths["agent"]),
            "--release-evidence",
            str(paths["release"]),
        ]
        for path in native_paths:
            argv.extend(("--native-evidence", str(path)))
        argv.extend(("--output", str(output)))
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream):
            self.assertEqual(gate.main(argv), 0)
        printed = json.loads(stream.getvalue())
        retained = json.loads(output.read_bytes())
        self.assertEqual(printed, retained)
        self.assertEqual(retained["classification"]["type"], "pass")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)

        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gate.main(argv), 3)
        self.assertEqual(json.loads(output.read_bytes()), retained)


if __name__ == "__main__":
    unittest.main()
