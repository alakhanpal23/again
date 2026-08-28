from __future__ import annotations

import copy
import json
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest

from bench import agent_gateway_alpha_trial as harness


class AgentGatewayAlphaTrialTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-alpha-trial-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.repository = self.root / "repository"
        self.repository.mkdir()
        self._git("init", "-q")
        self._git("config", "user.name", "Again Test")
        self._git("config", "user.email", "again-test@example.invalid")
        (self.repository / "README.md").write_text("alpha fixture\n", encoding="utf-8")
        self._git("add", "README.md")
        self._git("-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
        self.repository_sha = self._git("rev-parse", "HEAD").strip()
        observed = harness.observe_repository(str(self.repository), self.repository_sha)
        self.repository_identity = observed["identity_sha256"]
        self.again_binary = self.root / "again"
        self.agent_binary = self.root / "agent"
        shutil.copyfile(pathlib.Path(sys.executable).resolve(), self.again_binary)
        shutil.copyfile(pathlib.Path(sys.executable).resolve(), self.agent_binary)
        os.chmod(self.again_binary, 0o700)
        os.chmod(self.agent_binary, 0o700)
        self.binary_sha = harness.sha256_file(self.again_binary, harness.MAX_EXECUTABLE_BYTES)
        self.agent_sha = harness.sha256_file(self.agent_binary, harness.MAX_EXECUTABLE_BYTES)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=self.repository,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.root),
                "LANG": "C",
                "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1",
            },
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        return completed.stdout

    @staticmethod
    def digest(label: str) -> str:
        return harness.sha256_bytes(label.encode("utf-8"))

    def scenario(
        self,
        spec: harness.ScenarioSpec,
        participant_id: str,
        *,
        classification: str = "admitted_success",
        speedup: int = 4,
    ) -> dict[str, object]:
        counters = {
            "provider_executions": 1,
            "exact_reuse_hits": 0,
            "inflight_joins": 0,
            "cancellations": 0,
            "false_hits": 0,
        }
        if spec.expectation == "exact_reuse":
            counters["exact_reuse_hits"] = 1
        elif spec.expectation == "inflight_join":
            counters["inflight_joins"] = 1
        elif spec.expectation == "execute_after_change":
            counters["provider_executions"] = 2
        elif spec.expectation == "cancellation_recovery":
            counters["cancellations"] = 1
        stream = self.digest(f"stream:{spec.scenario_id}")
        cold: dict[str, object] | None = {
            "exit_status": 0,
            "stdout_sha256": stream,
            "stderr_sha256": self.digest("empty"),
            "elapsed_ms": 400,
        }
        warm: dict[str, object] | None = {
            "exit_status": 0,
            "stdout_sha256": stream,
            "stderr_sha256": self.digest("empty"),
            "elapsed_ms": 400 // speedup,
        }
        admitted = True
        outcome = "correct"
        if classification == "safe_refusal":
            admitted = False
            outcome = "not_observed"
            cold = None
            warm = None
            counters = {key: 0 for key in counters}
        elif classification == "incomplete_trial":
            admitted = False
            outcome = "incomplete"
            cold = None
            warm = None
            counters = {key: 0 for key in counters}
        elif classification == "unsupported_host_profile":
            admitted = False
            outcome = "not_observed"
            cold = None
            warm = None
            counters = {key: 0 for key in counters}
        elif classification == "incorrect_hit":
            outcome = "incorrect"
            counters["false_hits"] = 1
        return {
            "scenario_id": spec.scenario_id,
            "bindings": {
                "participant_id": participant_id,
                "binary_sha256": self.binary_sha,
                "repository_identity_sha256": self.repository_identity,
            },
            "request_digest": self.digest(f"request:{spec.scenario_id}"),
            "classification": classification,
            "admitted": admitted,
            "cold": cold,
            "warm": warm,
            "counters": counters,
            "user_observed_outcome": outcome,
            "dependency_proof_sha256": (
                self.digest("dependency-proof") if spec.requires_dependency_proof else None
            ),
            "notes": "",
        }

    def trial(
        self,
        participant_number: int = 1,
        *,
        outside_user: bool = True,
        local_simulation: bool = False,
        publisher_status: str = "verified",
        speedup: int = 4,
    ) -> dict[str, object]:
        participant_id = self.digest(f"participant:{participant_number}")
        return {
            "schema": harness.TRIAL_SCHEMA,
            "spec_version": harness.SPEC_VERSION,
            "trial_id": self.digest(f"trial:{participant_number}"),
            "participant": {
                "participant_id": participant_id,
                "outside_user": outside_user,
                "local_simulation": local_simulation,
            },
            "release": {
                "binary_path": str(self.again_binary),
                "binary_sha256": self.binary_sha,
                "source_git_sha": "a" * 40,
                "harness_sha256": harness.harness_sha256(),
                "publisher_authentication": {
                    "status": publisher_status,
                    "artifact_sha256": self.binary_sha,
                    "source_git_sha": "a" * 40,
                    "attestation_sha256": self.digest("attestation"),
                    "verifier": "github-cli-attestation-v1",
                    "issuer": "https://token.actions.githubusercontent.com",
                    "workflow": "alakhanpal23/again/.github/workflows/release.yml",
                },
            },
            "repository": {
                "canonical_path": str(self.repository),
                "git_sha": self.repository_sha,
                "dirty": False,
                "identity_sha256": self.repository_identity,
            },
            "platform": {
                "system": platform.system(),
                "machine": platform.machine(),
                "release": platform.release(),
            },
            "agent": {
                "client": "codex",
                "version": "test-1.0.0",
                "executable_path": str(self.agent_binary),
                "executable_sha256": self.agent_sha,
            },
            "scenarios": [
                self.scenario(spec, participant_id, speedup=speedup)
                for spec in harness.SCENARIOS
            ],
            "authenticated_delivery_receipts": [],
        }

    def verified(self, participant_number: int, **kwargs: object) -> dict[str, object]:
        trial = self.trial(participant_number, **kwargs)
        return harness.verify_trial_document(
            trial,
            self.digest(f"input:{participant_number}"),
            inspect_local=True,
        )

    def test_specification_is_stable_and_contains_exactly_ten_scenarios(self) -> None:
        spec = harness.trial_specification()
        self.assertEqual(spec["schema"], harness.SPEC_SCHEMA)
        self.assertEqual(spec["scenario_count"], 10)
        self.assertEqual(len(spec["scenarios"]), 10)
        self.assertEqual(
            harness.canonical_json_bytes(spec),
            harness.canonical_json_bytes(harness.trial_specification()),
        )

    def test_valid_trial_binds_local_repository_binaries_and_platform(self) -> None:
        report = self.verified(1)
        self.assertEqual(report["classification"], "pass")
        self.assertEqual(report["summary"]["admitted_successes"], 10)
        self.assertEqual(report["summary"]["false_hits"], 0)
        self.assertEqual(report["summary"]["delivery_confirmed_tokens_saved"], 0)
        self.assertFalse(report["authority"]["production_qualification"])

    def test_cold_warm_status_or_stream_difference_is_refused(self) -> None:
        for field, value in (
            ("exit_status", 1),
            ("stdout_sha256", "f" * 64),
            ("stderr_sha256", "e" * 64),
        ):
            with self.subTest(field=field):
                trial = self.trial()
                trial["scenarios"][0]["warm"][field] = value
                with self.assertRaises(harness.TrialRefusal) as refused:
                    harness.validate_trial(trial, inspect_local=True)
                self.assertEqual(refused.exception.code, "cold_warm_mismatch")

    def test_duplicate_missing_and_unknown_scenarios_are_refused(self) -> None:
        duplicate = self.trial()
        duplicate["scenarios"][-1] = copy.deepcopy(duplicate["scenarios"][0])
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(duplicate, inspect_local=True)
        self.assertEqual(refused.exception.code, "duplicate_scenario")

        unknown = self.trial()
        unknown["scenarios"][0]["scenario_id"] = "unknown"
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(unknown, inspect_local=True)
        self.assertEqual(refused.exception.code, "unknown_scenario")

    def test_conflicting_scenario_identity_is_refused(self) -> None:
        trial = self.trial()
        trial["scenarios"][0]["bindings"]["binary_sha256"] = "f" * 64
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(trial, inspect_local=True)
        self.assertEqual(refused.exception.code, "conflicting_identity")

    def test_negative_boolean_and_impossible_counters_are_refused(self) -> None:
        for value in (-1, True, harness.MAX_COUNTER + 1):
            with self.subTest(value=value):
                trial = self.trial()
                trial["scenarios"][0]["counters"]["provider_executions"] = value
                with self.assertRaises(harness.TrialRefusal) as refused:
                    harness.validate_trial(trial, inspect_local=True)
                self.assertEqual(refused.exception.code, "invalid_schema")

    def test_dependency_proof_is_required_for_irrelevant_mutation_hit(self) -> None:
        trial = self.trial()
        scenario = next(
            item for item in trial["scenarios"] if item["scenario_id"] == "irrelevant_mutation_exact"
        )
        scenario["dependency_proof_sha256"] = None
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(trial, inspect_local=True)
        self.assertEqual(refused.exception.code, "dependency_proof_missing")

    def test_caller_asserted_delivery_receipt_is_refused(self) -> None:
        trial = self.trial()
        trial["authenticated_delivery_receipts"] = [{"claimed": True}]
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(trial, inspect_local=True)
        self.assertEqual(refused.exception.code, "delivery_receipt_authority_unsupported")

    def test_local_simulation_is_typed_non_pass(self) -> None:
        report = self.verified(1, outside_user=False, local_simulation=True)
        self.assertEqual(report["classification"], "non_pass")

    def test_unverified_publisher_is_typed_non_pass(self) -> None:
        report = self.verified(1, publisher_status="unverified")
        self.assertEqual(report["classification"], "non_pass")

    def test_publisher_binding_mismatch_is_refused(self) -> None:
        trial = self.trial()
        trial["release"]["publisher_authentication"]["artifact_sha256"] = "f" * 64
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(trial, inspect_local=True)
        self.assertEqual(refused.exception.code, "publisher_binding_mismatch")

    def test_dirty_repository_is_refused_without_modifying_it(self) -> None:
        (self.repository / "untracked.txt").write_text("dirty\n", encoding="utf-8")
        before = (self.repository / "untracked.txt").read_bytes()
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(self.trial(), inspect_local=True)
        self.assertEqual(refused.exception.code, "repository_dirty")
        self.assertEqual((self.repository / "untracked.txt").read_bytes(), before)

    def test_symlinked_input_and_noncanonical_repository_are_refused(self) -> None:
        input_path = self.root / "trial.json"
        input_path.write_bytes(harness.canonical_json_bytes(self.trial()))
        link = self.root / "trial-link.json"
        link.symlink_to(input_path)
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.read_json_file(link)
        self.assertEqual(refused.exception.code, "input_not_canonical")

        trial = self.trial()
        repo_link = self.root / "repo-link"
        repo_link.symlink_to(self.repository, target_is_directory=True)
        trial["repository"]["canonical_path"] = str(repo_link)
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.validate_trial(trial, inspect_local=True)
        self.assertEqual(refused.exception.code, "repository_not_canonical")

    def test_strict_json_rejects_duplicate_keys_nonfinite_and_deep_input(self) -> None:
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.read_json_file(duplicate)
        self.assertEqual(refused.exception.code, "duplicate_json_key")

        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text('{"value":NaN}', encoding="utf-8")
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.read_json_file(nonfinite)
        self.assertEqual(refused.exception.code, "nonfinite_json_number")

        value: object = None
        for _ in range(harness.MAX_JSON_DEPTH + 1):
            value = [value]
        deep = self.root / "deep.json"
        deep.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.read_json_file(deep)
        self.assertEqual(refused.exception.code, "json_depth_limit")

    def test_exclusive_output_refuses_overwrite(self) -> None:
        output = self.root / "output.json"
        harness.write_json_exclusive(output, {"first": True})
        before = output.read_bytes()
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.write_json_exclusive(output, {"second": True})
        self.assertEqual(refused.exception.code, "output_exists")
        self.assertEqual(output.read_bytes(), before)

    def test_five_user_aggregate_closes_thresholds_but_claims_no_crypto_identity(self) -> None:
        reports = [self.verified(index) for index in range(1, 6)]
        hashes = [self.digest(f"verified:{index}") for index in range(1, 6)]
        aggregate = harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(aggregate["classification"], "pass")
        self.assertEqual(aggregate["summary"]["users"], 5)
        self.assertEqual(aggregate["summary"]["attempts"], 50)
        self.assertEqual(aggregate["summary"]["admitted_successes"], 50)
        self.assertEqual(aggregate["summary"]["median_warm_speedup"], 4.0)
        self.assertEqual(aggregate["summary"]["false_hits"], 0)
        self.assertFalse(aggregate["authority"]["production_qualification"])
        self.assertIn("not_cryptographic", aggregate["authority"]["participant_independence_basis"])

    def test_aggregate_rejects_duplicate_participants_and_release_conflicts(self) -> None:
        reports = [self.verified(index) for index in range(1, 6)]
        hashes = [self.digest(f"verified:{index}") for index in range(1, 6)]
        reports[1] = copy.deepcopy(reports[0])
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(refused.exception.code, "duplicate_participant")

        reports = [self.verified(index) for index in range(1, 6)]
        reports[1]["trial"]["release"]["binary_sha256"] = "f" * 64
        reports[1]["trial"]["release"]["publisher_authentication"]["artifact_sha256"] = "f" * 64
        for scenario in reports[1]["trial"]["scenarios"]:
            scenario["bindings"]["binary_sha256"] = "f" * 64
        normalized, summary, classification = harness.validate_trial(
            reports[1]["trial"], inspect_local=False
        )
        reports[1]["trial"] = normalized
        reports[1]["summary"] = summary
        reports[1]["classification"] = classification
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(refused.exception.code, "conflicting_release_identity")

    def test_gate_remains_non_pass_below_admission_and_speedup_thresholds(self) -> None:
        reports = [self.verified(index, speedup=2) for index in range(1, 6)]
        hashes = [self.digest(f"verified:{index}") for index in range(1, 6)]
        aggregate = harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(aggregate["classification"], "non_pass")
        self.assertEqual(aggregate["summary"]["median_warm_speedup"], 2.0)

        reports = []
        for index in range(1, 6):
            trial = self.trial(index)
            for scenario in trial["scenarios"][:4]:
                spec = harness.SCENARIO_BY_ID[scenario["scenario_id"]]
                replacement = self.scenario(
                    spec,
                    trial["participant"]["participant_id"],
                    classification="safe_refusal",
                )
                scenario.clear()
                scenario.update(replacement)
            reports.append(
                harness.verify_trial_document(
                    trial, self.digest(f"limited:{index}"), inspect_local=True
                )
            )
        aggregate = harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(aggregate["summary"]["admitted_successes"], 30)
        self.assertEqual(aggregate["classification"], "non_pass")

    def test_incorrect_hit_prevents_gate_pass(self) -> None:
        reports = [self.verified(index) for index in range(1, 6)]
        trial = self.trial(5)
        spec = harness.SCENARIOS[0]
        trial["scenarios"][0] = self.scenario(
            spec,
            trial["participant"]["participant_id"],
            classification="incorrect_hit",
        )
        reports[4] = harness.verify_trial_document(
            trial, self.digest("incorrect-input"), inspect_local=True
        )
        hashes = [self.digest(f"verified:{index}") for index in range(1, 6)]
        aggregate = harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(aggregate["classification"], "non_pass")
        self.assertEqual(aggregate["summary"]["incorrect_hits"], 1)
        self.assertEqual(aggregate["summary"]["false_hits"], 1)

    def test_verified_report_tampering_is_reconciled_and_refused(self) -> None:
        reports = [self.verified(index) for index in range(1, 6)]
        reports[0]["summary"]["admitted_successes"] = 999
        hashes = [self.digest(f"verified:{index}") for index in range(1, 6)]
        with self.assertRaises(harness.TrialRefusal) as refused:
            harness.aggregate_verified_documents(reports, hashes)
        self.assertEqual(refused.exception.code, "verified_report_mismatch")

    def test_canonical_json_is_order_stable(self) -> None:
        left = {"z": [2, {"b": 1, "a": "snow"}], "a": True}
        right = {"a": True, "z": [2, {"a": "snow", "b": 1}]}
        self.assertEqual(harness.canonical_json_bytes(left), harness.canonical_json_bytes(right))


if __name__ == "__main__":
    unittest.main()
