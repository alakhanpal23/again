#!/usr/bin/env python3
"""Offline tests for the paired editable-agent benchmark."""

from __future__ import annotations

import argparse
import importlib.util
import json
import pathlib
import sys
import tempfile
import unittest


MODULE = pathlib.Path(__file__).with_name("agent_gateway_editable_pair.py")
SPEC = importlib.util.spec_from_file_location("agent_gateway_editable_pair", MODULE)
assert SPEC is not None and SPEC.loader is not None
editable = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = editable
SPEC.loader.exec_module(editable)


class EditablePairTests(unittest.TestCase):
    def test_qualification_is_exact_and_disclaims_product_speed(self) -> None:
        args = argparse.Namespace(
            mode="qualify",
            runs=2,
            timeout_seconds=30.0,
            allow_network=False,
            model=None,
            settings_id=None,
            credential_env_name=None,
            baseline_command_json=None,
            again_command_json=None,
            again_bin=None,
        )
        report = editable.build_report(args)
        self.assertTrue(report["passed"])
        self.assertTrue(report["claims"]["editable_oracle_qualified"])
        self.assertFalse(report["claims"]["real_agent_task_quality"])
        self.assertFalse(report["claims"]["again_acceleration"])
        self.assertEqual(report["summary"]["baseline"]["passed"], 2)
        self.assertEqual(report["summary"]["again"]["passed"], 2)

    def test_collateral_mutation_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            before = editable.create_fixture(root)
            editable.reference_edit(root)
            (root / editable.TEST).write_text("# tampered\n", encoding="utf-8")
            result = editable.validate_edit(root, before, 30.0)
            self.assertFalse(result["passed"])
            self.assertFalse(result["collateral_safe"])
            self.assertEqual(result["changed_paths"], [editable.TARGET, editable.TEST])

    def test_live_requires_explicit_network_authority(self) -> None:
        args = argparse.Namespace(
            mode="live",
            runs=1,
            timeout_seconds=30.0,
            allow_network=False,
            model="pinned-model",
            settings_id="settings-v1",
            credential_env_name="TEST_AGENT_TOKEN",
            baseline_command_json=json.dumps(["/usr/bin/true"]),
            again_command_json=json.dumps(["/usr/bin/true"]),
            again_bin="/usr/bin/true",
        )
        with self.assertRaisesRegex(editable.Refusal, "allow-network"):
            editable.build_report(args)

    def test_command_templates_require_all_standalone_placeholders(self) -> None:
        with self.assertRaises(editable.Refusal):
            editable.parse_template(json.dumps(["/usr/bin/true", "{workspace}"]), "bad")


if __name__ == "__main__":
    unittest.main()
