from __future__ import annotations

import json
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import unittest

from bench import agent_gateway_onboarding_smoke as smoke


class AgentGatewayOnboardingSmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-onboarding-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()
        self.workspace = self.root / "workspace"
        self.workspace.mkdir(mode=0o700)
        self.executable = pathlib.Path(sys.executable).resolve(strict=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def plan(self, client: str, config_path: pathlib.Path) -> dict[str, object]:
        args = ["mcp", "serve", "--workspace", str(self.workspace)]
        config_document = smoke._expected_config_document(client, self.executable, args)
        local_cli = smoke._expected_local_cli(client, self.executable, args)
        ownership_digest = smoke.expected_ownership_digest(
            client=client,
            config_path=config_path,
            workspace=self.workspace,
            config_document=config_document,
        )
        return {
            "version": 2,
            "client": client,
            "server_name": "again",
            "stdio": {
                "transport": "stdio",
                "command": str(self.executable),
                "args": args,
            },
            "local_cli_command": local_cli,
            "workspace": str(self.workspace),
            "config_path": str(config_path),
            "ownership_path": str(
                config_path.with_name(config_path.name + smoke.OWNER_SUFFIX)
            ),
            "ownership_digest": ownership_digest,
            "writes_by_default": False,
            "install_policy": "create_absent_or_verify_exact_owned_v1",
            "config_document": config_document,
        }

    @staticmethod
    def write_private(path: pathlib.Path, value: bytes) -> None:
        path.write_bytes(value)
        if os.name == "posix":
            path.chmod(0o600)

    def install_pair(self, plan: dict[str, object]) -> pathlib.Path:
        config = pathlib.Path(str(plan["config_path"]))
        owner = pathlib.Path(str(plan["ownership_path"]))
        self.write_private(config, str(plan["config_document"]).encode())
        owner_record = (
            "again-agent-gateway-owner-v2\n"
            f"client={plan['client']}\n"
            "server=again\n"
            f"workspace_digest={smoke.expected_workspace_digest(self.workspace)}\n"
            f"digest={plan['ownership_digest']}\n"
        ).encode()
        self.write_private(owner, owner_record)
        return config

    def test_strict_json_rejects_duplicates_nonfinite_and_malformed_input(self) -> None:
        self.assertEqual(smoke.strict_json_loads(b'{"a":1}'), {"a": 1})
        for raw, code in (
            (b'{"a":1,"a":2}', "duplicate_json_key"),
            (b'{"a":NaN}', "nonfinite_json_number"),
            (b'{"a":', "malformed_json"),
        ):
            with self.subTest(code=code), self.assertRaises(smoke.HarnessRefusal) as refused:
                smoke.strict_json_loads(raw)
            self.assertEqual(refused.exception.code, code)

    def test_json_depth_and_node_bounds_are_enforced(self) -> None:
        deep: object = None
        for _ in range(smoke.MAX_JSON_DEPTH + 1):
            deep = [deep]
        with self.assertRaises(smoke.HarnessRefusal) as depth:
            smoke.strict_json_loads(json.dumps(deep).encode())
        self.assertEqual(depth.exception.code, "json_depth_limit")

        wide = [0] * smoke.MAX_JSON_NODES
        with self.assertRaises(smoke.HarnessRefusal) as nodes:
            smoke.strict_json_loads(json.dumps(wide).encode())
        self.assertEqual(nodes.exception.code, "json_node_limit")

    def test_canonical_report_bytes_are_stable(self) -> None:
        left = {"z": [3, {"b": 2, "a": 1}], "a": "snow"}
        right = {"a": "snow", "z": [3, {"a": 1, "b": 2}]}
        self.assertEqual(smoke.canonical_json_bytes(left), smoke.canonical_json_bytes(right))

    def test_embedded_blake3_matches_standard_vectors(self) -> None:
        self.assertEqual(
            smoke.blake3_single_chunk(b""),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        )
        self.assertEqual(
            smoke.blake3_single_chunk(b"abc"),
            "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
        )

    def test_output_is_exclusive_and_never_overwritten(self) -> None:
        output = self.root / "evidence.json"
        smoke.write_json_exclusive(output, {"first": True})
        before = output.read_bytes()
        with self.assertRaises(smoke.product.HarnessRefusal) as refused:
            smoke.write_json_exclusive(output, {"second": True})
        self.assertEqual(refused.exception.code, "output_exists")
        self.assertEqual(output.read_bytes(), before)

    def test_closed_environment_does_not_inherit_credentials(self) -> None:
        os.environ["AGAIN_ONBOARDING_TEST_SECRET"] = "must-not-be-inherited"
        try:
            environment = smoke.closed_environment(
                binary_directory=self.root / "bin",
                home=self.root / "home",
                state=self.root / "state",
                temporary=self.root / "tmp",
            )
        finally:
            del os.environ["AGAIN_ONBOARDING_TEST_SECRET"]
        self.assertNotIn("AGAIN_ONBOARDING_TEST_SECRET", environment)
        self.assertFalse(
            any(
                token in name.casefold()
                for name in environment
                for token in ("token", "secret", "password", "credential", "api_key")
            )
        )
        self.assertEqual(environment["HOME"], str(self.root / "home"))
        self.assertEqual(environment["AGAIN_HOME"], str(self.root / "state"))

    def test_codex_and_claude_plans_validate_exact_workspace_binding(self) -> None:
        for client, relative in (
            ("codex", ".codex/config.toml"),
            ("claude", ".claude.json"),
        ):
            with self.subTest(client=client):
                path = self.root / relative
                plan = self.plan(client, path)
                self.assertIs(
                    smoke.validate_setup_plan(
                        plan,
                        client=client,
                        workspace=self.workspace,
                        config_path=path,
                        executable=self.executable,
                    ),
                    plan,
                )

    def test_plan_rejects_workspace_argument_drift(self) -> None:
        path = self.root / "config.toml"
        plan = self.plan("codex", path)
        plan["stdio"]["args"][-1] = str(self.root)  # type: ignore[index]
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.validate_setup_plan(
                plan,
                client="codex",
                workspace=self.workspace,
                config_path=path,
                executable=self.executable,
            )
        self.assertEqual(refused.exception.code, "setup_plan_invalid")

    def test_owner_record_is_closed_and_bound_to_plan(self) -> None:
        path = self.root / "config.toml"
        plan = self.plan("codex", path)
        self.install_pair(plan)
        raw = pathlib.Path(str(plan["ownership_path"])).read_bytes()
        fields = smoke.parse_owner_record(raw, plan)
        self.assertEqual(fields["digest"], plan["ownership_digest"])
        self.assertEqual(
            fields["workspace_digest"], smoke.expected_workspace_digest(self.workspace)
        )
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.parse_owner_record(raw + b"extra=value\n", plan)
        self.assertEqual(refused.exception.code, "owner_record_invalid")

    def test_exact_unchanged_owned_pair_is_removed(self) -> None:
        path = self.root / "config.toml"
        plan = self.plan("codex", path)
        self.install_pair(plan)
        evidence = smoke.remove_exact_owned_pair(path, plan)
        self.assertTrue(evidence["removed"])
        self.assertFalse(path.exists())
        self.assertFalse(pathlib.Path(str(plan["ownership_path"])).exists())

    def test_changed_config_is_never_removed(self) -> None:
        path = self.root / "config.toml"
        plan = self.plan("codex", path)
        self.install_pair(plan)
        with path.open("ab") as output:
            output.write(b"# user change\n")
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.remove_exact_owned_pair(path, plan)
        self.assertEqual(refused.exception.code, "owned_file_changed")
        self.assertTrue(path.exists())
        self.assertTrue(pathlib.Path(str(plan["ownership_path"])).exists())

    def test_symlinked_owned_file_is_refused(self) -> None:
        if os.name != "posix":
            self.skipTest("symlink assertion requires POSIX")
        target = self.root / "target"
        target.write_bytes(b"user data")
        link = self.root / "config.toml"
        link.symlink_to(target)
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.inspect_private_regular(link, b"user data")
        self.assertEqual(refused.exception.code, "owned_file_unsafe")
        self.assertEqual(target.read_bytes(), b"user data")

    def test_installed_commands_are_derived_from_exact_config_bytes(self) -> None:
        for client, name in (("codex", "config.toml"), ("claude", "claude.json")):
            with self.subTest(client=client):
                path = self.root / name
                plan = self.plan(client, path)
                self.write_private(path, str(plan["config_document"]).encode())
                command, args = smoke.installed_stdio_command(
                    client=client,
                    config_path=path,
                    workspace=self.workspace,
                    executable=self.executable,
                    expected_document=str(plan["config_document"]),
                )
                self.assertEqual(command, str(self.executable))
                self.assertEqual(args, plan["stdio"]["args"])

    def test_exact_search_validation_rejects_echo_only_and_stale_content(self) -> None:
        echo_only = {
            "content": [{"type": "text", "text": ""}],
            "structuredContent": {
                "pattern": "ONBOARDING_SEARCH_V1",
                "path": "scope",
                "matches": [],
                "truncated": False,
            },
            "_meta": {"again": {"resultId": "a" * 64}},
        }
        with self.assertRaises(smoke.HarnessRefusal) as missing:
            smoke.require_exact_search_result(
                echo_only,
                expected_matches=[
                    {
                        "path": "scope/search.txt",
                        "line": 1,
                        "text": "ONBOARDING_SEARCH_V1",
                        "lineTruncated": False,
                    }
                ],
                expected_text="scope/search.txt:1:ONBOARDING_SEARCH_V1",
            )
        self.assertEqual(missing.exception.code, "search_output_mismatch")

        stale_content = dict(echo_only)
        stale_content["content"] = [
            {"type": "text", "text": "scope/search.txt:1:ONBOARDING_SEARCH_V1"}
        ]
        with self.assertRaises(smoke.HarnessRefusal) as stale:
            smoke.require_exact_search_result(
                stale_content, expected_matches=[], expected_text=""
            )
        self.assertEqual(stale.exception.code, "search_output_mismatch")

    def test_cleanup_kills_descendant_after_process_leader_exits(self) -> None:
        if os.name != "posix":
            self.skipTest("process-group assertion requires POSIX")
        process = subprocess.Popen(
            (
                sys.executable,
                "-c",
                "import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])",
            ),
            cwd=self.root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        process.wait(timeout=5)
        self.assertTrue(smoke._process_group_exists(process.pid))
        smoke._terminate_process_group(process, process.pid)
        self.assertFalse(smoke._process_group_exists(process.pid))

    def test_bounded_command_stops_oversized_output(self) -> None:
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.run_bounded_command(
                (
                    sys.executable,
                    "-c",
                    f"import sys; sys.stdout.buffer.write(b'x' * {smoke.MAX_COMMAND_BYTES + 1})",
                ),
                cwd=self.root,
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                timeout_seconds=5.0,
            )
        self.assertEqual(refused.exception.code, "command_output_limit")

    def test_bounded_command_terminates_timeout(self) -> None:
        with self.assertRaises(smoke.HarnessRefusal) as refused:
            smoke.run_bounded_command(
                (sys.executable, "-c", "import time; time.sleep(5)"),
                cwd=self.root,
                environment={"PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                timeout_seconds=0.2,
            )
        self.assertEqual(refused.exception.code, "command_timeout")


if __name__ == "__main__":
    unittest.main()
