#!/usr/bin/env python3
"""Portable tests for workspace_authority_fixture."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("workspace_authority_fixture.py")
SPEC = importlib.util.spec_from_file_location("workspace_authority_fixture", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
fixture = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = fixture
SPEC.loader.exec_module(fixture)


class WorkspaceAuthorityFixtureTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-authority-fixture-")
        self.root = pathlib.Path(self.temporary.name).resolve() / "repository"
        self.root.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative: str, value: bytes) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def git(self, *arguments: str) -> str:
        completed = subprocess.run(
            ("git", *arguments),
            cwd=self.root,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))
        return completed.stdout.decode().strip()

    def initialize_git(self) -> None:
        self.git("init", "-q")
        self.git("config", "user.name", "Again Authority Tests")
        self.git("config", "user.email", "authority-tests@example.invalid")
        self.git("config", "commit.gpgsign", "false")

    def commit_all(self, message: str) -> None:
        self.git("add", "--all")
        self.git("commit", "-q", "-m", message)

    def test_repository_mutation_matrix(self) -> None:
        self.initialize_git()
        self.write("src/tracked", b"tracked\n")
        self.commit_all("initial")
        content = fixture.ObservationPlan(content_paths=("src/tracked",))
        first = fixture.observe_repository(self.root, content)
        self.write("src/tracked", b"changed\n")
        changed = fixture.observe_repository(self.root, content)
        self.assertNotEqual(first["digest"], changed["digest"])

        tree = fixture.ObservationPlan(recursive_trees=("src",))
        before_untracked = fixture.observe_repository(self.root, tree)
        self.write("src/untracked", b"untracked\n")
        after_untracked = fixture.observe_repository(self.root, tree)
        self.assertNotEqual(before_untracked["digest"], after_untracked["digest"])

        negative = fixture.ObservationPlan(negative_dependencies=("src/generated",))
        absent = fixture.observe_repository(self.root, negative)
        self.write("src/generated", b"generated\n")
        present = fixture.observe_repository(self.root, negative)
        self.assertNotEqual(absent["digest"], present["digest"])

    def test_git_head_and_index_are_bound(self) -> None:
        self.initialize_git()
        self.write("tracked", b"one\n")
        self.commit_all("initial")
        plan = fixture.ObservationPlan()
        initial = fixture.observe_repository(self.root, plan)
        self.write("staged", b"staged\n")
        self.git("add", "staged")
        staged = fixture.observe_repository(self.root, plan)
        self.assertNotEqual(initial["digest"], staged["digest"])
        self.commit_all("second")
        committed = fixture.observe_repository(self.root, plan)
        self.assertNotEqual(staged["digest"], committed["digest"])

    def test_irrelevant_path_is_stable_under_explicit_plan(self) -> None:
        self.write("selected/input", b"selected\n")
        self.write("irrelevant/first", b"first\n")
        plan = fixture.ObservationPlan(content_paths=("selected/input",))
        before = fixture.observe_repository(self.root, plan)
        self.write("irrelevant/second", b"second\n")
        after = fixture.observe_repository(self.root, plan)
        self.assertEqual(before["digest"], after["digest"])

    def test_symlink_special_sparse_and_replacement_refusals(self) -> None:
        self.write("target", b"target\n")
        (self.root / "link").symlink_to("target")
        with self.assertRaises(fixture.FixtureRefusal) as symlink:
            fixture.observe_repository(
                self.root, fixture.ObservationPlan(content_paths=("link",))
            )
        self.assertEqual(symlink.exception.code, "symlink_refused")

        named_pipe = self.root / "named-pipe"
        os.mkfifo(named_pipe)
        with self.assertRaises(fixture.FixtureRefusal) as special:
            fixture.observe_repository(
                self.root, fixture.ObservationPlan(content_paths=("named-pipe",))
            )
        self.assertEqual(special.exception.code, "special_file_refused")
        named_pipe.unlink()

        self.initialize_git()
        (self.root / ".git" / "info" / "sparse-checkout").write_text("/*\n")
        with self.assertRaises(fixture.FixtureRefusal) as sparse:
            fixture.observe_repository(self.root, fixture.ObservationPlan())
        self.assertEqual(sparse.exception.code, "sparse_checkout_ambiguous")
        (self.root / ".git" / "info" / "sparse-checkout").unlink()

        displaced = self.root.parent / "displaced"

        def replace() -> None:
            self.root.rename(displaced)
            self.root.mkdir()

        with self.assertRaises(fixture.FixtureRefusal) as replacement:
            fixture.observe_repository(
                self.root, fixture.ObservationPlan(), between_samples=replace
            )
        self.assertEqual(replacement.exception.code, "repository_replaced")

    def test_intermediate_symlink_and_replacement_are_refused(self) -> None:
        self.write("inside/value", b"inside\n")
        with tempfile.TemporaryDirectory(prefix="again-authority-external-") as raw_external:
            external = pathlib.Path(raw_external).resolve()
            (external / "value").write_bytes(b"outside-secret\n")
            (self.root / "escape").symlink_to(external)
            with self.assertRaises(fixture.FixtureRefusal) as escaped:
                fixture.observe_repository(
                    self.root,
                    fixture.ObservationPlan(content_paths=("escape/value",)),
                )
            self.assertEqual(escaped.exception.code, "symlink_refused")

            displaced = self.root / "inside-old"

            def replace_intermediate() -> None:
                (self.root / "inside").rename(displaced)
                (self.root / "inside").symlink_to(external)

            with self.assertRaises(fixture.FixtureRefusal) as replaced:
                fixture.observe_repository(
                    self.root,
                    fixture.ObservationPlan(content_paths=("inside/value",)),
                    between_samples=replace_intermediate,
                )
            self.assertIn(
                replaced.exception.code,
                {"symlink_refused", "repository_replaced", "concurrent_mutation"},
            )

    def test_task_environment_and_secret_digests(self) -> None:
        first_task = fixture.task_digest(task_id="task", task_revision=1, plan_revision=1)
        second_task = fixture.task_digest(task_id="task", task_revision=2, plan_revision=1)
        self.assertNotEqual(first_task, second_task)

        tool = self.write("tool", b"tool bytes\n")
        first_environment = fixture.environment_digest(
            tool_path=tool, tool_version="1.0", limits=fixture.Limits()
        )
        second_environment = fixture.environment_digest(
            tool_path=tool, tool_version="2.0", limits=fixture.Limits()
        )
        self.assertNotEqual(first_environment, second_environment)
        secret = fixture.secret_digest(
            "test.secret.v1", b"plaintext-secret", maximum=1024
        )
        self.assertNotIn("plaintext-secret", secret)

    def test_deterministic_encoding_and_all_reference_bounds(self) -> None:
        self.write("a", b"a")
        self.write("b", b"bb")
        self.write("nested/deep/more/value", b"deep")
        forward = fixture.ObservationPlan(content_paths=("a", "b"))
        reverse = fixture.ObservationPlan(content_paths=("b", "a"))
        self.assertEqual(
            fixture.observe_repository(self.root, forward)["digest"],
            fixture.observe_repository(self.root, reverse)["digest"],
        )

        bound_cases = (
            (fixture.Limits(max_plan_entries=1), forward),
            (fixture.Limits(max_path_bytes=1), fixture.ObservationPlan(content_paths=("long",))),
            (fixture.Limits(max_file_bytes=1), fixture.ObservationPlan(content_paths=("b",))),
            (fixture.Limits(max_total_bytes=2), forward),
            (fixture.Limits(max_tree_entries=1), fixture.ObservationPlan(recursive_trees=("",))),
            (fixture.Limits(max_tree_depth=1), fixture.ObservationPlan(recursive_trees=("nested",))),
            (fixture.Limits(max_directory_entries=1), fixture.ObservationPlan(directory_listings=("",))),
        )
        for limits, plan in bound_cases:
            with self.subTest(limits=limits, plan=plan):
                with self.assertRaises(fixture.FixtureRefusal) as refused:
                    fixture.observe_repository(self.root, plan, limits)
                self.assertEqual(refused.exception.code, "input_limit_exceeded")


if __name__ == "__main__":
    unittest.main()
