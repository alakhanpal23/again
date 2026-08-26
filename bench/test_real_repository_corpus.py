#!/usr/bin/env python3
"""Portable unit tests for the real-repository corpus harness."""

from __future__ import annotations

import importlib.util
import os
import pathlib
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


MODULE_PATH = pathlib.Path(__file__).with_name("real_repository_corpus.py")
SPEC = importlib.util.spec_from_file_location("real_repository_corpus", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
corpus = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = corpus
SPEC.loader.exec_module(corpus)


class RepositoryFixture:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.git("init", "-q")
        self.git("config", "user.name", "Again Tests")
        self.git("config", "user.email", "again-tests@example.invalid")
        self.git("config", "commit.gpgsign", "false")

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
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode(errors="replace"))
        return completed.stdout.decode().strip()

    def write(self, relative: str, value: bytes) -> pathlib.Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(value)
        return path

    def commit(self) -> str:
        self.git("add", "--all")
        self.git("commit", "-q", "-m", "fixture")
        return self.git("rev-parse", "HEAD")


class RealRepositoryCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="again-real-repo-test-")
        self.root = pathlib.Path(self.temporary.name).resolve()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def repository(self, name: str = "repo") -> RepositoryFixture:
        root = self.root / name
        root.mkdir()
        return RepositoryFixture(root)

    def test_selection_and_command_corpus_are_deterministic(self) -> None:
        fixture = self.repository()
        fixture.write("src/z.rs", b"z\n")
        fixture.write("src/a.rs", b"a\n")
        fixture.write("src/m.rs", b"m\n")
        fixture.write("README.md", b"ignored\n")
        commit = fixture.commit()

        snapshot = corpus.inspect_repository(fixture.root, "rust")
        self.assertEqual(snapshot.git_sha, commit)
        self.assertEqual([item.path for item in snapshot.selected], ["src/a.rs", "src/m.rs"])
        commands = corpus.build_command_corpus(snapshot.selected)
        self.assertEqual(len(commands), 10)
        self.assertEqual(commands[0].argv, ("cat", "--", "src/a.rs"))
        self.assertEqual(commands[3].command_id, "file0-wc-bytes")
        self.assertEqual(commands[-1].argv, ("wc", "-c", "--", "src/m.rs"))
        self.assertEqual(commands, corpus.build_command_corpus(snapshot.selected))

    def test_nul_manifest_supports_non_utf8_and_newline_filenames(self) -> None:
        object_id = b"1" * 40
        raw_paths = (b"a-\xff.py", b"b\nname.py")
        manifest = b"".join(
            b"100644 " + object_id + b" 0\t" + path + b"\0" for path in raw_paths
        )
        entries = corpus.parse_tracked_manifest(manifest, corpus.DEFAULT_LIMITS)

        self.assertEqual([entry.path_bytes for entry in entries], list(raw_paths))
        self.assertEqual([os.fsencode(entry.path) for entry in entries], list(raw_paths))
        escaped = corpus.canonical_json_bytes({"path": entries[0].path})
        self.assertIn(b"\\udcff", escaped)

        fixture = self.repository()
        root_bytes = os.fsencode(fixture.root)
        materialized_paths = (b"a.py", b"b\nname.py")
        for raw_path, contents in zip(materialized_paths, (b"ordinary\n", b"newline\n")):
            descriptor = os.open(root_bytes + b"/" + raw_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, contents)
            finally:
                os.close(descriptor)
        fixture.commit()
        snapshot = corpus.inspect_repository(fixture.root, "python")
        self.assertEqual(
            [os.fsencode(selected.path) for selected in snapshot.selected],
            list(materialized_paths),
        )
        workspace = self.root / "raw-name-workspace"
        corpus.copy_selected_files(snapshot, workspace)
        for selected, contents in zip(snapshot.selected, (b"ordinary\n", b"newline\n")):
            self.assertEqual((workspace / selected.path).read_bytes(), contents)
        corpus.canonical_json_bytes(corpus.snapshot_record(snapshot, source_copy_verification="ok"))

    def test_submodule_selected_by_suffix_is_typed_unsupported(self) -> None:
        fixture = self.repository()
        fixture.write("a.rs", b"a\n")
        fixture.write("b.rs", b"b\n")
        commit = fixture.commit()
        fixture.git(
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{commit},0-submodule.rs",
        )
        fixture.git("commit", "-q", "-m", "gitlink")

        with self.assertRaises(corpus.HarnessRefusal) as refused:
            corpus.inspect_repository(fixture.root, "rust")
        self.assertEqual(refused.exception.code, "selected_input_special")

    def test_option_like_inputs_are_delimited_and_execute_as_files(self) -> None:
        fixture = self.repository()
        fixture.write("-a.rs", b"alpha\n")
        fixture.write("-b.rs", b"beta\n")
        fixture.commit()
        snapshot = corpus.inspect_repository(fixture.root, "rust")
        workspace = self.root / "workspace"
        corpus.copy_selected_files(snapshot, workspace)
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        for command in corpus.build_command_corpus(snapshot.selected):
            self.assertIn("--", command.argv)
            completed = corpus.run_bounded(
                command.argv,
                cwd=workspace,
                environment=environment,
                timeout_seconds=5.0,
                stream_limit_bytes=1024 * 1024,
            )
            self.assertEqual(completed.returncode, 0, command.command_id)

    def test_repository_count_and_byte_bounds_fail_closed(self) -> None:
        fixture = self.repository()
        fixture.write("a.rs", b"a\n")
        fixture.write("b.rs", b"b\n")
        fixture.write("c.txt", b"c\n")
        fixture.commit()

        with self.assertRaisesRegex(corpus.HarnessRefusal, "tracked file count") as count:
            corpus.inspect_repository(
                fixture.root,
                "rust",
                corpus.Limits(max_tracked_files=2),
            )
        self.assertEqual(count.exception.code, "repository_oversized")

        with self.assertRaisesRegex(corpus.HarnessRefusal, "tracked worktree bytes") as size:
            corpus.inspect_repository(
                fixture.root,
                "rust",
                corpus.Limits(max_repository_logical_bytes=3),
            )
        self.assertEqual(size.exception.code, "repository_oversized")

    def test_provenance_records_head_and_dirty_status_without_writes(self) -> None:
        fixture = self.repository()
        first = fixture.write("a.py", b"print('a')\n")
        second = fixture.write("b.py", b"print('b')\n")
        commit = fixture.commit()
        clean = corpus.inspect_repository(fixture.root, "python")
        self.assertEqual(clean.git_sha, commit)
        self.assertFalse(clean.dirty)
        manifest_before = clean.tracked_manifest_sha256

        first.write_bytes(b"print('changed')\n")
        dirty = corpus.inspect_repository(fixture.root, "python")
        self.assertTrue(dirty.dirty)
        self.assertNotEqual(dirty.dirty_status_sha256, clean.dirty_status_sha256)
        self.assertEqual(dirty.tracked_manifest_sha256, manifest_before)
        self.assertEqual(second.read_bytes(), b"print('b')\n")

    def test_git_inspection_ignores_inherited_repository_overrides(self) -> None:
        requested = self.repository("requested")
        requested.write("a.py", b"print('requested a')\n")
        requested.write("b.py", b"print('requested b')\n")
        requested_sha = requested.commit()
        other = self.repository("other")
        other.write("a.py", b"print('other a')\n")
        other.write("b.py", b"print('other b')\n")
        other.commit()

        hostile = {
            "GIT_DIR": str(other.root / ".git"),
            "GIT_INDEX_FILE": str(other.root / ".git" / "index"),
            "GIT_WORK_TREE": str(other.root),
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            snapshot = corpus.inspect_repository(requested.root, "python")
        self.assertEqual(snapshot.git_sha, requested_sha)
        self.assertEqual([item.path for item in snapshot.selected], ["a.py", "b.py"])

    def test_selected_symlink_special_and_sparse_inputs_are_rejected(self) -> None:
        symlink_repo = self.repository("symlink")
        symlink_repo.write("target", b"target\n")
        os.symlink("target", symlink_repo.root / "a.rs")
        symlink_repo.write("b.rs", b"b\n")
        symlink_repo.commit()
        with self.assertRaises(corpus.HarnessRefusal) as symlink:
            corpus.inspect_repository(symlink_repo.root, "rust")
        self.assertEqual(symlink.exception.code, "selected_input_symlink")

        if hasattr(os, "mkfifo"):
            special_repo = self.repository("special")
            special = special_repo.write("a.go", b"regular\n")
            special_repo.write("b.go", b"b\n")
            special_repo.commit()
            special.unlink()
            os.mkfifo(special)
            with self.assertRaises(corpus.HarnessRefusal) as special_error:
                corpus.inspect_repository(special_repo.root, "go")
            self.assertEqual(special_error.exception.code, "selected_input_special")

        sparse_repo = self.repository("sparse")
        sparse_repo.write("a.ts", b"a\n")
        sparse_repo.write("b.ts", b"b\n")
        sparse_repo.commit()
        with mock.patch.object(corpus, "is_sparse", return_value=True):
            with self.assertRaises(corpus.HarnessRefusal) as sparse_error:
                corpus.inspect_repository(sparse_repo.root, "typescript")
            self.assertEqual(sparse_error.exception.code, "selected_input_sparse")

    def test_intermediate_symlinks_and_copy_time_parent_swaps_are_rejected(self) -> None:
        escaped = self.repository("escaped")
        escaped.write("src/a.rs", b"alpha\n")
        escaped.write("src/b.rs", b"beta\n")
        escaped.commit()
        original = escaped.root / "src"
        original.rename(escaped.root / "src-original")
        os.symlink(self.root, original)
        with self.assertRaises(corpus.HarnessRefusal) as symlink:
            corpus.inspect_repository(escaped.root, "rust")
        self.assertEqual(symlink.exception.code, "selected_input_symlink")

        changed = self.repository("changed-parent")
        changed.write("src/a.rs", b"alpha\n")
        changed.write("src/b.rs", b"beta\n")
        changed.commit()
        snapshot = corpus.inspect_repository(changed.root, "rust")
        source_parent = changed.root / "src"
        replacement = self.root / "replacement"
        replacement.mkdir()
        (replacement / "a.rs").write_bytes(b"alpha\n")
        (replacement / "b.rs").write_bytes(b"beta\n")

        def swap_parent(_relative: str, index: int) -> None:
            if index == 0:
                source_parent.rename(changed.root / "src-original")
                os.symlink(replacement, source_parent)

        with self.assertRaises(corpus.HarnessRefusal) as source_changed:
            corpus.copy_selected_files(
                snapshot,
                self.root / "changed-parent-workspace",
                after_copy=swap_parent,
            )
        self.assertEqual(source_changed.exception.code, "source_changed_during_copy")

    def test_copy_detects_selected_source_change_and_never_follows_it(self) -> None:
        fixture = self.repository()
        selected = fixture.write("a.rs", b"alpha\n")
        fixture.write("b.rs", b"beta\n")
        fixture.commit()
        snapshot = corpus.inspect_repository(fixture.root, "rust")
        workspace = self.root / "workspace"

        def mutate(relative: str, index: int) -> None:
            if index == 0:
                self.assertEqual(relative, "a.rs")
                selected.write_bytes(b"ALPHA\n")

        with self.assertRaises(corpus.HarnessRefusal) as changed:
            corpus.copy_selected_files(snapshot, workspace, after_copy=mutate)
        self.assertEqual(changed.exception.code, "source_changed_during_copy")

    def test_copy_preserves_selected_bytes_in_private_workspace(self) -> None:
        fixture = self.repository()
        fixture.write("src/a.rs", b"alpha\n")
        fixture.write("src/b.rs", b"beta\n")
        fixture.commit()
        snapshot = corpus.inspect_repository(fixture.root, "rust")
        workspace = self.root / "workspace"
        copied = corpus.copy_selected_files(snapshot, workspace)
        self.assertEqual((workspace / "src/a.rs").read_bytes(), b"alpha\n")
        self.assertEqual((workspace / "src/b.rs").read_bytes(), b"beta\n")
        self.assertTrue((workspace / ".git").is_dir())
        self.assertEqual([item.sha256 for item in copied], [item.sha256 for item in snapshot.selected])

    def test_mutation_is_same_size_and_changes_digest(self) -> None:
        path = self.root / "input"
        path.write_bytes(b"abcdef\n")
        evidence = corpus.mutate_copied_input(path)
        self.assertEqual(evidence["size_before"], evidence["size_after"])
        self.assertNotEqual(evidence["sha256_before"], evidence["sha256_after"])
        self.assertEqual(path.stat().st_size, 7)

        event = {
            "disposition": "executed",
            "reason": "DOUBLE_EXECUTION_VALIDATED",
            "result_id": "result-after-mutation",
        }
        self.assertEqual(
            corpus.require_mutation_invalidation("result-before-mutation", event),
            "result-after-mutation",
        )
        with self.assertRaises(corpus.HarnessRefusal) as stale:
            corpus.require_mutation_invalidation("result-after-mutation", event)
        self.assertEqual(stale.exception.code, "stale_result_replayed")

    def test_json_is_stable_and_output_is_exclusive(self) -> None:
        left = {"z": [3, 2, 1], "a": {"y": False, "x": 1}}
        right = {"a": {"x": 1, "y": False}, "z": [3, 2, 1]}
        self.assertEqual(corpus.canonical_json_bytes(left), corpus.canonical_json_bytes(right))
        self.assertTrue(corpus.canonical_json_bytes(left).endswith(b"\n"))
        output = self.root / "result.json"
        corpus.write_json_exclusive(output, left)
        with self.assertRaises(corpus.HarnessRefusal) as existing:
            corpus.write_json_exclusive(output, right)
        self.assertEqual(existing.exception.code, "output_exists")

    def test_output_path_cannot_mutate_a_source_repository(self) -> None:
        fixture = self.repository()
        fixture.write("a.rs", b"a\n")
        fixture.write("b.rs", b"b\n")
        fixture.commit()
        direct = fixture.root / "evidence.json"
        nested = fixture.root / "new" / "evidence.json"
        for output in (direct, nested):
            with self.assertRaises(corpus.HarnessRefusal) as refused:
                corpus.require_new_output_path(output, [fixture.root])
            self.assertEqual(refused.exception.code, "output_inside_source")
            self.assertFalse(output.exists())
        outside = self.root / "evidence.json"
        self.assertEqual(
            corpus.require_new_output_path(outside, [fixture.root]), outside
        )

    def test_repository_roots_must_be_distinct(self) -> None:
        fixture = self.repository()
        with self.assertRaises(corpus.HarnessRefusal) as duplicate:
            corpus.require_distinct_repository_roots([fixture.root, fixture.root])
        self.assertEqual(duplicate.exception.code, "duplicate_repository_root")

    def test_command_environment_is_closed_and_records_removed_inputs(self) -> None:
        state = self.root / "state"
        home = self.root / "home"
        hostile = {
            "AGAIN_FULL": "1",
            "GIT_DIR": "/tmp/foreign.git",
            "GREP_OPTIONS": "-f /tmp/patterns",
            "RIPGREP_CONFIG_PATH": "/tmp/ripgreprc",
        }
        with mock.patch.dict(os.environ, hostile, clear=True):
            environment, removed = corpus.sanitized_environment(state, home)
        self.assertEqual(
            environment,
            {
                "AGAIN_HOME": str(state),
                "HOME": str(home),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin",
            },
        )
        self.assertEqual(removed, sorted(hostile))

    def test_subprocess_closes_network_fds_bounds_output_and_cleans_process_tree(self) -> None:
        environment = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
        left, right = socket.socketpair()
        try:
            right.set_inheritable(True)
            completed = corpus.run_bounded(
                (
                    sys.executable,
                    "-c",
                    "import os,sys\n"
                    "try: os.fstat(int(sys.argv[1]))\n"
                    "except OSError: print('closed')\n"
                    "else: print('inherited')",
                    str(right.fileno()),
                ),
                cwd=self.root,
                environment=environment,
                timeout_seconds=5.0,
                stream_limit_bytes=1024,
            )
        finally:
            left.close()
            right.close()
        self.assertEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, b"closed\n")

        with self.assertRaises(corpus.HarnessRefusal) as output_bound:
            corpus.run_bounded(
                (sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"),
                cwd=self.root,
                environment=environment,
                timeout_seconds=5.0,
                stream_limit_bytes=128,
            )
        self.assertEqual(output_bound.exception.code, "stream_limit_exceeded")

        tree = corpus.run_bounded(
            (
                sys.executable,
                "-c",
                "import subprocess,sys\n"
                "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])\n"
                "print(child.pid, flush=True)",
            ),
            cwd=self.root,
            environment=environment,
            timeout_seconds=5.0,
            stream_limit_bytes=1024,
        )
        descendant = int(tree.stdout)
        deadline = time.monotonic() + 2.0
        while True:
            try:
                os.kill(descendant, 0)
            except ProcessLookupError:
                break
            if time.monotonic() >= deadline:
                self.fail(f"descendant {descendant} survived process-group cleanup")
            time.sleep(0.01)

        with self.assertRaises(corpus.HarnessRefusal) as timeout:
            corpus.run_bounded(
                (sys.executable, "-c", "import time; time.sleep(60)"),
                cwd=self.root,
                environment=environment,
                timeout_seconds=0.05,
                stream_limit_bytes=1024,
            )
        self.assertEqual(timeout.exception.code, "command_timeout")

    def test_non_pass_report_is_typed_and_non_authoritative(self) -> None:
        binary = self.root / "again"
        binary.write_bytes(b"binary")
        snapshot = corpus.RepositorySnapshot(
            language="rust",
            root=self.root,
            git_sha="0" * 40,
            dirty=False,
            dirty_status_sha256=corpus.sha256_bytes(b""),
            tracked_manifest_sha256=corpus.sha256_bytes(b""),
            tracked_worktree_stat_sha256=corpus.sha256_bytes(b""),
            tracked_files=0,
            repository_logical_bytes=0,
            selected=(),
        )
        report = corpus.build_non_pass_report(
            code="unsupported_host_profile",
            detail="unsupported host",
            binary=binary,
            snapshots=[snapshot],
            removed_inputs=[],
        )
        self.assertEqual(report["result"], "non_pass")
        self.assertEqual(report["non_pass"]["code"], "unsupported_host_profile")
        self.assertFalse(report["correctness"]["passed"])
        self.assertEqual(report["repositories"], [])
        self.assertEqual(
            report["provenance"]["repositories"][0]["source_copy_verification"],
            "not_attempted",
        )


if __name__ == "__main__":
    unittest.main()
