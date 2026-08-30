from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "dependency_license_audit", ROOT / "scripts" / "audit_dependency_licenses.py"
)
assert SPEC is not None and SPEC.loader is not None
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def metadata(*dependencies: dict[str, object]) -> dict[str, object]:
    root_id = "path+file:///workspace#again-cli@0.1.0"
    return {
        "version": 1,
        "workspace_members": [root_id],
        "packages": [
            {
                "id": root_id,
                "name": "again-cli",
                "version": "0.1.0",
                "source": None,
                "license": "Apache-2.0",
            },
            *dependencies,
        ],
    }


def dependency(
    *, license_expression: object = "MIT OR Apache-2.0", source: object = None
) -> dict[str, object]:
    if source is None:
        source = AUDIT.CRATES_IO_SOURCE
    return {
        "id": "registry+https://github.com/rust-lang/crates.io-index#safe@1.0.0",
        "name": "safe",
        "version": "1.0.0",
        "source": source,
        "license": license_expression,
    }


class DependencyLicenseAuditTests(unittest.TestCase):
    def test_reviewed_crates_io_dependency_passes(self) -> None:
        report = AUDIT.audit_metadata(metadata(dependency()))
        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["registryPackages"], 1)
        self.assertEqual(report["gitDependencies"], 0)

    def test_git_dependency_refuses_even_with_an_approved_license(self) -> None:
        with self.assertRaisesRegex(AUDIT.AuditFailure, "reviewed crates.io"):
            AUDIT.audit_metadata(
                metadata(dependency(source="git+https://example.invalid/repository"))
            )

    def test_missing_or_unreviewed_license_refuses(self) -> None:
        for expression in (None, "GPL-3.0-only"):
            with self.subTest(expression=expression):
                with self.assertRaises(AUDIT.AuditFailure):
                    AUDIT.audit_metadata(
                        metadata(dependency(license_expression=expression))
                    )

    def test_workspace_license_is_exact(self) -> None:
        document = metadata()
        document["packages"][0]["license"] = "MIT"
        with self.assertRaisesRegex(AUDIT.AuditFailure, "workspace package"):
            AUDIT.audit_metadata(document)

    def test_duplicate_and_missing_workspace_identity_refuse(self) -> None:
        duplicate = metadata()
        duplicate["packages"].append(duplicate["packages"][0].copy())
        with self.assertRaisesRegex(AUDIT.AuditFailure, "repeats a package id"):
            AUDIT.audit_metadata(duplicate)

        missing = metadata()
        missing["packages"] = []
        with self.assertRaises(AUDIT.AuditFailure):
            AUDIT.audit_metadata(missing)

    def test_duplicate_json_key_refuses_before_policy_evaluation(self) -> None:
        with tempfile.TemporaryDirectory() as raw_fixture:
            path = pathlib.Path(raw_fixture) / "metadata.json"
            path.write_text('{"version":1,"version":1}', encoding="utf-8")
            with self.assertRaisesRegex(AUDIT.AuditFailure, "repeats JSON key"):
                AUDIT.load_metadata(path)


if __name__ == "__main__":
    unittest.main()
