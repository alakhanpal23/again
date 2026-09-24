#!/usr/bin/env python3
"""Run the frozen cold-task Codex diagnostic with accepted-outcome gates."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import math
import pathlib
import statistics
import subprocess
import sys

import agent_gateway_codex_pair_diagnostic_v1 as pair_harness
import agent_gateway_editable_pair as fixture
from agent_gateway_codex_live_probe_v1 import source_state


ROOT = pathlib.Path(__file__).resolve().parents[1]
MANIFEST = pathlib.Path(__file__).with_name("single_agent_cold_cohort_v1.json")
PAIR_HARNESS = pathlib.Path(pair_harness.__file__).resolve()


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_manifest(manifest: dict) -> None:
    if manifest.get("schema") not in {
        "again.single-agent-cold-cohort.v1",
        "again.single-agent-returning-cohort.v1",
    }:
        raise RuntimeError("unexpected cohort schema")
    if manifest.get("orders") != ["baseline-first", "again-first"]:
        raise RuntimeError("cohort must contain both treatment orders")
    for case in manifest["cases"]:
        pair_harness.configure_fixture(case["fixture"])
        actual_fixture = hashlib.sha256(fixture.canonical_bytes(fixture.FIXTURE)).hexdigest()
        actual_prompt = hashlib.sha256(fixture.PROMPT.encode()).hexdigest()
        if actual_fixture != case["fixtureSha256"] or actual_prompt != case["promptSha256"]:
            raise RuntimeError(f"frozen fixture or prompt changed: {case['fixture']}")


def validate_report(report: dict, case: dict, order: str, binary_hash: str, model: str,
                    output_dir: pathlib.Path) -> None:
    if (
        report.get("fixture") != case["fixture"]
        or report.get("sourceFiles") != case["sourceFiles"]
        or report.get("fixtureSha256") != case["fixtureSha256"]
        or report.get("promptSha256") != case["promptSha256"]
        or report.get("againBinarySha256") != binary_hash
        or report.get("harnessSha256") != sha256(PAIR_HARNESS)
        or report.get("model") != model
        or report.get("surface") != "product-wrapper"
        or report.get("requiredAgentValidation", []) != case.get("requiredAgentValidation", [])
        or report.get("returningTask") is not bool(case.get("returningTask", False))
        or report.get("source", {}).get("dirty") is not False
        or report.get("source", {}).get("binarySourceBindingVerified") is not True
        or report.get("order") != (["baseline", "product"] if order == "baseline-first" else ["product", "baseline"])
    ):
        raise RuntimeError(f"pair result does not match frozen case {case['fixture']} {order}")
    if len(report.get("observations", [])) != 2:
        raise RuntimeError("pair omitted an observation")
    if case.get("requiredAgentValidation") and any(
        item.get("agentValidationObserved") is not True
        for item in report["observations"]
    ):
        raise RuntimeError("agent did not run required validation")
    required_directory = case.get("requiredValidationWorkingDirectory")
    if required_directory and any(
        agent_validation_command(item, case["requiredAgentValidation"], required_directory) is None
        for item in report["observations"]
    ):
        raise RuntimeError("agent did not validate from the required package directory")
    if case.get("returningTask"):
        observations = {item["condition"]: item for item in report["observations"]}
        if observations["product"].get("priorBrain", {}).get("path") != "src/util.py":
            raise RuntimeError("returning task lacked its verified prior Brain read")
        if observations["product"].get("priorBrain", {}).get("mode") != case.get("priorBrainMode", "read"):
            raise RuntimeError("returning task used the wrong prior Brain observation mode")
        if observations["baseline"].get("priorBrain") is not None:
            raise RuntimeError("baseline was seeded with Again Brain")
    for observation in report["observations"]:
        raw = output_dir / observation["rawEventFile"]
        if not raw.is_file() or sha256(raw) != observation["rawEventSha256"]:
            raise RuntimeError(f"pair raw event evidence is missing or corrupt: {raw}")


def usage_vector(observation: dict) -> dict[str, int] | None:
    usage = observation.get("usage")
    if not isinstance(usage, dict):
        return None
    try:
        total = int(usage["input_tokens"])
        cached = int(usage["cached_input_tokens"])
        output = int(usage["output_tokens"])
    except (KeyError, TypeError, ValueError):
        return None
    if not 0 <= cached <= total or output < 0:
        return None
    return {"uncachedInput": total - cached, "cachedInput": cached, "output": output}


def agent_validation_command(observation: dict, selectors: list[str],
                             working_directory: str | None = None) -> str | None:
    return next((action["command"] for action in observation["completedActions"]
                 if action["type"] == "command_execution" and action.get("exitCode") == 0
                 and any(selector in action["command"] for selector in selectors)
                 and (working_directory is None or working_directory in action["command"])), None)


def summarize(manifest: dict, reports: list[dict], binary_hash: str,
              manifest_path: pathlib.Path = MANIFEST) -> dict:
    pairs = []
    ratios = []
    for report in reports:
        case = next(case for case in manifest["cases"]
                    if case["fixture"] == report["fixture"]
                    and case["sourceFiles"] == report["sourceFiles"])
        required_directory = case.get("requiredValidationWorkingDirectory")
        observations = {item["condition"]: item for item in report["observations"]}
        baseline, product = observations["baseline"], observations["product"]
        baseline_usage, product_usage = usage_vector(baseline), usage_vector(product)
        accepted = bool(report.get("accepted"))
        ratio = product["elapsedMs"] / baseline["elapsedMs"] if accepted and baseline["elapsedMs"] > 0 else None
        if ratio is not None:
            ratios.append(ratio)
        pairs.append({
            "fixture": report["fixture"],
            "sourceFiles": report["sourceFiles"],
            "order": report["order"],
            "accepted": accepted,
            "baselineMs": baseline["elapsedMs"],
            "againMs": product["elapsedMs"],
            "elapsedRatio": ratio,
            "baselineActions": len(baseline["completedActions"]),
            "againActions": len(product["completedActions"]),
            "baselineUsage": baseline_usage,
            "againUsage": product_usage,
            "baselineAgentValidation": agent_validation_command(
                baseline, report.get("requiredAgentValidation", []),
                required_directory,
            ),
            "againAgentValidation": agent_validation_command(
                product, report.get("requiredAgentValidation", []),
                required_directory,
            ),
        })
    median_ratio = statistics.median(ratios) if ratios else None
    p95_ratio = sorted(ratios)[math.ceil(0.95 * len(ratios)) - 1] if ratios else None
    baseline_usage = {key: sum(pair["baselineUsage"][key] for pair in pairs if pair["baselineUsage"])
                      for key in ("uncachedInput", "cachedInput", "output")}
    again_usage = {key: sum(pair["againUsage"][key] for pair in pairs if pair["againUsage"])
                   for key in ("uncachedInput", "cachedInput", "output")}
    return {
        "schema": manifest["schema"].replace("cohort.v1", "cohort-result.v1"),
        "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "manifestSha256": sha256(manifest_path),
        "binarySha256": binary_hash,
        "model": manifest["model"],
        "evidenceScope": manifest["purpose"],
        "acceptedPairs": sum(pair["accepted"] for pair in pairs),
        "totalPairs": len(pairs),
        "pairedMedianElapsedRatio": median_ratio,
        "pairedP95ElapsedRatio": p95_ratio,
        "pairedMedianElapsedTargetMet": median_ratio is not None and median_ratio <= 0.8,
        "baselineUsageTotals": baseline_usage,
        "againUsageTotals": again_usage,
        "allUsageVectorsComplete": all(pair["baselineUsage"] and pair["againUsage"] for pair in pairs),
        "pairs": pairs,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--manifest", type=pathlib.Path, default=MANIFEST)
    parser.add_argument("--output-dir", required=True, type=pathlib.Path)
    parser.add_argument("--plan-only", action="store_true")
    args = parser.parse_args()
    manifest_path = args.manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    verify_manifest(manifest)
    binary = args.binary.resolve(strict=True)
    binary_hash = sha256(binary)
    if args.plan_only:
        print(json.dumps({"manifestSha256": sha256(manifest_path), "binarySha256": binary_hash,
                          "pairs": len(manifest["cases"]) * len(manifest["orders"])}, indent=2))
        return 0
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT,
                            capture_output=True, text=True, check=True)
    if status.stdout.strip():
        raise RuntimeError("cohort requires a clean source tree and an output directory outside it")
    if args.output_dir.resolve().is_relative_to(ROOT):
        raise RuntimeError("cohort output directory must be outside the source tree")
    build_source = source_state(ROOT, binary)
    if build_source["binarySourceBindingVerified"] is not True:
        raise RuntimeError(f"cohort binary is not bound to this clean source: {build_source}")
    args.output_dir.mkdir(parents=True, exist_ok=True)
    reports = []
    for case in manifest["cases"]:
        for order in manifest["orders"]:
            output = args.output_dir / f"{case['fixture']}-{case['sourceFiles']}-{order}.json"
            if not output.exists():
                command = [sys.executable, str(PAIR_HARNESS), "--binary", str(binary),
                           "--model", manifest["model"], "--fixture", case["fixture"],
                           "--source-files", str(case["sourceFiles"]), "--order", order,
                           "--product-wrapper", "--output", str(output)]
                if case.get("priorBrainMode") == "search":
                    command.append("--seed-prior-brain-search")
                elif case.get("returningTask"):
                    command.append("--seed-prior-brain")
                for selector in case.get("requiredAgentValidation", []):
                    command.extend(["--required-agent-validation", selector])
                result = subprocess.run(command, cwd=ROOT, timeout=420, capture_output=True, text=True)
                if not output.exists():
                    raise RuntimeError(f"pair harness failed without a report: {case['fixture']} {order}: {result.stderr[-1000:]}")
            report = json.loads(output.read_text())
            validate_report(report, case, order, binary_hash, manifest["model"], args.output_dir)
            reports.append(report)
            print(json.dumps({"fixture": case["fixture"], "order": order,
                              "accepted": report["accepted"], "report": str(output)}), flush=True)
    summary = summarize(manifest, reports, binary_hash, manifest_path)
    summary["source"] = build_source
    (args.output_dir / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps({"acceptedPairs": summary["acceptedPairs"], "totalPairs": summary["totalPairs"],
                      "pairedMedianElapsedRatio": summary["pairedMedianElapsedRatio"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
