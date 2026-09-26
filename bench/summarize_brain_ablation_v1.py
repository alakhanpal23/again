#!/usr/bin/env python3
"""Verify and summarize accepted, source-bound Brain ablation pairs."""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import pathlib
import statistics

from estimate_api_equivalent_cost_v1 import cost


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def investigation_commands(path: pathlib.Path, expected_sha: str,
                           test_command: str) -> int:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RuntimeError(f"raw event digest mismatch: {path}")
    count = 0
    for line in raw.splitlines():
        event = json.loads(line)
        item = event.get("item", {})
        if (event.get("type") == "item.completed"
                and item.get("type") == "command_execution"
                and isinstance(item.get("exit_code"), int)
                and not (item["exit_code"] == 0
                         and test_command in item.get("command", ""))):
            count += 1
    return count


def validation_duration_ms(item: dict, path: pathlib.Path,
                           test_command: str) -> float:
    """Measure the required agent-run test from captured start/completion events."""
    test_ids = set()
    for line in path.read_bytes().splitlines():
        event = json.loads(line)
        action = event.get("item", {})
        if (event.get("type") == "item.completed"
                and action.get("type") == "command_execution"
                and action.get("exit_code") == 0
                and test_command in action.get("command", "")):
            test_ids.add(action.get("id"))
    if not test_ids or None in test_ids:
        raise RuntimeError(f"required test has no captured item ID: {path}")
    started = {}
    completed = {}
    for event in item.get("eventTimeline", []):
        event_id = event.get("itemId")
        if event_id not in test_ids:
            continue
        if event.get("event") == "item.started":
            started[event_id] = event.get("elapsedMs")
        elif event.get("event") == "item.completed":
            completed[event_id] = event.get("elapsedMs")
    if set(started) != test_ids or set(completed) != test_ids:
        raise RuntimeError(f"required test lacks start/completion timing: {path}")
    durations = [completed[event_id] - started[event_id] for event_id in test_ids]
    if any(duration < 0 for duration in durations):
        raise RuntimeError(f"required test timing is reversed: {path}")
    return round(sum(durations), 3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=pathlib.Path, action="append", required=True)
    parser.add_argument("--rate-card", type=pathlib.Path, required=True)
    parser.add_argument("--test-command", required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    card = json.loads(args.rate_card.read_text())
    rates = {key: decimal.Decimal(value)
             for key, value in card["usdPerMillionTokens"].items()}
    pairs = []
    cold_cost = decimal.Decimal(0)
    seeded_cost = decimal.Decimal(0)
    fixture = None
    model = None
    seen_reports = set()
    seen_orders = set()
    for report_path in args.report:
        if report_path.resolve() in seen_reports:
            raise RuntimeError(f"duplicate ablation report: {report_path}")
        seen_reports.add(report_path.resolve())
        report = json.loads(report_path.read_text())
        if (report.get("schema") != "again.brain-ablation.v1"
                or report.get("accepted") is not True
                or report.get("incomplete") is True
                or report["source"].get("binarySourceBindingVerified") is not True
                or report["source"].get("buildSourceSha") != report["source"].get("head")):
            raise RuntimeError(f"unaccepted or unbound report: {report_path}")
        if fixture is None:
            fixture, model = report["fixture"], report["model"]
        if report["fixture"] != fixture or report["model"] != model or model != card["model"]:
            raise RuntimeError("fixture, model, or rate card mismatch")
        observations = {item["condition"]: item for item in report["observations"]}
        if set(observations) != {"product", "product-cold"}:
            raise RuntimeError("ablation report must contain both treatment conditions")
        order = tuple(report["order"])
        if len(order) != 2 or set(order) != set(observations):
            raise RuntimeError("ablation report has an invalid treatment order")
        seen_orders.add(order)
        by_condition = {}
        for condition, item in observations.items():
            brain_run = item.get("brainRun") or {}
            if (item.get("exitCode") != 0 or item.get("timedOut")
                    or item.get("agentValidationObserved") is not True
                    or item.get("oracle", {}).get("passed") is not True
                    or brain_run.get("successful_tests", 0) < 1):
                raise RuntimeError(f"unaccepted leg in {report_path}: {condition}")
            raw_path = report_path.with_name(item["rawEventFile"])
            by_condition[condition] = (
                item,
                investigation_commands(raw_path, item["rawEventSha256"], args.test_command),
                validation_duration_ms(item, raw_path, args.test_command),
            )
        cold, cold_investigations, cold_validation_ms = by_condition["product-cold"]
        seeded, seeded_investigations, seeded_validation_ms = by_condition["product"]
        if cold.get("priorBrain") is not None or seeded.get("priorBrain") is None:
            raise RuntimeError("missing cold/seeded Brain contrast")
        cold_pair_cost = cost(cold["usage"], rates)
        seeded_pair_cost = cost(seeded["usage"], rates)
        cold_cost += cold_pair_cost
        seeded_cost += seeded_pair_cost
        pairs.append({
            "report": report_path.name,
            "order": report["order"],
            "sourceSha": report["source"]["head"],
            "coldElapsedMs": cold["elapsedMs"],
            "seededElapsedMs": seeded["elapsedMs"],
            "seededToColdElapsedRatio": seeded["elapsedMs"] / cold["elapsedMs"],
            "coldFirstEditMs": cold["firstEditMs"],
            "seededFirstEditMs": seeded["firstEditMs"],
            "coldInvestigationCommands": cold_investigations,
            "seededInvestigationCommands": seeded_investigations,
            "coldRequiredValidationMs": cold_validation_ms,
            "seededRequiredValidationMs": seeded_validation_ms,
            "coldNonValidationMs": round(cold["elapsedMs"] - cold_validation_ms, 3),
            "seededNonValidationMs": round(seeded["elapsedMs"] - seeded_validation_ms, 3),
            "coldSuccessfulTests": cold["brainRun"]["successful_tests"],
            "seededSuccessfulTests": seeded["brainRun"]["successful_tests"],
            "coldApiEquivalentUsd": str(cold_pair_cost),
            "seededApiEquivalentUsd": str(seeded_pair_cost),
        })
    ratios = [pair["seededToColdElapsedRatio"] for pair in pairs]
    if len(pairs) >= 2 and len(seen_orders) != 2:
        raise RuntimeError("multiple ablation pairs must cover both treatment orders")
    summary = {
        "schema": "again.brain-ablation-summary.v1",
        "fixture": fixture,
        "model": model,
        "testCommand": args.test_command,
        "totalPairs": len(pairs),
        "acceptedPairs": len(pairs),
        "pairs": pairs,
        "pairedMedianElapsedRatio": statistics.median(ratios),
        "pairedP95ElapsedRatio": percentile(ratios, 0.95),
        "coldInvestigationCommands": sum(pair["coldInvestigationCommands"] for pair in pairs),
        "seededInvestigationCommands": sum(pair["seededInvestigationCommands"] for pair in pairs),
        "coldApiEquivalentUsd": str(cold_cost),
        "seededApiEquivalentUsd": str(seeded_cost),
        "apiEquivalentCostRatio": float(seeded_cost / cold_cost),
        "rateCard": card,
        "limitations": [
            "one fixture in the supplied run orders; not a frozen balanced release cohort",
            "prior read seeded before timing; first-use economics unmeasured",
            "API-equivalent estimate, not billed Codex charges",
        ],
    }
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"acceptedPairs": len(pairs),
                      "pairedMedianElapsedRatio": summary["pairedMedianElapsedRatio"],
                      "apiEquivalentCostRatio": summary["apiEquivalentCostRatio"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
