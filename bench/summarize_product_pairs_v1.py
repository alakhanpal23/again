#!/usr/bin/env python3
"""Verify and summarize source-bound baseline/Again accepted-edit pairs."""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import pathlib
import statistics

from estimate_api_equivalent_cost_v1 import cost


def completed_commands(path: pathlib.Path, expected_sha: str) -> int:
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected_sha:
        raise RuntimeError(f"raw event digest mismatch: {path}")
    return sum(
        event.get("type") == "item.completed"
        and event.get("item", {}).get("type") == "command_execution"
        for event in (json.loads(line) for line in raw.splitlines())
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", action="append", required=True, type=pathlib.Path)
    parser.add_argument("--rate-card", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    card = json.loads(args.rate_card.read_text())
    rates = {name: decimal.Decimal(value)
             for name, value in card["usdPerMillionTokens"].items()}
    pairs = []
    seen = set()
    orders = set()
    source_sha = None
    fixture = None
    baseline_cost = decimal.Decimal(0)
    product_cost = decimal.Decimal(0)
    for path in args.report:
        if path.resolve() in seen:
            raise RuntimeError(f"duplicate report: {path}")
        seen.add(path.resolve())
        report = json.loads(path.read_text())
        source = report.get("source", {})
        if (report.get("schema") != "again.codex-editable-pair-diagnostic.v1"
                or report.get("accepted") is not True
                or source.get("binarySourceBindingVerified") is not True
                or source.get("buildSourceSha") != source.get("head")):
            raise RuntimeError(f"unaccepted or unbound report: {path}")
        if source_sha is None:
            source_sha, fixture = source["head"], report["fixture"]
        if (source["head"] != source_sha or report["fixture"] != fixture
                or report["model"] != card["model"]):
            raise RuntimeError("source, fixture, or model mismatch")
        observations = {item["condition"]: item for item in report["observations"]}
        order = tuple(report["order"])
        if (len(report["observations"]) != 2
                or set(observations) != {"baseline", "product"}
                or len(order) != 2 or set(order) != set(observations)):
            raise RuntimeError(f"invalid treatment conditions: {path}")
        orders.add(order)
        commands = {}
        for condition, item in observations.items():
            if (item["exitCode"] != 0 or item["timedOut"]
                    or item["agentValidationObserved"] is not True
                    or item["oracle"]["passed"] is not True
                    or item["eventsCaptured"] is not True):
                raise RuntimeError(f"unaccepted leg: {path}: {condition}")
            commands[condition] = completed_commands(
                path.with_name(item["rawEventFile"]), item["rawEventSha256"])
        baseline, product = observations["baseline"], observations["product"]
        if (baseline["againStatsDelta"]["requested"] != 0
                or product["brainRun"] is None
                or product["brainRun"]["successful_tests"] < 1):
            raise RuntimeError(f"invalid product/baseline contrast: {path}")
        pair_baseline_cost = cost(baseline["usage"], rates)
        pair_product_cost = cost(product["usage"], rates)
        baseline_cost += pair_baseline_cost
        product_cost += pair_product_cost
        pairs.append({
            "report": path.name,
            "order": list(order),
            "baselineElapsedMs": baseline["elapsedMs"],
            "productElapsedMs": product["elapsedMs"],
            "productToBaselineElapsedRatio": product["elapsedMs"] / baseline["elapsedMs"],
            "baselineFirstEditMs": baseline["firstEditMs"],
            "productFirstEditMs": product["firstEditMs"],
            "baselineCommands": commands["baseline"],
            "productCommands": commands["product"],
            "baselineApiEquivalentUsd": str(pair_baseline_cost),
            "productApiEquivalentUsd": str(pair_product_cost),
        })
    if len(pairs) >= 2 and len(orders) != 2:
        raise RuntimeError("paired repeat must cover both treatment orders")
    summary = {
        "schema": "again.product-pair-summary.v1",
        "sourceSha": source_sha,
        "fixture": fixture,
        "model": card["model"],
        "acceptedPairs": len(pairs),
        "pairs": pairs,
        "pairedMedianElapsedRatio": statistics.median(
            pair["productToBaselineElapsedRatio"] for pair in pairs),
        "baselineCommands": sum(pair["baselineCommands"] for pair in pairs),
        "productCommands": sum(pair["productCommands"] for pair in pairs),
        "baselineApiEquivalentUsd": str(baseline_cost),
        "productApiEquivalentUsd": str(product_cost),
        "apiEquivalentCostRatio": float(product_cost / baseline_cost),
        "rateCard": card,
        "limitations": [
            "one historical repair fixture; not a diverse release cohort",
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
