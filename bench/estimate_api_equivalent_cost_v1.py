#!/usr/bin/env python3
"""Estimate API-equivalent token cost for a source-bound accepted cohort.

This is a rate-card comparison, not the user's actual Codex invoice.
"""

from __future__ import annotations

import argparse
import decimal
import json
import pathlib
import statistics


DECIMAL = decimal.Decimal
MILLION = DECIMAL(1_000_000)


def cost(usage: dict, rates: dict[str, decimal.Decimal]) -> decimal.Decimal:
    total = usage["input_tokens"]
    cached = usage["cached_input_tokens"]
    written = usage.get("cache_write_input_tokens", 0)
    output = usage["output_tokens"]
    if any(not isinstance(value, int) or value < 0 for value in (total, cached, written, output)):
        raise RuntimeError("missing or invalid provider token usage")
    if cached + written > total:
        raise RuntimeError("cached and written tokens exceed input total")
    uncached = total - cached - written
    return (
        uncached * rates["uncachedInput"]
        + cached * rates["cachedInput"]
        + written * rates["cacheWriteInput"]
        + output * rates["output"]
    ) / MILLION


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort-dir", type=pathlib.Path, required=True)
    parser.add_argument("--rate-card", type=pathlib.Path, required=True)
    parser.add_argument("--output", type=pathlib.Path, required=True)
    args = parser.parse_args()
    summary = json.loads((args.cohort_dir / "summary.json").read_text())
    card = json.loads(args.rate_card.read_text())
    if summary["model"] != card["model"] or summary["acceptedPairs"] != summary["totalPairs"]:
        raise RuntimeError("model or accepted-task cohort does not match the rate card")
    if summary.get("source", {}).get("binarySourceBindingVerified") is not True:
        raise RuntimeError("cohort binary/source binding is not verified")
    rates = {key: DECIMAL(value) for key, value in card["usdPerMillionTokens"].items()}
    totals = {"baseline": DECIMAL(0), "product": DECIMAL(0)}
    paired_ratios = []
    for case in summary["pairs"]:
        name = f"{case['fixture']}-{case['sourceFiles']}-{'baseline-first' if case['order'][0] == 'baseline' else 'again-first'}.json"
        report = json.loads((args.cohort_dir / name).read_text())
        if not report["accepted"] or report["source"]["binarySourceBindingVerified"] is not True:
            raise RuntimeError(f"unaccepted or unbound pair: {name}")
        by_condition = {item["condition"]: item for item in report["observations"]}
        baseline = cost(by_condition["baseline"]["usage"], rates)
        product = cost(by_condition["product"]["usage"], rates)
        totals["baseline"] += baseline
        totals["product"] += product
        paired_ratios.append(product / baseline)
    ratio = totals["product"] / totals["baseline"]
    result = {
        "schema": "again.api-equivalent-cohort-cost.v1",
        "model": card["model"],
        "sourceSha": summary["source"]["head"],
        "binarySha256": summary["binarySha256"],
        "acceptedTasksPerCondition": summary["totalPairs"],
        "rateCard": card,
        "estimatedBaselineUsd": str(totals["baseline"].quantize(DECIMAL("0.000001"))),
        "estimatedAgainUsd": str(totals["product"].quantize(DECIMAL("0.000001"))),
        "againToBaselineRatio": float(ratio),
        "pairedMedianCostRatio": float(statistics.median(paired_ratios)),
        "limitations": [
            "API-equivalent estimate, not measured Codex charges or subscription economics",
            "assumes Standard short-context text pricing for every model request",
            "excludes tool fees, regional premiums, tax, and developer time",
        ],
    }
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"estimatedAgainUsd": result["estimatedAgainUsd"],
                      "againToBaselineRatio": result["againToBaselineRatio"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
