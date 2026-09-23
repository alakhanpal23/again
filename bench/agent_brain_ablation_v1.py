#!/usr/bin/env python3
"""Compare the same Again launcher with and without a verified prior Brain read."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import tempfile

import agent_gateway_codex_pair_diagnostic_v1 as pair_harness
import agent_gateway_editable_pair as fixture
from agent_gateway_codex_live_probe_v1 import sha256, source_state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--model", default="gpt-6-sol")
    parser.add_argument("--fixture", choices=("balance-helper", "balance-helper-large"), default="balance-helper")
    parser.add_argument("--source-files", type=int, choices=(0, 1000), required=True)
    parser.add_argument("--prior-brain-decoys", type=int, default=0)
    parser.add_argument("--order", choices=("cold-first", "seeded-first"), required=True)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    if not 0 <= args.prior_brain_decoys <= args.source_files:
        parser.error("--prior-brain-decoys must fit within --source-files")
    root = pathlib.Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.is_relative_to(root):
        parser.error("write diagnostic output outside the source tree")
    pair_harness.configure_fixture(args.fixture)
    order = ("product-cold", "product") if args.order == "cold-first" else ("product", "product-cold")
    observations = []
    output.parent.mkdir(parents=True, exist_ok=True)
    for condition in order:
        with tempfile.TemporaryDirectory(prefix=f"again-brain-ablation-{condition}-") as temporary:
            result, raw = pair_harness.run_condition(
                condition, pathlib.Path(temporary), binary, args.model,
                f"{args.fixture}-ablation", args.source_files,
                seed_brain=True, brain_decoys=args.prior_brain_decoys,
            )
        raw_path = output.with_name(output.stem + f"-{condition}.jsonl")
        raw_path.write_bytes(raw)
        result["rawEventFile"] = raw_path.name
        observations.append(result)
    by_condition = {item["condition"]: item for item in observations}
    cold, seeded = by_condition["product-cold"], by_condition["product"]
    accepted = all(
        item["exitCode"] == 0 and not item["timedOut"]
        and item["eventsCaptured"] and item["oracle"]["passed"]
        for item in observations
    ) and cold["priorBrain"] is None and seeded["priorBrain"] is not None
    report = {
        "schema": "again.brain-ablation.v1",
        "recordedAtUtc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "evidenceScope": "one local same-launcher ablation pair",
        "source": source_state(root),
        "binarySha256": sha256(binary),
        "harnessSha256": sha256(pathlib.Path(__file__)),
        "pairHarnessSha256": sha256(pathlib.Path(pair_harness.__file__)),
        "model": args.model,
        "fixture": args.fixture,
        "fixtureSha256": hashlib.sha256(fixture.canonical_bytes(fixture.FIXTURE)).hexdigest(),
        "promptSha256": hashlib.sha256(fixture.PROMPT.encode()).hexdigest(),
        "sourceFiles": args.source_files,
        "priorBrainDecoys": args.prior_brain_decoys,
        "order": list(order),
        "accepted": accepted,
        "seededOverColdElapsedRatio": seeded["elapsedMs"] / cold["elapsedMs"] if accepted else None,
        "observations": observations,
    }
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"accepted": accepted, "seededOverColdElapsedRatio": report["seededOverColdElapsedRatio"],
                      "output": str(output)}))
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
