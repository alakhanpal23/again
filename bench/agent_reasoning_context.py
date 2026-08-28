#!/usr/bin/env python3
"""Deterministic synthetic benchmark for bounded agent reasoning context."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MAX_FACTS = 64
MAX_RAW_BYTES_PER_FACT = 256 * 1024
MAX_TOTAL_RAW_BYTES = 16 * 1024 * 1024
MAX_ITERATIONS = 10_000


@dataclass(frozen=True)
class BenchmarkConfig:
    facts: int = 24
    raw_bytes_per_fact: int = 4096
    iterations: int = 100
    confirmed_delivery: bool = False

    def validate(self) -> None:
        if not 1 <= self.facts <= MAX_FACTS:
            raise ValueError(f"facts must be between 1 and {MAX_FACTS}")
        if not 1 <= self.raw_bytes_per_fact <= MAX_RAW_BYTES_PER_FACT:
            raise ValueError(
                "raw bytes per fact must be between 1 and "
                f"{MAX_RAW_BYTES_PER_FACT}"
            )
        if self.facts * self.raw_bytes_per_fact > MAX_TOTAL_RAW_BYTES:
            raise ValueError("total raw context bound exceeded")
        if not 1 <= self.iterations <= MAX_ITERATIONS:
            raise ValueError(f"iterations must be between 1 and {MAX_ITERATIONS}")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _raw_payload(index: int, size: int) -> str:
    prefix = f"verified-observation-{index:02d}:"
    repetitions = (size + len(prefix) - 1) // len(prefix)
    return (prefix * repetitions)[:size]


def build_contexts(config: BenchmarkConfig) -> tuple[bytes, bytes, bytes]:
    """Return raw history, full reasoning brief and compact reference bytes."""

    config.validate()
    raw_observations = []
    facts = []
    retrieval = []
    for index in range(config.facts):
        payload = _raw_payload(index, config.raw_bytes_per_fact)
        payload_bytes = payload.encode("utf-8")
        result_id = _digest(f"result-{index:02d}".encode("ascii"))
        result_digest = _digest(payload_bytes)
        raw_observations.append(
            {
                "command": ["repository-observation", f"subject-{index:02d}"],
                "exit_status": 0,
                "ordering": index,
                "stderr": "",
                "stdout": payload,
            }
        )
        facts.append(
            {
                "fact_id": f"fact-{index:02d}",
                "scope": "repository_wide",
                "sources": [
                    {
                        "locator": f"repository-file-{index:02d}:1",
                        "result_digest": result_digest,
                        "result_id": result_id,
                    }
                ],
                "statement": f"verified repository observation {index:02d} is current",
                "topic": f"subject-{index:02d}",
                "value_digest": result_digest,
            }
        )
        retrieval.append(
            {
                "result_digest": result_digest,
                "result_id": result_id,
                "total_bytes": len(payload_bytes),
            }
        )

    raw_context = _canonical_bytes(
        {
            "format": "raw-tool-history",
            "observations": raw_observations,
            "schema_version": 1,
        }
    )
    reasoning_brief = _canonical_bytes(
        {
            "authorization_scope": {"scope_digest": _digest(b"authorization")},
            "format": "again.reasoning-brief",
            "full_result_retrieval": retrieval,
            "repository": {
                "dependency_digest": _digest(b"dependencies"),
                "repository_id": "repository-01",
                "state_digest": _digest(b"state"),
                "verified_facts": facts,
                "workspace_id": "workspace-01",
            },
            "route_explanations": [
                {
                    "code": "shared_verified_fact",
                    "explanation": (
                        "verified observations match repository state, dependencies, "
                        "and authorization"
                    ),
                    "grants_reuse": False,
                }
            ],
            "schema_version": 1,
            "task": {"task_id": "task-01", "verified_facts": []},
        }
    )
    compact_reference = _canonical_bytes(
        {
            "brief_reference": (
                f"again-reasoning-v1:sha256:{_digest(reasoning_brief)}:"
                f"{len(reasoning_brief)}"
            ),
            "format": "again.reasoning-brief-reference",
            "full_result_retrieval": retrieval,
            "schema_version": 1,
        }
    )
    return raw_context, reasoning_brief, compact_reference


def benchmark(config: BenchmarkConfig) -> dict[str, Any]:
    config.validate()
    timings = []
    raw_context = reasoning_brief = compact_reference = b""
    for _ in range(config.iterations):
        started = time.perf_counter_ns()
        raw_context, reasoning_brief, compact_reference = build_contexts(config)
        timings.append(time.perf_counter_ns() - started)

    structural_omission = max(len(raw_context) - len(reasoning_brief), 0)
    confirmed_omission = 0
    delivered = reasoning_brief
    presentation = "full"
    if config.confirmed_delivery and len(compact_reference) < len(reasoning_brief):
        confirmed_omission = len(reasoning_brief) - len(compact_reference)
        delivered = compact_reference
        presentation = "compact_reference"

    return {
        "benchmark_version": 1,
        "confirmed_delivery": config.confirmed_delivery,
        "confirmed_tokens_avoided": confirmed_omission // 4,
        "context_bytes_delivered": len(delivered),
        "delivery_confirmed_bytes_omitted": confirmed_omission,
        "facts": config.facts,
        "iterations": config.iterations,
        "median_compile_ns": int(statistics.median(timings)),
        "presentation": presentation,
        "raw_bytes_per_fact": config.raw_bytes_per_fact,
        "raw_context_bytes": len(raw_context),
        "raw_context_sha256": _digest(raw_context),
        "reasoning_brief_bytes": len(reasoning_brief),
        "reasoning_brief_sha256": _digest(reasoning_brief),
        "structural_context_reduction_bytes": structural_omission,
        "structural_context_reduction_percent": round(
            (structural_omission * 100.0) / len(raw_context), 4
        ),
    }


def _write_no_overwrite(path: Path, payload: bytes) -> None:
    if not path.is_absolute():
        raise ValueError("output path must be absolute")
    if not path.parent.is_dir():
        raise ValueError("output parent must already exist")
    with path.open("xb") as output:
        output.write(payload)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--facts", type=int, default=24)
    parser.add_argument("--raw-bytes-per-fact", type=int, default=4096)
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--confirmed-delivery", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    config = BenchmarkConfig(
        facts=arguments.facts,
        raw_bytes_per_fact=arguments.raw_bytes_per_fact,
        iterations=arguments.iterations,
        confirmed_delivery=arguments.confirmed_delivery,
    )
    try:
        result = benchmark(config)
        payload = _canonical_bytes(result) + b"\n"
        if arguments.output is None:
            print(payload.decode("utf-8"), end="")
        else:
            _write_no_overwrite(arguments.output, payload)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
