#!/usr/bin/env python3
"""Deterministic offline accounting benchmark for reasoning-context metrics."""

from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

MAX_FACTS = 64
MAX_RAW_BYTES_PER_FACT = 256 * 1024
MAX_PROVIDER_CALLS_AVOIDED = 1_000_000
MAX_CONFIRMED_DELIVERIES = 100_000
MAX_DUPLICATES_PER_DELIVERY = 32


@dataclass(frozen=True)
class MetricsBenchmarkConfig:
    facts: int = 24
    raw_bytes_per_fact: int = 4096
    provider_calls_avoided: int = 20
    provider_duration_ms: int = 75
    confirmed_deliveries: int = 12
    duplicate_receipts_per_delivery: int = 2
    authenticated_delivery: bool = False
    legacy_compact_events: int = 0

    def validate(self) -> None:
        if not 1 <= self.facts <= MAX_FACTS:
            raise ValueError(f"facts must be between 1 and {MAX_FACTS}")
        if not 1 <= self.raw_bytes_per_fact <= MAX_RAW_BYTES_PER_FACT:
            raise ValueError(
                "raw bytes per fact must be between 1 and "
                f"{MAX_RAW_BYTES_PER_FACT}"
            )
        if not 0 <= self.provider_calls_avoided <= MAX_PROVIDER_CALLS_AVOIDED:
            raise ValueError("provider calls avoided bound exceeded")
        if not 0 <= self.provider_duration_ms <= 24 * 60 * 60 * 1000:
            raise ValueError("provider duration bound exceeded")
        if not 0 <= self.confirmed_deliveries <= MAX_CONFIRMED_DELIVERIES:
            raise ValueError("confirmed deliveries bound exceeded")
        if not 1 <= self.duplicate_receipts_per_delivery <= MAX_DUPLICATES_PER_DELIVERY:
            raise ValueError("duplicate receipt bound exceeded")
        if not 0 <= self.legacy_compact_events <= MAX_CONFIRMED_DELIVERIES:
            raise ValueError("legacy compact event bound exceeded")


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _payload(index: int, size: int) -> str:
    unit = f"verified-fact-{index:02d}:"
    return (unit * ((size + len(unit) - 1) // len(unit)))[:size]


def build_presentations(config: MetricsBenchmarkConfig) -> tuple[bytes, bytes, bytes]:
    config.validate()
    raw_items = []
    facts = []
    retrieval = []
    for index in range(config.facts):
        payload = _payload(index, config.raw_bytes_per_fact)
        payload_bytes = payload.encode("utf-8")
        result_id = _digest(f"result-{index}".encode("ascii"))
        result_digest = _digest(payload_bytes)
        raw_items.append({"ordinal": index, "stdout": payload})
        facts.append(
            {
                "fact_id": f"fact-{index:02d}",
                "statement": f"verified fact {index:02d}",
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
    raw = _canonical_bytes({"format": "raw-tool-history", "items": raw_items})
    full = _canonical_bytes(
        {
            "facts": facts,
            "format": "again.reasoning-brief",
            "full_result_retrieval": retrieval,
            "schema_version": 1,
        }
    )
    compact = _canonical_bytes(
        {
            "brief_reference": f"again-reasoning-v1:sha256:{_digest(full)}:{len(full)}",
            "format": "again.reasoning-brief-reference",
            "full_result_retrieval": retrieval,
            "schema_version": 1,
        }
    )
    return raw, full, compact


def benchmark(config: MetricsBenchmarkConfig) -> dict[str, Any]:
    """Compute three deliberately independent measurement categories."""

    raw, full, compact = build_presentations(config)
    structural_reduction = max(len(raw) - len(full), 0)
    omission_per_delivery = max(len(full) - len(compact), 0)

    # Duplicate receipt rows share an immutable envelope digest, so they add
    # accounting work but never add a second confirmed delivery.
    unique_confirmed = config.confirmed_deliveries if config.authenticated_delivery else 0
    stored_receipt_rows = (
        config.confirmed_deliveries * config.duplicate_receipts_per_delivery
    )
    confirmed_omission = unique_confirmed * omission_per_delivery
    estimated_execution_saved = (
        config.provider_calls_avoided * config.provider_duration_ms
    )

    return {
        "accounting_operations": stored_receipt_rows + config.legacy_compact_events,
        "authenticated_delivery": config.authenticated_delivery,
        "benchmark_version": 1,
        "confirmed_tokens_avoided": unique_confirmed * (omission_per_delivery // 4),
        "delivery_confirmed_bytes_omitted": confirmed_omission,
        "delivery_confirmed_bytes_omitted_per_delivery": omission_per_delivery,
        "duplicate_receipt_rows": max(
            stored_receipt_rows - config.confirmed_deliveries, 0
        ),
        "estimated_execution_time_saved_ms": estimated_execution_saved,
        "full_reasoning_bytes": len(full),
        "full_reasoning_sha256": _digest(full),
        "legacy_compact_events_ignored": config.legacy_compact_events,
        "provider_calls_avoided": config.provider_calls_avoided,
        "raw_context_bytes": len(raw),
        "raw_context_sha256": _digest(raw),
        "stored_receipt_rows": stored_receipt_rows,
        "structural_context_reduction_bytes": structural_reduction,
        "unique_confirmed_deliveries": unique_confirmed,
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
    parser.add_argument("--provider-calls-avoided", type=int, default=20)
    parser.add_argument("--provider-duration-ms", type=int, default=75)
    parser.add_argument("--confirmed-deliveries", type=int, default=12)
    parser.add_argument("--duplicate-receipts-per-delivery", type=int, default=2)
    parser.add_argument("--authenticated-delivery", action="store_true")
    parser.add_argument("--legacy-compact-events", type=int, default=0)
    parser.add_argument("--output", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    arguments = parser.parse_args(argv)
    config = MetricsBenchmarkConfig(
        facts=arguments.facts,
        raw_bytes_per_fact=arguments.raw_bytes_per_fact,
        provider_calls_avoided=arguments.provider_calls_avoided,
        provider_duration_ms=arguments.provider_duration_ms,
        confirmed_deliveries=arguments.confirmed_deliveries,
        duplicate_receipts_per_delivery=arguments.duplicate_receipts_per_delivery,
        authenticated_delivery=arguments.authenticated_delivery,
        legacy_compact_events=arguments.legacy_compact_events,
    )
    try:
        payload = _canonical_bytes(benchmark(config)) + b"\n"
        if arguments.output is None:
            print(payload.decode("utf-8"), end="")
        else:
            _write_no_overwrite(arguments.output, payload)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
