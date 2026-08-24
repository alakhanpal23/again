#!/usr/bin/env python3
"""Reproducible lookup-bundle-v1 local Worker benchmark.

The default mode starts the dedicated benchmark Worker with Wrangler/workerd
and drives real loopback HTTP requests. Injected RTT is one bounded
response-start delay per HTTP request; it is not a packet-level network
emulator and it is never reported as Cloudflare edge performance.
"""

import argparse
import concurrent.futures
import contextlib
import datetime as dt
import hashlib
import http.client
import json
import math
import os
import pathlib
import platform
import socket
import ssl
import statistics
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


SCHEMA = "again.lookup-bundle-v1-performance.v1"
SCOPE_HEADER = "again-lookup-bundle-benchmark-fixture-v1"
CONTENT_TYPE = "application/vnd.again.lookup-bundle-v1"
MAGIC = b"AGNBNDL1"
HEADER_BYTES = 32
MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024
READ_CHUNK_BYTES = 64 * 1024
DEFAULT_SIZES = (0, 4 * 1024, 1024 * 1024, MAX_CIPHERTEXT_BYTES)
DEFAULT_RTTS_MS = (0, 20, 50, 100)


class BenchmarkError(RuntimeError):
    pass


def run_checked(argv: Sequence[str], cwd: pathlib.Path) -> str:
    result = subprocess.run(
        list(argv),
        cwd=str(cwd),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        raise BenchmarkError(
            "command failed: {}\n{}".format(" ".join(argv), result.stderr.strip())
        )
    return result.stdout.rstrip()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_csv_integers(value: str, maximum: int) -> Tuple[int, ...]:
    parsed: List[int] = []
    for raw in value.split(","):
        if not raw or not raw.isdigit():
            raise argparse.ArgumentTypeError("values must be comma-separated nonnegative integers")
        number = int(raw)
        if number > maximum:
            raise argparse.ArgumentTypeError("value {} exceeds {}".format(number, maximum))
        if number not in parsed:
            parsed.append(number)
    if not parsed:
        raise argparse.ArgumentTypeError("at least one value is required")
    return tuple(parsed)


def percentile(values: Sequence[float], fraction: float) -> float:
    if not values:
        raise BenchmarkError("cannot summarize an empty timing sequence")
    ordered = sorted(values)
    index = max(0, math.ceil(fraction * len(ordered)) - 1)
    return ordered[index]


def timing_summary(values: Sequence[float]) -> Dict[str, float]:
    return {
        "min_ms": min(values),
        "p50_ms": statistics.median(values),
        "p95_ms": percentile(values, 0.95),
        "max_ms": max(values),
        "mean_ms": statistics.fmean(values),
    }


def one_header(response: http.client.HTTPResponse, name: str) -> Optional[str]:
    values = [value for key, value in response.getheaders() if key.lower() == name.lower()]
    if len(values) > 1:
        raise BenchmarkError("duplicate {} response header".format(name))
    return values[0] if values else None


def read_exact(response: http.client.HTTPResponse, length: int) -> bytes:
    chunks: List[bytes] = []
    remaining = length
    while remaining:
        chunk = response.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise BenchmarkError("response truncated with {} bytes remaining".format(remaining))
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def hash_exact(response: http.client.HTTPResponse, length: int) -> str:
    digest = hashlib.sha256()
    remaining = length
    while remaining:
        chunk = response.read(min(READ_CHUNK_BYTES, remaining))
        if not chunk:
            raise BenchmarkError("response truncated with {} bytes remaining".format(remaining))
        digest.update(chunk)
        remaining -= len(chunk)
    return digest.hexdigest()


def require_eof(response: http.client.HTTPResponse) -> None:
    if response.read(1) != b"":
        raise BenchmarkError("response contains trailing bytes")


class BenchmarkConnection:
    def __init__(self, base_url: str, timeout_seconds: float = 60.0) -> None:
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise BenchmarkError("base URL must use http or https and include a host")
        self.scheme = parsed.scheme
        self.host = parsed.hostname
        self.port = parsed.port
        self.prefix = parsed.path.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.connection: Optional[http.client.HTTPConnection] = None

    def _new_connection(self) -> http.client.HTTPConnection:
        if self.scheme == "https":
            return http.client.HTTPSConnection(
                self.host,
                self.port,
                timeout=self.timeout_seconds,
                context=ssl.create_default_context(),
            )
        return http.client.HTTPConnection(self.host, self.port, timeout=self.timeout_seconds)

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None

    def request(
        self,
        method: str,
        path: str,
        consumer: Callable[[http.client.HTTPResponse], Any],
    ) -> Tuple[Any, float]:
        if self.connection is None:
            self.connection = self._new_connection()
        request_path = self.prefix + path
        started = time.perf_counter_ns()
        try:
            self.connection.request(
                method,
                request_path,
                headers={
                    "Accept-Encoding": "identity",
                    "Cache-Control": "no-store",
                    "User-Agent": "again-lookup-bundle-v1-benchmark/1",
                },
            )
            response = self.connection.getresponse()
            if response.status != 200:
                body = response.read(4096)
                raise BenchmarkError(
                    "{} {} returned {}: {!r}".format(method, path, response.status, body)
                )
            scope = one_header(response, "X-Again-Benchmark-Scope")
            if scope != SCOPE_HEADER:
                raise BenchmarkError("unexpected benchmark Worker scope header: {!r}".format(scope))
            value = consumer(response)
            elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
            return value, elapsed_ms
        except Exception:
            self.close()
            raise


def query_path(path: str, size: int, rtt_ms: int, **extra: Any) -> str:
    values: Dict[str, Any] = {"size": size, "rtt_ms": rtt_ms}
    values.update(extra)
    return path + "?" + urllib.parse.urlencode(values)


def consume_small(response: http.client.HTTPResponse, limit: int = 2 * 1024 * 1024) -> bytes:
    length_raw = one_header(response, "Content-Length")
    if length_raw is None or not length_raw.isdigit():
        raise BenchmarkError("small response lacks a decimal Content-Length")
    length = int(length_raw)
    if length > limit:
        raise BenchmarkError("small response exceeds {} bytes".format(limit))
    body = read_exact(response, length)
    require_eof(response)
    return body


def consume_known_stream(response: http.client.HTTPResponse, expected: int) -> Dict[str, Any]:
    length_raw = one_header(response, "Content-Length")
    if length_raw is None or not length_raw.isdigit() or int(length_raw) != expected:
        raise BenchmarkError(
            "stream Content-Length mismatch: expected {}, got {!r}".format(expected, length_raw)
        )
    digest = hash_exact(response, expected)
    require_eof(response)
    return {"bytes": expected, "sha256": digest}


def consume_bundle(response: http.client.HTTPResponse) -> Dict[str, Any]:
    if one_header(response, "Content-Type") != CONTENT_TYPE:
        raise BenchmarkError("bundle response has wrong Content-Type")
    header = read_exact(response, HEADER_BYTES)
    magic, version, flags, trust_len, manifest_len, stdout_len, stderr_len, reserved = struct.unpack(
        ">8sHHIIIII", header
    )
    if magic != MAGIC or version != 1 or flags != 0 or reserved != 0:
        raise BenchmarkError("bundle header is malformed")
    total = HEADER_BYTES + trust_len + manifest_len + stdout_len + stderr_len
    length_raw = one_header(response, "Content-Length")
    if length_raw is None or not length_raw.isdigit() or int(length_raw) != total:
        raise BenchmarkError("bundle Content-Length does not match checked framing")
    trust = read_exact(response, trust_len)
    manifest = read_exact(response, manifest_len)
    stdout_sha256 = hash_exact(response, stdout_len)
    stderr_sha256 = hash_exact(response, stderr_len)
    require_eof(response)
    return {
        "trust_hex": trust.hex(),
        "manifest_hex": manifest.hex(),
        "stdout": {"bytes": stdout_len, "sha256": stdout_sha256},
        "stderr": {"bytes": stderr_len, "sha256": stderr_sha256},
        "wire_bytes": total,
    }


def run_bundle(
    connection: BenchmarkConnection, size: int, rtt_ms: int, strategy: str
) -> Dict[str, Any]:
    started = time.perf_counter_ns()
    payload, payload_ms = connection.request(
        "GET", query_path("/bundle", size, rtt_ms, strategy=strategy), consume_bundle
    )
    final_trust, trust_ms = connection.request(
        "GET", query_path("/bundle/final-trust", size, rtt_ms), consume_small
    )
    total_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    return {
        "requests": 2,
        "total_ms": total_ms,
        "stages_ms": {"payload": payload_ms, "post_decrypt_trust": trust_ms},
        "payload": payload,
        "final_trust_hex": final_trust.hex(),
    }


def run_reference(connection: BenchmarkConnection, size: int, rtt_ms: int) -> Dict[str, Any]:
    started = time.perf_counter_ns()
    stages: Dict[str, float] = {}
    initial_trust, stages["initial_trust"] = connection.request(
        "GET", query_path("/reference/initial-trust", size, rtt_ms), consume_small
    )
    manifest, stages["manifest"] = connection.request(
        "GET", query_path("/reference/manifest", size, rtt_ms), consume_small
    )
    stdout, stages["stdout"] = connection.request(
        "GET",
        query_path("/reference/stdout", size, rtt_ms),
        lambda response: consume_known_stream(response, size),
    )
    stderr, stages["stderr"] = connection.request(
        "GET",
        query_path("/reference/stderr", size, rtt_ms),
        lambda response: consume_known_stream(response, size),
    )
    final_trust, stages["post_decrypt_trust"] = connection.request(
        "GET", query_path("/reference/final-trust", size, rtt_ms), consume_small
    )
    total_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    return {
        "requests": 5,
        "total_ms": total_ms,
        "stages_ms": stages,
        "initial_trust_hex": initial_trust.hex(),
        "manifest_hex": manifest.hex(),
        "stdout": stdout,
        "stderr": stderr,
        "final_trust_hex": final_trust.hex(),
    }


def assert_equivalent(bundle: Dict[str, Any], reference: Dict[str, Any], size: int) -> None:
    payload = bundle["payload"]
    comparisons = (
        (payload["trust_hex"], reference["initial_trust_hex"], "initial trust"),
        (payload["manifest_hex"], reference["manifest_hex"], "manifest"),
        (payload["stdout"], reference["stdout"], "stdout"),
        (payload["stderr"], reference["stderr"], "stderr"),
        (bundle["final_trust_hex"], reference["final_trust_hex"], "final trust"),
    )
    for left, right, name in comparisons:
        if left != right:
            raise BenchmarkError("bundle/reference {} mismatch".format(name))
    if payload["stdout"]["bytes"] != size or payload["stderr"]["bytes"] != size:
        raise BenchmarkError("bundle output size mismatch")


def raw_container() -> Dict[str, Any]:
    return {
        "bundle_total_ms": [],
        "reference_total_ms": [],
        "bundle_stages_ms": {"payload": [], "post_decrypt_trust": []},
        "reference_stages_ms": {
            "initial_trust": [],
            "manifest": [],
            "stdout": [],
            "stderr": [],
            "post_decrypt_trust": [],
        },
    }


def append_raw(raw: Dict[str, Any], bundle: Dict[str, Any], reference: Dict[str, Any]) -> None:
    raw["bundle_total_ms"].append(bundle["total_ms"])
    raw["reference_total_ms"].append(reference["total_ms"])
    for name, value in bundle["stages_ms"].items():
        raw["bundle_stages_ms"][name].append(value)
    for name, value in reference["stages_ms"].items():
        raw["reference_stages_ms"][name].append(value)


def summarize_raw(raw: Dict[str, Any]) -> Dict[str, Any]:
    reference = timing_summary(raw["reference_total_ms"])
    bundle = timing_summary(raw["bundle_total_ms"])
    improvement = (reference["p95_ms"] - bundle["p95_ms"]) / reference["p95_ms"] * 100.0
    return {
        "bundle_total": bundle,
        "reference_total": reference,
        "bundle_stages": {
            name: timing_summary(values) for name, values in raw["bundle_stages_ms"].items()
        },
        "reference_stages": {
            name: timing_summary(values)
            for name, values in raw["reference_stages_ms"].items()
        },
        "bundle_p95_improvement_percent": improvement,
    }


def fetch_json(connection: BenchmarkConnection, method: str, path: str) -> Dict[str, Any]:
    def perform() -> Tuple[Any, float]:
        return connection.request(
            method,
            path,
            lambda response: json.loads(
                consume_small(response, 1024 * 1024).decode("utf-8")
            ),
        )

    try:
        value, _ = perform()
    except (OSError, http.client.HTTPException):
        # This control connection can sit idle for minutes while the measured
        # protocol connections run. Only this metrics/control channel retries;
        # payload and final-trust requests remain exactly once.
        connection.close()
        value, _ = perform()
    if not isinstance(value, dict):
        raise BenchmarkError("expected JSON object from {}".format(path))
    return value


def reserve_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class LocalWorker:
    def __init__(self, repo: pathlib.Path, startup_timeout: float) -> None:
        self.repo = repo
        self.startup_timeout = startup_timeout
        self.process: Optional[subprocess.Popen] = None
        self.log_file: Optional[Any] = None
        self.log_path: Optional[pathlib.Path] = None
        self.port = reserve_port()
        self.base_url = "http://127.0.0.1:{}".format(self.port)
        self.command = [
            str(repo / "service" / "node_modules" / ".bin" / "wrangler"),
            "dev",
            "--config",
            str(repo / "bench" / "wrangler.lookup-bundle-bench.jsonc"),
            "--ip",
            "127.0.0.1",
            "--port",
            str(self.port),
            "--local",
            "--log-level",
            "error",
        ]

    def __enter__(self) -> "LocalWorker":
        descriptor, log_name = tempfile.mkstemp(prefix="again-lookup-bundle-wrangler-", suffix=".log")
        os.close(descriptor)
        self.log_path = pathlib.Path(log_name)
        self.log_file = self.log_path.open("w+")
        environment = dict(os.environ)
        environment.update({"CI": "1", "NO_COLOR": "1"})
        self.process = subprocess.Popen(
            self.command,
            cwd=str(self.repo),
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            text=True,
        )
        deadline = time.monotonic() + self.startup_timeout
        last_error: Optional[Exception] = None
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                break
            try:
                probe = BenchmarkConnection(self.base_url, timeout_seconds=1.0)
                try:
                    health = fetch_json(probe, "GET", "/health")
                finally:
                    probe.close()
                if health.get("ok") is True and health.get("scope") == SCOPE_HEADER:
                    return self
            except Exception as error:
                last_error = error
            time.sleep(0.1)
        log_tail = self._log_tail()
        raise BenchmarkError(
            "local Worker did not become ready: {}\n{}".format(last_error, log_tail)
        )

    def _log_tail(self) -> str:
        if self.log_file is None:
            return ""
        self.log_file.flush()
        self.log_file.seek(0)
        return self.log_file.read()[-8000:]

    @property
    def pid(self) -> Optional[int]:
        return self.process.pid if self.process is not None else None

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self.process is not None and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        if self.log_file is not None:
            self.log_file.close()
        if self.log_path is not None:
            try:
                self.log_path.unlink()
            except FileNotFoundError:
                pass


def process_tree_rss_kib(root_pid: int) -> Optional[int]:
    try:
        output = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,rss="],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        return None
    rows: Dict[int, Tuple[int, int]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) != 3:
            continue
        try:
            pid, ppid, rss = (int(value) for value in fields)
        except ValueError:
            continue
        rows[pid] = (ppid, rss)
    descendants = {root_pid}
    changed = True
    while changed:
        changed = False
        for pid, (ppid, _rss) in rows.items():
            if ppid in descendants and pid not in descendants:
                descendants.add(pid)
                changed = True
    if root_pid not in rows:
        return None
    return sum(rows[pid][1] for pid in descendants if pid in rows)


def concurrency_probe(
    base_url: str,
    admin: BenchmarkConnection,
    worker_pid: Optional[int],
    clients: int,
    strategy: str,
) -> Dict[str, Any]:
    fetch_json(admin, "POST", "/metrics/reset")
    baseline_rss = process_tree_rss_kib(worker_pid) if worker_pid is not None else None
    samples: List[int] = []
    sampling_done = threading.Event()

    def sample() -> None:
        while not sampling_done.is_set():
            if worker_pid is not None:
                value = process_tree_rss_kib(worker_pid)
                if value is not None:
                    samples.append(value)
            sampling_done.wait(0.05)

    sampler = threading.Thread(target=sample, name="again-rss-sampler", daemon=True)
    sampler.start()

    def one_client(_index: int) -> Dict[str, Any]:
        connection = BenchmarkConnection(base_url, timeout_seconds=120.0)
        try:
            payload, elapsed_ms = connection.request(
                "GET",
                query_path(
                    "/bundle",
                    MAX_CIPHERTEXT_BYTES,
                    0,
                    stream_barrier=clients,
                    chunk_delay_ms=0,
                    strategy=strategy,
                ),
                consume_bundle,
            )
            return {"elapsed_ms": elapsed_ms, "payload": payload}
        finally:
            connection.close()

    started = time.perf_counter_ns()
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=clients) as executor:
            observations = list(executor.map(one_client, range(clients)))
    finally:
        sampling_done.set()
        sampler.join(timeout=2)
    elapsed_ms = (time.perf_counter_ns() - started) / 1_000_000.0
    deadline = time.monotonic() + 5
    metrics: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        metrics = fetch_json(admin, "GET", "/metrics")
        if metrics.get("activeBundleResponses") == 0:
            break
        time.sleep(0.05)
    fingerprints = {
        (item["payload"]["stdout"]["sha256"], item["payload"]["stderr"]["sha256"])
        for item in observations
    }
    if len(fingerprints) != 1:
        raise BenchmarkError("concurrent maximum-size responses differ")
    peak_rss = max(samples) if samples else baseline_rss
    return {
        "clients": clients,
        "bundle_strategy": strategy,
        "ciphertext_bytes_per_stream": MAX_CIPHERTEXT_BYTES,
        "wire_bytes_per_response": observations[0]["payload"]["wire_bytes"],
        "elapsed_ms": elapsed_ms,
        "client_elapsed_ms": [item["elapsed_ms"] for item in observations],
        "all_responses_exact_and_equal": True,
        "worker_metrics": metrics,
        "process_tree_rss_observation": {
            "scope": "wrangler_and_descendant_processes_not_worker_isolate_heap",
            "baseline_kib": baseline_rss,
            "peak_kib": peak_rss,
            "peak_minus_baseline_kib": (
                peak_rss - baseline_rss
                if peak_rss is not None and baseline_rss is not None
                else None
            ),
            "samples": len(samples),
            "proves_cloudflare_128_mib_isolate_limit": False,
        },
    }


def cancellation_probe(
    base_url: str,
    admin: BenchmarkConnection,
    strategy: str,
    source_mode: str,
) -> Dict[str, Any]:
    fetch_json(admin, "POST", "/metrics/reset")
    connection = BenchmarkConnection(base_url, timeout_seconds=30.0)
    if connection.connection is None:
        connection.connection = connection._new_connection()
    pending_source = 1 if source_mode == "pending" else 0
    chunk_delay_ms = 0 if source_mode == "pending" else 2
    path = query_path(
        "/bundle",
        MAX_CIPHERTEXT_BYTES,
        0,
        chunk_delay_ms=chunk_delay_ms,
        pending_source=pending_source,
        strategy=strategy,
    )
    started = time.perf_counter_ns()
    connection.connection.request(
        "GET",
        path,
        headers={"Accept-Encoding": "identity", "Cache-Control": "no-store"},
    )
    response = connection.connection.getresponse()
    if response.status != 200 or one_header(response, "X-Again-Benchmark-Scope") != SCOPE_HEADER:
        raise BenchmarkError("cancellation probe did not reach benchmark bundle endpoint")
    if source_mode == "pending":
        header = read_exact(response, HEADER_BYTES)
        (
            _magic,
            _version,
            _flags,
            trust_len,
            manifest_len,
            _stdout_len,
            _stderr_len,
            _reserved,
        ) = struct.unpack(">8sHHIIIII", header)
        observed = header + read_exact(response, trust_len + manifest_len)
    else:
        observed = read_exact(response, HEADER_BYTES + 128 * 1024)
    reset_transport = False
    if connection.connection.sock is not None:
        try:
            connection.connection.sock.setsockopt(
                socket.SOL_SOCKET,
                socket.SO_LINGER,
                struct.pack("ii", 1, 0),
            )
            reset_transport = True
        except OSError:
            pass
    response.close()
    connection.close()
    disconnected_at = time.perf_counter_ns()
    deadline = time.monotonic() + 3
    metrics: Dict[str, Any] = {}
    while time.monotonic() < deadline:
        metrics = fetch_json(admin, "GET", "/metrics")
        if metrics.get("activeBundleResponses") == 0 and metrics.get("cancelledSources", 0) >= 2:
            break
        time.sleep(0.05)
    return {
        "requested_ciphertext_bytes_per_stream": MAX_CIPHERTEXT_BYTES,
        "bundle_strategy": strategy,
        "source_mode": source_mode,
        "bytes_read_before_disconnect": len(observed),
        "elapsed_to_disconnect_ms": (disconnected_at - started) / 1_000_000.0,
        "settled_after_disconnect_ms":
            (time.perf_counter_ns() - disconnected_at) / 1_000_000.0,
        "transport": (
            "actual_loopback_http_tcp_reset"
            if reset_transport
            else "actual_loopback_http_connection_close"
        ),
        "worker_metrics": metrics,
        "both_sources_cancelled": metrics.get("cancelledSources", 0) >= 2,
        "response_completed_or_cancelled": metrics.get("activeBundleResponses") == 0,
    }


def source_provenance(repo: pathlib.Path) -> Dict[str, Any]:
    dirty_lines = run_checked(["git", "status", "--porcelain"], repo).splitlines()
    paths = [line[3:] if len(line) > 3 else line for line in dirty_lines]
    return {
        "git_revision": run_checked(["git", "rev-parse", "HEAD"], repo),
        "git_dirty": bool(dirty_lines),
        "git_dirty_paths": paths,
        "files_sha256": {
            "harness": sha256_file(repo / "bench" / "lookup_bundle_v1_benchmark.py"),
            "worker": sha256_file(repo / "bench" / "lookup_bundle_worker.ts"),
            "wrangler_config": sha256_file(
                repo / "bench" / "wrangler.lookup-bundle-bench.jsonc"
            ),
            "bundle_encoder": sha256_file(repo / "service" / "src" / "lookup-bundle-v1.ts"),
        },
    }


def runtime_provenance(repo: pathlib.Path) -> Dict[str, Any]:
    return {
        "host": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": sys.version,
        "node": run_checked(["node", "--version"], repo),
        "wrangler": run_checked(
            [str(repo / "service" / "node_modules" / ".bin" / "wrangler"), "--version"],
            repo,
        ),
    }


def expected_server_requests(combinations: int, repetitions: int, warmups: int) -> Dict[str, int]:
    each = combinations * (repetitions + warmups)
    return {
        "bundle": each,
        "bundle_final_trust": each,
        "reference_initial_trust": each,
        "reference_manifest": each,
        "reference_stdout": each,
        "reference_stderr": each,
        "reference_final_trust": each,
    }


def run_matrix(
    base_url: str,
    admin: BenchmarkConnection,
    sizes: Sequence[int],
    rtts_ms: Sequence[int],
    repetitions: int,
    warmups: int,
    strategy: str,
    checkpoint: Optional[Callable[[Sequence[Dict[str, Any]]], None]] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    fetch_json(admin, "POST", "/metrics/reset")
    bundle_connection = BenchmarkConnection(base_url, timeout_seconds=120.0)
    reference_connection = BenchmarkConnection(base_url, timeout_seconds=120.0)
    matrix: List[Dict[str, Any]] = []
    try:
        combination_index = 0
        for size in sizes:
            for rtt_ms in rtts_ms:
                raw = raw_container()
                fingerprint: Optional[Dict[str, Any]] = None
                for iteration in range(warmups + repetitions):
                    if (iteration + combination_index) % 2 == 0:
                        reference = run_reference(reference_connection, size, rtt_ms)
                        bundle = run_bundle(bundle_connection, size, rtt_ms, strategy)
                    else:
                        bundle = run_bundle(bundle_connection, size, rtt_ms, strategy)
                        reference = run_reference(reference_connection, size, rtt_ms)
                    assert_equivalent(bundle, reference, size)
                    if fingerprint is None:
                        fingerprint = {
                            "trust_sha256": hashlib.sha256(
                                bytes.fromhex(reference["initial_trust_hex"])
                            ).hexdigest(),
                            "manifest_sha256": hashlib.sha256(
                                bytes.fromhex(reference["manifest_hex"])
                            ).hexdigest(),
                            "stdout_sha256": reference["stdout"]["sha256"],
                            "stderr_sha256": reference["stderr"]["sha256"],
                            "exact_bytes_equal": True,
                        }
                    if iteration >= warmups:
                        append_raw(raw, bundle, reference)
                summary = summarize_raw(raw)
                matrix.append(
                    {
                        "ciphertext_bytes_per_stream": size,
                        "total_ciphertext_bytes": size * 2,
                        "injected_response_start_delay_per_request_ms": rtt_ms,
                        "repetitions": repetitions,
                        "warmups": warmups,
                        "measured_request_counts": {
                            "bundle_per_repetition": 2,
                            "reference_per_repetition": 5,
                            "bundle_total": repetitions * 2,
                            "reference_total": repetitions * 5,
                        },
                        "fingerprint": fingerprint,
                        "summary": summary,
                        "raw": raw,
                    }
                )
                print(
                    "size={} rtt={}ms bundle_p95={:.3f}ms reference_p95={:.3f}ms improvement={:.2f}%".format(
                        size,
                        rtt_ms,
                        summary["bundle_total"]["p95_ms"],
                        summary["reference_total"]["p95_ms"],
                        summary["bundle_p95_improvement_percent"],
                    ),
                    flush=True,
                )
                if checkpoint is not None:
                    checkpoint(matrix)
                combination_index += 1
    finally:
        bundle_connection.close()
        reference_connection.close()
    metrics = fetch_json(admin, "GET", "/metrics")
    return matrix, metrics


def evaluate_gates(
    matrix: Sequence[Dict[str, Any]],
    matrix_metrics: Dict[str, Any],
    expected_requests: Dict[str, int],
    concurrency: Dict[str, Any],
    cancellation: Dict[str, Any],
    repetitions: int,
    sizes: Sequence[int],
    rtts_ms: Sequence[int],
) -> Dict[str, Any]:
    rtt_50_rows = [
        row for row in matrix if row["injected_response_start_delay_per_request_ms"] == 50
    ]
    latency_applicable = 50 in rtts_ms
    latency_pass = latency_applicable and len(rtt_50_rows) == len(sizes) and all(
        row["summary"]["bundle_p95_improvement_percent"] >= 40.0 for row in rtt_50_rows
    )
    requests_pass = matrix_metrics.get("requests") == expected_requests
    repetitions_pass = repetitions >= 100
    concurrency_pass, cancellation_pass = probe_gate_results(concurrency, cancellation)
    strategy_safe = (
        cancellation.get("source_mode") == "pending" and cancellation_pass
    )
    local_pass = all(
        (
            repetitions_pass,
            requests_pass,
            latency_pass,
            concurrency_pass,
            cancellation_pass,
            strategy_safe,
        )
    )
    return {
        "local_correctness": {"pass": True, "basis": "all measured responses exact"},
        "minimum_100_repetitions": {"pass": repetitions_pass, "observed": repetitions},
        "exact_two_vs_five_requests": {
            "pass": requests_pass,
            "expected_server_requests": expected_requests,
            "observed_server_requests": matrix_metrics.get("requests"),
        },
        "p95_at_least_40_percent_better_at_50ms_each_size": {
            "applicable": latency_applicable,
            "pass": latency_pass,
            "observations": [
                {
                    "ciphertext_bytes_per_stream": row["ciphertext_bytes_per_stream"],
                    "improvement_percent": row["summary"][
                        "bundle_p95_improvement_percent"
                    ],
                }
                for row in rtt_50_rows
            ],
        },
        "four_concurrent_maximum_streams": {"pass": concurrency_pass},
        "actual_http_disconnect_cancels_both_sources": {"pass": cancellation_pass},
        "strategy_safe_for_pending_reads": {
            "pass": strategy_safe,
            "reason": (
                "strategy proved an explicit pending-read cancellation channel"
                if strategy_safe
                else "strategy did not cancel both indefinitely pending sources in local workerd"
            ),
        },
        "local_enforceable_gates_pass": local_pass,
        "ship_gate_status": "incomplete",
        "ship_gate_missing_evidence": [
            "100000 generated bundle/reference disposition-and-byte comparisons",
            "live public-CA HTTPS tunnel performance matrix",
            "direct Cloudflare isolate heap proof below 128 MiB",
            "live stateful zero-stale-hit proof; this fixture is immutable",
        ],
    }


def probe_gate_results(
    concurrency: Dict[str, Any], cancellation: Dict[str, Any]
) -> Tuple[bool, bool]:
    concurrency_metrics = concurrency.get("worker_metrics", {})
    concurrency_pass = (
        concurrency.get("clients") == 4
        and concurrency.get("all_responses_exact_and_equal") is True
        and concurrency_metrics.get("peakActiveBundleResponses", 0) >= 4
        and concurrency_metrics.get("peakStreamingBundleResponses", 0) >= 4
        and concurrency_metrics.get("streamStartedBundleResponses") == 4
        and concurrency_metrics.get("streamBarrierExpectedResponses") == 4
        and concurrency_metrics.get("streamBarrierArrivedResponses") == 4
        and concurrency_metrics.get("streamBarrierReleased") is True
        and concurrency_metrics.get("streamBarrierReleaseActiveSources", 0) >= 8
        and concurrency_metrics.get("streamBarrierReleaseConstructedSources", 0) >= 8
        and concurrency_metrics.get("activeBundleResponses") == 0
        and concurrency_metrics.get("streamingBundleResponses") == 0
        and concurrency_metrics.get("activeCiphertextSources") == 0
        and concurrency_metrics.get("largestGeneratedChunkBytes", MAX_CIPHERTEXT_BYTES + 1)
        <= READ_CHUNK_BYTES
    )
    cancellation_metrics = cancellation.get("worker_metrics", {})
    direct_writer_signal_pass = (
        cancellation.get("bundle_strategy") != "direct"
        or (
            cancellation_metrics.get("directWriterClosedRejectedSignals", 0) >= 1
            and cancellation_metrics.get("directWriterClosedLastSignalDelayMs") is not None
        )
    )
    request_signal_pass = (
        cancellation.get("bundle_strategy") != "direct_signal"
        or cancellation_metrics.get("requestSignalAbortSignals", 0) >= 1
    )
    cancellation_pass = (
        cancellation.get("both_sources_cancelled") is True
        and cancellation.get("response_completed_or_cancelled") is True
        and cancellation_metrics.get("activeCiphertextSources") == 0
        and cancellation.get("settled_after_disconnect_ms", 1_001) <= 1_000
        and direct_writer_signal_pass
        and request_signal_pass
    )
    return concurrency_pass, cancellation_pass


def evaluate_probe_gates(
    concurrency: Dict[str, Any], cancellation: Dict[str, Any]
) -> Dict[str, Any]:
    concurrency_pass, cancellation_pass = probe_gate_results(concurrency, cancellation)
    strategy_safe = (
        cancellation.get("source_mode") == "pending" and cancellation_pass
    )
    return {
        "four_concurrent_maximum_streams": {"pass": concurrency_pass},
        "actual_http_disconnect_cancels_both_sources": {"pass": cancellation_pass},
        "direct_writer_closed_rejection_observed": {
            "applicable": cancellation.get("bundle_strategy") == "direct",
            "pass": (
                cancellation.get("bundle_strategy") != "direct"
                or cancellation.get("worker_metrics", {}).get(
                    "directWriterClosedRejectedSignals", 0
                )
                >= 1
            ),
        },
        "incoming_request_signal_abort_observed": {
            "applicable": cancellation.get("bundle_strategy") == "direct_signal",
            "pass": (
                cancellation.get("bundle_strategy") != "direct_signal"
                or cancellation.get("worker_metrics", {}).get(
                    "requestSignalAbortSignals", 0
                )
                >= 1
            ),
        },
        "strategy_safe_for_pending_reads": {
            "pass": strategy_safe,
            "reason": (
                "strategy proved an explicit pending-read cancellation channel"
                if strategy_safe
                else "strategy did not cancel both indefinitely pending sources in local workerd"
            ),
        },
        "local_enforceable_gates_pass": concurrency_pass and cancellation_pass and strategy_safe,
        "ship_gate_status": "incomplete",
        "ship_gate_missing_evidence": [
            "the complete 100-repetition size/RTT performance matrix",
            "100000 generated bundle/reference disposition-and-byte comparisons",
            "live public-CA HTTPS tunnel performance matrix",
            "direct Cloudflare isolate heap proof below 128 MiB",
            "live stateful zero-stale-hit proof; this fixture is immutable",
        ],
    }


def write_json_new(path: pathlib.Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")


def write_json_atomic(path: pathlib.Path, value: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    temporary = pathlib.Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(str(temporary), str(path))
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repetitions", type=int, default=100)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument(
        "--sizes",
        type=lambda value: parse_csv_integers(value, MAX_CIPHERTEXT_BYTES),
        default=DEFAULT_SIZES,
        help="ciphertext bytes per stdout/stderr stream",
    )
    parser.add_argument(
        "--rtts-ms",
        type=lambda value: parse_csv_integers(value, 1000),
        default=DEFAULT_RTTS_MS,
        help="one injected response-start delay per request",
    )
    parser.add_argument("--json-out", type=pathlib.Path)
    parser.add_argument("--base-url", help="use a caller-managed compatible benchmark Worker")
    parser.add_argument("--worker-startup-timeout", type=float, default=30.0)
    parser.add_argument(
        "--bundle-strategy",
        choices=("bridge", "direct", "direct_signal"),
        default="bridge",
        help="bridge is production; direct is rejected; direct_signal tests Request.signal",
    )
    parser.add_argument(
        "--probes-only",
        action="store_true",
        help="run only cancellation and true four-response stream-overlap probes",
    )
    parser.add_argument(
        "--cancellation-source",
        choices=("finite", "pending"),
        default="pending",
        help="pending is the ship boundary; finite is a weaker diagnostic",
    )
    parser.add_argument("--enforce-local-gates", action="store_true")
    arguments = parser.parse_args(argv)
    if arguments.repetitions <= 0 or arguments.warmups < 0:
        parser.error("repetitions must be positive and warmups nonnegative")
    return arguments


def main(argv: Sequence[str]) -> int:
    args = parse_args(argv)
    repo = pathlib.Path(__file__).resolve().parents[1]
    output_path: Optional[pathlib.Path] = None
    if args.json_out is not None:
        output_path = args.json_out
        if not output_path.is_absolute():
            output_path = repo / output_path
        if output_path.exists():
            raise BenchmarkError("refusing to overwrite {}".format(output_path))
    checkpoint_path: Optional[pathlib.Path] = None
    if output_path is not None and not args.probes_only:
        checkpoint_path = pathlib.Path(str(output_path) + ".partial")
        if checkpoint_path.exists():
            raise BenchmarkError(
                "refusing to overwrite incomplete checkpoint {}".format(checkpoint_path)
            )
    source = source_provenance(repo)
    runtime = runtime_provenance(repo)
    worker_context: Any
    if args.base_url:
        worker_context = contextlib.nullcontext(None)
        base_url = args.base_url.rstrip("/")
        execution_scope = {
            "kind": "caller_managed_endpoint",
            "base_url": base_url,
            "claim": "compatible endpoint transport only; deployment provenance not inferred",
        }
    else:
        worker_context = LocalWorker(repo, args.worker_startup_timeout)
        base_url = ""
        execution_scope = {
            "kind": "local_wrangler_workerd_loopback_http",
            "claim": "local protocol benchmark, not Cloudflare edge or public-network performance",
            "rtt_injection": "one response-start delay inside the Worker per HTTP request",
            "packet_level_network_emulation": False,
        }
    with worker_context as worker:
        if worker is not None:
            base_url = worker.base_url
            execution_scope["launch_command"] = worker.command
        admin = BenchmarkConnection(base_url, timeout_seconds=30.0)
        try:
            health = fetch_json(admin, "GET", "/health")
            if health.get("scope") != SCOPE_HEADER:
                raise BenchmarkError("benchmark Worker health scope mismatch")
            matrix: List[Dict[str, Any]] = []
            matrix_metrics: Dict[str, Any] = {}
            if not args.probes_only:
                def checkpoint(rows: Sequence[Dict[str, Any]]) -> None:
                    if checkpoint_path is None:
                        return
                    write_json_atomic(
                        checkpoint_path,
                        {
                            "schema": SCHEMA + ".partial",
                            "source": source,
                            "runtime": runtime,
                            "execution_scope": execution_scope,
                            "workload": {
                                "ciphertext_bytes_per_stream": list(args.sizes),
                                "injected_response_start_delay_per_request_ms": list(
                                    args.rtts_ms
                                ),
                                "repetitions": args.repetitions,
                                "warmups": args.warmups,
                                "bundle_strategy": args.bundle_strategy,
                            },
                            "completed_matrix_cells": list(rows),
                        },
                    )

                matrix, matrix_metrics = run_matrix(
                    base_url,
                    admin,
                    args.sizes,
                    args.rtts_ms,
                    args.repetitions,
                    args.warmups,
                    args.bundle_strategy,
                    checkpoint,
                )
            concurrency = concurrency_probe(
                base_url,
                admin,
                worker.pid if worker is not None else None,
                4,
                args.bundle_strategy,
            )
            cancellation = cancellation_probe(
                base_url,
                admin,
                args.bundle_strategy,
                args.cancellation_source,
            )
        finally:
            admin.close()
        combinations = len(args.sizes) * len(args.rtts_ms)
        expected_requests = expected_server_requests(
            combinations, args.repetitions, args.warmups
        )
        if args.probes_only:
            gates = evaluate_probe_gates(concurrency, cancellation)
        else:
            gates = evaluate_gates(
                matrix,
                matrix_metrics,
                expected_requests,
                concurrency,
                cancellation,
                args.repetitions,
                args.sizes,
                args.rtts_ms,
            )
        result = {
            "schema": SCHEMA,
            "mode": "probes_only" if args.probes_only else "matrix_and_probes",
            "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source": source,
            "runtime": runtime,
            "execution_scope": execution_scope,
            "workload": {
                "ciphertext_bytes_per_stream": list(args.sizes),
                "injected_response_start_delay_per_request_ms": list(args.rtts_ms),
                "repetitions": args.repetitions,
                "warmups": args.warmups,
                "bundle_requests_per_repetition": 2,
                "reference_requests_per_repetition": 5,
                "streaming_chunk_bytes": READ_CHUNK_BYTES,
                "bundle_strategy": args.bundle_strategy,
                "cancellation_source": args.cancellation_source,
            },
            "matrix": matrix,
            "matrix_worker_metrics": matrix_metrics,
            "concurrency": concurrency,
            "cancellation": cancellation,
            "gates": gates,
            "limitations": [
                "Injected delay is a deterministic response-start delay, not packet-level RTT emulation.",
                "The dedicated Worker uses immutable deterministic bytes and does not exercise D1/R2 state transitions.",
                "Process-tree RSS includes Wrangler and descendants and cannot prove isolate heap usage.",
                "No command, agent, token, or cost speedup follows from this protocol-only benchmark.",
                "The direct strategy is a rejected experiment: writer.closed does not settle while an upstream read remains indefinitely pending.",
                "The direct_signal strategy is experimental and requires the enable_request_signal Workers compatibility flag.",
            ],
        }
        if output_path is not None:
            write_json_new(output_path, result)
            print("wrote {}".format(output_path), flush=True)
            if checkpoint_path is not None:
                checkpoint_path.unlink()
        else:
            json.dump(result, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        if args.enforce_local_gates and not gates["local_enforceable_gates_pass"]:
            return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BenchmarkError as error:
        print("benchmark error: {}".format(error), file=sys.stderr)
        raise SystemExit(2)
