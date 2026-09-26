#!/usr/bin/env python3
"""Diagnostic MCP proxy for task-start tool discovery and response-shape probes."""

from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import threading


MAX_FRAME_BYTES = 16 * 1024 * 1024


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=pathlib.Path, required=True)
    parser.add_argument("--workspace", type=pathlib.Path, required=True)
    parser.add_argument("--task-start-only", action="store_true")
    parser.add_argument("--compact-task-result", action="store_true")
    args = parser.parse_args()
    child = subprocess.Popen(
        [str(args.binary), "mcp", "connect", "--workspace", str(args.workspace)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.buffer,
        bufsize=0,
    )
    assert child.stdin is not None and child.stdout is not None
    pending_lists: set[object] = set()
    pending_task_starts: set[object] = set()
    lock = threading.Lock()
    output_lock = threading.Lock()

    def write_client(frame: bytes) -> None:
        with output_lock:
            sys.stdout.buffer.write(frame)
            sys.stdout.buffer.flush()

    def client_to_daemon() -> None:
        try:
            while frame := sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1):
                if len(frame) > MAX_FRAME_BYTES:
                    break
                try:
                    request = json.loads(frame)
                except json.JSONDecodeError:
                    break
                if request.get("method") == "tools/list":
                    with lock:
                        pending_lists.add(request.get("id"))
                elif request.get("method") == "tools/call" and request.get("params", {}).get("name") == "task.start":
                    with lock:
                        pending_task_starts.add(request.get("id"))
                elif args.task_start_only and request.get("method") == "tools/call":
                    refusal = {"jsonrpc": "2.0", "id": request.get("id"),
                               "error": {"code": -32601, "message": "tool not exposed by diagnostic surface"}}
                    write_client(json.dumps(refusal, separators=(",", ":")).encode() + b"\n")
                    continue
                child.stdin.write(frame)
                child.stdin.flush()
        finally:
            child.stdin.close()

    forward = threading.Thread(target=client_to_daemon, daemon=True)
    forward.start()
    try:
        while frame := child.stdout.readline(MAX_FRAME_BYTES + 1):
            if len(frame) > MAX_FRAME_BYTES:
                break
            try:
                response = json.loads(frame)
            except json.JSONDecodeError:
                break
            with lock:
                listed = response.get("id") in pending_lists
                if listed:
                    pending_lists.remove(response["id"])
                task_started = response.get("id") in pending_task_starts
                if task_started:
                    pending_task_starts.remove(response["id"])
            if listed and args.task_start_only and isinstance(response.get("result"), dict):
                tools = response["result"].get("tools", [])
                response["result"]["tools"] = [tool for tool in tools if tool.get("name") == "task.start"]
                frame = json.dumps(response, separators=(",", ":")).encode() + b"\n"
            if task_started and args.compact_task_result and isinstance(response.get("result"), dict):
                result = response["result"]
                structured = result.get("structuredContent")
                if isinstance(structured, dict):
                    summary = {
                        "taskId": structured.get("taskId"),
                        "presentation": structured.get("presentation"),
                        "coordination": (structured.get("coordination") or {}).get("status"),
                        "sourcePreviews": structured.get("sourcePreviews", []),
                        "validationPreview": structured.get("validationPreview"),
                        "fullStructuredResultAvailable": True,
                    }
                    context = structured.get("context") or {}
                    if context.get("current_facts") or context.get("result_references") or context.get("suggestions"):
                        summary["context"] = context
                    result["content"] = [{"type": "text", "text": json.dumps(summary, separators=(",", ":"))}]
                    frame = json.dumps(response, separators=(",", ":")).encode() + b"\n"
            write_client(frame)
    finally:
        child.terminate()
        child.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
