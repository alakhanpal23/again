#!/usr/bin/env python3
"""Diagnostic MCP proxy exposing only task.start from an authenticated Again connection."""

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
    args = parser.parse_args()
    child = subprocess.Popen(
        [str(args.binary), "mcp", "connect", "--workspace", str(args.workspace)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr.buffer,
        bufsize=0,
    )
    assert child.stdin is not None and child.stdout is not None
    pending_lists: set[object] = set()
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
                elif request.get("method") == "tools/call" and request.get("params", {}).get("name") != "task.start":
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
            if listed and isinstance(response.get("result"), dict):
                tools = response["result"].get("tools", [])
                response["result"]["tools"] = [tool for tool in tools if tool.get("name") == "task.start"]
                frame = json.dumps(response, separators=(",", ":")).encode() + b"\n"
            write_client(frame)
    finally:
        child.terminate()
        child.wait(timeout=5)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
