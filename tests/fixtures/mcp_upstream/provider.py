#!/usr/bin/env python3
"""Deterministic local MCP fixture; never opens the network."""

import json
import os
import subprocess
import sys
import time


def send(value):
    sys.stdout.write(json.dumps(value, separators=(",", ":"), sort_keys=True) + "\n")
    sys.stdout.flush()


def response(request_id, result):
    send({"id": request_id, "jsonrpc": "2.0", "result": result})


def main():
    mode = os.environ.get("FIXTURE_MODE", "normal")
    for line in sys.stdin:
        request = json.loads(line)
        method = request.get("method")
        request_id = request.get("id")
        if method == "initialize":
            response(
                request_id,
                {
                    "capabilities": {"tools": {"listChanged": False}},
                    "protocolVersion": "2025-06-18",
                    "serverInfo": {"name": "again-test-upstream", "version": "1"},
                },
            )
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            response(
                request_id,
                {
                    "tools": [
                        {
                            "annotations": {"readOnlyHint": True},
                            "description": "Local bounded echo fixture",
                            "inputSchema": {
                                "additionalProperties": False,
                                "properties": {"value": {}},
                                "type": "object",
                            },
                            "name": "echo",
                        }
                    ]
                },
            )
        elif method == "notifications/cancelled":
            continue
        elif method == "tools/call":
            arguments = request.get("params", {}).get("arguments", {})
            if mode == "malformed":
                sys.stdout.write('{"jsonrpc":"2.0","id":2,"result":{},"result":{}}\n')
                sys.stdout.flush()
                continue
            if mode == "wrong_id":
                response(987654, {"content": []})
                continue
            if mode == "oversized":
                response(request_id, {"content": [{"text": "x" * 200000, "type": "text"}]})
                continue
            if mode == "crash":
                os._exit(19)
            if mode == "hang_descendant":
                child = subprocess.Popen(
                    [sys.executable, "-c", "import time; time.sleep(60)"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                with open(os.environ["PID_FILE"], "w", encoding="ascii") as output:
                    output.write(str(child.pid))
                time.sleep(60)
                continue
            if mode == "notification_flood":
                for index in range(5000):
                    send(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/progress",
                            "params": {"progress": index, "progressToken": "flood"},
                        }
                    )
                continue
            if mode == "notifications":
                for index in range(8):
                    send(
                        {
                            "jsonrpc": "2.0",
                            "method": "notifications/progress",
                            "params": {"progress": index, "progressToken": "fixture"},
                        }
                    )
            response(
                request_id,
                {
                    "content": [
                        {
                            "text": json.dumps(arguments, separators=(",", ":"), sort_keys=True),
                            "type": "text",
                        }
                    ],
                    "structuredContent": {
                        "credentialPresent": bool(os.environ.get("FIXTURE_TOKEN")),
                        "value": arguments.get("value"),
                    },
                },
            )


if __name__ == "__main__":
    main()
