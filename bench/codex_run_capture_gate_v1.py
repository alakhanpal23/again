#!/usr/bin/env python3
"""Replay the failed Rust run and prove Codex capture failures reach the caller."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

import agent_gateway_codex_pair_diagnostic_v1 as harness
import agent_gateway_editable_pair as pair
from agent_gateway_codex_live_probe_v1 import sha256, source_state


ROOT = pathlib.Path(__file__).resolve().parents[1]
TRACE = ROOT / 'bench/results/2026-09-24-diverse-real-cohort-bb44f50/historical-search-unlocated-returning-again-first-product-repair.jsonl'


def raw_usage_and_commands(raw: bytes) -> tuple[dict, int]:
    events = [json.loads(line) for line in raw.splitlines()]
    completed = [event for event in events if event.get('type') == 'turn.completed']
    commands = [event for event in events if event.get('type') == 'item.completed'
                and event.get('item', {}).get('type') == 'command_execution'
                and isinstance(event['item'].get('exit_code'), int)]
    if len(completed) != 1 or not commands:
        raise RuntimeError('pinned Rust trace lacks its completed turn or commands')
    return completed[0]['usage'], len(commands)


def launch(binary: pathlib.Path, root: pathlib.Path, scenario: str,
           script_body: str, *, historical: bool = False,
           inspect_brain: bool = True) -> tuple[subprocess.CompletedProcess, dict | None]:
    workspace = root / scenario / 'repo'
    workspace.mkdir(parents=True)
    if historical:
        harness.configure_fixture('historical-search-unlocated')
        pair.create_fixture(workspace)
    else:
        (workspace / 'README.md').write_text('# Codex capture gate\n')
        subprocess.run(['git', 'init', '-q', str(workspace)], check=True)
    fake_bin = root / scenario / 'bin'
    fake_bin.mkdir()
    fake = fake_bin / 'codex'
    fake.write_text('#!/usr/bin/env python3\n' + script_body)
    fake.chmod(0o700)
    environment = os.environ.copy()
    environment['PATH'] = str(fake_bin) + os.pathsep + environment['PATH']
    environment['AGAIN_HOME'] = str(root / scenario / 'state')
    environment['AGAIN_REPLAY_TRACE'] = str(TRACE)
    task_id = 'rust-repair-replay' if historical else f'capture-{scenario}'
    command = [str(binary), 'codex', '--workspace', str(workspace),
               '--task-id', task_id, '--task', f'Inspect source for {scenario}',
               '--', '--ephemeral', '--json']
    try:
        result = subprocess.run(command, cwd=workspace, env=environment,
                                capture_output=True, timeout=90)
        if not inspect_brain:
            return result, None
        brain = subprocess.run([str(binary), 'brain', 'show', '--workspace', str(workspace)],
                               cwd=workspace, env=environment, capture_output=True,
                               text=True, check=True, timeout=10)
        runs = [run for run in json.loads(brain.stdout)['recentRuns']
                if run['task_id'] == task_id]
        if len(runs) != 1:
            raise RuntimeError(f'{scenario}: expected one Brain run, found {len(runs)}')
        return result, runs[0]
    finally:
        subprocess.run([str(binary), 'mcp', 'daemon', 'stop', '--workspace', str(workspace)],
                       cwd=workspace, env=environment, capture_output=True, timeout=10)


def run(binary: pathlib.Path) -> dict:
    source = source_state(ROOT, binary)
    if source['binarySourceBindingVerified'] is not True:
        raise RuntimeError('gate requires a clean source-bound release binary')
    raw = TRACE.read_bytes()
    usage, commands = raw_usage_and_commands(raw)
    with tempfile.TemporaryDirectory(prefix='again-codex-capture-') as temporary:
        root = pathlib.Path(temporary)
        replay, run = launch(binary, root, 'historical-rust',
                             "import os, pathlib, sys\n"
                             "sys.stdout.buffer.write(pathlib.Path(os.environ['AGAIN_REPLAY_TRACE']).read_bytes())\n"
                             "sys.stdout.buffer.flush()\n", historical=True)
        if (replay.returncode != 0 or run['exit_code'] != 0 or not run['turn_completed']
                or run['completed_commands'] != commands
                or run['completed_source_reads'] <= commands
                or any(run[field] != usage[field] for field in
                       ('input_tokens', 'cached_input_tokens', 'output_tokens'))):
            raise RuntimeError(f'failed Rust trace was not retained exactly: {run}, stderr={replay.stderr[-400:]}')

        malformed, malformed_run = launch(
            binary, root, 'malformed',
            "import json\n"
            "print('not-json', flush=True)\n"
            "print(json.dumps({'type':'turn.completed','usage':{'input_tokens':1,'cached_input_tokens':0,'output_tokens':1}}), flush=True)\n")
        if (malformed.returncode == 0 or b'non-JSON event line' not in malformed.stderr
                or not malformed_run['turn_completed'] or b'not-json' not in malformed.stdout):
            raise RuntimeError('malformed JSONL did not produce a visible capture failure')

        missing, missing_run = launch(
            binary, root, 'missing-turn',
            "import json\n"
            "print(json.dumps({'type':'item.completed','item':{'id':'done','type':'agent_message','text':'Done'}}), flush=True)\n")
        if (missing.returncode == 0 or b'without a completed turn' not in missing.stderr
                or missing_run['turn_completed']):
            raise RuntimeError('missing completed turn did not produce a visible capture failure')

        collision, collision_run = launch(
            binary, root, 'event-collision',
            "import json\n"
            "for command in ('cat README.md', 'rg README.md'):\n"
            "    print(json.dumps({'type':'item.completed','item':{'id':'same','type':'command_execution','command':command,'exit_code':0,'aggregated_output':'','status':'completed'}}), flush=True)\n"
            "print(json.dumps({'type':'turn.completed','usage':{'input_tokens':2,'cached_input_tokens':0,'output_tokens':1}}), flush=True)\n")
        if (collision.returncode == 0 or b'could not record a completed event' not in collision.stderr
                or collision_run['completed_commands'] != 2):
            raise RuntimeError('event storage collision did not reach the caller')

        multi_turn, multi_turn_run = launch(
            binary, root, 'multi-turn',
            "import json\n"
            "for usage in ({'input_tokens':11,'cached_input_tokens':3,'output_tokens':2},"
            " {'input_tokens':17,'cached_input_tokens':5,'output_tokens':4}):\n"
            "    print(json.dumps({'type':'turn.completed','usage':usage}), flush=True)\n")
        if (multi_turn.returncode != 0 or multi_turn_run['input_tokens'] != 28
                or multi_turn_run['cached_input_tokens'] != 8
                or multi_turn_run['output_tokens'] != 6):
            raise RuntimeError('multiple completed turns did not retain summed raw usage')

        storage_failure, _ = launch(
            binary, root, 'run-store-failure',
            "import json, os, pathlib\n"
            "database = pathlib.Path(os.environ['AGAIN_HOME']) / 'again.sqlite'\n"
            "database.rename(database.with_name('again.sqlite.moved'))\n"
            "database.mkdir()\n"
            "print(json.dumps({'type':'turn.completed','usage':{'input_tokens':1,'cached_input_tokens':0,'output_tokens':1}}), flush=True)\n",
            inspect_brain=False)
        if storage_failure.returncode == 0 or b'Brain capture is incomplete' not in storage_failure.stderr:
            raise RuntimeError('completed run storage failure did not reach the caller')

        held, held_run = launch(
            binary, root, 'held-stdout',
            "import json, subprocess, sys\n"
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(4)'], stdout=sys.stdout)\n"
            "print(json.dumps({'type':'turn.completed','usage':{'input_tokens':3,'cached_input_tokens':1,'output_tokens':1}}), flush=True)\n")
        if held.returncode != 0 or not held_run['turn_completed'] or held_run['input_tokens'] != 3:
            raise RuntimeError('held stdout lost the already completed turn')

    return {
        'schema': 'again.codex-run-capture-gate.v1', 'source': source,
        'binarySha256': sha256(binary), 'replayedRustTraceSha256': hashlib.sha256(raw).hexdigest(),
        'replayedCompletedCommands': commands, 'replayedVerifiedSourceFiles': run['completed_source_reads'],
        'replayedUsage': {field: run[field] for field in ('input_tokens', 'cached_input_tokens', 'output_tokens')},
        'malformedStreamVisible': True, 'missingTurnVisible': True,
        'eventStorageFailureVisible': True, 'heldStdoutRetainedCompletedRun': True,
        'multiTurnUsageMatchesRawEvents': True,
        'runStorageFailureVisible': True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = run(args.binary.resolve(strict=True))
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
