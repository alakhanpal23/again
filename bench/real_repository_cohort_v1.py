#!/usr/bin/env python3
"""Run a frozen, source-bound, real Codex cohort over pinned public repositories."""

from __future__ import annotations

import argparse
import datetime as dt
import decimal
import hashlib
import json
import pathlib
import statistics
import tempfile

import agent_gateway_codex_pair_diagnostic_v1 as harness
import agent_gateway_editable_pair as pair
import estimate_api_equivalent_cost_v1 as estimate
import public_historical_fixtures_v1 as public
from agent_gateway_codex_live_probe_v1 import sha256, source_state


MANIFEST = pathlib.Path(__file__).with_suffix('.json')
ROOT = pathlib.Path(__file__).resolve().parents[1]


def frozen_inputs(manifest: dict) -> None:
    if manifest.get('schema') != 'again.real-repository-cohort-manifest.v1':
        raise RuntimeError('unknown manifest schema')
    if manifest['modes'] != ['cold', 'returning'] or manifest['orders'] != ['baseline-first', 'again-first']:
        raise RuntimeError('cohort modes or orders changed')
    if len(manifest['cases']) < 2:
        raise RuntimeError('multi-repository cohort requires at least two cases')
    for case in manifest['cases']:
        name = case['fixture']
        source = public.CASES[name]
        harness.configure_fixture(name)
        checks = {
            'repository': source['url'], 'parent': source['parent'], 'fix': source['fix'],
            'fixtureSha256': hashlib.sha256(pair.canonical_bytes(pair.FIXTURE)).hexdigest(),
            'promptSha256': hashlib.sha256(pair.PROMPT.encode()).hexdigest(),
            'priorPromptSha256': hashlib.sha256(source['prior_task'].encode()).hexdigest(),
            'validationSelector': 'python3 -m unittest discover -s tests -p test_again_oracle.py',
        }
        if any(case[key] != value for key, value in checks.items()):
            raise RuntimeError(f'frozen fixture mismatch: {name}')


def accepted(observation: dict, mode: str, condition: str) -> bool:
    usage = observation.get('usage')
    prior = observation.get('livePriorTask')
    return bool(
        observation['exitCode'] == 0 and not observation['timedOut']
        and observation['eventsCaptured'] and observation['oracle']['passed']
        and observation['agentValidationObserved'] is True
        and isinstance(usage, dict) and all(isinstance(usage.get(key), int)
                                             for key in ('input_tokens', 'cached_input_tokens', 'output_tokens'))
        and (condition != 'product' or (observation['brainRun'] is not None
                                         and observation['brainRunError'] is None))
        and (mode != 'returning' or (prior is not None and prior['completedCommands'] >= 1
                                    and prior['brainObserved'] == (condition == 'product')))
    )


def observation_cost(observation: dict, rates: dict, mode: str) -> decimal.Decimal:
    value = estimate.cost(observation['usage'], rates)
    if mode == 'returning':
        value += estimate.cost(observation['livePriorTask']['usage'], rates)
    return value


def summarise(reports: list[dict], manifest: dict) -> dict:
    card = json.loads((MANIFEST.parent / manifest['rateCard']).read_text())
    if card['model'] != manifest['model']:
        raise RuntimeError('rate card model mismatch')
    rates = {key: decimal.Decimal(value) for key, value in card['usdPerMillionTokens'].items()}
    accepted_pairs = [r for r in reports if r['accepted']]
    time_ratios = []
    cost_ratios = []
    for report in accepted_pairs:
        by = {item['condition']: item for item in report['observations']}
        def elapsed(o: dict) -> float:
            return o['elapsedMs'] + (o['livePriorTask']['elapsedMs'] if report['mode'] == 'returning' else 0)
        time_ratios.append(elapsed(by['product']) / elapsed(by['baseline']))
        cost_ratios.append(float(observation_cost(by['product'], rates, report['mode']) /
                                 observation_cost(by['baseline'], rates, report['mode'])))
    complete = len(reports) == len(manifest['cases']) * len(manifest['modes']) * len(manifest['orders'])
    all_accepted = complete and len(accepted_pairs) == len(reports)
    median_time = statistics.median(time_ratios) if time_ratios else None
    median_cost = statistics.median(cost_ratios) if cost_ratios else None
    qualified = bool(all_accepted and median_time <= manifest['qualification']['maximumMedianTimeRatio']
                     and median_cost <= manifest['qualification']['maximumMedianApiEquivalentCostRatio'])
    return {
        'schema': 'again.real-repository-cohort-summary.v1',
        'completedPairs': len(reports), 'plannedPairs': len(manifest['cases']) * 4,
        'acceptedPairs': len(accepted_pairs), 'allAccepted': all_accepted,
        'medianTimeRatioAcceptedOnly': median_time,
        'medianApiEquivalentCostRatioAcceptedOnly': median_cost,
        'qualifiedAgainstFrozenGate': qualified,
        'warning': 'Accepted-only ratios are diagnostic until every planned pair is accepted.',
        'pairs': [{key: report[key] for key in ('fixture', 'mode', 'order', 'accepted')}
                  for report in reports],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=pathlib.Path, required=True)
    parser.add_argument('--output-dir', type=pathlib.Path, required=True)
    parser.add_argument('--plan-only', action='store_true')
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text())
    frozen_inputs(manifest)
    binary = args.binary.resolve(strict=True)
    source = source_state(ROOT, binary)
    if not source['binarySourceBindingVerified']:
        raise RuntimeError('binary is not bound to clean cohort source')
    output = args.output_dir.resolve()
    if output.is_relative_to(ROOT):
        raise RuntimeError('output must be outside the source repository')
    manifest_sha = sha256(MANIFEST)
    if args.plan_only:
        print(json.dumps({'manifestSha256': manifest_sha, 'source': source,
                          'plannedPairs': len(manifest['cases']) * 4}))
        return 0
    output.mkdir(parents=True, exist_ok=True)
    identity = {'manifestSha256': manifest_sha, 'source': source, 'binarySha256': sha256(binary),
                'model': manifest['model'], 'rateCardSha256': sha256(MANIFEST.parent / manifest['rateCard'])}
    identity_path = output / 'identity.json'
    if identity_path.exists():
        if json.loads(identity_path.read_text()) != identity:
            raise RuntimeError('resume identity mismatch')
    else:
        identity_path.write_text(json.dumps(identity, indent=2) + '\n')
        (output / 'manifest.json').write_bytes(MANIFEST.read_bytes())
    reports = []
    for case in manifest['cases']:
        for mode in manifest['modes']:
            for order in manifest['orders']:
                stem = f"{case['fixture']}-{mode}-{order}"
                report_path = output / f'{stem}.json'
                if report_path.exists():
                    report = json.loads(report_path.read_text())
                    if report['identity'] != identity:
                        raise RuntimeError(f'resume report mismatch: {stem}')
                    reports.append(report)
                    continue
                observations = []
                conditions = ('baseline', 'product') if order == 'baseline-first' else ('product', 'baseline')
                for condition in conditions:
                    harness.configure_fixture(case['fixture'])
                    with tempfile.TemporaryDirectory(prefix=f'again-real-{condition}-') as temp:
                        prior_trace = []
                        observation, raw = harness.run_condition(
                            condition, pathlib.Path(temp), binary, manifest['model'],
                            harness.TASK_IDS[case['fixture']],
                            required_agent_validation=(case['validationSelector'],),
                            live_prior_prompt=(public.CASES[case['fixture']]['prior_task']
                                               if mode == 'returning' else None),
                            prior_trace_sink=prior_trace)
                    raw_path = output / f'{stem}-{condition}-repair.jsonl'
                    raw_path.write_bytes(raw)
                    if mode == 'returning':
                        (output / f'{stem}-{condition}-prior.jsonl').write_bytes(prior_trace[0])
                    observations.append(observation)
                    print(json.dumps({'case': stem, 'condition': condition,
                                      'accepted': accepted(observation, mode, condition),
                                      'elapsedMs': observation['elapsedMs']}), flush=True)
                report = {'schema': 'again.real-repository-pair.v1', 'identity': identity,
                          'fixture': case['fixture'], 'mode': mode, 'order': order,
                          'observations': observations,
                          'accepted': all(accepted(o, mode, o['condition']) for o in observations),
                          'capturedAtUtc': dt.datetime.now(dt.timezone.utc).isoformat()}
                report_path.write_text(json.dumps(report, indent=2) + '\n')
                reports.append(report)
                (output / 'summary.json').write_text(json.dumps(summarise(reports, manifest), indent=2) + '\n')
    (output / 'summary.json').write_text(json.dumps(summarise(reports, manifest), indent=2) + '\n')
    print(json.dumps(summarise(reports, manifest), indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
