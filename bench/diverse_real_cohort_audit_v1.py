#!/usr/bin/env python3
"""Audit frozen real-agent traces and report quality before speed or cost."""

from __future__ import annotations

import argparse
import decimal
import hashlib
import json
import pathlib
import statistics
from collections import defaultdict

from estimate_api_equivalent_cost_v1 import cost
from diverse_real_cohort_v2 import accepted as condition_accepted


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def audit(cohort: pathlib.Path, card_path: pathlib.Path) -> dict:
    identity = json.loads((cohort / 'identity.json').read_text())
    manifest_path = cohort / 'manifest.json'
    if digest(manifest_path) != identity['manifestSha256']:
        raise RuntimeError('manifest hash mismatch')
    manifest = json.loads(manifest_path.read_text())
    if identity['source']['binarySourceBindingVerified'] is not True:
        raise RuntimeError('cohort binary/source binding was not verified')
    card = json.loads(card_path.read_text())
    if card['model'] != manifest['model'] or digest(card_path) != identity['rateCardSha256']:
        raise RuntimeError('rate card binding mismatch')
    rates = {key: decimal.Decimal(value) for key, value in card['usdPerMillionTokens'].items()}
    pairs = []
    trace_count = 0
    by_task: dict[str, list[dict]] = defaultdict(list)
    total_cost = {'baseline': decimal.Decimal(0), 'product': decimal.Decimal(0)}
    for case in manifest['cases']:
        for mode in manifest['modes']:
            for order in manifest['orders']:
                stem = f"{case['fixture']}-{mode}-{order}"
                report = json.loads((cohort / f'{stem}.json').read_text())
                if report['identity'] != identity or (report['fixture'], report['mode'], report['order']) != (case['fixture'], mode, order):
                    raise RuntimeError(f'pair identity mismatch: {stem}')
                observed = {}
                for item in report['observations']:
                    condition = item['condition']
                    raw = cohort / f'{stem}-{condition}-repair.jsonl'
                    if digest(raw) != item['rawEventSha256']:
                        raise RuntimeError(f'repair trace hash mismatch: {raw.name}')
                    trace_count += 1
                    prior = item['livePriorTask']
                    if mode == 'returning':
                        prior_raw = cohort / f'{stem}-{condition}-prior.jsonl'
                        if prior is None or digest(prior_raw) != prior['rawEventSha256']:
                            raise RuntimeError(f'prior trace hash mismatch: {stem} {condition}')
                        trace_count += 1
                    elif prior is not None:
                        raise RuntimeError(f'cold run has prior cost: {stem}')
                    elapsed = decimal.Decimal(str(item['elapsedMs']))
                    amount = cost(item['usage'], rates)
                    if prior is not None:
                        elapsed += decimal.Decimal(str(prior['elapsedMs']))
                        amount += cost(prior['usage'], rates)
                    total_cost[condition] += amount
                    observed[condition] = {'elapsedMs': float(elapsed), 'apiEquivalentUsd': str(amount),
                                           'oraclePassed': item['oracle']['passed'],
                                           'agentTestObserved': item['agentValidationObserved'],
                                           'brainRunError': item['brainRunError'],
                                           'completedActions': len(item['completedActions'])}
                if set(observed) != {'baseline', 'product'}:
                    raise RuntimeError(f'pair lacks a condition: {stem}')
                if report['accepted'] != all(condition_accepted(item, mode, item['condition'])
                                             for item in report['observations']):
                    raise RuntimeError(f'pair acceptance mismatch: {stem}')
                time_ratio = observed['product']['elapsedMs'] / observed['baseline']['elapsedMs']
                cost_ratio = float(decimal.Decimal(observed['product']['apiEquivalentUsd']) /
                                   decimal.Decimal(observed['baseline']['apiEquivalentUsd']))
                pair = {'fixture': case['fixture'], 'language': case['language'], 'mode': mode,
                        'order': order, 'accepted': report['accepted'], 'conditions': observed,
                        'timeRatioDiagnostic': time_ratio, 'costRatioDiagnostic': cost_ratio}
                pairs.append(pair)
                by_task[case['fixture']].append(pair)
    accepted = [pair for pair in pairs if pair['accepted']]
    task_summaries = {}
    for task, rows in by_task.items():
        valid = [row for row in rows if row['accepted']]
        task_summaries[task] = {
            'acceptedPairs': len(valid), 'plannedPairs': len(rows),
            'medianTimeRatioAcceptedOnly': statistics.median(row['timeRatioDiagnostic'] for row in valid) if valid else None,
            'medianCostRatioAcceptedOnly': statistics.median(row['costRatioDiagnostic'] for row in valid) if valid else None,
        }
    score = json.loads((cohort / 'summary.json').read_text())
    if len(pairs) != score['plannedPairs'] or len(accepted) != score['acceptedPairs']:
        raise RuntimeError('stored summary disagrees with audited pairs')
    if accepted and (
        abs(statistics.median(row['timeRatioDiagnostic'] for row in accepted) - score['medianTimeRatioAcceptedOnly']) > 1e-9
        or abs(statistics.median(row['costRatioDiagnostic'] for row in accepted) - score['medianApiEquivalentCostRatioAcceptedOnly']) > 1e-9
    ):
        raise RuntimeError('stored summary medians disagree with audited pairs')
    return {
        'schema': 'again.diverse-real-cohort-audit.v1',
        'sourceSha': identity['source']['head'], 'binarySha256': identity['binarySha256'],
        'manifestSha256': identity['manifestSha256'], 'verifiedRawTraces': trace_count,
        'plannedPairs': len(pairs), 'acceptedPairs': len(accepted),
        'qualificationPassed': score['qualifiedAgainstFrozenGate'] and len(accepted) == len(pairs),
        'acceptedOnlyMedianTimeRatioDiagnostic': score['medianTimeRatioAcceptedOnly'],
        'acceptedOnlyMedianCostRatioDiagnostic': score['medianApiEquivalentCostRatioAcceptedOnly'],
        'totalApiEquivalentUsdIncludingFailures': {key: str(value) for key, value in total_cost.items()},
        'taskSummaries': task_summaries, 'pairs': pairs,
        'interpretation': 'Failed pairs disqualify the cohort; accepted-only ratios and unequal-quality cost totals are diagnostic.',
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort-dir', type=pathlib.Path, required=True)
    parser.add_argument('--rate-card', type=pathlib.Path, required=True)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    args = parser.parse_args()
    result = audit(args.cohort_dir, args.rate_card)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({key: result[key] for key in ('verifiedRawTraces', 'plannedPairs',
                                                 'acceptedPairs', 'qualificationPassed')}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
