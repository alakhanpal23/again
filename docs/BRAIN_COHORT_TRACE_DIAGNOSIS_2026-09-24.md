# Four-repository Brain trace diagnosis (2026-09-24)

The [frozen four-repository audit](../bench/results/2026-09-24-diverse-real-cohort-bb44f50/audit.json) verifies all 48 raw traces. Fourteen of sixteen pairs were accepted. The cohort failed its all-pairs qualification gate, so accepted-only medians are diagnostic. The audit now retains preparation, first-edit, and post-edit fields for every condition alongside tool and token counts. In this live harness, `preparationMs: 0` is a placeholder for the product wrapper: launcher preparation is included in first-edit time. The separate `mcp brief` timings below are a proxy, not a decomposition of the live run.

| Task and mode | Order | Baseline first edit / post edit | Again first edit / post edit | Tool actions baseline / Again | Outcome |
| --- | --- | ---: | ---: | ---: | --- |
| Rust cold | baseline first | 54.6s / 13.3s | 44.6s / 9.6s | 10 / 11 | Both correct, Again faster |
| Rust cold | Again first | 40.7s / 12.9s | 52.3s / 13.1s | 7 / 6 | Both correct, Again slower |
| Rust returning | baseline first | 37.4s / 10.1s | 54.5s / 11.6s | 11 / 9 | Both correct, Again slower |
| Rust returning | Again first | 40.0s / 11.5s | 51.0s / 13.3s | 6 / 6 | Pair rejected: Brain run missing in original capture |
| tomlkit cold | baseline first | 9.9s / 6.3s | 14.0s / 7.4s | 4 / 4 | Both correct, Again slower |
| tomlkit cold | Again first | 11.0s / 5.6s | 11.6s / 7.1s | 4 / 4 | Both correct, Again slower |
| tomlkit returning | baseline first | 14.4s / 6.8s | 6.7s / 7.8s | 8 / 2 | Both correct, Again faster |
| tomlkit returning | Again first | 14.5s / 7.2s | 6.1s / 6.1s | 8 / 2 | Both correct, Again faster |

The Rust returning trace often repeats a locating `rg` despite a source-checked Brain excerpt. Cold tomlkit has no prior Brain memory; its Again run uses the same search, read, edit, and required test sequence as baseline. In both cold orders the regression is chiefly before the edit, not an extra tool call. Returning tomlkit shows the durable Brain benefit: the agent edits directly from a rechecked prior observation, then runs the required test.

## Rejected changes

The [source-bound experiment](../bench/results/2026-09-24-brain-excerpt-guidance/analysis.json) retains raw traces, binary hashes, oracle results, tool actions, tokens, and phase times.

1. **Python excerpt locator.** A class-aware method score moved the tomlkit partial preview from unrelated `_render_dotted` code to `Array.__setitem__`. A targeted unit test passed, but two new cold pairs gave Again repair times of 21.2s and 18.6s, essentially unchanged from 21.3s and 18.7s in the frozen run. The agent still searched and read the implementation. The change was dropped.
2. **Brain excerpt launch guidance.** A four-line conditional instruction told Codex to start at the rechecked Brain location. Against the exact source predecessor, two correct Rust returning product runs reduced median repair time from 54.4s to 49.7s and first-edit time from 43.0s to 39.2s. Completed tool actions stayed at 5.5 median, while median input tokens rose from 97.6k to 128.2k (31%). The change was reverted. A separately paired opposite-order baseline failed its oracle and required-test observation, so that pair cannot support a speed claim. A tomlkit returning guard passed, but it does not offset the Rust token regression.

The cold brief proxy had medians of 3.34s before and 2.40s after for Rust, and 335ms before and 342ms after for tomlkit (three fresh-workspace samples each). The prompt experiment does not change `task.start`; these timings include daemon startup and are too small and noisy to attribute to the prompt.

## Priority for the next Brain change

Keep source digests and current-byte rechecks, bounded partial previews, complete previews when small, and required validation. The next useful experiment needs a source-bound, exact-predecessor comparison that removes a repeated Rust locating call **without increasing input tokens**. Measure launcher preparation separately in the live harness before claiming a preparation win. Cold tomlkit needs a reduction in pre-edit reasoning or redundant context; a more accurate partial excerpt alone did not do it.
