# Implementation status

This file distinguishes code that exists from roadmap intent. Implementation status comes from reproducible tests; performance claims require retained benchmark evidence. Immutable CI retention for new test-only claims remains a release gate.

## 2026-09-24 long agent lease and historical returning task

The Brain now retains a successful, single-identifier filtered Cargo test as an execute-required hint. It offers that command on a later task only when the current bounded Rust candidate scan still finds the selected test or module name and a Cargo manifest is present. Qualified `module::test` commands still count as completed validation but are not promoted into cross-task hints. A focused store-to-brief regression checks delivery and retirement after the selector disappears. No completed-task speed or coverage improvement is claimed for this hint yet.

The historical unlocated `repo.search` repair exposed a real launcher bug: the daemon closes an idle MCP connection after 60 seconds, and the launcher previously waited 60 seconds before its first task-lease heartbeat. A successful agent-run Cargo test could therefore be followed by an exit-1 lease failure with no completed Brain run. The launcher now renews every 20 seconds, includes the renewal failure reason, and records the interrupted run even if a later heartbeat fails. The [source-bound 65-second gate](../bench/results/2026-09-24-historical-brain-unlocated-bound-98a450e/again-lease-heartbeat-bound-98a450e.json) passed with a normal exit and completed Brain run. The same release binary's seeded historical run lasted 68 seconds, passed the edit oracle and agent-run Cargo test, and retained a complete Brain run.

The [source-bound historical diagnostic](../bench/results/2026-09-24-historical-brain-unlocated-bound-98a450e/again-historical-unlocated-seeded-first-98a450e.json) accepted the seeded-first pair, but seeded completion was 1.309 times cold and the agent reread the target function. A second cold-first pair was unaccepted because its cold leg exited 1 before editing; its seeded leg passed. These results establish lease reliability improvement but do not establish a speed win on this real task. The old 2 KiB Brain excerpt ended before the search function did. A larger 5 KiB Brain-only excerpt, still bounded by an 8 KiB Brain brief, now covers the relevant function in the focused regression. Task-start previews remain 2 KiB. Its completed-task effect remains to be measured.

The [larger-excerpt historical repeat](../bench/results/2026-09-24-historical-brain-large-excerpt/summary.json) accepted both treatment orders with successful agent-run Cargo tests and independent patch oracles. Seeded runs used six investigation commands versus 16 cold; paired completion ratios were 0.668 and 0.953 (median 0.811). The frozen API-equivalent cost ratio was 0.696. Both raw traces and source-bound pair reports are retained. The second pair used a harness-only follow-up commit with identical runtime code. This is one real-repository returning task, and the median completion improvement is slightly below the 20% release target. One reverse-order attempt stopped in fixture setup when its expected-failing Cargo prewarm exceeded 120 seconds on a loaded host; the setup timeout is now 300 seconds and the ablation harness checkpoints each completed leg.

A [second historical repair](../bench/results/2026-09-24-historical-python-brain/summary.json) used an 884-file pre-fix Again checkout and independently injected Python triple-quote indexing regressions. The fixture verified both failures before the edit and both passes on the historical fix. Cold and seeded Codex each produced an accepted patch and ran the required Cargo test in both orders on a clean source-bound release binary. Seeded completion ratios were 0.770 and 0.875 (median 0.822), and the frozen API-equivalent cost ratio was 0.740. Seeded runs made five investigation commands versus seven cold. The cold-first seeded agent still reread the target source and made the same number of investigation commands as cold; call avoidance was seen only in the reverse order. These two historical tasks remain diagnostic rather than a frozen, diverse release cohort, and the prior-read setup cost was outside timed legs.

Inspecting the seeded Python brief showed the Brain selected the correct source file but excerpted the injected regression tests instead of the `sanitize_line_v1` implementation. Excerpt ranking now scores task terms against implementation declaration names and skips test declarations when choosing a preferred anchor. A focused regression covers this failure shape; a source-bound brief and completed-task repeat are still needed before crediting it with fewer reads or faster completion.

## 2026-09-23 prior large-source Brain previews

The Brain now supplies a bounded, task-anchored partial excerpt for a relevant prior source file of 2–256 KiB when task.start has not already previewed that path. It rereads the current file, verifies the stored whole-file digest, screens the excerpt, and labels its line range and incomplete status. The 4 KiB Brain brief limit still applies. A focused regression checks the anchor, deduplication against task.start, and withholding after a source edit. This is an additional opportunity to avoid a later source read; actual avoided calls and completed-task speed still need live measurement.

The [clean-source authenticated product gate](../bench/results/2026-09-23-auth-product-e2e-brain-partial-bound-a8ede8b.json) passed on the release binary at `a8ede8b`, including one executed duplicate read and one recorded follower cancellation. Two earlier gate runs raced: the follower completed before the harness sent cancellation, so no cancellation event was valid. The harness now sends cancellation immediately after the follower request is written and checks the resulting audit event. This gate exercises the broader task lifecycle; the new prior large-file excerpt itself is covered by the focused regression above, not by this product gate.

The first [large-helper returning-task ablation](../bench/results/2026-09-23-brain-excerpt-ablation-bound-02b006e/again-brain-excerpt-ablation-cold-first-02b006e.json) accepted both same-launcher edits and their agent-run unittests. A separate brief probe confirmed the seeded Brain supplied a current 8.8 KiB helper excerpt, but seeded Codex still read that helper and used six completed actions versus four cold. The seeded/cold completion ratio was 0.904; input and output tokens were higher when seeded. The ablation report did not verify binary source binding, so it is diagnostic evidence only. This directly contradicts a call-avoidance claim for the initial excerpt presentation. The launcher now renders the excerpt as readable source lines beside Brain metadata and tells the agent when a local edit can proceed from those lines. That presentation change needs its own completed-task repeat.

The [clean-source readable-excerpt repeat](../bench/results/2026-09-23-brain-excerpt-readable-bound-4f08ec6/summary.json) accepted both cold-first and seeded-first pairs with the same `again codex` launcher, exact edit oracle, and successful agent-run unittest. The seeded agent edited and tested directly in both orders; cold agents searched and read before editing. Across both pairs, seeded runs used two shell commands (both tests) versus nine cold commands. Paired completion ratios were 0.712 and 0.797 (median 0.754); the frozen API-equivalent cost ratio was 0.726. Raw Codex events, run summaries, and binary/source bindings are retained. This proves call avoidance and a speed/cost win for one synthetic returning task, not a diverse task cohort or first-use economics. In these trials, the readable presentation coincided with call avoidance; the previous escaped-JSON excerpt did not prevent rereads.

## 2026-09-23 large source previews

Task briefs now include a bounded excerpt when a named or indexed source file is larger than the 2 KiB complete-preview limit. The excerpt carries the digest of the entire current file, its line range, and `complete: false`; the launcher labels it partial and tells the agent to inspect more before editing. Complete small-file previews keep their existing read-avoidance guidance. The [clean-source release-binary probe](../bench/results/2026-09-23-large-source-preview-bound-cfc2522.json) used the same 50 KiB historical search target as the accepted-edit cohort. It returned a 2 KiB excerpt beginning at `fn repository_search_v1`, and a subsequent source edit changed the file digest while the new excerpt matched current bytes. Focused tests and strict Clippy pass. This proves a useful current starting location on that repository; its effect on accepted-task time is not yet measured.

The subsequent [source-bound historical repair repeat](../bench/results/2026-09-23-historical-excerpt-cohort-bound-316f06a/summary.json) accepted both baseline/Again run orders with successful agent-run Cargo tests. Again's completion ratios were **0.847** and **0.899** (paired median **0.873**), short of the 20% target. Again made six shell commands per task versus four for baseline; the [API-equivalent cost estimate](../bench/results/2026-09-23-historical-excerpt-cohort-bound-316f06a/api-equivalent-cost.json) was $0.123656 Again versus $0.132656 baseline, ratio **0.932**. The excerpt did not establish command avoidance or a cost win. A first attempt at the same revision stopped because the harness found no Brain run and retained no product trace. The harness now records that failure in future pair reports; a separate direct Again launch and both completed pairs retained exactly one Brain run with the successful Cargo test. This remains one historical task and an unresolved reliability signal, not release qualification.

The [clean-source large `sed` Brain gate](../bench/results/2026-09-23-large-sed-brain-bound-a55eb92/summary.json) passed through `again codex` with a controlled Codex event emitter. The launcher verified the returned line range against the current large Rust file, counted one completed source read, surfaced the source observation on a later task, and withheld it after an edit. A separate live Codex repair at that revision passed the edit and test oracles but exited with code 1 and left no Brain run. The launcher previously dropped the run summary if a descendant kept stdout open beyond two seconds; a follow-up change retains the observed snapshot in that case. The cause of the live Codex exit code remains unproven.

The [clean-source held-stdout gate](../bench/results/2026-09-23-held-stdout-brain-bound-ec8ffee/summary.json) reproduced that reader deadline with a controlled Codex emitter and a descendant holding the pipe open for four seconds. Again exited successfully and retained the completed turn, one command, one verified source read, and its file observation after the two-second deadline. This verifies the missing-run repair for that lifecycle shape; the live exit-code failure still needs separate diagnosis.

## 2026-09-23 historical repository repair cohort

The [clean-source historical search cohort](../bench/results/2026-09-23-historical-search-cohort-bound-146af52/summary.json) used a complete 212-file checkout of an earlier Again revision with two independently injected failing `repo.search` regression tests. Baseline and Again each repaired only `src/agent_gateway_runtime.rs`, passed both oracles, and ran `cargo test --locked --lib historical_search_oracle` in both run orders. Again used five completed actions versus six for baseline. Its completion-time ratios were **0.883** and **0.951** (paired median **0.917**); first-edit ratios were **0.827** and **0.859**. The [frozen API-equivalent cost estimate](../bench/results/2026-09-23-historical-search-cohort-bound-146af52/api-equivalent-cost.json) was $0.144333 Again versus $0.180138 baseline, a ratio of **0.801**. Both duration and cost miss the 20% release target. The raw Codex traces and pair reports are retained with the summary. This is one historical task with two orders, not broad real-task qualification.

The first attempt exposed a Python triple-quote sanitizer panic during repository indexing; the parser fix at `146af52` has two regression tests, and the rebuilt release binary opened the historical task brief. The completed Codex test command appears in the raw traces, but Brain run summaries at that source revision count `successful_tests: 0` because its recognized Rust command forms excluded `cargo test --locked --lib historical_search_oracle`. A subsequent focused fix counts successful filtered Cargo tests without suggesting the potentially stale selector for another task. The historical brief also produced no source previews for the named target. That brief gap needs work before this task represents the intended Brain-guided workflow.

## 2026-09-23 nested package validation and explicit source priority

Task briefs now look up a JavaScript or TypeScript candidate's nearest current `package.json` and return its declared test command with a repository-relative `workingDirectory`. They can suggest two distinct package commands when a task names sources in two packages. Nested packages without an explicit package manager or local lockfile receive no guessed command; conflicting lockfiles, symlinked source paths, and unsafe manifests also withhold a suggestion. Each selector remains unverified and requires execution. The launcher tells Codex to run a suggested command from that working directory.

The first [clean-source nested-package CLI gate](../bench/nested_package_validation_gate_v1.py) exposed a brief relevance error: when alpha's manifest became invalid, the code index supplied beta's test command for an alpha-only task. The task-start path had also discarded explicitly named source previews whenever the index was available. The brief now places current explicit previews first and deduplicates indexed candidates. The [source-bound rerun](../bench/results/2026-09-23-nested-package-validation-bound-3b51829/nested-package-gate.json) passed alpha and beta command selection, explicit-preview precedence, an independently executed `npm test`, and withholding after alpha's manifest changed. The [root package Brain gate](../bench/results/2026-09-23-nested-package-validation-bound-3b51829/root-package-brain-gate.json) still passed. This is test-guidance and brief-correctness evidence, not agent-run validation, test reuse, or task-speed evidence.

The [clean-source nested-package Codex cohort](../bench/results/2026-09-23-nested-agent-cohort-bound-e929214/summary.json) then accepted both baseline/Again orders. Each agent changed only `packages/alpha/src/total.mjs`, passed the independent target test oracle, and completed a successful `npm test`; the fixture's root and beta scripts fail after the fix, so a green script call identifies alpha's package. Again used two completed actions (edit and test), versus five or six for baseline. Completion ratios were **0.838** and **1.010**, paired median **0.924**, so this task misses the 20% median target and has a slight slow-order regression. The [API-equivalent cost ratio](../bench/results/2026-09-23-nested-agent-cohort-bound-e929214/api-equivalent-cost.json) was **0.874**, also short of the cost target. Raw Codex traces and pair reports are retained. The first attempt to gate the agent's working directory by command text was invalid because Codex omitted cwd from its completed command events; the final fixture uses failing alternative scripts instead. This remains one synthetic package repair, not broad real-repository qualification.

## 2026-09-23 agent-validated package-script cohort

The [clean-source package-script cohort](../bench/results/2026-09-23-package-validation-cohort-bound-09f7dc0/summary.json) accepted all four baseline/Again pairs at 0 and 1,000 background source files in both run orders. Each agent completed its own successful `npm test` after the edit. Again used two completed actions per task (edit and test); baseline used four or five. The paired median completion ratio was **0.826** (17.4% faster), with nearest-rank p95 **0.907**. This misses the 20% median release target. The [frozen API-equivalent cost estimate](../bench/results/2026-09-23-package-validation-cohort-bound-09f7dc0/api-equivalent-cost.json) was $0.093788 Again versus $0.106334 baseline, a ratio of **0.882**, which also misses the 20% cost target and is not a billed Codex charge. The release binary was built from and bound to the clean `09f7dc0` source; pair reports and raw Codex traces are retained beside the summary.

Again reached the first edit faster in every pair (paired median first-edit ratio **0.609**). The paired median duration from first edit to process exit was **1.177** times baseline; Again was slower in that phase in three pairs. Both conditions ran the same successful `npm test`, but these first-run traces lack per-event timestamps, so the cause of that post-edit gap is unproven. This cohort covers one small synthetic repair, so broader real-task quality, proof-based test reuse, and the balanced release gate remain open.

The [source-bound timing repeat](../bench/results/2026-09-23-package-validation-timeline-bound-f883f4e/summary.json) used the same frozen manifest after adding event-receipt timestamps to the paired harness. All four pairs again passed the edit oracle and an agent-run `npm test`. Its median completion ratio was **0.716** and p95 **0.904**; its [API-equivalent cost ratio](../bench/results/2026-09-23-package-validation-timeline-bound-f883f4e/api-equivalent-cost.json) was **0.677**. The first-edit median ratio was **0.586**, while the post-edit median ratio was **0.991**. Median time from receipt of `turn.completed` to process exit was 795 ms for Again and 764 ms for baseline. Event buffering sometimes delivers a test's start and completion in the same sample, so these receipt timestamps do not measure exact test runtime. The two runs straddle the 20% targets, which makes the result unstable for a release claim; they do not support changing the launcher architecture based on the first run's post-edit gap alone.

## 2026-09-23 package test guidance

For a JavaScript or TypeScript source candidate without a more specific previewed test, task start now reads a bounded current root `package.json` and suggests its declared test command through the matching npm, pnpm, yarn, or bun manager. The validation preview carries the manifest digest and a screened script preview, marks the selector unverified, and requires execution. Conflicting lockfiles, a conflicting `packageManager` field, placeholder scripts, oversized manifests, and symlinked manifests produce no guessed selector. Brain also recognizes an observed successful package test and can suggest it on a later matching task only while the current manifest still supports that command. The [clean-source release-binary cross-task gate](../bench/results/2026-09-23-package-test-brain-bound-7791d94/summary.json) passed: `mcp brief` supplied `pnpm test`, a completed fake-Codex launcher event made it a Brain hint on the next task, and a changed manifest withheld both hints. The fake client did not execute a test. A past pass never authorizes skipping validation. Focused unit tests cover selection, ambiguity, failed-test, and stale-manifest paths; broad task-outcome impact remains unmeasured.

## 2026-09-23 live multi-root search observation

The [clean-source live alternation gate](../bench/results/2026-09-23-live-search-multiroot-bound-ee60b2f/alternation-summary.json) passed with Codex 0.156.1 and a release binary bound to `ee60b2f`. Codex executed `rg -n 'balance|value' src tests 2>/dev/null`. Again checked the cited lines against current files, stored observations for a source and test file, surfaced them in a later brief, and withheld the edited source observation after its bytes changed. The [literal-search regression gate](../bench/results/2026-09-23-live-search-multiroot-bound-ee60b2f/literal-summary.json) also passed. Filtered Codex event traces are retained beside both reports. These gates show live capture of two common shell-search shapes, not search completeness, automatic command avoidance, or a task-speed improvement.

## 2026-09-23 live Codex search hook and trust boundary

The [clean-source live Codex search gate](../bench/results/2026-09-23-live-search-hook-bound-5e093de/summary.json) passed on a release binary bound to `5e093de`. Codex 0.156.1 completed a real `rg -n -F balance src` shell call in an isolated repository. The project `PostToolUse` observer stored a source-checked `src/ledger.py` observation, a later task brief surfaced that file, and a brief after a source edit withheld it. The gate removed the hook configuration afterward. A [filtered Codex event trace](../bench/results/2026-09-23-live-search-hook-bound-5e093de/trace-filtered.jsonl) is retained with a verified hash; unrelated error events were omitted because they can contain user config paths. This establishes one live search-capture and stale-source path, not broad command coverage or a task-speed gain.

The gate used Codex's one-off hook-trust bypass only for its fixed, inspected fixture. The [untrusted diagnostic](../bench/results/2026-09-23-live-search-hook-bound-5e093de/untrusted-diagnostic.json) completed the same search but stored no Brain observation. [Codex's hook guide](https://learn.chatgpt.com/docs/hooks) says project hooks require trust review and can be skipped until trusted. Again setup now reports its hook config as current while marking trust `not_verified`; interactive users review the exact hook in `/hooks` before expecting capture. The `again codex` launcher captures completed JSON events independently of this hook trust step.

## 2026-09-23 source-checked search handoff cohort

The [clean-source, release-binary returning search cohort](../bench/results/2026-09-23-search-returning-cohort-bound-8e982b9/summary.json) accepted all four baseline/Again pairs in both run orders and at 0 and 1,000 background source files. A fixture-controlled fake Codex client emitted a completed `rg -n -F adjust_total src` event for the prior task; Again independently matched its cited source lines against real fixture files and stored current file observations. The baseline condition received no Brain seed. In the measured tasks, Again made an edit and a unittest call without further investigation; baseline made four to seven investigation calls before the same edit and validation. The paired median completion-time ratio was 0.603 and the nearest-rank p95 ratio was 0.722. Aggregate uncached input, cached input, and output tokens were lower with Again. The [frozen API-equivalent cost estimate](../bench/results/2026-09-23-search-returning-cohort-bound-8e982b9/api-equivalent-cost.json) is $0.088684 Again versus $0.178125 baseline, a ratio of 0.498; it is not a Codex invoice. The binary embedded the same clean Git SHA as the source checkout, and raw traces and pair reports are retained beside the summary. This is one synthetic returning task at two repository sizes, not proof of general real-task or cold-task improvement. The prior search was synthetic, and the pair does not isolate the search observation from other Again task-brief features.

## 2026-09-23 combined Codex onboarding

`again mcp setup --client codex --workspace <path> --apply --with-skill --with-brain-hook` now installs the verified MCP entry, personal skill, and project Codex Brain observer configuration in one command. The matching `--inspect` reports whether each requested config is current without changing files. Codex hook trust is not verified by setup; an interactive user must review and trust the exact project hook in `/hooks` before interactive capture works. Hook ownership checks run before MCP mutation, and a hook failure after MCP installation removes a newly added MCP entry and a newly installed skill. An existing skill is preserved on rollback. The standalone `again brain hook-setup --remove` still restores the unchanged prior hook file. Focused CLI integration tests cover install, inspect, repeated install, existing handlers, removal, and conflicting hooks. This is onboarding consolidation; it does not expand the observer's tool coverage or establish an end-to-end speed gain.

The Brain now recognizes a bounded `node --test tests/test_<name>.js|mjs|cjs` command observed with exit code zero. It suggests that command on a later task only when the test file still resolves inside the repository and a current candidate source has the matching `<name>` stem. This replaces a calculator-only command, rejects shell operators and traversal, and still requires the agent to run the test again. The test file's existence is checked; its previous passing result is never reused as validation proof.

## 2026-09-23 release binary source binding

The [source-bound returning cohort](../bench/results/2026-09-23-returning-cohort-bound-e3f0067/summary.json)
accepted all four pairs, with a paired median completion ratio of 0.508 and
p95 of 0.569. Again used two actions in each run while baseline used four to
nine, and all three token totals were lower. Each Again condition received a
verified prior helper read through the real launcher; baseline did not. The
[API-equivalent estimate](../bench/results/2026-09-23-returning-cohort-bound-e3f0067/api-equivalent-cost.json)
is $0.085131 Again versus $0.168792 baseline under the frozen rate-card
assumptions. This demonstrates reduced duplicate investigation on one synthetic
returning task at two repository sizes, not product-wide or billed savings.

The [source-bound frozen cold cohort](../bench/results/2026-09-23-cold-cohort-bound-ffffc94/summary.json)
accepted all 10 pairs across five synthetic tasks and both treatment orders.
The embedded clean build SHA matched the clean source SHA before every pair.
Again's paired median completion ratio was 0.604; p95 was 1.076 because one
Rust pair completed 7.6% slower despite an earlier first edit and two fewer
actions. Aggregate uncached input, cached input, and output tokens were lower.
This meets the cohort's 20% median time target with equal accepted outcomes,
but the tail result, metered dollar cost, diverse real tasks, and proof-based
validation reuse remain release gates.
Using a frozen [GPT-6 Sol Standard short-context API rate card](https://developers.openai.com/api/docs/models/gpt-6-sol),
the [API-equivalent token estimate](../bench/results/2026-09-23-cold-cohort-bound-ffffc94/api-equivalent-cost.json)
is $0.364704 baseline versus $0.237858 Again across 10 accepted tasks per
condition, a ratio of 0.652. This is an estimate from complete reported token
counters. It is not an observed Codex invoice and assumes every request uses
the stated short-context Standard rate without other charges.

Again now embeds the Git source SHA and whether its source checkout was clean
at build time. `again build-info` reports both. The paired Codex harness
captures that identity before writing trace files and marks binary/source
binding verified only when both the build and starting checkout are clean and
the SHAs match. This strengthens provenance for future release-binary cohorts;
the already retained cold cohort below has no embedded binding and remains
diagnostic evidence.

## 2026-09-23 Node test guidance for source-adjacent validation

The [current frozen cold cohort](../bench/results/2026-09-23-cold-cohort-current-cb7828d/summary.json)
accepted all 10 baseline/Again pairs across five fixtures and both orders on
the release binary. The paired median completion ratio was 0.634, p95 was
0.868, and aggregate uncached input, cached input, and output tokens were
all lower with Again. Each pair recorded a clean source SHA; the harness does
not yet cryptographically bind the binary to that SHA, so this is diagnostic
release-binary evidence rather than final production qualification. The cohort
is small and synthetic, and metered dollar cost remains unqualified.

Task start can now fill the second complete preview with a matching
`tests/test_<source>.js|mjs|cjs` file when a task names a JavaScript source and
requests tests. A preview containing `node:test` yields an exact `node --test`
selector marked unverified and execution-required. The selector accepts only
bounded, simple relative test paths; no prior green result authorizes a skip.
An isolated 1,000-source-file `mcp brief` probe returned the explicit source,
the matching test preview, and the selector even while the full code index was
incomplete.

The [baseline-first](../bench/results/2026-09-23-js-generic-validation-trial-baseline-first.json)
and [Again-first](../bench/results/2026-09-23-js-generic-validation-trial-again-first.json)
editable diagnostics use a JavaScript repair whose prompt asks for the existing
tests without naming a command. All four patches and validations passed. Again
made an edit and test call in each run; baseline made five to seven completed
actions. Paired completion ratios were 0.604 and 0.446. These are unbalanced
debug-binary synthetic trials.
The [clean-source release-binary repeat](../bench/results/2026-09-23-js-generic-validation-clean-df1d912/summary.json)
again accepted all four outcomes in both treatment orders. Again made two
actions in each task, baseline six, and the paired median completion ratio
was 0.574. The raw event files and exact usage counters are retained beside
the summary. This is one synthetic task in two orders; it does not establish
the balanced product-wide speed or cost target.

## 2026-09-23 native Codex hook observation (opt-in)

The observer now also matches completed native `apply_patch` calls. It accepts
the documented local tool only after the live response reports exit code zero
and names a changed path that appears in the patch input. It stores a current
digest for a bounded edited file or retires the prior file observation when
the file was deleted or cannot be read. The first isolated live patch probe
reported a Codex `file_change` but lacked the Brain event with the original
five-second asynchronous timeout. After increasing that timeout to 30 seconds,
the [clean-source release-binary patch probe](../bench/results/2026-09-23-brain-patch-release-40506ff.json)
captured the native edit and current file observation in three of three runs.
This narrow result does not yet qualify all interactive edit paths.

`again brain hook-setup --workspace <path>` now previews a project Codex hook
change, `--apply` installs the observation-only handler, and `--remove`
restores an unchanged prior `hooks.json` byte for byte. Setup keeps unrelated
handlers, refuses symlinked configuration and user edits made after install,
and records ownership in a private snapshot. A
[clean-source release-binary Codex run](../bench/results/2026-09-23-brain-hook-setup-release-39327e8.json)
passed preview, apply, asynchronous read capture, preservation of an unrelated
handler, and byte-for-byte removal. This closes the manual
hook-file configuration step for opt-in interactive observation. The primary MCP
setup flow can now install the observer config with `--with-brain-hook`; Codex
still requires hook trust review before it runs.

The `again brain observe-codex-hook` stdin adapter can now record completed
interactive Codex Bash calls into the same repository Brain as the `again codex`
launcher. The adapter retains a command digest, not command text or output.
The live Codex 0.156.1 probe showed `tool_response` is a plain output string
for Bash, without an exit code. The existing source-byte matcher can record a
verified `cat` or bounded `sed` read from that string, while leaving exit
status unknown. An explicit zero exit in a structured response can yield a
recognized successful test hint. Unknown response shapes remain command
metadata only. The adapter
is idempotent for a repeated `tool_use_id`, bounded to 1 MiB input, and emits
no model-visible hook output. It is not installed by `again setup`; broader
live hook qualification remains.
The launcher remains the currently qualified automatic capture path.
An interactive read without a lifecycle task can now be nominated on a later
task by matching words in its path. The file is still rechecked against its
stored digest and authorization scope before any preview is shown.
The [live opt-in hook probe](../bench/results/2026-09-23-native-hook-e2e-09a7bb5/summary.json)
ran Codex against an isolated repository with a `PostToolUse` observer. It
captured the plain-string response, stored two bounded event rows and one
verified file observation, and retained no command text. This qualifies the
basic live read path; broader interactive tasks remain open.

## 2026-09-23 scoped cross-task Brain and cold cohort preparation

Again Brain now retains one bounded outcome row per completed Codex launcher
session. It counts completed commands, independently matched source reads,
edits, MCP calls, and recognized successful tests; it also records exit code,
whether Codex reported turn completion, and token usage when the event stream
provides valid counters. Schema 19 bounds these rows to the same 90-day and
10,000-record policy as Brain activity. `again brain show` exposes the rows,
and `again brain clear` removes them. These are client-observed measurements,
not accepted-task or validation proofs; raw command output is not stored.
The [isolated launcher handoff](../bench/results/2026-09-23-brain-run-summary-3c171dd/again-brain-run-summary-76ed747.json)
passed run capture, cross-task source freshness, and clear. In a
[live calculator pair](../bench/results/2026-09-23-brain-run-summary-3c171dd/again-brain-live-run-3c171dd.json),
both patches and validations passed, and the product run's stored token counts
matched the raw Codex event stream exactly. It recorded one edit, one test
command, and no source reread. The [authenticated release gate](../bench/results/2026-09-23-brain-run-summary-3c171dd/again-auth-product-76ed747-retry.json)
passed on the second attempt. Its first attempt timed out waiting for the
existing `follower_cancelled` audit event; that intermittent gate behavior
remains to be diagnosed before production qualification. After grouping Brain
task-query identity, the strict all-target/all-feature Clippy gate and 210
library tests passed. The current release binary also passed the
[isolated Brain gate](../bench/results/2026-09-23-brain-run-summary-f99df83/again-brain-run-summary-f99df83.json)
and [authenticated product gate](../bench/results/2026-09-23-brain-run-summary-f99df83/again-auth-product-f99df83.json)
at clean source `f99df83`.

Task matching now considers the Brain's bounded retained file set (at most
10,000 observations over 90 days) instead of only its 64 newest files. The
same scope check, two-file brief limit, and fresh content-digest check still
apply. A regression put the relevant file behind 999 newer unrelated
observations; the local 1,000-observation lookup took 5.6 ms. In the
[two-order returning-task ablation](../bench/results/2026-09-23-retained-brain-ablation-37fdc86/summary.json),
the real launcher seeded 100 newer unrelated reads in a 1,000-source-file
workspace. Both pairs passed the exact patch and unittest oracle. Seeded
Codex edited and tested without a helper search/read; cold Codex searched and
read the helper first. Seeded/cold elapsed ratios were 0.752 and 0.839.
This establishes retention beyond the old 64-file window for one synthetic
task; worst-case 10,000-file lookup latency and diverse real tasks remain
unqualified. The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-f4510d8.json)
also passed after this retrieval change.

The authenticated release-binary product gate had an outdated read-only
SQLite schema pin (15 versus the product's 18). Its verifier and unit fixture
now pin schema 18. All 18 harness unit tests pass, and the
[clean-source authenticated product gate](../bench/results/2026-09-23-auth-product-63ca04a.json)
passes `task_source_lifecycle_passed` on the release binary. This restores
the end-to-end gate for the current task-start and Brain changes.

Brain can now include a rechecked complete prior source file up to 2 KiB in
the next task brief. The whole Brain field remains capped at 4 KiB; when two
previews would exceed it, the lower-priority preview is withheld first.
The focused regression covers a 2,000-byte source, total brief bound, and
stale-source withholding. This removes the former 256-byte limit that made
many ordinary prior reads only path hints. In the [two-order live ablation](../bench/results/2026-09-23-large-brain-ablation-d105b04/summary.json)
on a 1,697-byte helper, both seeded and cold Again runs passed the exact
patch and unittest oracle. The seeded runs edited and tested without a read;
both cold runs searched and read the helper first. Seeded/cold completion
ratios were 0.626 and 0.529. This is evidence for one synthetic larger file,
not a diverse returning-task cohort.

The task-start validation preview now suggests `cargo test` for a Rust source
candidate with a current root `Cargo.toml`, or `go test ./...` for a Go source
candidate with a current root `go.mod`. These are unverified selectors and
still require execution. A release-binary `task.start` probe on the Rust
fixture returned the expected selector. The [two-order Rust diagnostic](../bench/results/2026-09-23-rust-validation-5134e43/summary.json)
accepted both baseline and Again patches and validations. Again made only an
edit and `cargo test` call in each run; baseline made additional source and
repository inspection calls. Paired elapsed ratios were 0.240 and 0.487, with
one unusually slow baseline run. This narrow diagnostic shows the new brief
did not break that workflow; it is not broad validation or Go outcome evidence.

The [returning-task cohort](../bench/results/2026-09-23-returning-cohort-e466f8a/summary.json)
uses a ledger repair whose faulty helper is outside the initial two source
previews. A prior completed `sed` read of that helper is seeded through the
real Again Codex launcher. Across both treatment orders and repositories with
0 or 1,000 decoy files, all four baseline and Again outcomes passed the edit
and validation oracle. Again's paired median completion ratio was 0.6018;
its p95 paired ratio was 0.6692. Again made the edit and test calls in every
pair while baseline made 4 to 8 calls. The comparison includes the whole
Again launch brief, so it does not isolate the Brain entry's contribution.

The [same-launcher Brain ablation](../bench/results/2026-09-23-brain-ablation-36adf59/summary.json)
isolates that contribution for the same synthetic returning task. Both
conditions use the real Again Codex launcher, workspace, fixture, task, and
model; only one has the previously verified helper read. All four pairs
passed the patch and test oracle. Seeded/cold completion ratios were
0.557, 0.600, 0.723, and 0.811 (median 0.661). In each cold run, Codex
searched for and read `src/util.py` before editing; in each seeded run it
edited and tested directly. This directly demonstrates avoided investigation
for that helper task. It does not yet establish the effect across diverse
returning tasks or justify skipping tests.

Brain observations now carry the local authorization-scope digest. Schema 18
migrates older rows with unknown scope but withholds them from scoped task
briefs until a new observation establishes provenance. The task-start lookup
can nominate up to two files from related earlier task prompts even if the
current code index did not select them. Prompt overlap only selects paths;
each nominated source must still pass a fresh content-digest check, and a
short complete preview is included only when it was not already supplied.
The old prompt text is not copied into the brief. Unit and fake-client gates
cover a history-selected file outside the initial two previews, stale-source
withholding, cross-scope isolation, and the version-17 migration.

The [frozen cold diagnostic cohort](../bench/single_agent_cold_cohort_v1.json)
adds Rust and JavaScript repairs and a Python feature edit to the two existing
Python repairs. Each fixed fixture fails its validation before the reference
change and passes its acceptance oracle afterward. The runner uses both
treatment orders for every case. Returning-task evidence is now recorded
above, while metered dollar cost and a broader accepted-task cohort remain
release gates.
At clean source `0d1008b`, the
[release Brain gate](../bench/results/2026-09-23-brain-scoped-0d1008b.json)
passed and the [cold cohort](../bench/results/2026-09-23-cold-cohort-0d1008b/summary.json)
accepted all 10 paired patches and validations. Again's paired median
completion ratio was 0.8703 (about 13% faster), short of the planned 0.80
target. The nearest-rank p95 ratio was 1.039. Aggregate uncached input,
cached input, and output tokens were all lower, but exact dollar-cost savings
are not yet qualified. Rust was nearly neutral and one JavaScript and one
feature pair regressed; those traces led to a trial prompt change that directs
the agent to use the edit result and validation before repeating a read or
diff. The trial's paired outcome evidence is recorded below.
At clean source `1a91d3d`, the same frozen
[cold cohort trial](../bench/results/2026-09-23-cold-cohort-postedit-1a91d3d/summary.json)
again accepted all 10 patches and validations. Again executed only the edit
and test actions in each task. Its paired median completion ratio improved to
0.5909; aggregate uncached input, cached input, and output tokens fell from
74,510/716,800/5,272 baseline to 57,871/428,416/2,526. The nearest-rank
p95 paired ratio was 1.148: reverse-order Rust and JavaScript tasks finished
slower despite fewer actions and tokens. This is a promising cold-task
diagnostic with a tail risk, not full release qualification. The post-edit
guidance remains in the default prompt pending
broader task evidence.

## 2026-09-23 source-matched native reads

The Brain also nominates up to four source files from a completed `rg -n` search using one literal identifier or a bounded alternation of identifiers, across up to four explicit workspace files, directories, or the root. A bounded `--glob` and trailing `2>/dev/null` are accepted. It accepts a cited match only when the reported line number and line bytes match an independently read current file, the file is within a searched subtree, and the source is at most 8 KiB. Both launcher events with a successful exit and interactive Bash hook responses without an exit code can yield these source observations. The later task still checks the file digest before showing it. This proves cited source lines, not search completeness, absence, or the command's exit status; unsupported searches remain command metadata only.

The Brain now recognizes single-file `cat` and bounded `sed -n 1,Np` reads,
including relative paths, only when completed client output exactly matches
bytes independently read from the named current workspace source file. It
records a path and digest, not the arbitrary output. Shell composition,
unmatched output, missing source files, large files, and unsupported selectors
remain plain command metadata. The later task still rechecks current bytes
before presenting a source preview. This extends read observation to the
`sed` shape seen in the live calculator trace without assuming that the
client’s session cwd was the effective command cwd.
The [clean-source release handoff gate](../bench/results/2026-09-23-brain-source-matched-5324f06.json)
passes at `5324f06` with a relative `sed` read, later-task handoff,
stale-source withholding, interactive brief delivery, and Brain clear. The
202 passing library tests include mismatched output and composed-command
refusal.

## 2026-09-23 materialized repository memory

Again Brain now retains a bounded latest observation per edited file and per
recognized successful test command, separate from its bounded raw event
timeline. A later task looks up files selected by the current source preview
and code relevance candidates, then rechecks the current bytes before showing
the history. The latest test command remains an unverified suggestion and
never authorizes a test skip. Event recording updates the materialized rows
atomically. `again brain show` exposes both event history and materialized
observations, labeling the latter as historical until a task brief rechecks
them; `again brain clear` clears both stores. The focused test pushes
the originating edit and test beyond the 64 most recent events yet still
finds their current materialized hints. The isolated Codex launcher gate also
passes. This fixes the recent-event-window limitation; it does not yet prove
that retained knowledge lowers real task time.
At clean source `78db32774cdd44ff5d3d55730902b3e6087cbbf4`, the
[release-binary Brain gate](../bench/results/2026-09-23-brain-materialized-e2e-78db327.json)
and [Codex launcher gate](../bench/results/2026-09-23-brain-materialized-codex-launch-78db327.json)
passed on the same binary. The materialized memory is repository-local; no
cross-user company knowledge or qualified test-result reuse exists yet.

The Brain's observed validation hints now retain and select among exact
successful Python, Rust (`cargo test`), and Go (`go test ./...`) commands.
A later task receives the newest command matching a candidate source language;
Rust and Go suggestions also require the corresponding root manifest to still
exist. A newer test in another language no longer hides a relevant earlier
command. Failed commands never become test hints. These are only suggestions:
the launcher still requires the agent to run validation, and the manifest
existence check does not prove that an old test result is current.
The 201 library tests and no-default-features check pass. The
[clean-source release launcher gate](../bench/results/2026-09-23-brain-multilang-e937d3d.json)
passes at `e937d3d`; the language-selection and stale-manifest behavior are
covered by focused unit tests, while the launcher gate exercises the existing
Python handoff path.

Completed Codex `cat` commands with one literal absolute source-file operand
now produce a second, source-checked observation. The Brain retains only the
path and digest, then rechecks file bytes on a later task. For a relevant file
that the ordinary prebrief did not already preview, it can include one complete
source preview up to 256 bytes; changed content withholds the old observation.
This covers a narrow common read shape and avoids storing arbitrary client
output. Relative paths and composed shell commands do not enter this path
because the event stream does not prove their effective working directory or
shell semantics. The 202 library tests pass, including preview suppression
when a file was already supplied by the prebrief, mutation withholding, and
absence of raw command output in the stored event.
The [clean-source release launcher gate](../bench/results/2026-09-23-brain-read-31b1f06.json)
passes at `31b1f06` with an observed absolute source read, next-task
handoff, stale-read withholding, edit/test handoff, and Brain clear.

The Brain brief is now calculated inside authenticated `task.start` and
included in both its structured result and bounded text summary. Interactive
agents using the MCP tool can receive the same current history as an `again
codex` launch. The launcher reads that field instead of reopening the store
and repeating the relevance/freshness work. The installed Codex skill tells
agents how to use current complete previews and treat prior test commands as
suggestions. A fake-client end-to-end gate exercises both entry points; live
interactive task-level speed remains to be measured.
Because Brain records do not yet carry an authorization scope, `task.start`
exposes them only through the canonical local-workspace scope; a custom MCP
scope gets no Brain field. This keeps repository history from crossing an
unmodeled authorization boundary.
The [clean-source release handoff gate](../bench/results/2026-09-23-brain-task-start-3788b4b.json)
passes at `3788b4b` for interactive `mcp brief` and launcher handoff. The
custom-scope service test exercises withholding even when the local Brain
contains a current file observation.
A [baseline-first live Codex calculator pair](../bench/results/2026-09-23-brain-task-start-live-calculator-v1.json)
then accepted and validated both patches. Again reached the first edit in
4.82 versus 13.39 seconds, completed in 13.97 versus 22.01 seconds, and made
4 versus 7 completed actions with 65,121 versus 97,892 input tokens. This
fixture began cold, so it tests the shared task-start architecture and launch
brief but does not isolate returning-task Brain value. The harness records a
dirty source tree because its report was created during the run; the binary
SHA-256 matches the clean-source release handoff gate. It is one local pair,
not the balanced task-level qualification.

## 2026-09-23 single-agent Again Brain first slice

`again codex` now requests Codex's structured event stream by default. Its
launcher renders completed agent messages and command output, and records
bounded metadata for completed commands and file edits in the workspace's
local SQLite store. It stores no raw command text or output. A small whitelist
recognizes successful Python test commands as unverified future hints. File
edit records carry a post-edit digest and enter a later task's brief only
after the current file still matches. `again brain show` and `again brain
clear` inspect and remove this retained activity. Existing same-task
suggestions now appear in the launcher prebrief with an explicit unverified
label.

The focused parser, migration, and store tests pass. A
[local fake-client gate](../bench/results/2026-09-23-brain-single-agent-local-v1.json)
confirmed automatic event capture, a current edit/test hint in the next task's
launch prompt, stale-edit withholding after mutation, and user-initiated
clear. At clean source `a302cd5aee5fed4bce87a24b315c5507a1c6d2e5`, the
same [release-binary Brain gate](../bench/results/2026-09-23-brain-release-e2e-a302cd5.json)
passed. The existing release-binary launcher gates also passed for
[Codex](../bench/results/2026-09-23-brain-codex-launch-a302cd5.json) and
[Claude](../bench/results/2026-09-23-brain-claude-launch-a302cd5.json),
including peer wait, edited-source refresh, and lease retirement. This is a
first implementation slice: the
brain does not yet verify arbitrary shell output, retain full agent knowledge,
intercept a call before execution, reuse tests, cover Claude events, or show
a measured single-agent completion-time gain. The new structured-output
renderer still needs qualification against a real Codex task; the fake-client
gate only proves its completed message rendering.

A [real Codex calculator pair](../bench/results/2026-09-23-brain-codex-live-a302cd5.json)
then passed both patch and validation oracles through the release binary. The
Again run made three agent actions versus six baseline, reached first edit in
5.19 versus 16.86 seconds, and finished in 14.67 versus 23.61 seconds. The
pair explicitly requested Codex JSONL, so it verifies real client event
capture and the accepted edit, but not the launcher's new human-readable
renderer. It is one unbalanced local diagnostic, not a general speed claim.

## 2026-09-23 four-platform native beta checkpoint

[Native qualification run 35919913635](https://github.com/alakhanpal23/again/actions/runs/35919913635)
completed successfully at exact source `56d9d3e4e2e1f0b349ab126d422a617b04dd1658`.
The [matrix summary](../bench/results/2026-09-23-native-beta-matrix-56d9d3e-summary.json)
binds four native reports: [macOS arm64](../bench/results/2026-09-23-again-v0.1.0-beta.1-aarch64-apple-darwin.native-smoke.json),
[macOS x86_64](../bench/results/2026-09-23-again-v0.1.0-beta.1-x86_64-apple-darwin.native-smoke.json),
[Linux arm64](../bench/results/2026-09-23-again-v0.1.0-beta.1-aarch64-unknown-linux-gnu.native-smoke.json),
and [Linux x86_64](../bench/results/2026-09-23-again-v0.1.0-beta.1-x86_64-unknown-linux-gnu.native-smoke.json).
Every package passed installation, removal, daemon startup, authenticated MCP,
tool catalog, client setup plan, and doctor checks. The downloaded archive
SHA-256 values match all four reports. This qualifies that exact source for
the native package smoke matrix; it is not a published release, live-agent
quality result, or Linux pytest execution qualification.

## 2026-09-23 peer-wait call budget

The Codex and Claude launchers now retry an active peer's `task.claim` with
bounded backoff: 250 ms, 500 ms, 1 second, then at most every 2 seconds until
the configured deadline. The previous fixed 250 ms interval could issue about
120 claim requests during the default 30-second wait even when the leader was
still working. The new schedule issues at most 19 in that interval, with up to
2 seconds of added handoff detection delay after the initial retries. This is
control-plane call reduction; it does not change repository result-cache hits.
The clean-source release-binary launcher gates passed for
[Codex](../bench/results/2026-09-23-codex-launch-peer-backoff-release-v1.json)
and [Claude](../bench/results/2026-09-23-claude-launch-peer-backoff-release-v1.json)
at `78a1de9c19e79416b626eed12529c907f24fde36`; they cover leader/follower
handoff, fresh source after takeover, lease retirement, and the one-second
fallback. These fake-client gates do not measure live model completion time.
A metadata-only proof variant for `repo.tree` and `repo.glob` was tested locally
and discarded: it saved 17–31 ms on cold 1,000-file calls, did not improve warm
calls, and added a separate proof schema. The existing direct route remains
the simpler choice until a complete, cheaper change signal is available.

## 2026-09-23 second live edit fixture

The [baseline-first](../bench/results/2026-09-23-codex-running-balance-wrapper-baseline-first-v1.json)
and [wrapper-first](../bench/results/2026-09-23-codex-running-balance-wrapper-again-first-v1.json)
Codex pairs accepted the same running-balance repair. The wrapper reached first
edit in 5.68/5.65 seconds versus 19.24/18.19 seconds baseline and completed in
20.68/18.75 seconds versus 26.10/26.39 seconds. Input tokens were
65,680/65,594 versus 101,534/115,688. These are two local dirty-source
diagnostics on one additional fixture, not a general speed qualification.
They exposed a post-edit validation detour: the wrapper had supplied a complete
indexed unittest preview, but the validation hint recognized only a different
preview origin. The indexed path now records its origin and can suggest
`python3 -m unittest discover -s tests` as an unverified selector. The agent
must still execute it; a test hint never grants a cached test result.
The [clean-source authenticated release gate](../bench/results/2026-09-23-auth-product-e2e-indexed-validation-hint-v1.json)
passed at `eb12c17fa027556e88ce6f56cf6c9a7cf1dbf2ba`. In one follow-up
[live pair](../bench/results/2026-09-23-codex-running-balance-hint-baseline-first-v1.json),
the wrapper ran `python3` on its first validation attempt, passed the edit
oracle, and completed in 16.20 seconds versus 20.15 seconds baseline. This is
still one local diagnostic, not a qualified general speed claim.

The second fixture now has two-agent, 1,000-file runs in both treatment orders:
[default wait, baseline first](../bench/results/2026-09-23-codex-parallel-running-balance-baseline-first-v1.json)
and [default wait, wrapper first](../bench/results/2026-09-23-codex-parallel-running-balance-again-first-v1.json).
Each passed the exact patch oracle with one source edit. Again made 3/5 agent
tool calls versus 14/13 baseline and used 81,316/98,430 input tokens versus
256,318/232,622. First edit took 5.29/5.48 seconds versus 12.89/11.81.
Completion was mixed: 22.71 versus 36.11 seconds, then 31.93 versus 28.16.
The follower reran unittest validation after the leader exited. That work
cannot be skipped without a qualified validation-result proof.

A [five-second wait, baseline-first](../bench/results/2026-09-23-codex-parallel-running-balance-wait5-baseline-first-v1.json)
and [reverse](../bench/results/2026-09-23-codex-parallel-running-balance-wait5-again-first-v1.json)
trial also passed the oracle, but the follower joined while the leader was
active and used about 151,000 input tokens in both orders. Again completed in
34.91/31.72 seconds versus baseline 38.86/30.05. The 30-second default remains
in place; shorter waiting did not produce a consistent completion-time gain
and materially increased repeated investigation in this fixture. These are
local task diagnostics, not a representative parallel-agent cohort.

## 2026-09-23 prebrief launch checkpoint

The daemon now supports `task.start` with `previewOnly=true`: it registers exact
task intent and returns verified source previews without claiming a
coordination lease. `again mcp brief` exposes that result through the
authenticated daemon. `again codex` now uses a normal task start, holds and
renews its elected leader lease while Codex runs, and supplies the verified
previews in the initial `codex exec` prompt while keeping the ordinary Again
MCP connection available. A daemon regression test confirms that a second
authenticated client can immediately become leader after a preview-only start.
The launch prompt also carries a bounded current snapshot of source-backed
facts, explicit unknowns, and result references. It omits that snapshot when
freshness is incomplete or the selected fields exceed 4 KiB, directing the
agent back to MCP. An isolated two-client CLI smoke confirmed that an unknown
published by one client appeared in the next client's launch prompt.
Preview-only task start now reads the current scoped task lease without
claiming it. If another leader is active, the launch prompt asks the agent to
join and inspect peer findings in its own authenticated MCP session before
duplicating work. This is an advisory point-in-time observation; the later
claim remains authoritative. A daemon regression test covers both an
available lease and an observed peer leader.
The [post-change live baseline-first pair](../bench/results/2026-09-23-codex-pair-product-wrapper-peer-preview-baseline-first-v1.json)
passed both edit oracles; the wrapper made no MCP calls before editing and
reached first edit in 4.85 seconds versus 14.29 seconds for baseline. This
single local pair does not qualify parallel-leader behavior with live agents.
The launcher subsequently changed to hold its own leader lease throughout
`codex exec`, because a fast first launch without a lease left the next fast
launch unable to see an active peer. An isolated two-process smoke observed
the leader during the run and its retirement at exit. A new release-binary
launcher gate exercises two concurrent fake Codex clients, the follower's
peer guidance, and lease retirement. One further live baseline-first pair
passed the edit oracle with a 5.32-second first edit versus 15.27 seconds in
baseline, and no model-initiated MCP call before editing. Its
[diagnostic report](../bench/results/2026-09-23-codex-pair-held-lease-baseline-first-v1.json)
is local dirty-source evidence; a live two-agent cohort remains open.
Two formal live parallel Codex pairs on committed 1,000-file fixtures passed
the edit oracle in both orders with one repair and a joining follower. Again
used 3–4 shell calls plus 1–2 MCP calls versus 13 shell calls in each baseline
pair, and reached first edit in 5.37/6.49 seconds versus 13.48/16.87 seconds.
Validated completion was mixed: 29.66 versus 28.28 seconds in baseline-first
order and 23.41 versus 33.79 seconds in reverse order. Input tokens were
204,159 versus 225,779 and 150,351 versus 213,322. See the
[baseline-first](../bench/results/2026-09-23-codex-parallel-pair-committed-baseline-first-v1.json)
and [reverse](../bench/results/2026-09-23-codex-parallel-pair-committed-again-first-v1.json)
reports. Earlier uncommitted-fixture diagnostics are retained but not used for
comparison because `git status` treated every file as untracked.
In a diagnostic that delayed the second Again launch until the leader exited,
the follower used the fresh source preview, made no MCP call or file read, and
only ran validation. Both orders passed; total input tokens were 80,996 and
80,932 versus 197,810 and 214,874 in their concurrent baselines. Completion
was 24.44 versus 24.53 seconds and 24.28 versus 25.61 seconds. See
[baseline-first](../bench/results/2026-09-23-codex-parallel-pair-delayed-baseline-first-v1.json)
and [reverse](../bench/results/2026-09-23-codex-parallel-pair-delayed-again-first-v1.json).
The launcher now waits up to 30 seconds on an exact peer task, then refreshes
verified source/context and takes over the lease when available. The
[release-binary launcher gate](../bench/results/2026-09-23-codex-launch-peer-wait-release-v1.json)
at clean source `63c5730` passed a leader/follower handoff: the follower stayed
idle during the lease and received the leader's edited source in its fresh
brief. The [expanded release gate](../bench/results/2026-09-23-codex-launch-peer-wait-fallback-release-v1.json)
at clean source `b207f2a` also passed the one-second timeout path: the follower
launched with peer guidance while the leader remained active. Two live release-binary parallel pairs then passed the edit oracle in
both orders with one source edit. The default wrapper used no model-initiated
MCP calls, 2/5 shell calls versus 14/13 baseline, and 80,942/97,871 input
tokens versus 224,695/242,154 baseline. First edit was 6.87/5.87 seconds
versus 13.05/12.55; completion was 23.81/31.95 versus 23.46/32.43.
See [baseline-first](../bench/results/2026-09-23-codex-parallel-pair-wrapper-wait-baseline-first-v1.json)
and [reverse](../bench/results/2026-09-23-codex-parallel-pair-wrapper-wait-again-first-v1.json).
This is still a small local two-agent fixture; it does not prove repeat-heavy
performance across repositories or a general completion-time gain.
The [authenticated release-binary product lifecycle gate](../bench/results/2026-09-23-auth-product-e2e-peer-wait-v1.json)
also passed at clean source `45a5777` after the peer-wait launcher change.
`again claude` now shares the authenticated prebrief, bounded peer wait,
lease renewal, and current-source takeover path in Claude Code print mode.
The launcher passes a workspace-bound MCP configuration through the documented
CLI flag. The [clean-source fake-client release gate](../bench/results/2026-09-23-claude-launch-peer-wait-release-v1.json)
at `18b3176` passed its argument shape, lease handoff, refreshed source, and
bounded timeout path. A live Claude Code binary is unavailable on this host, so Claude
quality, latency, and token cost remain unverified.
The same shared-client harness passed again for Codex at clean source
`3951310` in its [release report](../bench/results/2026-09-23-codex-launch-shared-client-release-v1.json).
The [authenticated product lifecycle gate](../bench/results/2026-09-23-auth-product-e2e-shared-launchers-v1.json)
also passed at clean source `3bc5d90` after the shared launch code landed.
The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-prebrief-peer-v1.json)
passed at clean source `917959f` after the peer observation and blocked-task
guard were added. Its product lifecycle assertions do not exercise a real
parallel Codex leader.
The CLI was smoke-tested with a private temporary repository, a fake Codex
executable that captured arguments, and a second authenticated MCP client.
The same smoke passed on the release binary built from clean source
`6d25a2f`, and the [authenticated release-binary product gate](../bench/results/2026-09-23-auth-product-e2e-prebrief-v1.json)
passed at that source. The retained gate covers the existing task/source
lifecycle; the new CLI smoke is currently local terminal evidence.

Two live Codex pairs using preview-only prebrief and the full Again MCP
connection passed the exact edit oracle in both treatment orders. In the
[baseline-first pair](../bench/results/2026-09-23-codex-pair-preview-only-baseline-first-v1.json),
first edit and completion took 8.43/15.99 seconds with prebrief versus
13.15/20.99 seconds with baseline; input tokens were 48,218 versus 121,291.
In the [reverse pair](../bench/results/2026-09-23-codex-pair-preview-only-again-first-v1.json),
they took 5.11/11.04 versus 13.42/23.19 seconds; input tokens were 48,242
versus 97,536. Times include 0.15 second of brief preparation. These are
small local dirty-source diagnostics on one edit fixture, not a qualified
speed or cost claim. A compact `task.start` text response and a one-tool MCP
surface did not improve the same workload. The next gate is clean-source
release-binary verification of the new CLI and balanced repeat-heavy parallel
agent cohorts, including shared context after an agent claims its own task.

The first actual `again codex` wrapper pairs also passed the edit oracle but
Codex redundantly called `task.start` before editing, erasing much of the
latency gain ([baseline-first](../bench/results/2026-09-23-codex-pair-product-wrapper-baseline-first-v1.json),
[reverse](../bench/results/2026-09-23-codex-pair-product-wrapper-again-first-v1.json)).
The launch prompt now says explicitly that its verified previews are sufficient
for the first edit and that MCP is available when fresh or peer context is
needed. The next two actual-wrapper pairs made no MCP calls before the edit,
passed the same oracle, and reached first edit in 5.31 versus 13.17 seconds
([baseline first](../bench/results/2026-09-23-codex-pair-product-wrapper-guided-baseline-first-v1.json))
and 5.51 versus 12.86 seconds
([wrapper first](../bench/results/2026-09-23-codex-pair-product-wrapper-guided-again-first-v1.json)).
Completion was 14.20 versus 20.88 seconds and 14.34 versus 19.26 seconds;
input tokens were 48,494 versus 97,698 and 48,437 versus 87,632. The
wrapper's daemon preparation is included in elapsed and first-edit time.
These are local dirty-source diagnostics on one fixture, not product-wide
performance qualification.
The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-prebrief-context-v1.json)
passed at clean source `d1095ed`; it retains the existing task/source lifecycle
checks after the prompt change. The actual-wrapper live pairs are local
diagnostics, and the release gate does not yet run Codex.

## 2026-09-23 direct context architecture checkpoint

Schema v15 separates direct task observations from leased cache results.
Task-bound `repo.stat` and `repo.read` of files up to 8 KiB publish
source-backed facts without acquiring a cache lease or granting a result
reference. Larger reads retain the lease path and its concurrent join.
Repeated direct calls execute the built-in provider and return fresh output;
the observation can only support shared context. A second provider observation
checks the initial fact admission,
and the source recipe reexecutes the built-in tool during task-start or delta
revalidation. The [clean-source authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-direct-small-read-v1.json)
passed at `69d4ffde3959bc4c4e65d15e34ab4e07f3c97165`, including peer facts
from direct stat and small read, unrelated-edit preservation, relevant-edit
retirement, and refusal to grant cache retrieval from either direct observation.
Local daemon library
tests passed 193 with two ignored; the Python product harness tests passed 27.

The [1,000-file local value probe](../bench/results/2026-09-23-direct-context-stat-value-provider-v3.json)
measured `repo.stat` warm p50 at 0.347 ms through the direct context lane versus
0.171 ms execute-only; cold p50 was 11.493 ms versus 0.400 ms. These are
per-call dirty-source diagnostics, not task-level acceleration evidence.
The [small-read value probe](../bench/results/2026-09-23-direct-context-small-read-value-v1.json)
measured cold small read at 16.153 ms through direct context versus 1.048 ms
execute-only; warm p50 was 0.473 versus 0.266 ms. The previous exact first
small-read path took about 60 ms on this fixture. These runs used a local
dirty source and do not establish a task-level gain. Large reads and broad
search/tree paths remain coupled to costly exact-result proof, and the paired
Codex MCP-only fixtures at this point had not shown a validated completion or
token-cost win. Later prebrief wrapper pairs above did on one local fixture.
Wider direct admission, corruption
recovery, balanced repeat-heavy agent cohorts, and exact-SHA hosted gates
remain open.

The first `task.start` index refresh on the same 1,000-file fixture previously
spent its full two-second parse budget and returned a brief marked
`parse_time_exceeded`. Increasing the bounded manifest observation batch from
64 to 512 amortizes workspace and Git fences. The [release-binary task-start
probe](../bench/results/2026-09-23-release-task-start-batch512-v1.json)
measured a 0.964-second median across twelve fresh tasks versus 2.220 seconds
in the [previous release probe](../bench/results/2026-09-23-release-task-start-value-v1.json).
Both returned 24 candidates; the faster brief no longer reported parse-time
exhaustion. These are local synthetic task-start measurements with an unverified
source-to-binary binding, not a coding-task speed result. The index still
revalidates all admitted files and can remain expensive on larger repositories.
The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-batched-index-v1.json)
passed against clean source `8f8cbf2fe9c01e39b0ee7faf49010a0aa3079262` after the
batch change, covering shared direct facts, exact in-flight work avoidance,
invalidation, scoped retrieval, corruption refusal, and lease recovery.

Two further live Codex pairs on the 1,000-file edit fixture passed the exact
edit oracle in both orders, but Again reached the first edit later in both:
14.1 versus 11.1 seconds in the [baseline-first pair](../bench/results/2026-09-23-codex-pair-batched-index-baseline-first-v1.json)
and 18.3 versus 12.0 seconds in the [reverse pair](../bench/results/2026-09-23-codex-pair-batched-index-again-first-v1.json).
Again made one `task.start` call, no follow-up repository calls, and one
successful validation call; baseline made several shell inspection calls.
The Again input-token counts were about 123k in both orders, above the
baseline's 97k and 114k. These are small local diagnostics on dirty source,
not a qualified cost estimate. A diagnostic proxy advertised only `task.start`
instead of the full 22-tool, 17.3 KiB MCP surface. Its
[baseline-first](../bench/results/2026-09-23-codex-pair-minimal-surface-baseline-first-v1.json)
and [reverse](../bench/results/2026-09-23-codex-pair-minimal-surface-again-first-v1.json)
pairs also passed but did not improve first-edit time or input tokens. A
schema-only reduction is therefore not a demonstrated fix for this workload.
The next client experiment must isolate brief content and model turns, and the
product still needs repeat-heavy parallel-agent cohorts.

Gateway stats now count `direct_observations_published` separately from
`provider_calls_avoided`; direct facts never increment the avoided-call count.
The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-direct-metrics-v1.json)
passed at clean source `81e0a857da3654f0ac51a4c6dd0d7944cca9dc85` and checked two
direct observations against one genuinely avoided provider execution.

Current hosted evidence checkpoint: source commit
`bd24946e613af656d35c6af653a6cf25adc8359d` passed exact-SHA hosted
[`CI run 33145078831`](https://github.com/alakhanpal23/again/actions/runs/33145078831)
on 2026-08-27. Its macOS and Ubuntu jobs passed formatting, pinned Rust 1.88
strict Clippy, locked tests, offline evidence/harness suites, and the explicit
100,000-case gate; the stock-Linux lane also retained the required typed
non-qualifying capability result. Gate 2 retains a narrower live-evidence checkpoint: source
commit `3d1fb201507a43b830d5ce341b2253957634016d` passed exact-SHA hosted
[`CI run 32963128960`](https://github.com/alakhanpal23/again/actions/runs/32963128960)
and the provisioned Linux x86_64
[`Gate 2 run 32965300493`](https://github.com/alakhanpal23/again/actions/runs/32965300493)
on 2026-08-26. The latter completed 100/100 fixed two-task samples with both
live delivery orders on kernel `6.8.0-134-generic`. The hardened offline
verifier accepted artifact `9605461989` with 302 exact members, archive SHA-256
`43f3be33e9d92e28198ccab64deab1db6533c6a66c0ed7d1523f6fde4f371dfa`,
and member-manifest SHA-256
`4cb7287d6940b43a9720b10b82f90518b32abd319b3c9343df69c42ab20cf3ae`.
This closes only the command-free, non-authoritative Gate 2 transport proof;
it grants no Python, EffectIR, profile, execution, or reuse authority.

## Local vertical slice

| Capability | Status | Evidence / limitation |
|---|---|---|
| Durable task-intent coordination | implemented locally; live-agent qualification open | `task.start` stores exact agent-supplied prompt bytes as unverified local intent, converges different external task IDs for the same prompt within one repository/workspace/authorization scope, and refuses reuse of a task ID with conflicting prompt bytes. It automatically elects one bounded task leader, exposes owner-authenticated heartbeat/finish/cancel operations, retires leadership on recipient disconnect or cancellation, and preserves canonical identity across daemon restarts. Canonical tasks and aliases have separate hard limits; schema-open validation checks prompt bindings, canonical aliases, foreign keys, and capacity. Similar prompts deliberately remain distinct because semantic similarity grants no convergence authority. Durable stats expose task, alias, and exact-prompt convergence counts. |
| Repository-aware MCP gateway | default CLI product; expanded local E2E/onboarding/chaos passed; not production-qualified | The gateway lists 13 bounded read-only repository/Git tools, five task tools (`start`, `inspect`, `list`, `claim`, `transition`), and four context tools (`delta`, `publish`, `retrieve`, `cancel`). The task/context tools require the same-user daemon transport; ordinary stdio cannot mint recipient authority. Canonical request translation, descriptor-retained workspace observation, exact dependency-bound reuse, cross-process SQLite/CAS coordination, bounded queues, session cancellation, serialized responses, lease recovery, corruption quarantine, and workspace-bound Codex/Claude setup are integrated. Git reuse binds bounded control state, HEAD, index, source dependencies, and the exact Git executable. Repository-local includes and external ignore/attribute dependencies cannot create reuse authority; nested worktree/submodule state bypasses reuse for affected status/diff queries; configured filters, diff commands, text converters, alternate-reference commands, and external worktrees are refused before Git starts. The local context ledger admits only exact built-in observations as verified facts, retains agent prose as unverified suggestions, exposes task-scoped exact retrieval, and invalidates facts and references through complete dependency edges. The same-user daemon proves full delivery only after complete response write and flush, then permits a compact reference solely for the exact recipient/scope/session/turn/connection/compaction/lifecycle tuple; cancellation, disconnect, compaction, partial write, and generation changes fall back to full. Durable metrics revalidate exact unquarantined result bytes and source receipts and count duplicate response envelopes once. The earlier retained [release E2E](../bench/results/2026-08-27-agent-gateway-product-e2e-release-v3.json), [onboarding smoke](../bench/results/2026-08-27-agent-gateway-onboarding-smoke-v2.json), and [chaos run](../bench/results/2026-08-27-agent-gateway-chaos-soak-v3.json) remain the immutable baseline. Expanded source `bd24946e613af656d35c6af653a6cf25adc8359d` passed hosted CI. Local hardening source `c530586f9dfddb0faef30f4ec919b8937d3a71a4` passed the prior complete test matrix plus release-binary product and repository harnesses. Current paired-agent evidence is local and test-only, not a retained hosted artifact or real-agent task-quality benchmark. Production/cross-user recipient authentication, upstream CLI configuration, task-quality qualification, hostile-binary network isolation, and production qualification remain absent. All Linux execution/reuse authority remains disabled. |
| Paired local multi-agent gate | deterministic daemon E2E and editable harness implemented; live agent cohort open | Two independent authenticated MCP clients start one task, receive full context before acknowledged compact context, converge two concurrent eligible repository reads to one physical execution plus one join or exact retrieval, share verified facts/source locators/full-result references, preserve the result after an unrelated mutation, and both receive invalidation after a relevant mutation. The gate requires the stale result reference to refuse, the changed result to execute once, and false-hit quarantines to remain zero. The separate editable paired harness uses independent identical Git fixtures, allows exactly one accepted source repair, rejects test/collateral edits, balances treatment order, retains first-edit through final-outcome timings, requires real durable Again activity in live treatments, and bounds runs, time, files, and captured output. Its retained 10-pair offline qualification passed, but deliberately grants no real-agent quality or acceleration claim. Pinned Codex/Claude cohorts and outside-user evidence remain open. |
| Explicit local CLI | implemented MVP path | `again run -- <argv...>` observes actual cwd/streams/environment, enforces `strict-read-v0.5`, returns full streams, and executes audited TTY calls once uncached with inherited streams |
| Explicit compact reference | implemented opt-in path | `again reference -- <argv...>` performs the same live request/runtime/executable/proof/blob validation, emits bounded content-addressed JSON on an existing hit, records actual bytes omitted, and never executes on a miss; context visibility remains the caller's explicit assertion |
| Instruction-only Codex skill | implemented onboarding path | `again setup --codex` manages the personal `$HOME/.agents/skills/again` skill by default or project `<repo>/.agents/skills/again` with `--project`; ownership-checked removal is reversible, no hooks are installed, and doctor reports both scopes plus duplication |
| Automatic Codex hook rewriting | disabled before parsing | current hooks support `updatedInput` and expose session `cwd`, but drop an `exec_command` call's effective per-call workdir and omit TTY, shell/login, sandbox and remote environment. Production therefore returns before reading/parsing stdin and emits nothing. Exact-envelope parsing, explicit-absolute-executable guard, opaque handoff, runtime checks, and `PreCompact`/`PostCompact` are reachable only through the explicit unsafe test flag |
| Account-free external per-workspace state | implemented with same-user/root trust boundary | disposable Unix state defaults to `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>` with private app-owned levels and no workspace mutation; `AGAIN_HOME` selects an absolute external persistent root; final symlinks, unowned/non-root ancestors, writable non-sticky ancestors, and existing roots that are not owned real `0700` directories are rejected; same-user/root pathname races and unauthenticated same-user DB writers remain |
| Strict parsing and explicit refusal | implemented for narrow macOS v0 | an ineligible explicit call errors without execution so the caller can rerun unchanged; policy requires `pwd -P`, `ls --color=never`, explicit paths for every `grep`/`rg`, and `--no-ignore --sort=path` for every `rg`; configured ripgrep and explicit recursive `.git` directories/aliases are rejected; Linux execution intentionally fails closed |
| Executable and OS identity | implemented for macOS `strict-read-v0.5` | exact Apple path/tool BLAKE3 plus an exact reviewed `SystemVersion.plist` BLAKE3; macOS 15.6.1/24G90 and 26.5/25F71 have separate profiles. Codex ripgrep requires an exact reviewed bundle or standalone-package path/BLAKE3/OS profile. Codesign identifier/team is descriptive metadata, not strict signature or byte authentication. Unknown updates fail closed |
| Ambient external-byte overrides | implemented fail-closed | any present loader, sanitizer, locale, terminal or timezone override in the documented `DYLD_*`/`LD_*`/`Malloc*` and fixed-name denylist refuses v0 admission because referenced external bytes are not fingerprinted |
| Runtime-context binding and hit probe | implemented with transient-resource limitation | key/proof bind real/effective uid/gid, supplementary groups, supported macOS rlimits, and signal mask/dispositions/flags; every served hit spawns the exact executable with fixed probe arguments, not requested work. The probe cannot model later or workload-sized transient global resource needs |
| Scoped request fingerprint | implemented with concurrency limitation | content, recursive tree, listing, identity, absent path, symlink, special-file, restored-mtime, inode and ctime tests; observations are sampled/path-based and do not close plan-to-use or concurrent-mutation races |
| Verified digest memoization | implemented | dev/inode/mode/uid/gid/size/mtime/ctime tuple, SQLite v2, corruption/migration/inode/ctime tests |
| Local result CAS, lifecycle, and quarantine | implemented with same-user trust limitation | BLAKE3 blobs, bounded cleanup, atomic convergence/divergence, SQLite WAL/FULL sync, and fail-closed semantic record/result-row validation; no cryptographic binding against a malicious same-user DB writer |
| First-run double validation | implemented | exact streams/status/post-input fingerprint and fixed equality fixtures; no deliberate shadow-divergence fixture and not complete evidence of determinism |
| Bounded exact-output admission | implemented | cold output streams live; reusable results require exit zero, empty stderr, exact shadow agreement and captures no larger than 16 MiB per stream; blobs are capped at 16 MiB; after presentation, bookkeeping failures preserve child status |
| Exact full-stream replay | implemented | every `again run` cache hit returns complete stdout/stderr after a real exact-executable capability-probe child; requested argv is not rerun; `show` retrieves stored bytes; the separately requested `reference` presentation is described above |
| Opt-in encrypted team CLI | implemented vertical slice, not publicly provisioned | `again team run --profile <absolute-private-profile> -- <bare argv...>` preflights the portable subset, uses exact `LANG=C`/`LC_ALL=C`, bypasses all cache work on any TTY, binds a profile-specific runtime checkpoint, accepts only verified encrypted v2 plaintext as a hit, captures/publishes misses when producer credentials exist, and otherwise executes locally once. `again team inspect --profile <absolute-private-profile> --json -- <bare argv...>` reuses that exact local admission and emits deterministic secret-free request/trust requirements without transport or requested-command execution. All profile state is rejected inside the workspace. The checked-in CI wrapper/action consumes the same manually created state; no hosted endpoint, profile generator, or signed-trust control plane exists |
| Automatic output compaction | local shared-context path implemented; generic hook path disabled | The same-user coordinator sends full task context first and permits compact references or deltas only after the exact response is completely written and flushed for that recipient. Cancellation, disconnect, compaction, lifecycle change, or retirement removes compact authority. Generic Codex hooks still expose neither an effective output ceiling nor a delivery receipt, and the separate explicit `reference` command does not infer delivery. |
| Explain/stats/doctor | expanded product diagnostics implemented locally | `explain` selects the latest terminal decision across explicit execution and gateway events and classifies execute, reuse, join, bypass, and refusal with its durable reason. `stats` exposes gateway coverage/joins/delivery metrics plus durable context events, current facts/references, active work, invalidations, receipts, and acknowledged byte omission. `doctor` reports same-user coordinator feature/platform/transport readiness and the pytest contract-only passthrough state with exact qualification blockers. Pre-event refusal traces, per-resource dependency explanations, GC detail, and hosted diagnostic qualification remain open. |
| Gate 1 real-repository corpus harness | four-language local gate passed; outside-user gate open | The offline Python harness accepts explicit absolute paths to local Rust, Python, Go, and TypeScript Git worktrees, copies a bounded deterministic tracked-file subset into private temporary workspaces, pins the exact Again binary bytes, and compares native, cold, warm, and mutated-input results with exact status/stdout/stderr checks. It never clones, downloads, or accesses the network. The current [13-tool gateway corpus](../bench/results/2026-08-28-agent-gateway-real-repository-four-language-private-release-v1.json), file SHA-256 `00209e4957cbd386ac72e9d17a4b42ed1cd10e6d73c57b0a3fa9459bd0bd4037`, passed four explicit clean repositories on release binary `8fcff5ebe8fa21c2fd568b3e442ac3df9b4ba3c8b787db1145e7ed6305376182`: four repositories passed, zero typed non-passes, and zero false hits. The separate [explicit-command corpus](../bench/results/2026-08-28-real-repository-four-language-private-release-v1.json) also passed. This closes the local language gap only; Gate 1 remains open until outside-user evidence exists. |
| Gate 1 outside-user alpha trial | verifier implemented; 0/5 users and 0/50 attempts | The bounded offline harness freezes ten scenarios, verifies exact binary/source/repository/client/outcome bindings, rejects malformed or conflicting evidence, and closes only at 35 admitted successes, at least 3x eligible median warm speedup, authenticated publisher identity, and zero incorrect hits. Its spec SHA-256 is `f7c73dd574f900e963d0623cfeb9eb85266222d736fa7e660aa5bbac8b1332d9`. No outside-user evidence exists, and local simulation is explicitly non-evidence. |
| macOS Seatbelt profile compiler | implemented, not active in Codex path | profile tests pass; nested application is rejected by Codex's existing sandbox on this machine |
| Linux pytest Stage-0 contract | implemented and crate-private; product disabled | strict allocation-bounded canonical EffectIR v2, manifest, identity, executable-chain witness, observation/request proof, promotion ordering, exact-request quarantine, redacted environment, and live-capability trait boundaries have deterministic/adversarial tests. No concrete pytest execution profile or command-accepting Linux CLI route exists; the hidden fixed diagnostic below cannot run pytest |
| Linux pytest portable profile control plane | F1 implemented crate-private; F2 blocked on native qualification | The router recognizes only the frozen single-selector `.venv/bin/python -I -m pytest <selector>` shape and still routes it through ordinary execution without storage. A profile-private SQLite store durably separates execute-only records from candidates, requires an independently linked shadow, commits promotion with one-shot compare-and-swap, quarantines divergence/corruption, and mints a one-use hit only after a fresh exact observation closure. Terminal A validation-dependent identities retire relevant promotions while unrelated invalidations preserve them. The current non-Linux host returns typed `unsupported_os`; x86_64 Linux still returns `kernel_tuple_not_enabled` until the provisioned native execution qualifier supplies evidence. No pytest command execution, public route, verified ledger publication, or Linux qualification is claimed. |
| Linux pytest Gate 3 acceptance/evidence scaffold | implemented and CI-tested; diagnostic-only | A fixed fixture, pure acceptance oracle, reference snapshot oracle, offline five-member ZIP verifier, and deterministic offline packager bind the exact selector/argv and reject fixture drift, malformed or ambiguous evidence, stream/status mismatch, cleanup/reap failure, workspace drift, nonzero candidate/shadow/promotion/replay/hit counts, and every authority claim. The packager reads only the closed bounded input set, verifies a private `0600` staging archive before atomic no-replace publication, revalidates the final inode/bytes/hash, and reports cleanup uncertainty without replacing the primary refusal. Their closed success classifications are `diagnostic_consistent` or an integrity audit, never product pass or qualification. The snapshot oracle explicitly labels caller-supplied source, binary, and qualified-tuple provenance as unverified; packaging and ZIP verification authenticate structure and internal consistency, not the truth of producer claims or a malicious same-UID output-directory race. No component starts pytest or grants execution, candidate, hit, replay, or reuse authority. |
| Linux pytest Gate 3 execution components | integrated crate-private command-free filesystem and supervisor-owned checkpoints; workload execution pending | The fixed admission now progresses through two real snapshot-publication pipelines: one descriptor-bound workspace checkpoint for `.venv/bin/python` and one separately published runtime tree. A bounded structural inventory consumes both linear owners, binds both publication root digests and 102-byte `statx` commitments, retains descriptor pins for every selected object, revalidates the complete set, and distinguishes root executable, interpreter, and dependency-DSO ELF roles. It resolves only a fixed six-directory structural search; loader cache, preload, environment, `RPATH`/`RUNPATH`, and glibc-hwcaps semantics remain unmodeled, so the result explicitly grants no loader or execution authority. The real dual-publication test uses test-only no-atime qualification and passed hosted Ubuntu at source commit `eec5d95edd2b01a94c3ac8bd76c2c5dc0f26f502` in [CI run 33028269206](https://github.com/alakhanpal23/again/actions/runs/33028269206), including complete fixed-directory lookup and refusal after published-runtime mutation; this is live structural evidence, not mount, loader, or execution qualification. Profile-owned stdio authenticates and relocates every endpoint above protocol fds 3/4 and splits disjoint child/parent ownership. The command-free connector now requires and retains the two-publication structural inventory before it can create the concrete isolation-ready child, closing the weaker runtime-checkpoint bypass. The parent owns bounded EOF capture and cancellation; every cancellation terminates and reaps before draining, uncertain reap closes without capture, and no release frame, command, PID, or descriptor is exposed. The new command-free filesystem-ready continuation rebinds both retained publication roots inside the child's private mount namespace, recursively seals and attaches them, authenticates both targets, detaches the old root, and remains stopped and cancellation-only. Its hidden argument-free probe runs one successful attach/cancel/reap and one domain-separated fixed runtime-`open_tree` refusal after workspace attachment; random descriptor-pinned fixture roots are deleted only after terminal cleanup is proven, while uncertainty deliberately quarantines them. The JSON keeps all authority false. A separate live connector installs and reads back the exact 223-instruction workload filter in a disposable single-task child, then kills, reaps, proves final `ECHILD`, and restores signal state before returning a distinct completed-probe record. Terminal waits and ownership loss permanently retire PID signaling, and pending-state drift leaves the conservative mask blocked. Because that child is already gone, the record is not an installed-filter witness for the filesystem-ready child and portable green runs do not constitute universal positive filter qualification. A linear same-child handoff now performs `PTRACE_SEIZE`, issues `PTRACE_INTERRUPT`, requires the exact ptrace-event stop, reauthenticates the single task, tracer ownership, `NoNewPrivs`, and pre-filter seccomp mode, and transfers the existing cleanup guard and retained publication anchors to an opaque supervisor owner. A provisioned x86_64 Linux VM completed 100/100 filesystem attach, supervisor handoff, cancel, and terminal-reap samples. No production orchestrator yet installs and reads back the workload filter on that same held child, releases the fixed command, supervises its post-release tree, or delivers foreground results. Every new result remains command-free and non-authoritative; public Linux dispatch is disabled and execution, profile, candidate, shadow, promotion, replay, hit, and reuse authority are all false. |
| Linux pytest snapshot leaf set | implemented crate-private foundation; not a snapshot backend | Linux x86_64 leaves descriptor-enumerate raw tree names without crossing mounts, copy regular files with reflink/sparse fallback and race checks, record hardlinks/xattrs/logical metadata, populate a private charged stage through the existing tree walker and charged regular-copy leaf, and contain an identity-checked staged publication protocol. Regular-file and directory xattrs are now read through a second non-`O_PATH` descriptor whose exact `statx` identity must match the pinned `O_PATH` anchor before and after capture; the added opens and identity checks are charged and remain inside the existing live-FD ceiling. A no-atime source-view qualification path exists as a crate-private leaf, but production publication does not automatically qualify its source mount; the hosted structural test uses the explicit unsafe test-only qualified-view constructor. The qualifier's symlink xattr probe uses descriptor-relative `listxattrat(..., AT_SYMLINK_NOFOLLOW)` on the pinned parent and requires exact non-following reopened identities before and after; unsupported kernels are a typed non-pass and no unbound pathname fallback exists. Production and legacy test materialization still refuse symlinks pending a qualified dedicated staging filesystem. The private destination observer reuses the single tree-walk and regular-observation cores under a distinct charged session: destination directories and regular files are read with `O_NOATIME`, while a destination symlink is refused after descriptor-selected type identification and before xattr or target acquisition, including before `readlinkat`. Individually these leaves grant no canonical snapshot identity, execution, or reuse authority; production publication is reachable only through the connector-integrated checkpoint described next |
| Linux pytest connector/resource checkpoint | crate-private mechanics CI-validated; not a snapshot backend | One non-`Clone`, non-`Copy` connector owns the preflighted policies and shared operation/heap ledger, bounds retained S1/S2/D1/D2 views, and keeps cleanup reserves disjoint. After S1/D1 it replaces D1 with an exact transient-charged `57N + 24G` raw stability witness, retaining S1 through D2 without admitting a third full-plan lease or a hash approximation. The charged compiler consumes only that verifier-minted stable S1/D2 projection, keeps moved plan buffers under both retained-view leases, charges every new typed/canonical outer allocation, and computes the canonical workspace-tree bytes, root digest, and D2 root commitment. The integrated path escrows finalization and child binding before sealing, durably publishes, verifies the reopened exact child against the D2 commitment, and returns opaque physical descriptors paired with the still-charged canonical evidence. It does not yet issue a reusable or content-addressed snapshot identity/backend token, protect against a malicious same-UID process or host root, or grant execution, Python, isolation, or reuse authority; no pytest process can run through it |
| Linux rootless bootstrap and Landlock diagnostic | hidden, fixed, and non-qualifying | `again __linux-pytest-namespace-probe-v1` accepts no argument, command, caller path, environment parameter, callback, or descriptor. Its raw child proves the fixed private tmpfs root and directory layout, three independently bounded scratch mounts, a fresh read-only `subset=pid` procfs, the exact fd-0 report channel plus one transient fd-1 audit, complete capability elimination, securebits `0xEF`, and `no_new_privs == 1`. It then independently rereads that boundary, reopens and identity-checks only `.`, `tmp`, `run`, and `proc`, and selects Landlock ABI 6 or the stable ABI-7-or-newer ruleset prefix. ABI 1–5 and a VERSION-query `ENOSYS`/`EOPNOTSUPP` are typed `landlock_unavailable`; malformed version results and policy construction, enforcement, canary, or cleanup failures are broken `isolation_preflight_failed`. The fixed ruleset handles filesystem mask `0xFFFF`, TCP mask `0x3`, and scope mask `0x3`; it grants `tmp` mask `0x77BE` and `run/restricted` mask `0x17BE`, with no workspace or TCP rule. Functional canaries require tmp create/write/truncate/rename success, restricted `ftruncate` `EACCES` and cross-directory rename `EXDEV`, workspace file/directory reads `EACCES`, and TCP bind/connect `EACCES`. ABI 7 and newer pass only `LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF`; that is flag-acceptance evidence, not an audit-log or full signal/abstract-Unix scope proof, and no post-ABI-7 rights are claimed. Every post-audit outcome closes tracked resources and requires the exact `{0,1}` proc inventory, fd-1 close plus `EBADF`, and fd-0 reauthentication. This boundary feeds only the terminal seccomp diagnostic below; Landlock-only success mask `0x00FF` is stale. |
| Linux terminal seccomp diagnostic | source and adversarial tests implemented; no positive live composition evidence | After the Landlock audit, the same fixed child reauthenticates fd 0, rereads `no_new_privs`, requires inherited seccomp mode 0, queries bare `ERRNO` and `KILL_PROCESS` action availability, and installs one fixed 93-instruction x86_64 cBPF program with `TSYNC` and exact return 0. Unit tests pin its byte fingerprint to `0x185859bbc1525aac`. Wrong architecture and the x32 syscall bit are fatal; on native x86_64 every non-allowed syscall returns private errno marker `0x05A5`. The only allowed terminal-report calls are `write(0, *, 64)`, `poll(*, 1, 0..=8000)`, `clock_gettime(CLOCK_MONOTONIC, *)`, `prctl(PR_GET_SECCOMP,0,0,0,0)` or `prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)`, `close(0)`, and raw `exit(0)` or `exit(125)`. Pointer values are deliberately not authenticated and the unused sixth syscall slot, `seccomp_data.args[5]`, is uninspected for `prctl`, so this is neither a memory-integrity nor a full-register proof. Six harmless canaries—`unshare(0)`, `setns(-1,0)`, `clone3(NULL,0)`, `socket(-1,0,0)`, `ioctl(-1,0,0)`, and `openat(AT_FDCWD,NULL,flags,0)` with exactly `O_RDONLY` and `O_CLOEXEC`—must all receive `0x05A5`. Only an action-query `ENOSYS`/`EOPNOTSUPP` is canonical status 12, expected `seccomp_unavailable` at `ChildSeccomp` (serialized `child_seccomp`); inherited filters, action mismatch, install/readback/canary failure, positive `TSYNC`, and all other errno shapes are status 13, non-expected `isolation_preflight_failed`. The 64-byte protocol V2 stores version and flags as little-endian `u16`; success requires exact mask `0x01FF`. Stock hosted Ubuntu still stops at the earlier UTS `EPERM`, so there is no positive live evidence that the diagnostic slices compose. The terminal child still has inherited executable mappings and potentially authoritative supplementary groups; it has no descriptor-selected workspace/runtime attachment, populated `/dev`, profile-owned stdio, production workload seccomp/tracer split, command, Python, isolation-session, execution, or reuse authority, and makes no claim against same-UID peers or host root. |
| Linux fixed no-command ptrace transport | implemented diagnostic with positive live transport evidence; non-qualifying | `again __linux-pytest-ptrace-transport-probe-v1` accepts no command or workload. In a dedicated single-task process with bounded loader-injection refusal, it creates one blocked child with `clone3(CLONE_PIDFD)`, applies exact `PTRACE_SEIZE` options for `EXITKILL`, `TRACESYSGOOD`, fork, vfork, clone, exec, exit, and seccomp, then releases the child into one frozen 122-instruction x86_64 filter. The child makes only raw zero-argument `getpid`/`getppid` calls tagged `0xA611`/`0xA612` and an allowed raw exit. The parent requires matching `PTRACE_GETEVENTMSG`, exact 84-byte `PTRACE_GET_SYSCALL_INFO`, one exit event, one terminal reap, `ECHILD`, complete signal drain/mask restoration, and the exact four-event protocol fingerprint `0xf4101836ef74bb4f`. Recorder construction requires the qualification module's private permit. This proves one fixed transport, not namespaces/root/Landlock composition, a task tree, a command, Python, EffectIR, tracing completeness, or execution/profile/reuse authority. Its evidence-only JSON changes no persisted `LINUX_PYTEST_WIRE_V1` field. |
| Linux production tracer decoder and fixed two-task connector | Gate 2 qualified transport checkpoint; non-authoritative | Allocation-free, bounded x86_64 decoders and a fixed-capacity pure supervisor planner retain the exact token, fork-ordering, lifecycle, and 64/80/88-byte `clone3` capture checks. The hidden argument-free `again __linux-pytest-supervisor-tree-probe-v1` now owns the sole production issuer and a fixed raw two-task tracee: it seizes the root with the frozen options, installs and reads back the seven-instruction trace-all filter, drives real wait/event/syscall-info/resume operations, proves a single-task private anonymous 88-byte source range before `process_vm_readv`, correlates event-message child identity with the same real child stop before creating pidfd signal authority, drains both tasks through final `ECHILD`, and consumes an opaque cleanup completion. A wait-returned stopped tracee is retained before that correlation so a mismatched event message cannot discard cleanup authority. Proc maps and the raw loader environment are capped before allocation, the established injection-name set is refused, idle waits use bounded nanosleep backoff, and seccomp/process-memory errno shapes are typed. Success is fixed to 2 tasks, 11 transitions, 1 fork, 3 seccomp entries, 1 syscall exit, 2 no-return resolutions, 2 ptrace-exit events, and 2 reaps; the only additional completed field is the redacted parent-event-first or child-stop-first delivery class. The JSON exposes no command, TID, address, descriptor, EffectIR, execution, profile, or reuse authority; cleanup failure is reported separately without replacing the first error. Private test-only injection seams cover run/cleanup waits, every ptrace exchange, stopped-memory reads, both resume modes, PID/pidfd termination, and signal-state verification. Focused Linux tests require forward faults to preserve their first typed error while cleanup reaches final `ECHILD`, and require cleanup-operation faults to retain uncertainty without replacing that first error. After Linux produces the fork event, the connector reads the stopped root's signal mask, adds only `SIGCHLD`, writes it with `PTRACE_SETSIGMASK`, and reads the exact mask back; this preserves the live parent-event/child-stop ordering while preventing a later signal-delivery stop outside the fixed transcript. Read, write, and verification are separate injected-failure boundaries. Exact-SHA hosted CI run `32963128960` and provisioned Gate 2 run `32965300493` are green at `3d1fb201507a43b830d5ce341b2253957634016d`. The latter passed 100/100 with both delivery orders on kernel `6.8.0-134-generic`; the hardened offline verifier accepted artifact `9605461989`, all 302 members, archive SHA-256 `43f3be33e9d92e28198ccab64deab1db6533c6a66c0ed7d1523f6fde4f371dfa`, and member-manifest SHA-256 `4cb7287d6940b43a9720b10b82f90518b32abd319b3c9343df69c42ab20cf3ae`. This qualifies only the fixed command-free transport, not Python, EffectIR, profile, execution, or reuse; public Linux command dispatch remains disabled. |
| Remote service boundary | implemented and locally tested, not deployed | authenticated tenant/repository API, separate blob/metadata quotas, byte-verified R2 blobs, signed manifests/trust, audit, rate windows, repository-generation lifecycle, bounded reconciliation, and a stateful streaming bundle route; local Miniflare/Vitest coverage is not production Cloudflare evidence |
| Strict async remote HTTP client and sealed v2 orchestration | CLI-integrated for manually provisioned team alpha, not deployed | production requires HTTPS, bounded redirects/deadlines/bodies, distinct read/write credentials, root-signed fresh trust with durable monotonic checkpoint, producer/revocation/allowlist verification, XChaCha20-Poly1305 encrypted streams, manifest-last publication, and local privacy rescan. The CLI derives bindings from the live repository/runtime and implements both the five-request reference and two-request bundle lifecycle; no public operator control plane provisions profiles or trust |
| Two-request `bundle_v1` lookup | implemented experiment, opt-in only and unshipped | Worker route, strict client, actual 18-state Worker/reference matrix, exact two-versus-five request test, four overlapping maximum responses, and a manual two-client HTTPS lifecycle exist. The 16 MiB/50 ms result improves only 1.208%, below the 40% gate; an indefinitely pending TCP-reset probe cancels 0/2 sources after 3.014 s. Full 4x4 local plus live performance, direct proof of current Worker-isolate heap usage, a 100,000-case stateful D1/R2 path, and the cross-layer post-decrypt race remain missing; see [bundle status](TEAM_LOOKUP_BUNDLE_V1.md) |
| Release packaging | private alpha release candidate; exact tag run pending | Draft-first native macOS/Linux packaging, locked dependencies, an exact 14-asset inventory, checksums, CycloneDX SBOM, build-origin keyless Sigstore bundles, exact source/ref/workflow/trigger verification, rollback-safe installer/uninstaller, authenticated private-release download, and pinned Homebrew formula generation are implemented and adversarially tested. GitHub's native private-repository attestation service is unavailable on the current plan, so the repository remains private and uses patched Cosign `v3.1.3` with Fulcio, RFC3161 timestamps, and Rekor instead. No candidate using this replacement path has completed its exact tag workflow yet; checksums alone do not close Gate 1. Linux or unknown-macOS installation still grants no reuse authority until its backend/profile is audited. |

[Rust CI run 32806429152](https://github.com/alakhanpal23/again/actions/runs/32806429152) passed the fixed ptrace-transport checkpoint at source commit `4b98b2ad574209ed3e7048d79d6b177034cffe4c`. The qualifier and pure protocol sources had SHA-256 `d1493f1f3be7db935fcc8c7844a487594741e09fcbb658e1fb9763c4e2be6914` and `6a411a7efc36c8c3a47189cca254867f099496aecd9b748e62181ccbaad510c3`. Ubuntu's library lane passed 656 tests with 7 ignored and macOS passed 478 with 7 ignored; both passed pinned formatting, strict all-target/all-feature Clippy, the full locked suites, and the explicit 100,000-case gate. Artifact `9548321539`, `linux-capability-32806429152-1-4b98b2ad574209ed3e7048d79d6b177034cffe4c`, was created `2026-08-25T03:48:06Z`, expires `2026-09-24T03:48:06Z`, contains exactly 101 files, has GitHub archive digest `sha256:94653f2ae85dc97823438c92e5853893944745d656d9ffa774b0ca1da4196153`, and has canonical extracted-manifest SHA-256 `bb042b03f074f963df673991bfa61596cf666c25d291c61f636ae3d149571a11`. The capability, namespace, ptrace aggregate, and validated JSONL SHA-256 values are respectively `256feee193edd2a269f505904f84190a18f392d264a6260fdf724d513f0d5586`, `7346fa492d952f85cb1b38e4c9a1497b60d09893f7bc3cefb6fe47bf9781ec34`, `9f4c51e0aa7bc887fb4d39e57af438feec83704087d6fd94ee6e44d539f8ec3f`, and `fd2597756be5a5be905cba2e8f8d60fb9c48044cc2fa74b79029adc28c007a08`. All 32 raw stdout files are identical with SHA-256 `8fa5eac1b9746f1a0defcf1770c56c846d272b61fd55dccedd93a8a2f03a0424`; all 32 numeric exit statuses are zero, and all 32 stderr files are empty with SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`. Every validated record has exactly four events—two seccomp stops, one ptrace exit event, and one terminal reap—complete cleanup, protocol fingerprint `f4101836ef74bb4f`, and every command, EffectIR, execution, profile, and reuse authority flag false. The runner was image `20260816.277.1`, kernel `6.17.0-1022-azure`, glibc 2.39. Its separate namespace diagnostic still returned the exact UTS `EPERM` expected-unavailability result. This is positive evidence only for the fixed single-child no-command ptrace transport; the profile is **not qualified**, and the run proves no namespace/root/Landlock composition, workload/Python execution, task-tree tracer, EffectIR, tracing completeness, or reuse.

[Rust CI run 32802788152](https://github.com/alakhanpal23/again/actions/runs/32802788152) passed the terminal-seccomp source checkpoint at commit `d7ffb4ecd43ed2be9be2ec16e4f24fb907219a6d`; `src/linux_pytest/isolation_qualification.rs` had SHA-256 `8f05d4ad1bd97a7d4efd944dd816e5f141e43d710e6d9b353ccd607613b7de65`. Ubuntu ran 650 library tests (643 passed, 7 ignored) and macOS ran 480 (473 passed, 7 ignored); both passed pinned formatting, strict all-target/all-feature Clippy, the full locked suites, and the explicit 100,000-case gate. Artifact `9547105077`, `linux-capability-32802788152-1-d7ffb4ecd43ed2be9be2ec16e4f24fb907219a6d`, was created `2026-08-25T02:49:49Z` with GitHub archive digest `sha256:5b846ee094c69f48a920484eb90a606247af3676ec5791b0e4493d634fec1caf`. Its exactly three files were the capability report (`f2b050d4a34cc01779cc5c3ac8fa3bb1b1bacd99aa1e49b02563b08ae63d9a99`), namespace report (`7346fa492d952f85cb1b38e4c9a1497b60d09893f7bc3cefb6fe47bf9781ec34`), and empty stderr (`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) by SHA-256. On image `20260816.277.1`, kernel `6.17.0-1022-azure`, the independent Landlock query returned ABI 7 and the independent user-namespace probe returned `EACCES`; the product diagnostic exited 77 with the exact UTS `EPERM` refusal, completed cleanup, and every authority field false. The archive expires `2026-09-24T02:49:48Z`. This proves source compilation, adversarial protocol/filter tests, and the stock-Ubuntu negative lane only—not live `TSYNC`/Landlock composition, Python, tracing, execution, or reuse.

[Failed Rust CI run 32784270117](https://github.com/alakhanpal23/again/actions/runs/32784270117) retained the first product-owned fixed-bootstrap artifact at commit `df68613`. The independent stock-Ubuntu probe returned `EACCES` from `unshare(CLONE_NEWUSER)`, while Again's combined `clone3` route created its child, wrote and verified the maps, validated all six namespace descriptors, released the child, and received a generic `EPERM` proof. The job failed intentionally because the then-current protocol could not attribute that errno and the workflow still required the older clone-time refusal. macOS passed; the Ubuntu library lane passed 612 tests with 7 ignored and zero failures before the exact E2E assertion stopped it. This is retained discovery evidence, not positive isolation/profile evidence: the diagnostic accepted no command and granted no execution authority, and no Python process ran through it.

[Failed Rust CI run 32786126330](https://github.com/alakhanpal23/again/actions/runs/32786126330) retained and reproduced a narrower control-channel race at commit `948069e`: both bootstrap attempts returned exact authenticated child `PROTOCOL`/`EPROTO` evidence with completed cleanup, while the independent probe remained `EACCES`. The child could drain the complete release frame before the parent closed its writer, then misread the resulting HUP-only wake as protocol failure. The correction admits HUP only as a wake in the post-frame EOF loop and still requires a subsequent zero-byte read; deterministic 63/64/65-byte fixtures preserve exact framing. Both full macOS and Ubuntu format, strict-Clippy, locked-test, and 100,000-case jobs passed. The workflow remains failed evidence, not isolation or profile qualification.

[Rust CI run 32786996039](https://github.com/alakhanpal23/again/actions/runs/32786996039) passed the corrected fixed-bootstrap lane at commit `ca51b6a`. The retained product artifact is exactly `required_namespace_failed` / `child_uts_configuration` / `administrative_policy` with `EPERM`, completed cleanup, empty stderr, and every command/profile/execution-authority scope field false. Its independent probe separately retained `EACCES` from `unshare(CLONE_NEWUSER)` on runner image `ubuntu24` version `20260816.277.1`, kernel `6.17.0-1022-azure`, UID/GID 1001, and zero effective host capabilities. The Linux library run passed 615 tests with 7 ignored and zero failures; the macOS library run passed 473 tests with 7 ignored and zero failures. Both platforms also passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, locked integration/doc tests, and the explicit 100,000-case gate. This is positive evidence for exact fail-closed bootstrap classification and framing cleanup only. It is not positive namespace/root isolation, profile qualification, command, Python, tracing, or reuse evidence.

[Rust CI run 32788942118](https://github.com/alakhanpal23/again/actions/runs/32788942118) passed the source-integrated private-tmpfs/pivot slice at commit `36f60f9`. Linux compiled and exercised the closed root-success/root-OS/root-invariant frame rules, stale pre-root rejection, fixed tmpfs policy bounds, and all prior tests: its library lane passed 617 tests with 7 ignored and zero failures, while macOS passed 473 with 7 ignored. Both platforms passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, locked integration/doc tests, and the explicit 100,000-case gate. The retained product artifact still contains the exact UTS-policy refusal with completed cleanup, empty stderr, and all authority scopes false, proving the stock child stopped before the new mount branch. This is compile/unit/fail-closed compatibility evidence for the slice, not a positive live tmpfs, pivot, old-root detach, isolation, profile, command, Python, tracing, or reuse result.

[Rust CI run 32791466632](https://github.com/alakhanpal23/again/actions/runs/32791466632) passed the fixed layout, independent scratch, and PID-namespace-bound procfs source checkpoint at commit `883a0a6`. The Ubuntu library lane passed 621 tests with 7 ignored and zero failures; macOS passed 473 with 7 ignored. Both platforms passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, locked integration/doc tests, and the explicit 100,000-case gate. The retained product artifact remains the exact `required_namespace_failed` / `child_uts_configuration` / `administrative_policy` refusal with `EPERM`, completed cleanup, empty stderr, and command/profile/execution-authority scopes false. It proves that stock Ubuntu still stops before the mount path. This is compile, unit-policy, framing, and negative-lane compatibility evidence, not positive live root, scratch, procfs, FD isolation, profile, command, Python, tracing, or reuse evidence.

[Rust CI run 32795373220](https://github.com/alakhanpal23/again/actions/runs/32795373220) passed the descriptor-scrub source checkpoint at commit `a6ec471`. Ubuntu ran the Linux-only sparse-high-FD/range-close/exact-inventory child and passed 624 library tests with 7 ignored; macOS passed 473 with 7 ignored. Both platforms passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, all locked integration/doc tests, and the explicit 100,000-case gate. The retained product artifact remains the exact earlier UTS-policy `EPERM` refusal with completed cleanup, empty stderr, and every authority scope false, so stock CI still did not compose the verified namespace bootstrap with the root, layout, and FD branches. The independent artifact separately proved `CLOSE_RANGE_UNSHARE` with a deliberately shared FD table; that evidence does not elevate the product diagnostic. [Failed predecessor 32794670806](https://github.com/alakhanpal23/again/actions/runs/32794670806) caught an empty-chunk streaming-parser test-oracle error, and [failed predecessor 32795004750](https://github.com/alakhanpal23/again/actions/runs/32795004750) then passed Ubuntu but exposed a pre-existing macOS signal-test readiness race; both corrections were test-only and are included in the passing checkpoint. For the product diagnostic, this remains source, adversarial-test, and negative-lane evidence—not positive live private-root composition, workload stdio, profile, command, Python, tracing, execution, or reuse evidence.

[Rust CI run 32797272516](https://github.com/alakhanpal23/again/actions/runs/32797272516) passed the capability-elimination source checkpoint at commit `7a5eb4a`. Ubuntu executed the Linux-only range, v3 capability-layout, securebits, empty-set, stale-mask, and status-9 adversarial tests and passed 632 library tests with 7 ignored; macOS passed 473 with 7 ignored. Both platforms passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, all locked integration/doc tests, and the explicit 100,000-case gate. The retained product artifact is still the exact UTS-policy `EPERM` refusal with completed cleanup, empty stderr, and every authority scope false. The run therefore proves source compilation and exact fail-closed contract compatibility, but stock CI did not execute the capability syscalls inside the composed product child. Positive root/layout/FD/capability composition still requires the provisioned runner, and no command, Python, isolation-session, execution, or reuse authority follows.

[Rust CI run 32778963400](https://github.com/alakhanpal23/again/actions/runs/32778963400) passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, the locked suite, and the explicit 100,000-case gate on macOS and Ubuntu at commit `68bcaf6`. The Ubuntu library run passed 604 tests with 7 ignored and zero failures; the macOS library run passed 472 tests with 7 ignored and zero failures. This run validates the connector-integrated transition from stable S1/D2 projection through charged canonical workspace-tree construction, exact pre-seal finalization/binding escrow, durable publication, reopened-child commitment verification, and the opaque composite that retains exactly two physical descriptors with its charged canonical evidence. Production exposes neither the raw physical-only seal transition nor detachable child descriptors. Adversarial coverage includes pre-publication invalid names and resource exhaustion, post-publication open/stat/commitment failures, exact ownership/refund behavior, and descriptor identity against the durable final path. [Predecessor run 32778473131](https://github.com/alakhanpal23/again/actions/runs/32778473131) retains the Linux-only strict-Clippy failure that changed one test assertion from `.err().expect(...)` to `.expect_err(...)`; macOS and its explicit corpus gate had already passed. The hosted capability inventory remained correctly non-qualifying. This is not evidence for a full snapshot manifest or content-addressed name, same-UID/root protection, isolation, Python execution, or reuse.

[Rust CI run 32772890425](https://github.com/alakhanpal23/again/actions/runs/32772890425) passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, the locked suite, and the explicit 100,000-case gate on macOS and Ubuntu at commit `7126206`. The Ubuntu library run passed 588 tests with 7 ignored and zero failures; the macOS library run passed 468 tests with 7 ignored and zero failures. The charged compiler consumes only the verifier-minted stable S1/D2 projection, validates both plans before allocation, preserves moved nested buffers beneath their two retained-view leases, charges every new typed/canonical outer allocation, and retains exact canonical tree bytes plus the 102-byte D2 `SourceStatxV1` commitment. Adversarial coverage includes malformed destination semantics, authority mismatch, raw names, hard links, nested xattrs, exact and one-byte-short heap boundaries, checked conversions, and ledger release. Publication remains deliberately unwired and the hosted capability inventory remained correctly non-qualifying. This is not evidence for a manifest-bound snapshot backend, isolation, Python execution, or reuse.

[Rust CI run 32768698059](https://github.com/alakhanpal23/again/actions/runs/32768698059) passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, the locked suite, and the explicit 100,000-case gate on macOS and Ubuntu at commit `fee3c80`. The Ubuntu library run passed 575 tests with 7 ignored and zero failures; the macOS library run passed 455 tests with 7 ignored and zero failures. The verifier now transports the exact connector-charged S1 and D2 owners through its private success typestate instead of returning independently substitutable plans. A distinct persistent-manifest heap ledger owns exact logical `Vec` slot capacities, remains separate from publication transient memory, and is included in the unchanged aggregate hard cap. Frozen tree-manifest canonical bytes and node/hardlink digests now share one allocation-free production writer with a test-only independent builder oracle, checked lengths, exact-minus-one refusal, and raw-byte/optional/payload differential coverage. This is foundation evidence only: the charged compiler is not yet connector-wired, nested manifest allocations have not yet moved under retained leases, publication is not bound to a canonical tree identity, and the hosted capability inventory remained correctly non-qualifying. It is not evidence for a canonical snapshot backend, isolation, Python execution, or reuse.

[Rust CI run 32766148249](https://github.com/alakhanpal23/again/actions/runs/32766148249) passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, the locked suite, and the explicit 100,000-case gate on macOS and Ubuntu at commit `c3193ab`. The Ubuntu library run passed 563 tests with 7 ignored and zero failures; the macOS library run passed 443 tests with 7 ignored and zero failures. This run compiled the Linux-only connector wiring and exercised the exact `57N + 24G` destination witness, its connector-minted charged buffer, and the pure bottom-up manifest compiler. It is evidence for stable tree-evidence preparation only: the compiler remains outside the connector and authority path, and the hosted capability inventory remained correctly non-qualifying. It is not evidence for a canonical snapshot backend, manifest-bound publication, isolation, Python execution, or reuse.

[Rust CI run 32761340875](https://github.com/alakhanpal23/again/actions/runs/32761340875) passed formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, the locked suite, and the explicit 100,000-case gate on macOS and Ubuntu at commit `0994e1e`. The Ubuntu library run passed 548 tests with 7 ignored and zero failures. It explicitly exercised exact finalization-escrow admission and pre-seal refusal, invalid-final-name refusal before qualification or one-shot use, effect-then-interrupt rename reconciliation, the allowed staging-container link-count refresh, and post-fsync replacement detection without deleting the replacement. The macOS library run passed 428 tests with 7 ignored and zero failures. This is positive evidence for the charged publication mechanics, not for the qualified end-to-end flow: the full exact-byte four-view-and-publication test remains ignored until both source and destination filesystems are functionally qualified for no-atime access, and the hosted capability inventory remained correctly non-qualifying. [Failed run 32755128153](https://github.com/alakhanpal23/again/actions/runs/32755128153) retains evidence that an unqualified hosted destination observation refused; [failed run 32750203189](https://github.com/alakhanpal23/again/actions/runs/32750203189) separately retains evidence that ordinary hosted overlayfs changed source atime and the production walker failed closed. None of these hosted runs is evidence for a canonical snapshot backend, isolation, Python execution, or reuse. [Service CI run 32664343315](https://github.com/alakhanpal23/again/actions/runs/32664343315) passed the earlier Worker gates. Current macOS success E2Es are gated on the exact audited host OS and all audited Apple-tool bytes, while unknown profiles have explicit fail-closed unit coverage. No release workflow has run and no release has been published.

Stock GitHub-hosted Ubuntu remains a negative, non-qualifying capability lane
because host policy prevents completion of the required rootless bootstrap.
Retained evidence shows the independent route refusing user-namespace creation
with `EACCES` and Again's combined route reaching the mapped namespace child
before an exact UTS-configuration `EPERM` after capability and namespace
verification. The exact lane passes only that closed tuple with completed
cleanup. Neither route can provide positive isolation/profile evidence, and
the product route accepts no command or Python workload.

## Measured gates

[`2026-08-23-direct-v1.json`](../bench/results/2026-08-23-direct-v1.json) represents the current explicit-CLI, full-stream implementation at clean source commit `7a238d5`. On its recorded macOS arm64 host and 2 GiB logical sparse-file `grep` fixture, native p50 was 721.467 ms, warm Again p95 was 10.537 ms, and the conditional speedup was 68.473x. All 15 warm calls returned exact full streams, and a same-output input mutation correctly forced a miss. Cold double validation took 2,713.629 ms, so this is a repeated-work result rather than a first-run or general workload claim. Earlier hook/compact-reference runs remain historical and superseded.

[`2026-08-23-reference-v2.json`](../bench/results/2026-08-23-reference-v2.json) is the current dirty-tree release-binary gate for the separate explicit reference path. Over 25 full hits and 25 references to one 1 MiB result, every binding/retrieval/no-execution check passed, reference p95 was 11.468 ms, and observed duplicate output-byte reduction was 99.9719%. No Codex model or tokenizer ran, so this is not measured token, inference-cost, or task-quality evidence. The passing v1 run remains retained and is superseded for timing.

[`2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json) records 100 repetitions at the decisive 50 ms injected response-start delay. Bundle-v1 p95 improvement over the five-request reference was 59.41% at 0 B, 59.61% at 4 KiB, 52.17% at 1 MiB, and 1.208% at 16 MiB; the unchanged per-size 40% gate therefore fails. Exact two-versus-five request counts and four simultaneous maximum-response streams passed. The same artifact's pending-source TCP-reset probe cancelled 0/2 sources after 3.014 seconds; the separate [`finite-disconnect` result](../bench/results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json) cancelled 2/2 finite sources in 62.5 ms. These are synthetic local Worker protocol measurements, not stateful D1/R2, deployed-edge, command, or agent speed evidence.

[`2026-08-23-team-live-e2e-bundle-v1.json`](../bench/results/2026-08-23-team-live-e2e-bundle-v1.json) records the implemented two-client `bundle_v1` lifecycle through production rustls over a public-CA Quick Tunnel to a local Wrangler Worker with real local D1/R2 state: publish/miss, exact reader hit, trust rotation, corruption quarantine, producer revocation, generation deletion/recreation, stale-generation refusal, and republish/hit passed. It is a manual single-host dirty-tree run, not a deployment, full live performance matrix, or cross-layer post-decrypt revocation-race proof.

[`2026-08-29-agent-gateway-editable-pair-qualification-v1.json`](../bench/results/2026-08-29-agent-gateway-editable-pair-qualification-v1.json)
retains 10 balanced offline pairs for the editable benchmark itself. All 20
observations produced the exact one-file repair, left the tests and all other
files unchanged, and passed the fixed acceptance suite. The report retains
first-edit, accepted-edit, validation, final-outcome, and total timings, but its
actor is a deterministic reference editor. It therefore claims neither
real-agent task quality nor Again acceleration; those require explicitly
authorized pinned live cohorts.

## Immediate product gates

Current local setup probe: [Codex CLI 0.156.0](../bench/results/2026-09-22-codex-setup-local-probe-v1.json)
passed combined MCP/skill apply, inspect, idempotent apply, and MCP removal in
an isolated home with zero model calls. The source checkout was dirty and its
binary-to-source binding was unverified, so this is integration diagnostic
evidence only. A current installed Claude CLI was unavailable for the same
probe; fake official-CLI contract tests pass for both clients.

A separate [live Codex MCP probe](../bench/results/2026-09-23-codex-live-probe-v1.json)
used Codex CLI 0.156.0 with its existing login in an isolated read-only
fixture. It discovered and completed `task.start` and `repo.read`, returned the
exact fixture content, and left the fixture unchanged. The default
noninteractive `never` approval mode refused MCP calls; `--approve-for-me`
allowed them. This single-session diagnostic does not establish repeated-work speed,
validated task completion, or a release-binary source binding.
A retained [live repeated-read probe](../bench/results/2026-09-23-codex-repeat-probe-v1.json)
made two identical Codex `repo.read` calls and recorded two gateway requests,
one physical provider execution, one exact hit, one avoided provider call, and
zero false-hit quarantines. It demonstrates the exact repeated-call lane for
this fixture, without establishing workload-wide time or cost savings.
A retained [two-session Codex context probe](../bench/results/2026-09-23-codex-context-probe-v1.json)
completed `task.start`, `repo.read`, and `context.publish` in one session, then
`task.start` and `context.delta` in another. The second session saw the first
session's suggestion explicitly as `unverified_suggestion`. This local
diagnostic has a dirty source checkout and no independently verified
source-to-binary binding; it is not concurrent-agent task-quality or release
evidence.

Five retained [Codex editable pair diagnostics](../bench/results/2026-09-23-codex-editable-pair-diagnostic-v5.json)
each produced the exact calculator repair and passing tests in baseline and
Again conditions. The source-preview implementation lets `task.start` return
up to two complete digest-checked small files when requested, so the agent can
skip separate pre-edit reads. Its text response now summarizes the edit brief
while retaining complete structured output. In the latest single unbalanced
pair, first accepted edit was 19.7 seconds baseline versus 17.9 seconds with
Again, while validated completion was 31.1 versus 26.9 seconds. The preceding
pair had the opposite completion ordering (23.4 versus 28.7 seconds), and
reported input usage was higher with Again in both. The pairs used different
binary revisions and prompts, so they are diagnostics, not a causal speed claim.
Repeat-heavy balanced cohorts and total metered cost still need qualification.

The [gateway reuse-value probe](../bench/results/2026-09-23-gateway-reuse-value-probe-v7.json)
compares exact stdio MCP calls with an execute-only diagnostic mode over the
same built-in provider. Before the default bypass, a 1,000-file fixture had
warm p50 direct/reuse times of 0.23/5.41 ms for a small read, 4.91/15.73 ms
for a 128 KiB read, 0.27/5.12 ms for stat, 29.78/90.07 ms for tree, and
60.14/90.03 ms for a simple search. The default gateway now executes all
eight `repo.*` tools directly when no authenticated task is active; task-bound
calls retain result storage and source-backed shared context. A 1,000-file
follow-up confirmed near-direct latency for read/stat/search/tree/list/glob/manifest.
An adaptive live value model for task-bound and Git paths and broader
host/workload qualification remain open.
For standalone `git.status`, the default now executes directly when the
on-disk index is at least 16 KiB. A [250-file probe](../bench/results/2026-09-23-gateway-reuse-value-probe-250-v8.json)
measured 14.90 ms automatic versus 14.84 ms execute-only warm p50; the
[one-file control](../bench/results/2026-09-23-gateway-reuse-value-probe-small-v8.json)
kept reuse and measured 8.25 ms automatic versus 11.56 ms execute-only. This
is a conservative local threshold for one Git operation, not a general
adaptive policy or evidence of task-level acceleration.

An [authenticated daemon probe](../bench/results/2026-09-23-gateway-task-reuse-value-probe-v2.json)
now isolates that open task-bound path. With an active `task.start`, a repeated
small `repo.read` on a 1,000-file fixture took 60.83 ms warm p50 through reuse
versus 0.24 ms through execute-only; `git.status` took 193.24 ms versus
15.34 ms. The [one-file control](../bench/results/2026-09-23-gateway-task-reuse-value-probe-small-v2.json)
also showed slower repository reads, while Git status reuse was slightly faster.
This is per-call diagnostic evidence on local dirty source, not a task-level
result. The current gateway now seeds a task with one proven repository result,
then executes repeated same-task `repo.*` calls directly when their fresh
provider output matches that stored result. It returns the fresh output
without a cache-result ID; divergence invokes the full proof path, which
retires stale context and stores the changed result when proof completes.
Large-index `git.status` uses
the same warm path, while small-index Git status retains reuse. The
[current 1,000-file probe](../bench/results/2026-09-23-gateway-task-reuse-value-probe-fast-v9.json)
measured warm p50 of 0.25 ms for small read, 5.28 ms for 128 KiB read,
64.01 ms for search, 28.93 ms for tree, and 27.27 ms for Git status; their
execute-only controls were 0.24, 5.31, 64.23, 28.89, and 26.46 ms. The
[one-file probe](../bench/results/2026-09-23-gateway-task-reuse-value-probe-fast-small-v9.json)
kept the measured small-index Git reuse win. The first source-backed call
still costs 0.13–0.41 seconds on the 1,000-file fixture, and warm direct calls
do not avoid physical executions. Cheap direct source admission and broader
task-level qualification remain open.

A three-client authenticated test now covers a source disappearing during a
repeated task-bound read. The failed fresh read atomically retires matching
facts and full-result references in the active task and another task that
admitted the same source, emits an invalidation in each task, and refuses the
old references. The store matches old dependency keys and values within one
repository and authorization scope, leaving unrelated references current. A
restored read can admit a new verified result; the ledger also supports a
later admission version if the same result ID is observed again. A failed
retirement makes the observing tool call fail. The schema-v14 source recipe
now retains the bounded observation plan and repository digest for each newly
admitted built-in result. `task.start`, `context.delta`, and `context.retrieve`
reobserve that plan from a fresh descriptor-bound workspace epoch and retire
references after an unobserved edit, including after daemon restart. An old
reference with no recipe is retired before presentation. Authenticated tests
cover read and search sources, Git HEAD changes, restart, recovery, and an
unrelated edit that preserves the old reference. Freshness scans cap at 256
sources per task and withhold unchecked context above that bound. Concurrent mutation during
reobservation and delivery, wider workload performance, and hosted
qualification remain open.

The [clean-source release-binary follow-up](../bench/results/2026-09-23-gateway-task-reuse-value-release-shared-launchers-v1.json)
at `ed4bb55` used the `daemon` feature and five warm samples per case on a
1,000-file fixture. Automatic/direct cold calls took 14.31/0.44 ms for a
small read, 138.34/1.07 ms for a 128 KiB read, 356.48/76.87 ms for search,
and 480.39/29.13 ms for tree. Warm calls executed the provider on every
request, with zero exact hits; warm p50 was 0.35/0.19 ms for small read,
0.76/0.41 ms for large read, 63.00/66.52 ms for search, and 35.44/28.81 ms
for tree. The one-fixture, five-sample measurements show cold admission is
still the major task-bound cost. A blanket bypass of task-bound search would
remove its source-backed fact and the tested relevant-edit retirement path;
the next route change must preserve that contract or explicitly withhold a
shared fact. The report pins binary bytes and clean source, but its harness
does not verify binary-to-source binding.

A [matched 40-sample shared-manifest control](../bench/results/2026-09-23-gateway-task-reuse-value-shared-manifest-40-control-v1.json)
and [split-manifest trial](../bench/results/2026-09-23-gateway-task-reuse-value-split-manifest-40-matched-v1.json)
used separate release binaries on the same 1,000-file fixture. The code index
now has an independent observed manifest over the same sealed workspace epoch;
repository and Git tools still share their proof manifest and the task ledger
still owns facts and invalidation. Cold automatic calls improved from
135.70 to 27.28 ms for a 128 KiB read, 346.58 to 251.27 ms for search,
395.63 to 223.07 ms for tree, and 398.29 to 328.37 ms for Git status.
Warm p50 search was 62.80 versus 61.10 ms and tree 37.28 versus 28.85 ms.
Both variants physically executed every warm call; this reduces proof cost,
not provider work. The matched trial is local and source-dirty, so it is not
the clean-source release qualification.
The [authenticated product gate](../bench/results/2026-09-23-auth-product-e2e-split-manifest-release-v1.json)
and [Codex](../bench/results/2026-09-23-codex-launch-generic-prompt-split-release-v1.json)
and [fake-Claude launcher](../bench/results/2026-09-23-claude-launch-generic-prompt-split-release-v1.json)
gates passed on the clean-source release binary at `17510ad`. They cover
source-backed task lifecycle, peer lease handoff, stale-source refresh, and
both client launch arguments. They do not measure a live Claude coding task.
A [40-sample clean-source release probe](../bench/results/2026-09-23-gateway-task-reuse-value-split-manifest-clean-release-v1.json)
using the same binary bytes recorded cold automatic calls of 21.36 ms for
128 KiB read, 294.67 ms for search, 239.76 ms for tree, and 313.22 ms for
Git status. All 41 requests per case still executed the provider with zero
exact hits. Warm search was 69.74 ms versus 63.40 ms direct; the remaining
proof/reference check has not become a repeated-call speed win. The probe
records a clean source SHA but does not independently bind binary bytes to it.
The [10,000-file split-manifest control](../bench/results/2026-09-23-gateway-task-reuse-value-split-manifest-10k-release-v1.json)
still measured cold task-bound search/tree/Git status at 3.11/3.39/3.76
seconds. An [overflow direct-route trial](../bench/results/2026-09-23-gateway-task-reuse-value-overflow-direct-10k-trial-v1.json)
measured 0.47/0.30/0.03 seconds on the same fixture and release build mode.
Warm p50 search/tree/Git status in the trial was 478/296/26 ms, close to its
direct controls of 486/298/26 ms. All six calls in each case executed the
provider, with zero exact hits. The route applies only after task-start's
source inventory reports more than 4,096 files and the requested subtree also
exceeds that bound; Git status uses the workspace bound. A broad direct
search now separately admits up to two verified matches from files no larger
than 8 KiB, with file-specific source recipes. It does not publish a
retrievable full-search result or claim that other matches are absent. Other
broad direct calls publish no fact. Narrow source reads and stats remain
source backed. The authenticated 4,097-file test covers a peer receiving a
verified match and its invalidation after mutation. The
[10k-file match-fact trial](../bench/results/2026-09-23-gateway-task-reuse-value-match-facts-10k-trial-v1.json)
measured cold/warm task-bound search at 0.505/0.489 seconds, with six physical
provider executions and zero exact hits. The
[clean-source authenticated release gate](../bench/results/2026-09-23-auth-product-e2e-search-match-release-v1.json)
at `5c88120` passed peer delivery and relevant-edit retirement for a match in
the 4,097-file fixture, along with the existing task lifecycle scenarios. The
report binds source SHA `5c88120c865a93eaa1f832fd004903853bcc08eb` to
release binary SHA-256 `4be421877b75bf700c275e728f2ba97f49e5c04b5314d9b524ff13982e33feb9`.
After rebasing onto `origin/main` at `6a8f88a`, the source tree remained
identical. The [rebased clean-source release gate](../bench/results/2026-09-23-auth-product-e2e-search-match-rebased-release-v1.json)
passed the same lifecycle scenarios at `eda4ab8`, with the same release binary
SHA-256. Codex and fake-Claude launcher lease handoff gates also passed on the
pre-rebase identical tree; the rebased daemon suite, formatting, and strict
Clippy passed.
The manifest now validates cached witnesses before observation and at the
final mutation fence, without repeating the same check while assembling a
cached plan. In one local debug scale comparison against the exact parent
commit, warm 1,000-file observation fell from 89 to 55 ms and warm 10,000-file
observation from 959 to 595 ms. This measures manifest work, not whole-task
speed or exact cache hits. A cancellation arriving between durable follower
acquisition and provider registration is now retained for that exact call
attempt; a focused test confirms the follower is retired while the leader
remains in flight. Daemon-only constructors and authenticated transport entry
points are excluded from non-daemon builds, and the unused leader-owner field
was removed. The [clean-source release gate](../bench/results/2026-09-23-auth-product-e2e-manifest-cancel-release-v1.json)
at `e9e04c9` passed all 14 lifecycle scenarios with release binary SHA-256
`0aeb4862981119a53ca10289b074c0236f930e75cd0e116226aeceec2a9c1023`.
The full daemon suite, strict daemon Clippy, and strict non-daemon check passed.
The [clean-source authenticated release gate](../bench/results/2026-09-23-auth-product-e2e-scoped-overflow-release-v1.json)
at `d0ee560` passed the full task source lifecycle. In particular, a
concurrent search of a bounded `lease/` subtree in the same large workspace
still joined one in-flight execution after the route was scoped to the
requested subtree.
The [Codex](../bench/results/2026-09-23-codex-launch-scoped-overflow-release-v1.json)
and [fake-Claude](../bench/results/2026-09-23-claude-launch-scoped-overflow-release-v1.json)
clean-source launcher gates also passed lease handoff and stale-brief refresh
on that release binary. A live Claude coding outcome remains unverified.
The [clean-source 10,000-file release probe](../bench/results/2026-09-23-gateway-task-reuse-value-scoped-overflow-10k-clean-release-v1.json)
using the same binary bytes measured cold task-bound search/tree/Git status at
0.49/0.30/0.03 seconds. Warm p50 was 506/301/30 ms, near the respective
direct controls of 493/302/28 ms. All six calls in each case executed the
provider and none claimed a hit. The report does not independently verify
binary-to-source binding; the clean-source authenticated gate pins the binary
and source together.

A [10,000-file task-bound diagnostic baseline](../bench/results/2026-09-23-gateway-task-reuse-value-10k-baseline-v1.json)
measured task-start median 4,254 ms across ten isolated daemon cases. The
[bounded-index follow-up](../bench/results/2026-09-23-gateway-task-reuse-value-10k-preflight-v2.json)
measured 3 ms median: a source-inventory preflight now declines optional full
indexing above 4,096 source files and marks the edit brief incomplete. Exact
tool-result digests matched the direct controls. All warm `repo.*` cases still
executed each call; this is a task-start latency improvement, not redundant
call avoidance or validated task completion. The current source also returns
small explicit task-path previews when that fallback runs and previews were
requested. The [clean-source release-binary task gate](../bench/results/2026-09-23-authenticated-product-e2e-large-index-release-v3.json)
at `ca721c2` passed this behavior with 4,097 source files, alongside the
earlier shared-context and 257-source ledger scenarios. No live agent outcome
has been measured for this fallback.
The separate [1,000-file control](../bench/results/2026-09-23-gateway-task-reuse-value-1k-quality-control-v1.json)
still took 2,152 ms median for task start and returned 24 code candidates.
A local 150 ms synchronous index-budget trial reduced that to about 383 ms
but returned zero candidates, so it was reverted. Faster task start on
mid-sized repositories needs a path that preserves useful entry points;
this control is a diagnostic with three warm calls per case.
For an explicit small file in that 1,000-file fixture, the
[requested-preview route](../bench/results/2026-09-23-gateway-task-1k-explicit-preview-v1.json)
measured 1.7 ms median task start and returned one complete source preview;
the [same-prompt no-preview control](../bench/results/2026-09-23-gateway-task-1k-explicit-control-v1.json)
measured 2,162 ms and returned 24 index candidates. The opt-in fast route
marks broader indexing incomplete. It is a conditional latency win, with
edit-quality parity and actual redundant-call displacement still unproven.
The [clean-source release-binary task gate](../bench/results/2026-09-23-authenticated-product-e2e-mid-index-preview-release-v4.json)
at `7a608ad` passed the 1,000-file named-preview route as well as the
shared-context, 257-source freshness, and 4,097-file fallback scenarios.
The [live Codex pair](../bench/results/2026-09-23-codex-1k-preview-pair-v1.json)
on 1,000 files passed the edit oracle but finished in 60.4 seconds with Again
versus 25.7 seconds baseline; the Again trace included invalid empty-root
`repo.list` and an overflowing `git.status`. The gateway now accepts an empty
optional root path and returns a bounded, explicitly truncated Git status
with a total count. The [repeat pair](../bench/results/2026-09-23-codex-1k-preview-pair-fixed-v1.json)
at `167de67` removed those two failures and again passed the edit oracle, but
finished in 46.7 versus 20.7 seconds, used 204k versus 107k input tokens,
and had zero exact hits. This is one unbalanced pair per build, not a cohort;
it does not establish acceleration or redundant-call avoidance.
The [test-companion live pair](../bench/results/2026-09-23-codex-1k-test-preview-pair-v1.json)
at `2c7f3cb` passed both edit oracles. Again included an explicitly labeled,
unverified `tests/test_calculator.py` preview beside the requested source
preview; Codex then edited and ran the unittest suite with no follow-up
repository calls or failed tools. Completion was 21.6 seconds versus 19.7
seconds baseline, and input tokens were 122k versus 99k. This is a large
reduction in follow-up calls on one fixture, but still misses the task-level
speed and cost targets. The [authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-test-preview-v1.json)
also passed the bounded test-candidate preview alongside its lifecycle cases.
The [reverse-order pair](../bench/results/2026-09-23-codex-1k-test-preview-reverse-v1.json)
at `8926d39` likewise passed both edits and made zero Again repository
follow-up calls, but Again finished in 24.5 seconds versus 22.0 seconds
baseline and used 150k versus 98k input tokens. It first tried unavailable
`python`, then passed with `python3`. Together the two orders do not prove
task-level acceleration on this fixture.

The task-start brief now suggests `python3 -m unittest discover -s tests`
when its complete but relevance-unverified Python test companion explicitly
uses `unittest.TestCase`. The suggestion remains `execute_required` and
`verified: false`; it grants no test reuse authority. A first local pair used
a binary built without the `daemon` feature, so Codex could not discover
Again, spent 54.7 seconds looking for an integration, and made no edit. The
pair harness now refuses that binary before a model run. With a daemon-enabled
debug binary, the [rerun](../bench/results/2026-09-23-codex-1k-validation-hint-daemon-pair-v1.json)
passed both edit oracles. Again made one `task.start` call, no follow-up
repository calls, and ran `python3` successfully; it finished in 21.9 seconds
versus 28.2 seconds baseline. Input tokens were 123k versus 113k. This is one
unbalanced, dirty-source diagnostic, so task-level speed and token gates
remain open.
The [clean-source authenticated release-binary gate](../bench/results/2026-09-23-auth-product-e2e-validation-hint-v1.json)
at `0e70e54` passed the bounded, unverified unittest selector along with the
existing shared-context, source invalidation, in-flight follower cancellation,
and lease-recovery lifecycle scenarios.

The [one-file cross-task guard probe](../bench/results/2026-09-23-gateway-task-reuse-cross-task-guard-v1.json)
measured 40 warm calls per case on local dirty source. The current-reference
check added 48 µs to small-read p50, 76 µs to search p50, and 53 µs to tree
p50 versus execute-only; all three paths still executed 41 physical calls.
This is a correctness guard with a measurable small-call cost, not evidence of
faster repeated reads. Reducing that cost while preserving cross-connection
and cross-process freshness remains open.

With source recipes enabled, the [one-file daemon probe](../bench/results/2026-09-23-gateway-task-source-recipe-v1.json)
measured a 22.85 ms first task-bound small read versus 0.57 ms execute-only,
and 0.315 ms versus 0.244 ms warm p50 across 40 calls. Search and tree had
similar small-call warm overhead; Git status kept a warm reuse win. These are
local dirty-source per-call diagnostics. The initial admission cost and task
latency need optimization before this path satisfies the acceleration gate.

At source `2578646e152be5fc3fff42f665f99b06a1064438`, the clean-source
production-binary product E2E harness stops in its first concurrent-search
scenario with `result_reference_missing`. Both standalone `repo.search` calls
correctly take the current direct-execution route and have no stored result
ID; the harness still assumes the earlier storage route. This is a harness
qualification gap, not passing release evidence. The harness must start
authenticated tasks for shared-context and result-reference scenarios and
check direct standalone behavior separately.
The new authenticated [task harness](../bench/agent_gateway_authenticated_product_e2e.py)
exercises that route with two daemon-connected clients. Its retained
[clean-source release-binary run](../bench/results/2026-09-23-authenticated-product-e2e-release-v1.json)
at `a7c4e3f9a9325d08aaf229bb0b966a8fd0581047` passed standalone direct
execution, one physical execution and one join for two simultaneous task reads,
peer fact/retrieval, preservation after an unrelated edit, and retirement after
an unobserved relevant edit. This focused gate does not replace the legacy
cancellation, lease, or corruption scenarios, and it does not prove task-level
speed or quality.
Task start now returns an explicitly incomplete full brief when current source
revalidation exceeds its 256-source bound or its workspace observation is
unavailable. The brief omits unchecked verified facts, result references, code
candidates, and source previews; incomplete delivery grants no compact-context
acknowledgment. Context delta likewise returns no unchecked events or compact
acknowledgment at this bound. A 257-source authenticated service test covers
both responses.
The expanded [clean-source release-binary run](../bench/results/2026-09-23-authenticated-product-e2e-large-ledger-release-v2.json)
at `753c3ba5617b193822c09747382ce4e8d0530048` passed the same task
scenarios plus a 257-source ledger: both task-start and delta withheld
unchecked entries, the brief stayed full on retry, and targeted retrieval
refused an edited source. This is bounded-behavior evidence, not a throughput
or task-quality claim.
The latest [clean-source release-binary gate](../bench/results/2026-09-23-auth-product-e2e-2dad98f.json)
at `2dad98f` passed those task scenarios, including the 1,000-file named-file
preview and 4,097-file fallback. It recorded one physical execution and one
in-flight join for two duplicate authenticated reads.
The expanded [authenticated lifecycle gate](../bench/results/2026-09-23-auth-product-e2e-lifecycle-v2.json)
at `717c980` additionally passed recipient-scoped cancellation, corrupt blob
refusal with a `result_corrupt` quarantine event, and killed-daemon lease
recovery after the recorded expiry. The recovery had one `lease_expired`
event and a completed second lease generation. The full locked Rust suite and
strict all-target/all-feature Clippy passed locally. Two further
[authenticated runs](../bench/results/2026-09-23-auth-product-e2e-inflight-cancel-v1.json)
at `110bf88` also passed in-flight follower cancellation: one provider
execution and completed leader, one canceled joined follower, and no follower
result delivery. The local
beta aggregator now requires the authenticated report and binds its clean
source and release-binary digests; its synthetic validator tests pass. The
full packaged beta release decision remains unqualified because the current
real-client speed cohort, complete product scenario, and signed packages are
not yet passing evidence.

The current local source also closes unrelated inherited file descriptors at
macOS daemon startup. A 100-connector stress test exposed a retained pipe that
could keep a completed client waiting for EOF; the focused test now completes
in under one second. The locked all-features suite, strict all-target Clippy,
formatting, and diff checks passed locally after this fix. This remains local
evidence until an exact-SHA hosted run qualifies the committed source.

- **Maintain evidence authority:** exact-SHA hosted CI and the provisioned Gate
  2 workflow are green at `3d1fb201507a43b830d5ce341b2253957634016d`.
  Preserve immutable run/artifact identifiers for every later qualification.
- **Distribute the local alpha:** consolidate the audited profile registry,
  exercise real Codex sessions and non-sparse polyglot repositories, add reviewed
  signing/attestation plus independent verification, then publish a prerelease.
  No current unsigned artifact qualifies for outside-alpha distribution.
- **Preserve the qualified Linux supervisor boundary:** Gate 2 is closed at the
  exact evidence checkpoint above. Keep both hidden diagnostics command-free
  and non-authoritative; later changes to their syscall, cleanup, filter, or
  transcript contract require a fresh provisioned qualification.
- **Execute before reusing:** compose one exact pytest
  selector through snapshot, isolation, tracing, stdio, and cleanup as an
  execute-only foreground run. The command-free child can now attach and
  authenticate both publication roots, transfer the exact stopped identity and
  cleanup guard to a ptrace supervisor, and cancel with terminal-reap proof.
  The provisional trace-only workload filter is frozen but is not yet installed
  and read back on that same child. Fixed command release, post-release tree
  supervision, exact foreground delivery, and execution qualification remain
  open.
  Candidate construction, shadow, promotion, and hit authority are later
  independent gates.

The dependency order and exit criteria are normative in
[ROADMAP.md](ROADMAP.md). Terminal ownership and validation levels are in
[DEVELOPMENT_WORKSTREAMS.md](DEVELOPMENT_WORKSTREAMS.md).

## Team foundation versus remaining product

Implemented foundation: versioned strict remote manifest types, deterministic signing bytes, schema-level namespace/request/policy/profile/platform/image/blob bindings, bounded lifetimes/timestamps, producer-key authorization, expiry/revocation/privacy rules, strict Ed25519 signing/verification with immutable key-id ownership, a locally tested Cloudflare D1/R2 service boundary, and CLI-integrated async Rust clients for the reference and bundle transports. The client obtains and verifies fresh offline-root-signed repository trust and durably checkpoints its epoch; an operator must still provision the root, profiles, keys, credentials, trust, and service manually.

Not yet a team product: the opt-in CLI invokes the encrypted remote protocol only for manually provisioned profiles. The service is undeployed and lacks public onboarding/control-plane UX, production bucket-isolation evidence, edge pre-auth abuse controls, external security review, and production operations. A bounded CI wrapper and composite action now integrate already-provisioned alpha state, but they do not create accounts, trust, credentials, or a deployed endpoint. A two-machine product E2E/cross-machine equality corpus, signed production artifacts, live hit-rate/savings benchmarks, and design-partner/payment evidence remain.
