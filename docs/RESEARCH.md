# Research basis and implementation consequences

Again treats papers as constraints to test, not borrowed marketing claims.

- [Incr, OSDI 2026](https://www.usenix.org/conference/osdi26/presentation/xie-yizheng): automatic effect/dependency discovery can incrementalize unmodified programs. Consequence: build toward internal sub-process reuse, but reproduce results on Again’s own workloads before citing speedups.
- [Riker, USENIX ATC 2022](https://www.usenix.org/conference/atc22/presentation/curtsinger): correct incremental execution must model directories and the wider POSIX filesystem. Consequence: content reads alone are incomplete.
- [Rattle formal model](https://arxiv.org/abs/2202.05328): optimized build execution needs explicit observational-equivalence assumptions and hazard handling. Consequence: define the execution profile and preconditions, not “same output.”
- [ProcessCache](https://repository.upenn.edu/bitstreams/94d981be-86c5-40e9-8d8a-2d4e625c5b9e/download): process-level pre/postconditions make transparent reuse plausible. Consequence: persist proof-carrying execution records and fail closed outside representable effects.
- [Try / semisolates, OSDI 2026](https://www.usenix.org/conference/osdi26/presentation/lamprou): speculative effects can be captured, inspected and selectively committed. Consequence: execute/restore in disposable branches; semisolates alone are not a security sandbox.
- [Sandlock](https://arxiv.org/abs/2605.26298): static kernel enforcement plus a narrow dynamic supervisor is a useful split. Consequence: enforcement establishes the boundary; observation is not enough.
- [mkcheck2, ICSE 2026](https://conf.researchr.org/details/icse-2026/icse-2026-research-track/162/Efficient-Build-Dependency-Verification-Using-eBPF-and-Incremental-Analysis): eBPF can lower continuous dependency-audit overhead. Consequence: use it as a completeness cross-check and performance path, not sole proof.
- [DetTrace](https://doi.org/10.1145/3373376.3378519): time, IDs, scheduling and other ambient state defeat reproducibility, and determinization has costs. Consequence: nondeterminism bypasses default reuse; any deterministic profile is explicit.
- [FastCDC, USENIX ATC 2016](https://www.usenix.org/conference/atc16/technical-sessions/presentation/xia): content-defined chunking improves deduplicated blob storage. Consequence: use it for large-artifact transport/storage only, never semantic validity.
- [Ekstazi](https://users.ece.utexas.edu/~gligoric/papers/GligoricETAL15Ekstazi.pdf): dependency-based regression-test selection can reduce work under controlled safety assumptions. Consequence: validation selection may optimize cost only after dependency closure is demonstrated.

Each source gets a reproducibility entry before it changes an eligibility rule: tested version/platform, fixture, measured effect, divergence, and decision. Upstream code and licenses are reviewed before reuse.

