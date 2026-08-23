# Security policy and threat model

Again sits on the path of agent-generated shell commands. A bug can change command semantics, leak output, or weaken an approval boundary, so conservative misses are a feature.

## Non-negotiable rules

- Unknown means execute normally; never infer purity from popularity or repeated equality.
- The hook rewrites only commands admitted by a strict read-only policy. All others produce no allow decision.
- Original shell text is never concatenated into the rewritten hook command; an opaque local call id is used.
- Local cache entries are untrusted until request, policy, platform and blob digests revalidate.
- Non-zero, signaled, incomplete, secret-tainted, networked or externally effectful executions are not stored as reusable v0 entries.
- Compact output references are presentation-only and always reversible.
- Remote records are untrusted, tenant-scoped, signed, revocable and validated locally.

## Threats covered now

Current tests cover shell injection and nested wrapping; PATH/basename spoofing; path traversal, runtime namespaces, symlink escape/cycles and special files; environment and executable drift; directory membership and absent-path changes; many concurrent filesystem mutations; corrupt blobs and same-key divergence quarantine; nondeterministic double-run output; malicious hook JSON; non-zero and oversized-output storage rules; and exact-output recovery.

The following are roadmap requirements, not shipped claims: complete descendant/effect tracing, COW mutation replay, crash-atomic effect commits, secret-taint classification, remote cache poisoning defenses, tenant/repository isolation, signed provenance/revocation, and production denial-of-service controls.

## Reporting

This is currently a private pre-alpha repository. Report security issues directly to the repository owner and do not place exploit details in ordinary issues. A public disclosure address and response SLA will be added before public release.
