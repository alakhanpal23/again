# Gate 1 four-language repository evidence

This evidence-only checkpoint was produced from clean source commit
`573293dbc2b09008fc1ea5b651645cef5a112d30`. It changes no product code and
grants no new runtime, delivery, execution, or reuse authority.

## Result

The release binary with SHA-256
`8fcff5ebe8fa21c2fd568b3e442ac3df9b4ba3c8b787db1145e7ed6305376182`
passed the real-repository corpus on four explicit clean Git repositories:

| Language | Repository commit | Requests | Provider executions | Exact hits | Inflight joins | False hits |
|---|---|---:|---:|---:|---:|---:|
| Rust | `573293dbc2b09008fc1ea5b651645cef5a112d30` | 75 | 43 | 31 | 1 | 0 |
| Python | `db5537fa6945f9bdc0a32fba3d6783ea69a858f5` | 75 | 43 | 31 | 1 | 0 |
| Go (`https://github.com/golang/example.git`) | `7f05d217867b2af52b0a28c6d1c91df97e1b5b39` | 75 | 43 | 31 | 1 | 0 |
| TypeScript | `2d9b89c6ca6b0ee3cc04f72b8462df113c95ff8b` | 75 | 43 | 31 | 1 | 0 |

All four repository reports passed, with zero typed non-passes and zero false
hits. The harness exercised all 13 advertised repository/Git tools, exact
native-output comparisons, deterministic concurrent joining, Git
configuration/object/index/HEAD changes, relevant and irrelevant dependency
mutations, rename/delete/replacement, and same-path repository identity
replacement. Authenticated delivery receipts and claimed token savings were
both zero.

The report's `go_repository_eligible` field is false because optional automatic
Go discovery was not requested. A clean complete-history Go repository was
supplied explicitly and its individual outcome is `pass`.

## Retained evidence manifest

| Evidence | Outcome | File SHA-256 |
|---|---|---|
| `bench/results/2026-08-28-agent-gateway-product-e2e-reconciliation-v1.json` | pass | `b3b6fde9fb7cff8c2c8911aca711c5195502557e40b555c3ad02c2df14fff49a` |
| `bench/results/2026-08-28-agent-gateway-onboarding-smoke-reconciliation-v1.json` | pass | `5d30f6b2ab9405cf7d90504ee46c8807745c1350bcd0caf52fda144b81db972b` |
| `bench/results/2026-08-28-agent-gateway-repository-tools-e2e-v1.json` | pass | `887ea0a5909700d208ee282f52baabc273d82fa60cfad586d933f6c10daf2b60` |
| `bench/results/2026-08-28-agent-gateway-real-repository-four-language-v1.json` | pass | `a82b5e243a974a1f935f07666c9f374403cee8a5ee2c6d9a39ebde26cade4ac4` |
| `bench/results/2026-08-28-agent-gateway-chaos-soak-v4.json` | pass | `101d434198b52911a4bfdf3ebdff4bfa83cbbf7bfe5ebec6738af99d045ac837` |

## Limitations

- This closes the local four-language corpus gap only. It is not outside-user,
  real-agent, task-quality, or cross-machine evidence.
- Absolute source paths identify the local inputs; report payloads contain
  hashes and metadata, not copied repository contents or MCP response bodies.
- The public stdio product still cannot issue authenticated recipient or
  delivery authority. Compact presentation and delivery-confirmed savings
  remain unavailable.
- Production Linux command release and reuse remain separately unqualified.
