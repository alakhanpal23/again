# Private alpha readiness evidence

The candidate release binary was built from signed source
`502570b3c278360eedfd13210fa6c0d674551b3a`. It is 7,771,568 bytes and has
SHA-256 `8fcff5ebe8fa21c2fd568b3e442ac3df9b4ba3c8b787db1145e7ed6305376182`.
The evidence commit containing this document is expected to be a documentation
and report-only descendant of that source commit.

## Local release-binary gates

| Gate | Outcome | Report SHA-256 |
|---|---|---|
| [Product gateway E2E](../bench/results/2026-08-28-agent-gateway-product-e2e-private-release-v1.json) | pass; 8 scenarios, 12 provider executions, 0 false hits | `c5cc8f8508d08bc09f2e6276a274934c2b2cf4576ea00e69318a307784fa3395` |
| [Isolated onboarding smoke](../bench/results/2026-08-28-agent-gateway-onboarding-smoke-private-release-v1.json) | pass | `4d19010d6408590e610785000d7772928607dcdae16bbeaa651f5186f5c8eb13` |
| [Repository-tool E2E](../bench/results/2026-08-28-agent-gateway-repository-tools-private-release-v1.json) | pass; 0 false hits | `7d10c3686b4350a3dfa1f19026626c0bfac5c60ac4b083d7c664bbc49b21c6f4` |
| [Four-language gateway corpus](../bench/results/2026-08-28-agent-gateway-real-repository-four-language-private-release-v1.json) | pass; 4 repositories, 0 typed non-passes, 0 false hits | `00209e4957cbd386ac72e9d17a4b42ed1cd10e6d73c57b0a3fa9459bd0bd4037` |
| [Four-language explicit-command corpus](../bench/results/2026-08-28-real-repository-four-language-private-release-v1.json) | pass | `4d48b9c5ca9fa7f5e3ce567bc1e4afe030bee63b61d93998bdb5e1a7b43ef2f0` |
| [Quick chaos and cleanup run](../bench/results/2026-08-28-agent-gateway-chaos-soak-private-release-v1.json) | pass; 0 false hits, no owned process/descriptor/temporary-state leak | `4ce4443959838b029e43d1ed038ab8e8203ad7334ad3d7ff381d1fca4ed5c5e8` |

The passing reports were generated directly under
`/Users/arjun/again-release-evidence-2026-08-28` rather than an ephemeral
`/private/tmp` directory, then copied byte-for-byte into `bench/results/`.
Bounded non-pass diagnostics for one abbreviated SHA, one malformed corpus
argument, and sandbox-denied process inventory remain in that external audit
directory and are not cited as product evidence.

## Private publisher path

The repository remains private. GitHub-native private-repository artifact
attestations are unavailable on the current plan. The tag workflow instead
uses pinned clean Cosign `v3.1.3` commit
`11926fa5bbbbde47e88fc006b625a17769b743b2` to publish one standardized
Sigstore bundle for each of seven release subjects. Verification requires the
exact GitHub workflow certificate identity, OIDC issuer, tag ref, repository,
source SHA, `push` trigger, SLSA provenance predicate, signed claims, RFC3161
timestamp, and Rekor transparency proof. The release inventory is closed at
seven subjects plus seven bundles.

This local checkpoint is not publisher evidence. Readiness still requires the
exact signed tag workflow to pass all four native builds, publish an immutable
private prerelease, independently verify all 14 assets, exercise the
authenticated installer and uninstaller, and retain the release-evidence
artifact.

## Unsupported capabilities

- Outside-user validation remains at 0 of 5 users and 0 of 50 attempts.
- The public MCP path has no authenticated recipient issuer, so compact
  recipient delivery and delivery-confirmed byte/token savings remain zero.
- Production Linux command execution and reuse remain disabled pending a
  separate qualified profile.
- The team service is not deployed or publicly provisioned.
- Live Codex/Claude task-quality, paid-model, hostile-binary network-isolation,
  cross-machine, and production-traffic evidence remain absent.
- macOS support remains restricted to audited profiles; unknown architectures
  refuse with `UnsupportedArchitecture`.
