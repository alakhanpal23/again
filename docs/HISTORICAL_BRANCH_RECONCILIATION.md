# Historical branch reconciliation

This ledger accounts for every commit unique to the twelve historical branches
listed below, relative to clean base
`4d8869c828b745e0abfce10ff2fe541b43bb7fb0`. It does not grant any new product
authority. In particular, a result identifier or digest is not bearer
authorization, caller-supplied recipient or session identifiers grant no
authority, response write or flush is not recipient delivery, and compact
presentation and savings require authenticated delivery evidence.

## Audit method and integrated reconciliation lanes

Before each integration, `main` was clean and each reconciliation candidate's
merge base was the exact base above. All candidate and historical commits were
checked with `git verify-commit`; all 31 historical commits and all eight
candidate commits had good signatures from key
`231D6118F785110C8E09CE0470E491BD898FEC6F`. Complete histories and diffs were
inspected. `git cherry` and `git range-diff` were run between each candidate,
`main`, and its source historical branches. Candidate branches were not merged
or pushed; accepted changes were narrow signed cherry-picks, except for the
documented compatibility-preserving developer-command reimplementation.

| Lane | Frozen candidate tip | Main replacement | Targeted validation |
|---|---|---|---|
| Delivery and retrieval | `7e932fd1ab76ce358595305928327200ea854307` | `36f49ce8d17279ab150463a983ee32798a417730`, `325f60b0d6b523a27b42472a01b82b2c3858efb3` | 38 MCP/retrieval integration tests, 4 retrieval-authority tests, and 8 delivery-receipt tests passed. |
| Daemon and developer commands | `e91c6d7ebd521583d7dd992b9c7966cdd6ea8f3f` | `dba803f946984daa1719461904c4197b9fc240fe`, `2a50f80bfa68227a783c54f118eaab02d7b2f6da` | 17 service/backend/developer-command integration tests and 4 service unit tests passed. |
| Gate 3 Linux | `adea6a11ce7d10978c8f2bd0f014a0ca932b2c79` | `1e25e1e8516bef64c0ad59c96473791f6363f371` | 377 portable `linux_pytest` unit tests passed; these are not positive Linux qualification evidence. |
| Evidence and benchmarks | `2e9239dafade669923c8baa3e1882812119bbdcd` | `1230d740e69bc680b2053261aca265aa21b2ba1c`, `bcf92da265e1093337ff74fb01eeada623321712`, `bdfe35a15a1047a426d255129112e4272f98925a` | Release-evidence shell tests and 53 chaos/real-repository unit tests passed. |

The terms in the disposition column are exclusive: **integrated as written**
means the exact patch was already present under the replacement SHA;
**safely reimplemented** means the intent was retained behind stronger current
authority or compatibility boundaries; **superseded** means stronger main-tree
code already covered the useful behavior; and **rejected** means the historical
implementation itself was not safe or sufficient to integrate.

## Per-commit disposition

| Historical branch and unique SHA | Disposition | Replacement SHA(s) and reason | Supporting tests | Remaining limitation |
|---|---|---|---|---|
| `codex/agent-gateway-docs`<br>`2a32253ad48a71245289e7ff73f967dae36627c4` | Superseded | `21c0f5e37cf48fdb3950142e53219677a9526be0`, `8e77826b969d9ada6b642c687865a9498a81ace8`: current documentation describes the implemented repository gateway and later fail-closed delivery boundary more precisely. | Full documentation and all-target validation below. | Documentation is not production qualification; public recipient authentication and production upstream configuration remain absent. |
| `codex/agent-reasoning-delivery-integration`<br>`6d7c76700cc550387b707bc0d0d427978d138383` | Integrated as written | `c49a95b004e8e570eba26453061c095316bc3870`: patch-equivalent. | Delivery lane and full suite. | The reasoning compiler is internal and grants no delivery or reuse authority. |
| same branch<br>`fa06c45fceb98b9e60e3dc193e8c7ac988da2425` | Integrated as written | `50c390735cf8d4d4e6c27d84ac9e4638ae04b176`: patch-equivalent. | Delivery lane and full suite. | Verified reads alone do not authenticate a recipient. |
| same branch<br>`6628bf14f0a2b3e083b77b383633def3941ab3cf` | Integrated as written | `64b08578ea14779aec52874504aadf8b3cbe2b57`: patch-equivalent. | Delivery lane and full suite. | Adversarial model evidence is not public delivery evidence. |
| same branch<br>`4836eba0d34dcd5a7e37d220a440a564746b4284` | Superseded | `6bfd3e1cdaa15b3e04802911fc451ca284dbe1ed`, `4cf416c75c03acfe1b80cd56f96888bf9c7c71ae`, `f3a2870fc80cbb1babf3bf9d7948823fe88c671a`, then `36f49ce8d17279ab150463a983ee32798a417730`: main has the delivery integration plus race closure, durable-metric proof, and a public fail-closed recipient boundary. | Delivery lane: 50 tests. | Only authenticated internal composition can confirm full delivery; public stdio cannot issue recipient authority. |
| `codex/agent-result-retrieval`<br>`d39e5cdac50eab1ff59fa8518b7a22b1e92ff8aa` | Safely reimplemented | `8edfaabd84a1f49d9ff0a691f384459699082dc7`, `325f60b0d6b523a27b42472a01b82b2c3858efb3`: retrieval is now recipient/scope/session/turn/connection/compaction bound, expiring, single-use, and revalidates receipt, source, policy, coordinator, leader, dependency, and CAS state. | Delivery lane: 50 tests. | Result ID and digest never authorize retrieval; no public recipient issuer exists. |
| `codex/alpha-release-evidence`<br>`78f24bfdd57769ba5c70ae0ea262736e40f7720d` | Integrated as written | `b76911d10e749e329116487f2aada2f538bc8f0b`: patch-equivalent. | Release workflow tests and full suite. | A release workflow must still run on an immutable tag to produce publisher evidence. |
| same branch<br>`5b1a71b26c7ba09b114be400edaab31cce0e600c` | Integrated as written | `90630807e2ea727e8e27bbefb0491772e0f45d7d`: patch-equivalent. | Installer and release tests. | Rollback hardening does not authenticate an unpublished build. |
| same branch<br>`1946654b83019a6d62b6726c182e9edc55823624` | Integrated as written | `d9458400c75ed1865f562ba69d48a2ed11848d04`: patch-equivalent. | Packaging and release tests. | The formula remains alpha packaging, not a published release by itself. |
| same branch<br>`08875963ec3f87be956154af1e6da2ba124d8f85` | Safely reimplemented | `9ac7884f9d333f5060e68c27b54d7fd746fec87f`, `8fc61fd767862c5cf4d98fe1222f65d9f933e1c9`, `1230d740e69bc680b2053261aca265aa21b2ba1c`: bounded summaries now also enforce exact archive layout, immutable release inventory, binary hashes, certificate-derived publisher/workflow/source identity, workflow invocation, and harness hashes. | Release-evidence shell matrix. | Local fixture verification is not proof that a new public release exists. |
| `codex/developer-command-reuse-v2`<br>`38b84b621f1899b97826ed7000ab3ef59f8e8497` | Rejected | `2a50f80bfa68227a783c54f118eaab02d7b2f6da`: the historical deterministic-command qualifier could make a positive reuse decision without complete runtime, mutation, credential, network, deployment, payment, destructive, or unknown-operation proof. The replacement is assessment-only and always passes through without storage or reuse, while preserving the unavailable `RootlessLinux` descriptor and serialized enum. | Daemon/command lane: 21 tests. | Developer commands do not reuse; semantic or AI suggestions cannot upgrade them. |
| `codex/gate3-filesystem-transaction`<br>`fbf52cf5b8d028390de5b02af425222c60c62b52` | Rejected | `2e1ce4d6af0d3e8a69f255f2419ec120d4847f35`, `8486104eb1df34fc3ca50d1fbd0fd3092cc975c1`, `41e6cd3d58ea24a49ecea2543665ca195208f4b8`, `a829980045dafb18ccc74e413e00ba3b2a3e8777`, `1e25e1e8516bef64c0ad59c96473791f6363f371`: the historical production operations always returned `Unsupported`; its success existed only in a scripted model. Main has checked live child-only leaves and now validates each source immediately before attachment. | Gate 3 lane: 377 portable tests. | Production Linux command release remains unavailable and separately unqualified. |
| `codex/gate3-supervisor-handoff-v2`<br>`c8d6613ab13ab46992c24034a04bd7de71e4b0f1` | Rejected | `b5f6a7cf8f531b232231bf8fe35541328e02d96a`, `1e25e1e8516bef64c0ad59c96473791f6363f371`: the historical wrapper did not seize, stop, or authenticate a live tracee. Main performs checked ptrace ownership and now uses a linear seize-to-release witness. | Gate 3 lane: 377 portable tests. | The child remains command-free, cancellation-only, and non-authoritative. |
| `codex/gateway-chaos-soak`<br>`c2a45df01dee6a81030ded02655498de8e84a66a` | Superseded | `afbd85db1993952720d74cf5aa9638b4eebcec26`, `bcf92da265e1093337ff74fb01eeada623321712`: the current bounded harness covers the earlier scenarios plus transport framing, saturation, corruption/restore, process descendants, cleanup, and resource accounting. | Evidence lane chaos unit tests and final release-binary soak. | Bounded local chaos is not production traffic or outside-user evidence. |
| same branch<br>`9c371d0d08db8b56e8a7d8497d6e9d96e36f38ff` | Superseded | `afbd85db1993952720d74cf5aa9638b4eebcec26`, `bcf92da265e1093337ff74fb01eeada623321712`: its fixture fix is included in the rewritten harness. | Evidence lane chaos unit tests and final release-binary soak. | Same bounded-host limitation. |
| same branch<br>`2d8db5f4fce1732095cf6eac5717fbf098fa8aff` | Superseded | `afbd85db1993952720d74cf5aa9638b4eebcec26`, `bcf92da265e1093337ff74fb01eeada623321712`: stronger schema-v3 evidence separates unsupported hosts from failures and requires cleanup/resource proof. | Evidence lane chaos unit tests and final release-binary soak. | No delivery-confirmed savings or public recipient authority is claimed. |
| same branch<br>`34451b39db220fbe1ccfa2007ad02697cc414b68` | Integrated as written | `bce942097482eed7d6a65f0daf676ea8d6e2a86c`: patch-equivalent. | Chaos unit tests. | Direct invocation still provides only local harness evidence. |
| `codex/gateway-daemon-product-v1`<br>`13317a53efc5a4e5940fe5c5e37b965db791ec6d` | Safely reimplemented | `33dea07327b91612a362c1e03f79d22c6da4d508`, `dba803f946984daa1719461904c4197b9fc240fe`: the opt-in daemon now uses authenticated private locators, nonce socket names, exact modes, same-UID checks, identity-checked cleanup, bounded I/O, TTL, and shutdown. | Daemon/command lane: 21 tests. | It is a local same-user service on supported macOS/Linux hosts, not a public control plane. |
| same branch<br>`712b768d39bcf68905a52f071805106f366cd4e5` | Safely reimplemented | `dba803f946984daa1719461904c4197b9fc240fe`: socket-read hardening is retained inside the stronger authenticated and bounded session design. | Daemon/command lane: 21 tests. | Same-user malicious writers remain outside this local trust boundary. |
| `codex/gateway-delivery-authority-v2`<br>`a1af384768b7f27ae7be7a06a9b96da2a2f07bcd` | Integrated as written | `4da1aaa0f0576d2f55ffec6c2fbb5883a513f549`: patch-equivalent schema-v10 tables. | Delivery lane and full store suite. | Tables store evidence; they do not create recipient authority. |
| same branch<br>`4ccb21d862885b912aa785bf3abfc544acd8fc43` | Safely reimplemented | `36f49ce8d17279ab150463a983ee32798a417730`: acknowledgements now require authenticated internal composition, a flushed full response, a challenge/ack round trip on the same live connection generation, and lifecycle validity. | Delivery lane: 50 tests. | Writing or flushing alone is explicitly insufficient; public stdio is `Unknown`. |
| same branch<br>`af0dbe6f4cf34e508fd16a9749264f289346ec19` | Safely reimplemented | `325f60b0d6b523a27b42472a01b82b2c3858efb3`: retrieval/compact authority now has complete recipient and snapshot binding with one-use consumption and last-moment revalidation. | Delivery lane: 50 tests. | Full retrieval and compact presentation are unavailable without authenticated delivery evidence. |
| same branch<br>`75247c65b086e24cbe25e8a81dae3db5f545db30` | Superseded | `36f49ce8d17279ab150463a983ee32798a417730`, `325f60b0d6b523a27b42472a01b82b2c3858efb3`: constructor sealing is incorporated into opaque, test-only authority issuance and private production composition. | Delivery lane: 50 tests. | No public authority constructor exists. |
| same branch<br>`2a7903677b3eeacb3dde006fa56e41524e608dbb` | Superseded | `325f60b0d6b523a27b42472a01b82b2c3858efb3`: CAS drift is one of the required retrieval snapshot revalidations. | Retrieval-authority and delivery tests. | CAS identity remains evidence, never bearer authorization. |
| same branch<br>`e56676903315542926cef3c46d1b0806b0e3c2bc` | Superseded | `36f49ce8d17279ab150463a983ee32798a417730`, `325f60b0d6b523a27b42472a01b82b2c3858efb3`: current schema and behavior tests cover every retained authority constraint plus live lifecycle invalidation. | Delivery lane and full store suite. | Durable constraints cannot authenticate a public recipient by themselves. |
| `codex/gateway-delivery-receipts`<br>`75ece902e0bc61b3ca43634b408f336607630506` | Integrated as written | `fcbeded3a82d71e528385844b3f9912196e629b4`: patch-equivalent. | Delivery-receipt tests. | A receipt requires a trusted issuer; caller identity strings do not suffice. |
| same branch<br>`4aaa1e6baa81a7dc33a2c1770c3bf7bb7fe3f4c1` | Safely reimplemented | `36f49ce8d17279ab150463a983ee32798a417730`, `325f60b0d6b523a27b42472a01b82b2c3858efb3`: scoped retrieval and compact references survive only behind authenticated recipient/lifecycle authority and source revalidation. | Delivery lane: 50 tests. | Public retrieval/compact delivery remains unavailable. |
| same branch<br>`02b54381250c45cc32dda8658dd91d0d480f6d7c` | Safely reimplemented | `fcb63a854f3291a8278adfee33acd03f7814a1bd`, `5ad0b91ed079e631690fdaf47d7d19fac6554448`, `36f49ce8d17279ab150463a983ee32798a417730`, `325f60b0d6b523a27b42472a01b82b2c3858efb3`: adversarial receipt hardening and receipt-backed savings are retained with stricter public fail-closed issuance and retrieval. | Delivery lane: 50 tests. | Delivery-confirmed savings remain zero on the public product path. |
| `codex/repository-intelligence-v2`<br>`d046630cf2e0ed7bdb6d56015e3484c44949ec07` | Integrated as written | `fcdb5b88bacd4efc2e9ddafbf41fe8a379816268`: patch-equivalent. | Repository tool and full suites. | Primitives are bounded read-only operations, not general command authority. |
| same branch<br>`15ae9d7b0a921b9b15cb7c043a21a23c671ecf05` | Integrated as written | `c04d8869b48eff080eca9cce7702b69a83ad1b61`: patch-equivalent. | Repository tool and full suites. | Unsafe Git configuration/dependencies still refuse or bypass reuse. |
| same branch<br>`3c29d14db6e3d8488530d7df6c84973f30c978fd` | Superseded | `651aa4fd2d3b243251e2ab48a645ddd821b7fba1`, `77158ee7da4a5c419779af896a506deb55155dde`, `bdfe35a15a1047a426d255129112e4272f98925a`: the current E2E/corpus adds all 13 tools, deterministic concurrent join proof, Git config/object/index/HEAD mutations, same-path repository replacement, resources, cleanup, and zero-delivery claims. | Evidence lane corpus unit tests and final release-binary repository runs. | Four-language and outside-user corpus gates remain open when an eligible local repository is absent. |

## Cleanup manifest (no deletion performed)

After the final `main` CI succeeds, the following fully accounted historical
branch/worktree pairs are safe to remove. They are retained for now exactly as
requested:

| Branch | Worktree |
|---|---|
| `codex/agent-gateway-docs` | `/Users/arjun/again-agent-gateway-docs` |
| `codex/agent-reasoning-delivery-integration` | `/Users/arjun/again-agent-reasoning-delivery-integration` |
| `codex/agent-result-retrieval` | `/Users/arjun/again-agent-result-retrieval` |
| `codex/alpha-release-evidence` | `/Users/arjun/again-alpha-release-evidence` |
| `codex/developer-command-reuse-v2` | `/Users/arjun/again-developer-command-reuse-v2` |
| `codex/gate3-filesystem-transaction` | `/Users/arjun/again-gate3-filesystem-transaction` |
| `codex/gate3-supervisor-handoff-v2` | `/Users/arjun/again-gate3-supervisor-handoff-v2` |
| `codex/gateway-chaos-soak` | `/Users/arjun/again-gateway-chaos-soak` |
| `codex/gateway-daemon-product-v1` | `/Users/arjun/again-gateway-daemon-product-v1` |
| `codex/gateway-delivery-authority-v2` | `/Users/arjun/again-delivery-authority-v2` |
| `codex/gateway-delivery-receipts` | `/Users/arjun/again-gateway-delivery-receipts` |
| `codex/repository-intelligence-v2` | `/Users/arjun/again-repository-intelligence-v2` |

Retain the four reconciliation branch/worktree pairs for audit until an
explicit later cleanup decision: `codex/reconcile-delivery-retrieval` at
`/Users/arjun/again-reconcile-delivery-retrieval`,
`codex/reconcile-daemon-commands` at
`/Users/arjun/again-reconcile-daemon-commands`,
`codex/reconcile-gate3-linux` at `/Users/arjun/again-reconcile-gate3-linux`,
and `codex/reconcile-evidence-benchmarks` at
`/Users/arjun/again-reconcile-evidence-benchmarks`. Every other branch and
worktree is outside this reconciliation scope and must be retained.

