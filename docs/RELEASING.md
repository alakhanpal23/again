# Releasing Again

Releases are tag-driven, but a tag is not sufficient by itself. A pushed tag
must use the workflow's supported SemVer form (for example, `v0.1.0`), equal
`v` plus the version in `Cargo.toml`, and point to a commit contained in
`origin/main`. Immediately before publication, the workflow resolves the
remote tag again and requires it to still equal the triggering `GITHUB_SHA`.
This makes publication fail if the tag moved before that check; it does not
replace a protected-tag policy or make the tag immutable after publication.
Tags with a prerelease suffix are published as GitHub prereleases rather than
as stable releases.

Only a named human release authority may create or push a release tag. Before
tagging, that person must verify that the applicable exact-SHA CI jobs actually
ran and passed; a skipped, canceled, zero-step, or billing-blocked run is not a
release gate. The workflow currently publishes unsigned artifacts, so it is not
eligible for the outside-alpha gate until the reviewed signing/attestation and
independent verification work below is complete. See
[DEVELOPMENT_WORKSTREAMS.md](DEVELOPMENT_WORKSTREAMS.md#evidence-and-release-authority)
and [Roadmap Gate 1](ROADMAP.md#gate-1--distributable-local-alpha).

The release workflow uses Rust `1.88.0` explicitly for verification, native
tests, builds, and SBOM generation. `rust-toolchain.toml` pins the same version,
and release builds use `Cargo.lock` through `--locked`. All referenced GitHub
Actions are pinned to full commit SHAs and use Node 24 action runtimes.
Checkout credentials are not persisted, and the verify, build, and SBOM jobs
receive only read access. The source is not
checked out in the publishing job; that job alone receives `contents: write`
and exposes its token only to tag revalidation and release publication.

Before any build, the verify job runs formatting, clippy with warnings denied,
all feature-enabled tests, the deterministic 100,000-case differential corpus,
shell and Python syntax checks, and the packaging rollback tests. Each platform
job also runs the feature-enabled Rust tests natively before building and
smoke-tests the packaged binary's reported version.

## Native release matrix

| Target | Runner |
| --- | --- |
| `aarch64-apple-darwin` | `macos-15` |
| `x86_64-apple-darwin` | `macos-15-intel` |
| `aarch64-unknown-linux-gnu` | `ubuntu-24.04-arm` |
| `x86_64-unknown-linux-gnu` | `ubuntu-24.04` |

The matrix is intentionally limited to native runners. It does not claim that
an untested linker, cross-compiler, or emulator produces a supported release.
The Linux artifacts use the GNU target and require glibc; musl systems such as
Alpine are not supported by these artifacts.

## Archives, checksums, and SBOM

The packaging script creates one `tar.gz` per target containing exactly one
member named `again`. It normalizes the packaging layer to a `0755` mode,
root UID/GID and names, and a tar and gzip timestamp derived from the tagged
source commit. Given the same binary bytes and source timestamp, the packaging
test requires repeated archives in the same packaging environment to be
identical; it does not prove cross-version Python or zlib reproducibility.

This is not a claim that two independent Rust builds produce bit-for-bit
identical binaries. GitHub-hosted runner images and parts of the native build
environment can change. Archive normalization removes packaging variation; it
does not establish reproducible compilation.

The separate SBOM job installs exact `cargo-cyclonedx` version `0.5.9` with its
lockfile and generates CycloneDX 1.5 JSON with all crate features enabled. It
derives `SOURCE_DATE_EPOCH` from the tagged source commit so the tool does not
inject the wall clock or a random serial number. The resulting file is a source
dependency SBOM generated on Ubuntu x86_64. It is not represented as a
per-target binary SBOM or as build provenance.

The publisher requires all four explicitly named platform archives and the
source SBOM, then creates and verifies a combined `SHA256SUMS` before publishing
them. These checksums bind the downloaded files to that manifest, but they do
not identify or authenticate the publisher.

## Signing status

Release artifacts are currently unsigned. Full-SHA action pins, source gates,
checksums, and restricted workflow credentials reduce release risk, but none is
an artifact signature. The workflow deliberately does not publish a fabricated
provenance statement.

Keyless signing and attestations remain pending a reviewed GitHub OIDC design
with:

- an explicit trusted workflow/repository identity and tag policy;
- a public transparency-log entry or equivalent verifier;
- verification instructions tested independently of the publishing job; and
- a recovery and revocation procedure for compromised workflows.

Until that work lands, consumers must verify `SHA256SUMS` obtained through a
trusted channel. A checksum manifest downloaded from the same compromised
release as an archive would not provide an independent trust anchor. GitHub
release immutability is also a repository setting outside this workflow and
must not be assumed unless it has been enabled and verified for the release.

## Maintainer checklist

1. Confirm the named human release authority, intended release class, exact
   candidate SHA, and successful nonempty applicable CI jobs. Do not use the
   current unsigned path for an outside-alpha release.
2. Confirm that `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, and the
   intended release notes are correct on `main`.
3. Run the same source and packaging gates locally:

   ```sh
   cargo +1.88.0 fmt --check
   cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings
   cargo +1.88.0 test --locked --all-features
   cargo +1.88.0 test --locked --test generated_differential \
     generated_differential_100k -- --ignored --exact --nocapture
   sh -n scripts/install.sh scripts/uninstall.sh scripts/test_packaging.sh
   python3 -m py_compile scripts/package_release.py
   sh scripts/test_packaging.sh
   ```

4. Create and push an annotated tag whose version exactly matches
   `Cargo.toml`, for example:

   ```sh
   git tag -a v0.1.0 -m 'Again v0.1.0'
   git push origin v0.1.0
   ```

5. Review the source verification, all four native build jobs, the source SBOM
   job, and the final tag revalidation and publication job.
6. Download an archive and `SHA256SUMS`, verify the checksum, and exercise
   install, managed upgrade, lock contention, injected-error and injected-signal
   rollback, and uninstall in a temporary trusted destination.

## Installation

The installer requires an explicit version and destination. It accepts the
same release-tag shape, selects an archive for macOS or glibc Linux on arm64 or
x86_64, and rejects detected musl Linux. It never pipes a response to a shell
or executes the downloaded binary.

Remote requests are HTTPS-only and have connection and operation timeouts.
After download, the installer requires regular non-symlink files and rejects a
release archive over 64 MiB or a checksum manifest over 1 MiB. Extraction also
runs with a file-size limit. These controls bound retained inputs and extracted
output; they are not a streaming proof that a server can never transmit more
bytes before rejection.

The archive checksum must match a valid hexadecimal entry in `SHA256SUMS`, and
the archive must contain exactly one regular executable named `again`. The
installer then copies it with mode `0755` into a securely generated staging
file in the destination directory, so archive ownership is not inherited.

```sh
./scripts/install.sh \
  --version v0.1.0 \
  --dest "$HOME/.local/bin/again"
```

The default URL is an unauthenticated GitHub release URL. While the repository
is private, that path will not work for an ordinary `curl` or `wget` request.
Download private release assets with an authenticated tool such as
`gh release download` first and use `--artifact-dir`; the installer does not
accept a GitHub token or add authentication headers itself.

```sh
./scripts/install.sh --version v0.1.0 \
  --artifact-dir ./release-assets \
  --dest "$PWD/.tmp/bin/again"
```

The destination's parent directory is part of the trust boundary. Running the
installer with elevated privileges into a directory writable by less-privileged
users is unsupported because those users can race adjacent destination, backup,
marker, or lock paths. Use a user-owned private directory without elevation, or
a root-owned non-shared directory for a privileged installation.

## Upgrade, rollback, and uninstall

For an initial takeover, an existing regular non-symlink file is moved to the
adjacent `<destination>.previous` backup. Existing directories, symbolic links,
devices, and other non-regular destinations are refused. A successful install
writes a mode-`0600` `<destination>.again-install` marker containing the
installed binary hash.

Install, managed upgrade, and uninstall serialize mutations with an atomically
created adjacent `<destination>.again-lock` directory. If that path already
exists, the command fails closed without changing managed state or removing the
other operation's lock. A lock created by the current command is removed on
normal completion, ordinary command errors, and handled `HUP`, `INT`, or `TERM`.

For a managed upgrade, the installer first verifies that the current binary
still matches its marker and snapshots the managed binary and marker. It stages
the replacement binary and marker in the destination directory and uses
renames for their individual commits. The user's original `.previous` backup
is preserved across managed upgrades.

If a command returns an error or a handled `HUP`, `INT`, or `TERM` interrupts
the sequence before commit, the cleanup path attempts to restore the previous
binary, marker, and original backup. Packaging tests inject command failures
and `TERM` immediately after the first state-changing rename during both upgrade
and uninstall; they require a nonzero signal status, prior-state restoration,
and lock removal.

This is transactional rollback for tested, catchable process failures, not a
filesystem transaction across the binary and marker. It cannot guarantee
rollback after `SIGKILL`, power loss, kernel failure, storage failure, or a
hostile process that ignores the lock. Recovery after those events may require
inspecting the adjacent marker, backup, lock, and staging state manually. In
particular, `SIGKILL` or a machine failure can leave a stale
`<destination>.again-lock`; after confirming that no install or uninstall is
active and inspecting the adjacent state, remove that exact empty lock directory
manually before retrying.

Uninstall verifies the marker and current binary hash, stages the managed
binary and marker, restores the original backup when present, and removes the
staged files only after commit:

```sh
./scripts/uninstall.sh --dest "$HOME/.local/bin/again"
```

If a user edits or replaces the managed binary or marker, upgrade and uninstall
fail closed and leave the installation in place. A present original backup must
remain a regular non-symlink file; its contents are not authenticated and are
what uninstall will restore.

## Known limitations

- macOS and glibc Linux on arm64 and x86_64 are the only release targets.
  There is no musl artifact, and compatibility with older glibc distributions
  must be measured before claiming a minimum supported version.
- Native runner labels and images are external dependencies. A retired label
  requires a reviewed matrix update and a fresh release run.
- Archive metadata is normalized, but compiled binaries are not yet proven
  bit-for-bit reproducible across independent builders.
- The CycloneDX file is a source dependency SBOM, not a target-specific binary
  SBOM or a signed provenance attestation.
- SHA-256 manifests provide integrity relative to the manifest, not publisher
  authentication. Artifact signing and attestations remain pending.
- Catchable-failure rollback does not cover power loss, `SIGKILL`, hardware or
  filesystem failure, or a hostile process that ignores the adjacent lock. An
  uncatchable failure can leave a stale lock requiring deliberate inspection and
  manual removal before retrying.
- Privileged installation into a shared-writable destination directory is
  unsupported.
- The default installer download is unauthenticated and therefore unavailable
  while the GitHub repository and its releases are private.
- The installer intentionally does not modify `PATH`, shell startup files, or
  Codex configuration. After installation, run `again setup --codex`
  explicitly and review that integration through Codex's normal trust flow.
