# Security

keysentry runs on your computer and talks directly to the services you choose. Scanning needs no
keysentry account. The [access guide](docs/ACCESS.md) explains which credentials each integration needs,
what those credentials could do, and what keysentry actually asks them to do.

The [trust promise](docs/superpowers/specs/2026-10-27-trust-autopilot-design.md#3-the-trust-promise)
sets the direction for 1.0. This document describes phase 1 and its limits. There has been **no external
security audit**, and adapters have **not yet been run against live accounts**. Tests use recorded
formats and fake HTTP clients. Build and publishing workflows are prepared; that does not establish
that a public release has been published or independently reproduced.

## Report a security issue privately

Use [GitHub's private vulnerability reporting page for keysentry](https://github.com/grzenio22/keysentry/security/advisories/new).
Include the affected version or commit, the command you ran, the expected result, and a small
reproduction with invented credentials. Do not include a working token, vault contents, or an
unencrypted state file. If private reporting is unavailable to you while the repository is private,
ask the repository owner to arrange private access; do not put sensitive details in a public issue.

Our response targets are to acknowledge a report within **72 hours** and fix a confirmed critical
issue within **7 days**. These are targets, not a service guarantee. We will coordinate a disclosure
date with the reporter and explain if a fix needs longer.

## Supported versions

Phase 1 of keysentry 1.0 is under development. No public 1.0 security support window is established
yet. When 1.x is released, security fixes will target the latest 1.x release; earlier 1.x versions
must be upgraded to receive fixes. The experimental 0.1 series has no promised security maintenance.

The CLI requires Node.js **22.13 or later**. Its optional Node permission sandbox is enabled only on
supported, patched versions. On the Node 22 line it requires **22.23.4 or later**; running on an older
22.x version does not enable that sandbox. Node 22 has no network permission flag: the HTTP client's
host allow-list is the network control. The Node permission model is an extra boundary and does not
make malicious code safe to run. See the [recorded version and permission facts](notes/phase1-facts.md#4-nodejs-permission-model-versions)
and [Node's permission documentation](https://nodejs.org/docs/latest-v22.x/api/permissions.html).

## Dependencies and installation

Phase 1 keeps five direct runtime dependencies in the source tree:

| Dependency | Why it is used |
|---|---|
| `commander` | Parses the CLI's commands and options. |
| `fast-xml-parser` 5 | Parses RSS and Atom advisory feeds. |
| `libsodium-wrappers` | Encrypts GitHub Actions secret values using GitHub's required sealed-box format. |
| `yaml` | Reads the user's YAML configuration. |
| `zod` 4 | Validates configuration and saved input shapes before use. |

`fast-xml-parser` 5 brings six small packages from the same maintainer: `strnum`, `is-unsafe`,
`xml-naming`, `fast-xml-builder`, `@nodable/entities`, and `path-expression-matcher`. These are part
of the dependency review surface. The lockfile records resolved packages and integrity hashes.
`esbuild` is a development dependency, used to make the readable release bundle.

The release package built by `scripts/release-build.mjs` contains the bundle, its local manifest,
README, LICENSE, and NOTICE. Its package manifest has **no dependencies, scripts, or install hooks**.
It does not download dependencies during installation. The source checkout has development and
runtime dependencies; CI installs them with `npm ci --ignore-scripts`. The MCP SDK, MCP server, and
agent skill are removed as part of the CLI integration work for this phase.

## Rebuild a release

Use the same source revision and exact Node.js and npm versions as the release builder. The
manifest records the Node version. The release workflow pins its build runtime; the normal test
matrix also exercises Node 22.x and 24.x on Linux, macOS, and Windows.

```sh
npm ci --ignore-scripts
npm run typecheck
npm run release:build
npm run release:check
```

Use the release's `KEYSENTRY_BUILD_COMMIT` and `KEYSENTRY_RELEASE_REPO` values when reproducing it;
otherwise the build uses development defaults. No build metadata depends on the current time.
The default release output is `dist-release/out/`. It contains `keysentry.mjs`,
`release-manifest.json`, sorted `SHA256SUMS`, the package directory `pkg/`, and its packed npm
tarball. `release:check` builds twice with different time zones, locales, and output directories,
compares every file hash, and rejects a bundle containing the checkout's absolute path. A matching
result shows that these two builds agree; independent rebuilds are still useful.

The release scripts can build without contacting a registry once the locked development dependencies
are installed. `npm pack` creates the tarball locally. Builds do not sign, upload, or publish anything
unless those separate release operations are requested.

## Verify an installed copy

Run verification from an independently obtained copy, for example a fresh `npm pack` of the
published version unpacked into a separate directory. A modified bundle can lie about its own
verification result. To assess a copy you suspect has changed, compare its bytes with the
independently verified release; do not trust that copy's verifier alone.

```sh
keysentry verify --offline
keysentry verify
```

The offline check hashes the running `keysentry.mjs` and compares it with the adjacent
`release-manifest.json`. Source runs report `dev`; a missing manifest and a changed bundle are
reported separately. A local manifest can detect a changed bundle only while the manifest itself
is trusted. It does not prove who built the package.

Online release verification uses the configured release repository's `SHA256SUMS` and
`SHA256SUMS.sig`. The signature file is exactly one line:

```text
<keyId> <base64 Ed25519 signature>
```

The signed message is UTF-8 `keysentry-release:v1\n` followed by the exact bytes of `SHA256SUMS`.
The verifier requires a trusted public key with the matching key ID, checks the signature, then
compares the `keysentry.mjs` checksum with the local bundle hash. It reports which URLs it fetched.
Those requests use the same guarded HTTP client as other API calls.

**Phase 1 ships with an empty release public-key list.** Online signature verification therefore
reports `unconfigured` and makes no release requests. This is not a verified release result. Before
publishing signed releases, a maintainer must generate and securely store a release signing key,
publish its public key in the source trust list, and review that change.
`npm run release:sign -- --generate` prints a new private key once, its public key, and its key ID;
normal signing (`npm run release:sign -- dist-release/out/SHA256SUMS`) reads the
base64 PKCS#8 DER private key from `KEYSENTRY_RELEASE_SIGNING_KEY`, never from command arguments.
That environment variable is for the release-signing script, not a user's provider credentials.

The release workflow builds and tests without the signing secret, then passes its artifacts to a
separate signing job. That job checks out the release tag, installs no dependencies, uses no npm
cache, and re-hashes the bundle, manifest and package against `SHA256SUMS` with Node built-ins before
signing. The checkout is pinned to the tagged event's commit so a moved tag cannot replace the
signing script during review. The signer checks the hashes again before reading the signing key. Checksums establish
that the downloaded files match the build output; they do not establish that the build's
dependencies produced trustworthy code.

Before enabling signing, configure a GitHub environment named **`release`** with **required
reviewers**, disable self-review, and restrict deployments to reviewed release tags. Store
`KEYSENTRY_RELEASE_SIGNING_KEY` as that environment's secret, not as a repository or organization
secret available to build jobs. Reviewers should check the tag, workflow and build artifacts before
approving the signing job. These protections are repository settings; the workflow cannot create
or enforce its own required reviewers.

The public release workflow prepares Sigstore build-provenance attestation bundles on the GitHub
release and npm publishing with provenance. Attestation, public release upload, and npm publishing are disabled for a private
repository. The CLI's phase-1 verifier checks the Ed25519 checksum signature; it does **not** verify
GitHub or npm provenance. Standalone Sigstore checksum signatures, an SBOM, signed container images, and the
later cloud-box attestation design are not supplied by this phase.

## Protecting credentials and changes

Tokens and keysentry's encryption/signing keys belong in the OS vault, with an explicitly chosen
encrypted-file fallback when the OS store is unavailable. Environment credentials remain supported
and are identified as a weaker source by `doctor`. Saved state is encrypted; recoverable rotation
values use a per-rotation key that is deleted when that rotation no longer needs them. JavaScript
and the OS can retain copies in memory, swap, crash dumps, or backups; keysentry cannot promise
that every earlier copy has been erased.

Scanning uses read operations. Some platforms require a token that can also write, so the promise
concerns the calls keysentry makes, not a permission the platform does not offer. Changes require
the human approval path; known coding-agent environments are refused for mutating commands. No
model or agent service receives keys through keysentry. A local agent or other process running as
your user may still have access outside keysentry.

The [threat model](docs/THREAT-MODEL.md) covers the trusted boundaries, failure cases, and what
keysentry does not protect against.
