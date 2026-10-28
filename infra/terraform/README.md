# Cloud box infrastructure — not deployed

**do not apply in this project**. These three independent Terraform roots describe future infrastructure. Phase 4
uses local fakes; no project, service, key or VM has been provisioned by this work. There is no deployment workflow
or shared root that applies these modules together.

All roots require Terraform `>= 1.6` and pin `hashicorp/google` to `8.9.0`. Resource names, claims and arguments are
based on [the verified phase 4 facts](../../notes/phase4-facts.md), sections 3–4. Projects, enabled APIs and the box
image's Artifact Registry repository must already exist. Provider authentication is external; there are no
credential, plaintext token, key-share or private-key inputs. Outputs contain resource identifiers only.

## Roots and ownership

| Root | Intended owner | Resources and trust |
| --- | --- | --- |
| `box/` | keysentry, in a dedicated box project | A custom VPC, private subnet, outbound NAT, ingress deny-all, box service account, Confidential Space VM, dedicated identity pool/provider and standard KMS sealing key. keysentry controls this key-release policy. |
| `byo-kms/` | Customer, in their own project | A customer-owned pool/provider, sealing key and per-digest IAM members. The assertion pins identify keysentry's approved external box; the principal sets belong to the customer's pool. No keysentry principal receives policy administration. |
| `control-plane/` | keysentry, in a separate control-plane project | An authenticated Cloud Run service and private versioned bucket for ciphertext blobs and signed documents. Its dedicated service account has object access only to that bucket. This is a minimal, not-deployed scaffold. |

BYO-KMS is intended for a customer to review and apply independently in their own project after launch review.
`project_id` in that root is the customer's project. `box_project_id` and `box_service_account_email` must come from
the verified box identity, and have no defaults. They are deliberately different from the customer's key ownership.

## Key-release policy

Each key root creates its own dedicated pool with exactly one OIDC provider. The issuer is
`https://confidentialcomputing.googleapis.com/`, matching the documented federation setup; the accepted token
audience is `https://sts.googleapis.com`. The custom STS exchange audience is a different value, exported as
`workload_identity_provider_audience` (`//iam.googleapis.com/projects/NUMBER/locations/global/.../providers/...`).

The provider requires **all** of these CEL conditions:

- `assertion.swname == 'CONFIDENTIAL_SPACE'`;
- `'STABLE' in assertion.submods.confidential_space.support_attributes`;
- `assertion.dbgstat == 'disabled-since-boot'`;
- the approved box project ID in `assertion.submods.gce.project_id`;
- the exact approved box account in `assertion.google_service_accounts`.

`attribute.image_digest` maps the attested container digest. Every digest in the required, nonempty
`allowed_image_digests` set gets a separate `roles/cloudkms.cryptoKeyDecrypter` member. A separate, identically
restricted `roles/cloudkms.cryptoKeyEncrypter` member permits wrapping fresh data keys. Neither role is granted
directly to the VM service account or control plane. Principal sets use the pool's full resource name, which
contains the pool owner's **project number**, not its project ID. No service-account impersonation is involved.

Use only digests approved by the verified signed public allow-list. Terraform does not fetch or verify that log,
publish policy changes, or enforce its append-only history. The orchestrator must connect those release checks;
editing this variable alone is not proof of an approved release. Keep each pool dedicated to this provider: an
additional provider in the same pool could otherwise mint the same mapped attribute. KMS keys rotate every 90 days;
key rings and keys have `prevent_destroy`, and keys additionally use `deletion_policy = "PREVENT"`. These guards
prevent accidental Terraform removal while the configuration retains them; they do not remove administrators'
ability to change policy or key versions.

## Box runtime and network

`confidential_type` defaults to `TDX`: `c3-standard-4`, host maintenance `TERMINATE`. Selecting `SEV` chooses
`n2d-standard-2`, minimum CPU `AMD Milan`, and maintenance `MIGRATE`. Capacity and regional support must be checked
before any future deployment. TDX maintenance can restart the box; unlock-on-restart must pause for the device share.

The boot image is the production `confidential-space` family in `confidential-space-images`, with secure boot.
The container `image_reference` must be a single-platform amd64 reference pinned by `@sha256:`; its digest must also
be in `allowed_image_digests`. Metadata contains only `tee-image-reference` and `tee-restart-policy = "Always"`.
Secrets and overrides never belong in instance metadata. The VM account can attest and read only the selected
Artifact Registry repository; it has no direct KMS or storage access. The `cloud-platform` OAuth scope does not
add IAM permissions.

The custom VPC creates no default allow rules. The VM has no external IP, and an explicit priority-zero rule
denies IPv4 ingress. Private Google Access and Cloud NAT provide outbound connectivity for the launcher, APIs and
relay. **This VPC does not enforce a hostname egress allow-list.** The guarded `HttpClient` must enforce the
application's approved destinations. Independent network enforcement would need separately reviewed firewall or
proxy configuration; the facts do not verify its pricing. Container launch-policy labels and all CLI attestation
checks remain separate release checks. Terraform configuration and its outputs are not attestation evidence.

## Control-plane boundary

The service runs the `Dockerfile.control-plane` image by digest, as a public Cloud Run service
(`invoker_iam_disabled`; every route authenticates its own caller: passkey sessions, box attestation tokens, Stripe
signatures). Its account has bucket-scoped `roles/storage.objectUser` and `secretAccessor` on the two Stripe secrets,
whose references (never values) the service reads at startup. Only with `live_provisioning = true` does it get a
create-only custom role in the box project and `roles/iam.serviceAccountUser` on the box service account. It has no
KMS, IAM administration or project-wide storage permission. Uniform bucket access, enforced public-access prevention, versioning, `force_destroy = false` and
`prevent_destroy` protect the ciphertext store against unintended exposure or removal through this configuration.

Before a future launch, separately review application authentication, relay routing, bucket configuration in the
application, ciphertext retention (including noncurrent versions), registry pulling permissions for the Cloud Run
service agent, and any narrowly scoped provisioning identity. Passkey, billing and webhook configuration are not
injected here. This scaffold does not yet authorize or configure the live control-plane application.

Google's attestation service/signing keys and the selected TDX/SEV hardware remain trusted. In standard mode,
keysentry controls KMS policy; with BYO-KMS, the customer controls it. All plaintext tokens and unlock shares stay
in the CLI or verified box memory, never Terraform inputs/state, relay storage or notifications.

## Offline checks

From the repository root:

```text
node tools/vitest-sandbox.mjs test/infra/terraform.test.ts
npx tsc -p tsconfig.json --noEmit
terraform fmt -check -recursive infra/terraform
```

Static tests check the trust constraints and attempt `terraform fmt -check` for each root when Terraform can be
spawned. They skip native checks if Terraform is absent or the Windows sandbox denies Node child processes
(`EPERM`); in the latter case run the formatting command directly through the shell. Terraform checkpoint checks
can be disabled with `CHECKPOINT_DISABLE=1`.

`terraform -chdir=infra/terraform/<root> validate` can check provider schemas only when the pinned provider is
already installed locally. No provider cache is available in this workspace, so validation reports **Missing
required provider**. Do not initialize providers over the network or apply infrastructure as part of this task.
