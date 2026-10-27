# Cloud box fixtures

Recorded 2026-10-27 by the orchestrator (see `notes/phase4-facts.md`):

| File | Source | Notes |
|---|---|---|
| `google-jwks-2026-10-27.json` | `https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com` | 2 RSA-2048 RS256 keys; Google rotates them, so tests use it only to check JWK parsing |
| `confidential-space-root.crt` | `https://confidentialcomputing.googleapis.com/.well-known/confidential_space_root.crt` | Confidential Space Root CA, valid to 2034-01-16, SHA-256 `14:8B:29:38:21:BB:0C:6A:31:7F:41:3C:8B:A4:75:81:40:91:CB:22:D4:9B:9E:3C:94:19:8D:B8:E8:F8:6C:39`; pinned by the CLI |
| `openid-configuration-2026-10-27.json` | `https://confidentialcomputing.googleapis.com/.well-known/openid-configuration` | issuer and supported claims |
| `example-claims-oak.json` | real payload published in `project-oak/oak` (`oak_session/examples/e10_confidential_space_client_server/data/claims.json`), as quoted in the facts file | shape reference only; its digest and project are someone else's |

Emulator tokens are signed by test keys generated inside the tests; no real Google token is used.
