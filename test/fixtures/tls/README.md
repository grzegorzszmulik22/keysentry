# Test-only TLS certificate

Self-signed P-256 certificate for `localhost` / `127.0.0.1`, generated 2026-10-27 with OpenSSL for the in-process SMTP
and HTTPS test servers. The key protects nothing and must never be used outside tests. keysentry's own scanners treat
this directory as a known test fixture.
