#!/bin/sh
# Runs a release bundle under the Node permission model the way a user would: hook install, a blocked
# commit, init, scan, a real .env rotation and audit verification. Unit tests run without the sandbox,
# so this is what catches calls the sandbox refuses (fsync, file-handle chmod/utimes, hidden PATH).
# Usage: sh scripts/sandbox-smoke.sh dist-release/out/keysentry.mjs   (needs git, script and timeout)
set -eu
bundle="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir "$work/bin" "$work/repo" "$work/home"
printf '#!/bin/sh\nexec node "%s" "$@"\n' "$bundle" > "$work/bin/keysentry"
chmod +x "$work/bin/keysentry"
export PATH="$work/bin:$PATH" HOME="$work/home"
export KEYSENTRY_VAULT=encrypted-file KEYSENTRY_VAULT_PASSPHRASE=ci-smoke-passphrase-not-a-secret
fail() { echo "sandbox smoke: $1" >&2; [ -f "$work/out" ] && cat "$work/out" >&2; exit 1; }
# A pseudo-terminal, so commands take their interactive paths; a hung prompt fails after a minute.
in_tty() { timeout 60 script -qec "$1" /dev/null > "$work/out" 2>&1; }

cd "$work/repo"
git init -q
git config user.email ci@example.invalid
git config user.name ci
git commit -q --allow-empty -m init
in_tty "keysentry doctor" || true
grep -q "Node permission sandbox is on" "$work/out" || fail "the bundle did not run in the sandbox"

in_tty "keysentry guard install-hook" || fail "hook install failed"
[ -x .git/hooks/pre-commit ] || fail "hook is not executable"
grep -q "from your PATH" "$work/out" && fail "PATH warning although keysentry is on PATH"

printf 'OPENROUTER_API_KEY=sk-or-v1-%s\n' "$(printf 'a1b2%.0s' $(seq 16))" > leak.env
git add leak.env
if git commit -q -m leak > "$work/out" 2>&1; then fail "the guard let a key through"; fi
git reset -q
rm leak.env

old=0123456789abcdef0123456789abcdef0123456789abcdef
printf 'SESSION_SECRET=%s\n' "$old" > .env
in_tty "keysentry init" || fail "init failed"
sed -i.bak 's/graceSeconds: 120/graceSeconds: 0/' keysentry.yaml && rm keysentry.yaml.bak
grep -q 'graceSeconds: 0' keysentry.yaml || fail "sample config has no graceSeconds: 120"
in_tty "keysentry scan" || fail "scan failed"
in_tty "keysentry rotate --execute --yes" || fail "rotation failed"
grep -q "$old" .env && fail "the .env value was not rotated"
grep -q '^SESSION_SECRET=.' .env || fail "the .env lost its variable"
in_tty "keysentry audit verify" || fail "audit verification failed"
echo "sandbox smoke passed on $(node --version)"
