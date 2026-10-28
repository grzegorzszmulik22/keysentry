// What the hosted control-plane bundle may contain: the package's hosted modules and the shared modules they import,
// never the watcher, the CLI, the box agent or image code, the dashboard, or the local emulator. Shared by
// scripts/build.mjs (checks esbuild's metafile) and test/image.test.ts (checks the source import graph).

/** Module paths (repository-relative, forward slashes) that may be bundled. */
export const BUNDLE_ALLOWED = [
  /^packages\/control-plane\/src\/(?!emulator\/|local-box\.ts$)[a-z-]+\.ts$/,
  /^src\/approvals\/webauthn\/[a-z-]+\.ts$/,
  /^src\/box\/attestation\/[a-z-]+\.ts$/,
  /^src\/box\/handshake\/[a-z-]+\.ts$/,
  /^src\/core\/(?:classify|redact)\.ts$/,
  /^src\/http\.ts$/,
  /^src\/net\/(?:allowlist|guarded-http)\.ts$/,
  /^src\/types\.ts$/,
  // Reached only through the src/security/index.ts barrel (src/box/handshake imports it; audit imports vault/keys).
  /^src\/security\/[a-z-]+\.ts$/,
  /^src\/vault\/(?:backends\/[a-z-]+|credentials|errors|keys|names)\.ts$/,
  /^src\/hosts\/credentials\.ts$/,
  /^src\/providers\/[a-z0-9-]+\.ts$/,
  // Runtime dependencies only (zod; fast-xml-parser and its own dependencies through the provider modules).
  /^node_modules\/(?:zod|fast-xml-parser|fast-xml-builder|strnum|anynum|xml-naming|is-unsafe|path-expression-matcher|@nodable\/entities)\//,
];

/** Never in the bundle, whatever the allow-list says. */
export const BUNDLE_FORBIDDEN = [
  /^src\/(?:watcher|cli|dashboard|autopilot|rotate|notify|monitor|feeds|guard|firstrun|report|hygiene|release|safety|doctor|approvals\/(?!webauthn\/))\//,
  /^src\/box\/(?:agent|seal|allowlist)\//,
  /^packages\/control-plane\/src\/(?:emulator\/|local-box\.ts$)/,
  /^node_modules\/(?:typescript|vitest|happy-dom|tsx|esbuild|@esbuild|@types|libsodium)/,
];

/** The inputs that break the policy; empty when the bundle is allowed. */
export function bundleViolations(inputs) {
  return inputs.map(input => input.replaceAll('\\', '/'))
    .filter(input => BUNDLE_FORBIDDEN.some(rule => rule.test(input)) || !BUNDLE_ALLOWED.some(rule => rule.test(input)))
    .sort();
}
