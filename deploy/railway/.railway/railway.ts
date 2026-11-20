// Railway Infrastructure as Code; copy the containing railway folder.
// The SDK export names must be checked against `railway config init` before apply.
// They are not part of keysentry's runtime dependencies.
import { image, preserve, project, service, volume } from 'railway';

export default function () {
  const data = volume('keysentry-data', { sizeMB: 1024 });
  const watcher = service('watcher', {
    // After the first release, replace this tag with ghcr.io/grzegorzszmulik22/keysentry@sha256:<release-digest>.
    source: image('ghcr.io/grzegorzszmulik22/keysentry:1.0.0'),
    env: {
      KEYSENTRY_STATE_DIR: '/data',
      KEYSENTRY_VAULT: 'encrypted-file',
      NODE_ENV: 'production',
      KEYSENTRY_VAULT_PASSPHRASE: preserve(),
      KEYSENTRY_STATE_KEY: preserve(),
      KEYSENTRY_WATCHER_KEY: preserve(),
      KEYSENTRY_WATCHER_CONFIG: preserve(),
      KEYSENTRY_WATCHER_VAULT: preserve(),
    },
    volumeMounts: { '/data': data },
  });
  return project('keysentry', { resources: [watcher, data] });
}
