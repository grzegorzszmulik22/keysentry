// Replaced by esbuild for a release; typeof keeps source/tsx runs usable.
declare const __KEYSENTRY_VERSION__: string;
declare const __KEYSENTRY_COMMIT__: string;
declare const __KEYSENTRY_RELEASE_REPO__: string;

export const BUILD_VERSION = typeof __KEYSENTRY_VERSION__ === 'undefined' ? '0.0.0-dev' : __KEYSENTRY_VERSION__;
export const BUILD_COMMIT = typeof __KEYSENTRY_COMMIT__ === 'undefined' ? 'dev' : __KEYSENTRY_COMMIT__;
export const RELEASE_REPO = typeof __KEYSENTRY_RELEASE_REPO__ === 'undefined'
  ? 'grzegorzszmulik22/keysentry' : __KEYSENTRY_RELEASE_REPO__;
