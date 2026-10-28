import js from '@eslint/js';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// ESLint matches ignores relative to this file, so `**/` is needed to cover nested build output such as
// packages/control-plane/dist.
const ignored = [
  '**/dist/',
  '**/dist-release/',
  '**/dist-control-plane/',
  '**/node_modules/',
  '**/package-lock.json',
  '**/.keysentry/',
  '**/logs/',
  '**/.terraform/',
  '**/*.tfstate',
  '**/*.tfstate.*',
  '**/*.tfplan',
  '**/.terraform.lock.hcl',
  'src/dashboard/generated/assets.ts',
  'packages/control-plane/src/ui-assets.ts',
];

const typeAwareRules = {
  '@typescript-eslint/no-floating-promises': 'error',
  '@typescript-eslint/no-misused-promises': 'error',
  '@typescript-eslint/await-thenable': 'error',
};

const typeAware = (files, project, ignores = []) => ({
  files,
  ignores,
  languageOptions: { parserOptions: { project, tsconfigRootDir: import.meta.dirname } },
  rules: typeAwareRules,
});

export default tseslint.config(
  { ignores: ignored },
  js.configs.recommended,
  ...tseslint.configs.recommended,
  {
    files: ['**/*.{ts,js,mjs}'],
    ignores: ['src/dashboard/client/**', 'packages/control-plane/ui/**'],
    languageOptions: { globals: globals.node },
  },
  {
    files: ['src/dashboard/client/**/*.ts', 'packages/control-plane/ui/**/*.ts'],
    languageOptions: { globals: globals.browser },
  },
  {
    files: ['**/*.ts'],
    rules: {
      '@typescript-eslint/consistent-type-imports': [
        'error',
        { prefer: 'type-imports', fixStyle: 'inline-type-imports' },
      ],
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', varsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' },
      ],
      eqeqeq: ['error', 'smart'],
    },
  },
  // Type-aware rules are limited to files a tsconfig includes. Tests under test/ have no tsconfig yet, so they keep
  // the non-type-aware rules above.
  typeAware(['src/**/*.ts'], './tsconfig.json', ['src/dashboard/client/**']),
  typeAware(['src/dashboard/client/**/*.ts'], './tsconfig.client.json'),
  typeAware(
    ['packages/control-plane/src/**/*.ts', 'packages/control-plane/test/**/*.ts'],
    './packages/control-plane/tsconfig.json',
  ),
  typeAware(['packages/control-plane/ui/**/*.ts'], './packages/control-plane/tsconfig.ui.json'),
);
