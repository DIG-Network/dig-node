// Conventional Commits enforcement for this repo.
// Every commit + PR title must be `type(scope): summary`, where type is one of the
// allowed types below. A breaking change appends `!` (feat!: …) and/or a
// `BREAKING CHANGE:` body footer. The type drives the SemVer bump for the release
// (fix -> patch, feat -> minor, ! / BREAKING CHANGE -> major).
// Enforced in CI by .github/workflows/commitlint.yml (wagoid/commitlint-github-action).
export default {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'type-enum': [
      2,
      'always',
      ['feat', 'fix', 'docs', 'style', 'refactor', 'perf', 'test', 'build', 'ci', 'chore', 'revert'],
    ],
    'subject-case': [0], // allow any subject casing (proper nouns, scheme literals like chia://)
    'body-max-line-length': [0], // long bodies (URLs, logs) are fine
    'footer-max-line-length': [0],
  },
};
