# ProxyForge Alpha Hotfix Process

This process applies to `0.1.0-alpha.1` and later alpha cuts.

## Branching

1. Create a branch from the affected release tag, for example `hotfix/v0.1.0-alpha.1/<short-fix>`.
2. Keep the patch narrowly scoped to the regression, security issue, packaging failure, or documentation correction.
3. Do not mix roadmap feature work into a hotfix.

## Required Validation

Run these before tagging a hotfix:

```bash
npm ci
npm run build
npm run release:fuses
node tests/electron-fuse-policy.mjs
node tests/release-readiness.mjs
node tests/ci-nightly-policy.mjs
node tests/agent-option-audit.mjs
npm run test:ci:fast
npm run release:trust
npm audit --omit=dev
```

Security or packaging hotfixes must also run the focused regression test for the affected area.

## Native Artifact Receipts

The release operator must collect native Linux and Windows receipts from clean hosts or the GitHub native artifact matrix:

- build the exact hotfix commit with the package `dist:*` script;
- verify Electron fuses on the packaged executable;
- run `scripts/release-smoke.mjs` against the packaged executable;
- attach checksums, smoke JSON, and release trust evidence to the release.

## Tagging

Use a patch-suffixed alpha tag, for example:

```bash
git tag -a v0.1.0-alpha.1+hotfix.1 -m "ProxyForge v0.1.0-alpha.1 hotfix 1"
git push public v0.1.0-alpha.1+hotfix.1
```

## Disclosure

Security hotfix notes should summarize impact, affected versions, fixed version, and any operator action needed. Do not publish exploit details or live third-party material in public notes.
