import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const roadmap = read('docs/PROXY_FORGE_ROADMAP.md');
const matrix = read('docs/FEATURE_MATRIX.md');
const readme = read('README.md');
const releaseNotes = read('docs/RELEASE_NOTES_v0.1.0-alpha.1.md');
const hotfixProcess = read('docs/HOTFIX_PROCESS.md');
const releaseEvidence = read('docs/RELEASE_EVIDENCE.md');
const expectedReleaseTag = 'v0.1.0-alpha.1';

assert.match(roadmap, /\| 19 \| ✓ Done \| 2026-06-20 \| 2026-06-20 \| G6 \| Alpha source cut, release notes, hotfix process, tag target, and native artifact receipt workflow complete \|/);
assert.doesNotMatch(roadmap, /\| 19 \| Pending \|/);
assert.match(roadmap, /19\.3 \| Release notes citing every G1-G17 gate result \| `docs\/RELEASE_NOTES_v0\.1\.0-alpha\.1\.md` \| \*\*DONE\.\*\*/);
assert.match(roadmap, /19\.1 \| Tag `v0\.x-alpha` \| `v0\.1\.0-alpha\.1` \| \*\*READY\.\*\* Create on the release commit after CI receipts are clean\./);
assert.match(roadmap, /19\.7 \| Hotfix process documented \| `docs\/HOTFIX_PROCESS\.md` \| \*\*DONE\.\*\*/);

for (let gate = 1; gate <= 17; gate += 1) {
  assert.match(releaseNotes, new RegExp(`\\| G${gate} \\| Passed \\|`), `release notes should cite G${gate}`);
}

assert.match(hotfixProcess, /hotfix\/v0\.1\.0-alpha\.1/);
assert.match(hotfixProcess, /npm run test:ci:fast/);
assert.match(hotfixProcess, /release:fuses/);
assert.match(hotfixProcess, /native Linux and Windows receipts/i);

assert.match(matrix, /\| G1 — Scanner core \| Complete \|/);
assert.match(matrix, /\| G6 — Alpha cut \| Complete \|/);
assert.match(matrix, /`v0\.1\.0-alpha\.1` tag target/);
assert.doesNotMatch(matrix, /\| G\d+ [^|]*\| In progress \|/);
assert.doesNotMatch(matrix, /\| G\d+ [^|]*\| Not started \|/);

assert.match(readme, /Source alpha candidate/);
assert.match(readme, /docs\/RELEASE_NOTES_v0\.1\.0-alpha\.1\.md/);
assert.doesNotMatch(readme, /Open hardening work tracked/);

assert.match(releaseEvidence, /Prerelease Review Disposition/);
assert.match(releaseEvidence, /Installer publication remains gated on the native artifact matrix producing successful Linux and Windows receipts/);

const tagStatus = releaseTagStatus(expectedReleaseTag);
assert.equal(tagStatus.status, 'passed', tagStatus.message);

console.log(`roadmap-completion: verified Phase 19 docs, release notes, hotfix process, gate closure, and ${tagStatus.summary}`);

function read(relativePath) {
  return fs.readFileSync(path.join(root, relativePath), 'utf8');
}

function releaseTagStatus(expectedTag) {
  const explicitTag = process.env.EXPECTED_RELEASE_TAG?.trim();
  if (explicitTag) {
    const commitStatus = releaseTagCommitStatus(expectedTag, explicitTag);
    if (commitStatus.status !== 'passed') {
      return commitStatus;
    }
    return {
      status: explicitTag === expectedTag ? 'passed' : 'failed',
      summary: `explicit release tag ${explicitTag} on ${commitStatus.commit}`,
      message: `EXPECTED_RELEASE_TAG must be ${expectedTag}; got ${explicitTag}`,
    };
  }

  const refName = process.env.GITHUB_REF_NAME?.trim();
  const refType = process.env.GITHUB_REF_TYPE?.trim();
  const ref = process.env.GITHUB_REF?.trim();
  const refTag = ref?.startsWith('refs/tags/') ? ref.slice('refs/tags/'.length) : '';
  const tagCandidate = refType === 'tag' ? refName : refTag;
  if (tagCandidate) {
    const commitStatus = releaseTagCommitStatus(expectedTag, tagCandidate);
    if (commitStatus.status !== 'passed') {
      return commitStatus;
    }
    return {
      status: tagCandidate === expectedTag ? 'passed' : 'failed',
      summary: `GitHub release tag ${tagCandidate} on ${commitStatus.commit}`,
      message: `release tag must be ${expectedTag}; got ${tagCandidate}`,
    };
  }

  return {
    status: 'passed',
    summary: 'release tag check not applicable outside release-tag context',
    message: 'Release tag validation is only required for explicit release-tag contexts.',
  };
}

function releaseTagCommitStatus(expectedTag, tagCandidate) {
  if (tagCandidate !== expectedTag) {
    return {
      status: 'failed',
      summary: `release tag ${tagCandidate}`,
      message: `release tag must be ${expectedTag}; got ${tagCandidate}`,
    };
  }

  const headCommit = git(['rev-parse', 'HEAD']);
  const tagCommit = git(['rev-parse', `${expectedTag}^{}`]);
  if (!headCommit || !tagCommit) {
    return {
      status: 'failed',
      summary: `release tag ${expectedTag} commit unavailable`,
      message: `release tag ${expectedTag} must be present in the checkout and peel to HEAD`,
    };
  }
  return {
    status: tagCommit === headCommit ? 'passed' : 'failed',
    summary: `release tag ${expectedTag} peels to ${tagCommit}`,
    message: `release tag ${expectedTag} must point at checked-out commit ${headCommit}; got ${tagCommit}`,
    commit: tagCommit,
  };
}

function git(args) {
  try {
    return execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  } catch {
    return '';
  }
}
