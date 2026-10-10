/**
 * Guard release-branch publishes against downgrades and same-version content drift.
 *
 * Rules:
 * - next < current  → refuse (require higher version)
 * - next > current  → allow
 * - next == current → allow only when artifact SHA-256 matches current release file
 * - missing current → allow (first publish)
 *
 * Uses the `semver` package so pre-releases (1.2.2-beta.1) compare correctly.
 */
import crypto from 'node:crypto'
import fs from 'node:fs'
import semver from 'semver'

/**
 * @param {string|null|undefined} currentVersion - @version on release branch (may be empty)
 * @param {string} nextVersion - package.json version being published
 * @param {string|null|undefined} currentSha256 - hex digest of current release artifact, or null
 * @param {string} nextSha256 - hex digest of the newly built artifact
 * @returns {{ ok: true, reason: string } | { ok: false, reason: string }}
 */
export function evaluateReleaseGuard(currentVersion, nextVersion, currentSha256, nextSha256) {
  const next = String(nextVersion || '').trim()
  if (!semver.valid(next)) {
    return { ok: false, reason: `invalid next version: ${nextVersion}` }
  }
  const nextHash = String(nextSha256 || '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(nextHash)) {
    return { ok: false, reason: `invalid next sha256: ${nextSha256}` }
  }

  const cur = String(currentVersion || '').trim()
  if (!cur) {
    return { ok: true, reason: 'first publish (no current version on release)' }
  }
  if (!semver.valid(cur)) {
    return { ok: false, reason: `invalid current version on release branch: ${currentVersion}` }
  }

  if (semver.lt(next, cur)) {
    return {
      ok: false,
      reason: `refuse downgrade: release has ${cur}, refusing ${next}`,
    }
  }
  if (semver.gt(next, cur)) {
    return { ok: true, reason: `upgrade ${cur} → ${next}` }
  }

  // Same version: content must be byte-identical (SHA-256).
  const curHash = String(currentSha256 || '').toLowerCase()
  if (!/^[0-9a-f]{64}$/.test(curHash)) {
    return {
      ok: false,
      reason: `same version ${next} but current release sha256 missing/invalid; refuse overwrite`,
    }
  }
  if (curHash !== nextHash) {
    return {
      ok: false,
      reason:
        `same version ${next} but artifact content differs (release=${curHash.slice(0, 12)}… ` +
        `new=${nextHash.slice(0, 12)}…). Bump the version number to republish.`,
    }
  }
  return { ok: true, reason: `idempotent republish of ${next} (sha256 match)` }
}

/**
 * @param {string|Buffer} data
 * @returns {string} hex sha256
 */
export function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex')
}

/**
 * CLI: node scripts/release-guard.mjs <currentVersion|""> <nextVersion> <currentFile|-> <nextFile>
 * Prints JSON decision to stdout; exits 0 on allow, 1 on refuse.
 */
function main(argv) {
  const [currentVersion, nextVersion, currentFile, nextFile] = argv
  if (!nextVersion || !nextFile) {
    console.error(
      'usage: node scripts/release-guard.mjs <currentVersion|""> <nextVersion> <currentFile|-> <nextFile>',
    )
    process.exit(2)
  }
  const nextBuf = fs.readFileSync(nextFile)
  const nextSha = sha256Hex(nextBuf)
  let currentSha = null
  if (currentFile && currentFile !== '-') {
    if (fs.existsSync(currentFile)) {
      currentSha = sha256Hex(fs.readFileSync(currentFile))
    }
  }
  const decision = evaluateReleaseGuard(currentVersion, nextVersion, currentSha, nextSha)
  console.log(JSON.stringify({ ...decision, nextSha256: nextSha, currentSha256: currentSha }))
  process.exit(decision.ok ? 0 : 1)
}

const isDirect =
  process.argv[1] &&
  (process.argv[1].endsWith('release-guard.mjs') ||
    process.argv[1].replace(/\\/g, '/').endsWith('scripts/release-guard.mjs'))

if (isDirect) {
  main(process.argv.slice(2))
}
