import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  evaluateReleaseGuard,
  sha256Hex,
} from '../scripts/release-guard.mjs'

describe('evaluateReleaseGuard', () => {
  const a = sha256Hex('artifact-a')
  const b = sha256Hex('artifact-b')

  it('allows first publish when current version is empty', () => {
    const d = evaluateReleaseGuard('', '1.2.2', null, a)
    assert.equal(d.ok, true)
  })

  it('allows upgrade', () => {
    const d = evaluateReleaseGuard('1.2.1', '1.2.2', a, b)
    assert.equal(d.ok, true)
    assert.match(d.reason, /upgrade/)
  })

  it('refuses downgrade', () => {
    const d = evaluateReleaseGuard('1.2.2', '1.2.1', a, b)
    assert.equal(d.ok, false)
    assert.match(d.reason, /downgrade/)
  })

  it('allows same version when sha256 matches', () => {
    const d = evaluateReleaseGuard('1.2.2', '1.2.2', a, a)
    assert.equal(d.ok, true)
    assert.match(d.reason, /idempotent|sha256/i)
  })

  it('refuses same version when content differs', () => {
    const d = evaluateReleaseGuard('1.2.2', '1.2.2', a, b)
    assert.equal(d.ok, false)
    assert.match(d.reason, /differs|Bump/i)
  })

  it('compares pre-release versions via semver', () => {
    // 1.2.2-beta.1 < 1.2.2
    assert.equal(evaluateReleaseGuard('1.2.2-beta.1', '1.2.2', a, b).ok, true)
    assert.equal(evaluateReleaseGuard('1.2.2', '1.2.2-beta.1', a, b).ok, false)
    // beta.1 < beta.2
    assert.equal(evaluateReleaseGuard('1.2.2-beta.1', '1.2.2-beta.2', a, b).ok, true)
    assert.equal(evaluateReleaseGuard('1.2.2-beta.2', '1.2.2-beta.1', a, b).ok, false)
  })

  it('rejects invalid versions', () => {
    assert.equal(evaluateReleaseGuard('1.2.1', 'not-a-version', a, a).ok, false)
    assert.equal(evaluateReleaseGuard('nope', '1.2.1', a, a).ok, false)
  })
})

describe('sha256Hex', () => {
  it('is stable for identical content', () => {
    assert.equal(sha256Hex('x'), sha256Hex(Buffer.from('x')))
    assert.notEqual(sha256Hex('x'), sha256Hex('y'))
    assert.equal(sha256Hex('x').length, 64)
  })
})
