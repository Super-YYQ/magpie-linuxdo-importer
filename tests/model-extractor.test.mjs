import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { extractModels } from '../userscript/lib/model-extractor.mjs'
import { base64Encode } from '../userscript/lib/core.mjs'

// magpie takes a flat comma models list — no per-app preference, so the
// extractor returns every detected id in document order.

describe('extractModels', () => {
  it('extracts Claude models from share text', () => {
    const text = `支持 claude-3.5-sonnet、claude-3-opus 等模型`
    const result = extractModels(text)
    assert.ok(result.models.length >= 2)
    assert.ok(result.models.some((m) => /sonnet/.test(m)))
    assert.ok(result.models.some((m) => /opus/.test(m)))
  })

  it('extracts GPT models from share text', () => {
    const text = `模型设置 gpt-5.5，gpt-5.6-sol，gpt-4o`
    const result = extractModels(text)
    assert.ok(result.models.length >= 2)
    assert.ok(result.models.some((m) => /gpt-5/.test(m)))
    assert.ok(result.models.some((m) => /gpt-4o/.test(m)))
  })

  it('extracts Grok models', () => {
    const text = `claude系列均会转发到grok-4.5`
    const result = extractModels(text)
    assert.ok(result.models.some((m) => /grok/.test(m)))
  })

  it('extracts informal Grok4.5 spelling (no hyphen, mixed case)', () => {
    for (const text of [
      '第一波】福利Grok4.5 1000刀',
      '转发到grok4.5',
      '模型 grok-4.5',
      '支持 Grok-4',
    ]) {
      const result = extractModels(text)
      assert.ok(
        result.models.some((m) => /grok/i.test(m)),
        `expected grok model in: ${text}`,
      )
    }
    assert.ok(extractModels('福利Grok4.5 1000刀').models.includes('grok-4.5'))
  })

  it('does not match Grok as substring of unrelated tokens', () => {
    assert.equal(extractModels('mygrok4.5x is not a model id').models.length, 0)
    assert.equal(extractModels('grok4.50 typo version').models.length, 0)
  })

  it('does not treat o3/o1 substrings inside base64 API keys as models', () => {
    // Synthetic key body that still contains "o3" letter runs when base64-encoded
    const key = 'sk-test-o3o1-only-synthetic-body-00000000'
    const b64 = base64Encode(key)
    const r = extractModels(
      `{"_type":"newapi_channel_conn","key":"${b64}","url":"https://api.example.invalid"}`,
    )
    assert.equal(r.models.length, 0)
  })

  it('still extracts real o3 / o1 model names with word boundaries', () => {
    const r = extractModels('支持 o3 与 o1-mini 模型')
    assert.ok(r.models.some((m) => m === 'o3'))
    assert.ok(r.models.some((m) => /o1/.test(m)))
  })

  it('handles "支持所有模型" gracefully', () => {
    const text = `支持所有模型，无限制`
    const result = extractModels(text)
    assert.ok(Array.isArray(result.models))
  })

  it('returns an empty list when no models found', () => {
    const text = `这是一段普通的中文介绍，没有模型名`
    const result = extractModels(text)
    assert.equal(result.models.length, 0)
  })

  it('handles mixed case and variant spellings', () => {
    const text = `GPT-4o-MINI and Claude-Sonnet-4.5`
    const result = extractModels(text)
    assert.ok(result.models.some((m) => /gpt-4o/.test(m)))
    assert.ok(result.models.some((m) => /sonnet/.test(m)))
  })

  it('keeps longest match when patterns overlap (sonnet-4.5 / opus-4.8 / gpt-4o / deepseek-v3.2)', () => {
    const text = '支持 claude-sonnet-4.5、claude-opus-4.8、gpt-4o、deepseek-v3.2'
    const r = extractModels(text)
    assert.ok(r.models.includes('claude-sonnet-4.5'))
    assert.ok(!r.models.includes('claude-sonnet-4'), `short sonnet leak: ${r.models}`)
    assert.ok(r.models.includes('claude-opus-4.8'))
    assert.ok(!r.models.includes('claude-opus-4'), `short opus leak: ${r.models}`)
    assert.ok(r.models.includes('gpt-4o'))
    assert.ok(!r.models.includes('gpt-4'), `short gpt leak: ${r.models}`)
    assert.ok(r.models.includes('deepseek-v3.2'))
    assert.ok(!r.models.includes('deepseek-v3'), `truncated deepseek: ${r.models}`)
  })

  it('extracts modern Claude 4 ids with date / minor / haiku-4.5', () => {
    const r = extractModels(
      'claude-sonnet-4-20250514 claude-opus-4-1 claude-haiku-4.5 claude-haiku-4',
    )
    assert.ok(r.models.includes('claude-sonnet-4-20250514'), `models=${r.models}`)
    assert.ok(r.models.includes('claude-opus-4-1'), `models=${r.models}`)
    assert.ok(r.models.includes('claude-haiku-4.5'), `models=${r.models}`)
    assert.ok(r.models.includes('claude-haiku-4'), `models=${r.models}`)
    assert.ok(!r.models.includes('claude-haiku'), `bare haiku leak: ${r.models}`)
    assert.ok(!r.models.includes('claude-opus-4'), `short opus leak: ${r.models}`)
  })

  it('preserves dated minor snapshots and recognizes current Claude families', () => {
    const ids = [
      'claude-sonnet-4-5-20250929',
      'claude-haiku-4-5-20251001',
      'claude-opus-4-1-20250805',
      'claude-sonnet-4-6',
      'claude-fable-5',
      'claude-mythos-5-0',
    ]
    const r = extractModels(ids.join(' '))

    for (const id of ids) assert.ok(r.models.includes(id), `missing ${id}: ${r.models}`)
    assert.ok(!r.models.includes('claude-sonnet-4-5'))
    assert.ok(!r.models.includes('claude-haiku-4-5'))
    assert.ok(!r.models.includes('claude-opus-4-1'))
  })
})

describe('regression · current model ids (#3)', () => {
  it('extracts OpenAI 2025+ ids (gpt-5 family / gpt-4.1 / o4-mini / o3-pro)', () => {
    for (const id of [
      'gpt-5',
      'gpt-5.1',
      'gpt-5-pro',
      'gpt-5.1-codex',
      'gpt-5.5',
      'gpt-4.1',
      'gpt-4.1-mini',
      'o4-mini',
      'o3-pro',
    ]) {
      const r = extractModels(`模型：${id}`)
      assert.ok(r.models.includes(id), `expected ${id}, got ${JSON.stringify(r.models)}`)
    }
  })

  it('extracts claude-3.7-sonnet with optional date suffix', () => {
    assert.ok(extractModels('转发 claude-3.7-sonnet').models.includes('claude-3.7-sonnet'))
    const dated = extractModels('claude-3.7-sonnet-20250224 可用')
    assert.ok(dated.models.includes('claude-3.7-sonnet-20250224'))
  })

  it('extracts Chinese vendor ids common on linux.do (glm/qwen/kimi/doubao/deepseek-r)', () => {
    for (const id of [
      'glm-4.6',
      'glm-4.5-air',
      'qwen3',
      'qwen3-235b-a22b',
      'qwen2.5-coder',
      'kimi-k2',
      'kimi-k1.5',
      'doubao-seed-1.6',
      'doubao-1.5-pro',
      'deepseek-r1',
    ]) {
      const r = extractModels(`支持 ${id} 模型`)
      assert.ok(r.models.includes(id), `expected ${id}, got ${JSON.stringify(r.models)}`)
    }
  })

  it('does not invent models from unrelated prose', () => {
    assert.equal(extractModels('glm 的一般讨论，没有版本号').models.length, 0)
    assert.equal(extractModels('qwen 是通义千问的英文名').models.length, 0)
  })
})
