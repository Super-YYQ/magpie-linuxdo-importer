import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  parseShareText,
  looksLikeConfig,
  buildDeeplink,
  maskKey,
  base64Encode,
  enrichTextWithAnchorHrefs,
  selectCandidate,
  describeProviderParams,
  suggestPresetLinks,
  classifyEndpointProtocol,
  MAX_DEEPLINK_LEN,
} from '../userscript/lib/core.mjs'
import { extractModels } from '../userscript/lib/model-extractor.mjs'

// Synthetic fixtures only — never paste live share secrets into the suite.
const SYNTH = {
  skAnt: 'sk-ant-api03-TESTONLY00000000000000000000',
  skAntShort: 'sk-ant-api03-abcdefghij',
  skAntMixed: 'sk-ant-api03-mixedkeyvalue99',
  skAntA: 'sk-ant-api03-aaaaaaaaaaaaaaaa',
  skAntB: 'sk-ant-api03-bbbbbbbbbbbbbbbb',
  skAntDeeplink: 'sk-ant-api03-deeplinkkey',
  skAntJson: 'sk-ant-api03-xyzxyzxyzxyz',
  skPlain: 'sk-test-only-000000000000000000000000',
  skHex: 'sk-hexonlysyntheticvalue1234567890ab',
  skWatermarkBody: 'sk-test-only-222222222222222222222222',
  g2a: 'g2a_testonly_not_a_real_token_abcdefghij',
  tp: 'tp-test-only-not-a-real-token-abcdefghij01',
  // Volcengine 方舟: base64-shared key decodes to ark-<uuid>-<suffix>.
  // Synthetic body (clearly not a real UUID) so push protection does not flag it.
  ark: 'ark-testonly-not-a-real-token-abcdefghij0123456789',
  arkEndpointAnthropic: 'https://ark.cn-beijing.volces.com/api/coding',
  arkEndpointOpenai: 'https://ark.cn-beijing.volces.com/api/coding/v3',
  // StepFun 阶跃: prefix-less random-string token, often base64-shared with a
  // "64解密" hint. Synthetic body (no vendor prefix, 32+ alnum) — never a real key.
  stepfun: 'testonlynotrealstepfuntokenabcdefghij0123456789abcd',
  stepfunEndpoint: 'https://api.stepfun.com/step_plan/v1',
  // Mistral-style prefix-less plaintext key (synthetic, for C-gap + loose-body).
  mistral: 'testonlynotrealmistraltokenabcdefghij0123456',
  mistralEndpoint: 'https://api.mistral.ai/v1',
  // Additional vendor prefixes (xAI / Groq / Perplexity / Replicate).
  xai: 'xai-testonlynotrealkey0123456789abcdef',
  xaiEndpoint: 'https://api.x.ai/v1',
  gsk: 'gsk_testonlynotrealtoken0123456789abcdef',
  pplx: 'pplx-testonlynotrealtoken0123456789',
  r8: 'r8_testonlynotrealtoken0123456',
  hf: 'hf_testonlynotrealtoken0123456789abcdef',
  fw: 'fw_testonlynotrealtoken0123456789abcdefgh',
  ocSk: 'oc_sk_TESTONLY0000000000000000000000000000',
  bareKey: 'Ab9Cd8Ef7Gh6Ij5Kl4Mn3Op2Qr1St0Uv9Wx8Yz7',
  endpoint: 'https://api.example.invalid',
  endpointV1: 'https://api.example.invalid/v1',
  endpointAnthropic: 'https://api.example.invalid/anthropic',
  endpointRelay: 'https://relay.example.invalid/v1',
  endpointProxy: 'https://proxy.example.invalid/v1',
  endpointOpenai: 'https://api.openai-proxy.test',
  endpointB64: 'https://b64.example.invalid',
  endpointHex: 'https://hex.example.invalid',
  endpointA: 'https://a.example.invalid',
  endpointB: 'https://b.example.invalid',
  endpointMid: 'https://mid.example.invalid/anthropic',
  endpointGrok: 'https://grok.example.invalid',
  endpointNewapi: 'https://newapi.example.invalid',
}

describe('looksLikeConfig', () => {
  it('rejects short or plain Chinese posts', () => {
    assert.equal(looksLikeConfig('短'), false)
    assert.equal(
      looksLikeConfig('这个帖子只是随便聊聊编程学习经验，没有任何密钥内容在里面哈哈哈哈'),
      false,
    )
  })

  it('rejects plain chat containing the word "token" + emoji shortcode (no config)', () => {
    // Real linux.do chat: "token" as an everyday word + a long emoji shortcode
    // (:backhand_index_pointing_left:) — must NOT light the import button.
    const chat =
      '“佬，你为什么不搞个玻利维亚的 gptpro 到公益站给我爽爽，我没token 用了。”\n' +
      '@dingding1 :backhand_index_pointing_left:这是受害者站长\n\n' +
      '“佬，我没有多少 ldc，能不能送个你站的邀请码给我”'
    assert.equal(looksLikeConfig(chat), false)
  })

  it('rejects a lone long English word (no label, no key shape)', () => {
    assert.equal(
      looksLikeConfig('我们讨论一下 supercalifragilisticexpialidocious 这个词'),
      false,
    )
  })

  it('accepts env-style shares', () => {
    assert.equal(
      looksLikeConfig(`
        分享一个可用的：
        ANTHROPIC_BASE_URL=${SYNTH.endpoint}
        ANTHROPIC_AUTH_TOKEN=${SYNTH.skAntShort}
      `),
      true,
    )
  })

  it('rejects long base64-ish noise without a decodable key/config', () => {
    assert.equal(
      looksLikeConfig('这是一段讨论 ' + 'A'.repeat(50) + ' 填充填充填充填充'),
      false,
    )
  })

  it('accepts standalone base64 that decodes to an sk- key', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    assert.equal(looksLikeConfig(`请自行解码\n${b64}\n谢谢`), true)
  })

  it('accepts g2a_ vendor keys (with or without https URL)', () => {
    const key = SYNTH.g2a
    assert.equal(looksLikeConfig(key), true)
    assert.equal(
      looksLikeConfig(`https://grok2api-v2.onrender.com\nGrok2API\n${key}`),
      true,
    )
    // Discourse onebox often pastes bare host without scheme
    assert.equal(
      looksLikeConfig(`grok2api-v2.onrender.com\nGrok2API\n总结\n${key}`),
      true,
    )
  })

  it('recognizes Volcengine Ark base64-shared key (decodes to ark-…)', () => {
    // Real linux.do share shape: key shared as base64, decodes to `ark-<uuid>-<suffix>`.
    const b64 = base64Encode(SYNTH.ark)
    assert.equal(looksLikeConfig(`API-Key Base64\n${b64}`), true)
    const r = parseShareText(
      [
        '当前仓库对于 8月1号到期',
        '',
        'Base URL',
        `兼容 Anthropic 接口协议工具：${SYNTH.arkEndpointAnthropic}`,
        '',
        `兼容 OpenAI 接口协议工具：${SYNTH.arkEndpointOpenai}`,
        '',
        'API-Key Base64',
        b64,
      ].join('\n'),
    )
    assert.ok(r, 'should parse')
    assert.equal(r.apiKey, SYNTH.ark)
    assert.equal(r.anthropic, SYNTH.arkEndpointAnthropic)
    assert.ok(Object(r).candidates.length >= 1)
  })

  it('bare ark- vendor token lights the import button', () => {
    assert.equal(looksLikeConfig(SYNTH.ark), true)
  })

  it('recognizes xai-/gsk_/pplx-/r8- vendor prefixes', () => {
    assert.equal(looksLikeConfig(SYNTH.xai), true)
    assert.equal(looksLikeConfig(SYNTH.gsk), true)
    assert.equal(looksLikeConfig(SYNTH.pplx), true)
    assert.equal(looksLikeConfig(SYNTH.r8), true)
    const r = parseShareText(`endpoint: ${SYNTH.xaiEndpoint}\nkey: ${SYNTH.xai}`)
    assert.equal(r.apiKey, SYNTH.xai)
    assert.equal(r.chat, SYNTH.xaiEndpoint)
  })

  it('recognizes hf_ (HuggingFace) and fw_ (Fireworks) prefixes', () => {
    assert.equal(looksLikeConfig(SYNTH.hf), true)
    assert.equal(looksLikeConfig(SYNTH.fw), true)
    const r = parseShareText(
      `endpoint: https://api.fireworks.ai/inference/v1\nkey: ${SYNTH.fw}`,
    )
    assert.equal(r.apiKey, SYNTH.fw)
  })

  it('accepts magpie import deeplinks', () => {
    const link = `magpie://import?name=Shared&chat=${encodeURIComponent(SYNTH.endpointV1)}&key=${SYNTH.skAntDeeplink}`
    assert.equal(looksLikeConfig(`一键导入：${link}`), true)
  })

  it('rejects non-import magpie deeplinks so the floating button stays hidden', () => {
    for (const action of ['install', 'v1/import', 'help']) {
      const link = `magpie://${action}?name=X&chat=${encodeURIComponent(SYNTH.endpoint)}&key=${SYNTH.skAnt}`
      assert.equal(looksLikeConfig(`导入：${link}`), false, `action=${action}`)
    }
  })
})

describe('standalone key shares', () => {
  it('recognizes an OpenCode-shaped key shared as bare base64 without a URL or label', () => {
    const encoded = base64Encode(SYNTH.ocSk)
    for (const text of [encoded, `OpenCode GO 马上过期\n${encoded}`, SYNTH.ocSk]) {
      assert.equal(looksLikeConfig(text), true)
      const result = parseShareText(text)
      assert.ok(result)
      assert.equal(result.apiKey, SYNTH.ocSk)
      assert.equal(hasAnyUrl(result), false)
    }
  })

  it('recognizes an isolated long key without a vendor prefix, plain or base64-encoded', () => {
    for (const text of [SYNTH.bareKey, base64Encode(SYNTH.bareKey)]) {
      assert.equal(looksLikeConfig(text), true)
      const result = parseShareText(text)
      assert.ok(result)
      assert.equal(result.apiKey, SYNTH.bareKey)
      assert.equal(hasAnyUrl(result), false)
      assert.ok(result.confidence < 0.7)
    }
  })

  it('does not promote repeated characters or encoded prose into standalone keys', () => {
    for (const text of [
      'A'.repeat(64),
      base64Encode('This is an ordinary sentence, not a credential.'),
    ]) {
      assert.equal(looksLikeConfig(text), false)
      assert.equal(parseShareText(text), null)
    }
  })
})

describe('prefix-less keys & label-line-with-descriptor', () => {
  it('StepFun: base64 blob + 64解密 hint + endpoint (no prefix, no label)', () => {
    const b64 = base64Encode(SYNTH.stepfun)
    const text = `阶跃星辰的token Plan只用了2%，截止今晚11点，大家用力蹬。64解密\n\n${b64}\n\n${SYNTH.stepfunEndpoint}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r, 'should parse')
    assert.equal(r.apiKey, SYNTH.stepfun)
    assert.equal(r.chat, SYNTH.stepfunEndpoint)
    // Weak shape (no vendor prefix) -> lowered confidence, warning present
    assert.ok(r.confidence < 0.9, 'prefix-less key should not read as fully confident')
  })

  it('Mistral: API-Key Base64 label-line + newline token (prefix-less, C-gap)', () => {
    const b64 = base64Encode(SYNTH.mistral)
    const text = `endpoint：${SYNTH.mistralEndpoint}\nAPI-Key Base64\n${b64}`
    const r = parseShareText(text)
    assert.ok(r, 'should parse')
    assert.equal(r.apiKey, SYNTH.mistral)
    assert.equal(r.chat, SYNTH.mistralEndpoint)
  })

  it('does NOT harvest prefix-less base64 without a decode hint', () => {
    // endpoint URL + a random base64-ish blob, but no "base64/解密" hint:
    // must not be mistaken for an API key.
    const r = parseShareText(
      `图片缓存地址 https://img.example.invalid/x\nhash: QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU`,
    )
    assert.equal(r && r.apiKey, null)
  })

  it('does NOT light button for prefix-less base64 without endpoint context', () => {
    assert.equal(
      looksLikeConfig(`讨论一下 ${'A'.repeat(60)} 这段内容`),
      false,
    )
  })
})

describe('mergeParseResults · base64 fragment + base_url', () => {
  it('stitches base64 OPENAI_API_KEY fragment with curly-quoted base_url (no wipe in finalize)', () => {
    // Real linux.do shape: a base64 blob that decodes only to a JSON-ish key field
    // (not a full config object), plus a separate base_url = “…” line with curly quotes.
    // Each half-parser succeeds alone; merge must keep BOTH after finalizeResult.
    const key = SYNTH.skPlain
    const b64 = base64Encode(` "OPENAI_API_KEY": "${key}"`)
    const text = `${b64}\n\nbase_url = “https://ricktoken.example.net”`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r, 'should parse')
    assert.equal(r.apiKey, key)
    assert.ok(r.chat || r.anthropic, 'stitched URL must survive')
    // candidates must stay in sync — otherwise finalizeResult re-applies a key-only
    // pair and wipes the stitched URL
    assert.ok(r.candidates?.length >= 1)
    const active = r.candidates[r.candidateIndex || 0]
    assert.equal(active.chat || active.anthropic, r.chat || r.anthropic)
    assert.equal(active.apiKey, key)
  })

  it('decodes key field value out of base64 JSON fragment behind a key label', () => {
    // The blob decodes to ` "OPENAI_API_KEY": "sk-..."` — a JSON *fragment*, not a
    // bare key. Whether bare or behind a `key：` label, the sk- value must be pulled
    // out, not returned as the raw `"OPENAI_API_KEY": "..."` wrapper string.
    const key = SYNTH.skPlain
    const b64 = base64Encode(` "OPENAI_API_KEY": "${key}"`)
    const variants = [
      `key ：${b64}\n\nbase_url = “https://ricktoken.example.net”`, // fullwidth label+space (reported)
      `key：${b64}\nbase_url = “https://ricktoken.example.net”`, // glued fullwidth
      `key: ${b64}\nbase_url = "https://ricktoken.example.net"`, // ascii
      `KEY ：${b64}\nbase_url = “https://ricktoken.example.net”`, // uppercase
      `api_key ：${b64}\nbase_url = “https://ricktoken.example.net”`, // api_key label
      `key（base64）：${b64}\nbase_url = “https://ricktoken.example.net”`, // CJK note label
      `这是配置\nkey ：${b64}\n\nbase_url = “https://ricktoken.example.net”\n谢谢`, // prose around
    ]
    for (const text of variants) {
      const r = parseShareText(text)
      assert.ok(r, `should parse: ${text.slice(0, 40)}…`)
      assert.equal(r.apiKey, key, `key must be decoded sk- for: ${text.slice(0, 30)}…`)
      assert.ok(r.chat || r.anthropic, `URL for: ${text.slice(0, 30)}…`)
    }
  })

  it('decodes various env field names out of a base64 fragment', () => {
    // The same fragment shape with different field names must all yield the key.
    const key = SYNTH.skPlain
    for (const field of ['OPENAI_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'api_key', 'key', 'token']) {
      const b64 = base64Encode(` "${field}": "${key}"`)
      const r = parseShareText(`key ：${b64}\nbase_url = "https://ricktoken.example.net"`)
      assert.ok(r, `field ${field} should parse`)
      assert.equal(r.apiKey, key, `field ${field}`)
    }
  })
})

describe('parseShareText · env', () => {
  it('extracts ANTHROPIC env from Chinese noise', () => {
    const text = `
大家好，下面是我用了一周的配置，自己测试可用：
ANTHROPIC_BASE_URL=${SYNTH.endpointProxy}
ANTHROPIC_AUTH_TOKEN=${SYNTH.skAnt}
用的时候注意别泄露，谢谢各位佬。
`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointProxy)
    assert.equal(r.apiKey, SYNTH.skAnt)
    assert.equal(r.source, 'env')
    assert.ok(r.confidence >= 0.7)
    assert.ok(r.confidence <= 1, `confidence must be <= 1, got ${r.confidence}`)
  })

  it('extracts OPENAI-style env', () => {
    const text = `
OPENAI_BASE_URL=${SYNTH.endpointOpenai}
OPENAI_API_KEY=${SYNTH.skPlain}
`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointOpenai)
    assert.equal(r.apiKey, SYNTH.skPlain)
  })
})

describe('parseShareText · json', () => {
  it('parses JSON provider object embedded in prose', () => {
    const text = `
可以导入这个 JSON：
{"name":"MyRelay","baseUrl":"https://relay.example.com","apiKey":"${SYNTH.skAntJson}"}
祝好
`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.name, 'MyRelay')
    assert.equal(r.chat, 'https://relay.example.com')
    assert.equal(r.anthropic, 'https://relay.example.com')
    assert.equal(r.apiKey, SYNTH.skAntJson)
    assert.equal(r.source, 'json')
  })

  it('carries a JSON models array into the result and the deeplink', () => {
    const text = JSON.stringify({
      name: 'ModelsRelay',
      baseUrl: 'https://relay.example.com/v1',
      apiKey: SYNTH.skPlain,
      models: ['claude-sonnet-4-20250514', 'gpt-5.1'],
    })
    const r = parseShareText(text)
    assert.ok(r)
    assert.deepEqual(r.models, ['claude-sonnet-4-20250514', 'gpt-5.1'])
    const link = new URL(buildDeeplink(r, {}))
    assert.equal(link.searchParams.get('models'), 'claude-sonnet-4-20250514,gpt-5.1')
  })

  it('handles nested/quoted braces, many objects, and an earlier unclosed string', () => {
    const provider = JSON.stringify({
      name: 'Scanner fixture',
      env: {
        ANTHROPIC_BASE_URL: SYNTH.endpoint,
        ANTHROPIC_AUTH_TOKEN: SYNTH.skAnt,
      },
      notes: 'literal { brace } and an escaped "quote"',
    })
    const text = `{"broken":"unterminated\n${'{}\n'.repeat(15)}${provider}`
    const r = parseShareText(text)

    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.skAnt)
    assert.equal(r.name, 'Scanner fixture')
    assert.ok(r.chat || r.anthropic)
  })
})

describe('parseShareText · base64', () => {
  it('decodes base64 JSON config', () => {
    const json = JSON.stringify({
      name: 'B64Provider',
      base_url: SYNTH.endpointB64,
      api_key: SYNTH.skPlain,
    })
    const b64 = base64Encode(json)
    const text = `配置已加密分享如下（base64）：\n${b64}\n解码后自行导入`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointB64)
    assert.equal(r.anthropic, SYNTH.endpointB64)
    assert.equal(r.apiKey, SYNTH.skPlain)
    assert.equal(r.source, 'base64')
  })
})

describe('parseShareText · deeplink', () => {
  it('parses existing magpie import link', () => {
    const link = `magpie://import?name=Shared&chat=${encodeURIComponent(SYNTH.endpointV1)}&key=${SYNTH.skAntDeeplink}`
    const text = `一键导入：${link} 点了就能用`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.source, 'deeplink')
    assert.equal(r.chat, SYNTH.endpointV1)
    assert.equal(r.apiKey, SYNTH.skAntDeeplink)
    assert.equal(r.name, 'Shared')
  })

  it('rejects non-import magpie deeplinks', () => {
    for (const action of ['install', 'v1/import', 'help']) {
      const link = `magpie://${action}?name=X&chat=${encodeURIComponent(SYNTH.endpoint)}&key=${SYNTH.skAnt}`
      const r = parseShareText(`导入：${link}`)
      // Must not rewrite into an import
      assert.equal(r, null, `action=${action} should be rejected`)
    }
  })

  it('skips non-import deeplink and continues with ordinary endpoint/key text', () => {
    const bad = `magpie://install?name=X&chat=${encodeURIComponent(SYNTH.endpoint)}&key=${SYNTH.skAnt}`
    const text = `${bad}
下面还有：
url：${SYNTH.endpointRelay}
key：${SYNTH.skAntMixed}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.notEqual(r.source, 'deeplink')
    assert.equal(r.chat, SYNTH.endpointRelay)
    assert.equal(r.apiKey, SYNTH.skAntMixed)
  })

  it('parses magpie: without authority slashes', () => {
    const link = `magpie:import?name=NoSlash&chat=${encodeURIComponent(SYNTH.endpoint)}&key=${SYNTH.skAntDeeplink}`
    assert.equal(looksLikeConfig(`导入：${link}`), true)
    const r = parseShareText(`导入：${link}`)
    assert.ok(r)
    assert.equal(r.source, 'deeplink')
    assert.equal(r.chat, SYNTH.endpoint)
    assert.equal(r.apiKey, SYNTH.skAntDeeplink)
    assert.equal(r.name, 'NoSlash')
  })

  it('round-trips recognized safe provider parameters', () => {
    const params = new URLSearchParams({
      name: 'Safe metadata',
      chat: SYNTH.endpointV1,
      key: SYNTH.skAntDeeplink,
      region: 'cn-beijing',
      catalog: 'example-relay',
      id: 'example-relay',
    })
    const r = parseShareText(`magpie://import?${params}`)
    assert.ok(r)
    const rebuilt = new URL(buildDeeplink(r, {}))

    for (const name of ['region', 'catalog', 'id']) {
      assert.equal(rebuilt.searchParams.get(name), params.get(name), name)
    }
  })

  it('round-trips the models comma list', () => {
    const params = new URLSearchParams({
      name: 'Models link',
      chat: SYNTH.endpointV1,
      key: SYNTH.skAntDeeplink,
      models: 'claude-sonnet-4-20250514,gpt-5.1, gemini-2.5-pro',
    })
    const r = parseShareText(`magpie://import?${params}`)
    assert.ok(r)
    assert.deepEqual(r.models, [
      'claude-sonnet-4-20250514',
      'gpt-5.1',
      'gemini-2.5-pro',
    ])
    const rebuilt = new URL(buildDeeplink(r, {}))
    assert.equal(
      rebuilt.searchParams.get('models'),
      'claude-sonnet-4-20250514,gpt-5.1,gemini-2.5-pro',
    )
  })

  it('discloses risky and unknown provider parameters and requires opt-in', () => {
    const params = new URLSearchParams({
      name: 'Risky metadata',
      chat: SYNTH.endpointV1,
      key: SYNTH.skPlain,
      region: 'cn-beijing',
      website: 'https://vendor.example.invalid',
      keys: 'https://vendor.example.invalid/keys',
      icon: 'https://vendor.example.invalid/icon.png',
      futureToggle: 'on',
    })
    const r = parseShareText(`magpie://import?${params}`)
    assert.ok(r)
    const info = describeProviderParams(r.providerParams)
    assert.equal(info.risky, true)
    assert.deepEqual(
      info.riskyFields.slice().sort(),
      ['icon', 'keys', 'website'],
    )
    assert.deepEqual(info.unknownFields, ['futureToggle'])

    const safeOnly = new URL(buildDeeplink(r, {}))
    assert.equal(safeOnly.searchParams.get('region'), 'cn-beijing')
    assert.equal(safeOnly.searchParams.has('website'), false)
    assert.equal(safeOnly.searchParams.has('keys'), false)
    assert.equal(safeOnly.searchParams.has('icon'), false)
    assert.equal(safeOnly.searchParams.has('futureToggle'), false)

    const optedIn = new URL(buildDeeplink(r, { includeRiskyParams: true }))
    assert.equal(optedIn.searchParams.get('website'), params.get('website'))
    assert.equal(optedIn.searchParams.get('keys'), params.get('keys'))
    assert.equal(optedIn.searchParams.get('icon'), params.get('icon'))
    assert.equal(optedIn.searchParams.get('futureToggle'), params.get('futureToggle'))
  })

  it('preserves preset and region from an existing link', () => {
    const link = `magpie://import?preset=deepseek&key=${SYNTH.skAntDeeplink}`
    const r = parseShareText(link)
    assert.ok(r)
    assert.equal(r.preset, 'deepseek')
    assert.equal(hasAnyUrl(r), false)
    // preset replaces the URL requirement entirely
    const rebuilt = new URL(buildDeeplink(r, {}))
    assert.equal(rebuilt.searchParams.get('preset'), 'deepseek')
    assert.equal(rebuilt.searchParams.has('name'), false)
  })
})

describe('parseShareText · mixed', () => {
  it('pulls url + key from messy Chinese paragraph', () => {
    const text = `
佬友们好，今天分享一个中转，地址是 ${SYNTH.endpointMid} 密钥 ${SYNTH.skAntMixed}
别问我怎么来的，自己测试。限速别骂人。
`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.anthropic, 'https://mid.example.invalid/anthropic')
    assert.equal(r.apiKey, SYNTH.skAntMixed)
    assert.ok(['mixed', 'env'].includes(r.source))
  })

  it('parses url：/key： fullwidth labels with base64 key', () => {
    const b64 = base64Encode(SYNTH.g2a)
    const text = `免费500刀（并发80，rpm1200）
url：${SYNTH.endpointGrok}
key：${b64}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    // root-ish URL → both chat and anthropic
    assert.equal(r.chat, SYNTH.endpointGrok)
    assert.equal(r.anthropic, SYNTH.endpointGrok)
    assert.equal(r.apiKey, SYNTH.g2a)
    assert.ok(r.confidence >= 0.6)
  })

  it('parses table Base URL + next-line Base64 API Key', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const text = `配置项    值
Base URL    ${SYNTH.endpoint}
额度查询页    打开网站后输入 key 可以查询使用额度记录
模型设置    gpt-5.5，gpt-5.6-sol，claude系列均会转发到grok4.5
API Key（Base64，请自行解码）
${b64}
如果想自己稳定`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpoint)
    assert.equal(r.anthropic, SYNTH.endpoint)
    assert.equal(r.apiKey, SYNTH.skPlain)
  })

  it('handles Discourse noise: zwsp, soft-hyphen, spaced base64, glued label', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const expected = SYNTH.skPlain
    const cases = [
      // glued label+value
      `API Key（Base64，请自行解码）${b64}\nBase URL ${SYNTH.endpoint}`,
      // zwsp before key
      `Base URL ${SYNTH.endpoint}\nAPI Key（Base64，请自行解码）\n​` + b64,
      // space-split base64
      `Base URL ${SYNTH.endpoint}\nAPI Key（Base64，请自行解码）\n${b64.slice(0, 20)} ${b64.slice(20)}`,
      // soft hyphen inside base64
      `Base URL ${SYNTH.endpoint}\nAPI Key（Base64，请自行解码）\n${b64.slice(0, 16)}­${b64.slice(16)}`,
    ]
    for (const text of cases) {
      const r = parseShareText(text)
      assert.ok(r, 'expected parse result')
      assert.equal(r.chat, SYNTH.endpoint)
      assert.equal(r.apiKey, expected)
    }
  })

  it('returns null for pure prose', () => {
    const r = parseShareText(
      '今天天气不错，我们来讨论一下如何学习 Linux 内核以及写驱动的心得体会吧朋友们',
    )
    assert.equal(r, null)
  })

  it('fails to find endpoint when selection only has link label "base url" (Discourse onebox)', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const text = `API Key（Base64，请自行解码）
${b64}
base url`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.skPlain)
    // endpoint missing — real URL only lived in <a href>
    assert.equal(hasAnyUrl(r), false)
  })

  it('recovers endpoint after enriching selection with anchor hrefs', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const selectionText = `API Key（Base64，请自行解码）
${b64}
base url`
    const anchors = [{ text: 'base url', href: SYNTH.endpointRelay }]
    const enriched = enrichTextWithAnchorHrefs(selectionText, anchors)
    const r = parseShareText(enriched)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointRelay)
    assert.equal(r.apiKey, SYNTH.skPlain)
  })

  it('decodes base64 key with CJK watermark 去除文中 injected (linux.do anti-scrape)', () => {
    // Synthetic: insert CJK anti-scrape watermark mid-token, then base64.
    const clean = SYNTH.skWatermarkBody
    const mid = Math.floor(clean.length / 2)
    const withWatermark = clean.slice(0, mid) + '去除文中' + clean.slice(mid)
    const b64 = base64Encode(withWatermark)
    const text = `API Key（Base64，请自行解码）
${b64}
base url：${SYNTH.endpoint}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, clean)
    assert.equal(r.chat, SYNTH.endpoint)
  })

  it('strips CJK watermark mid plain sk- key (linux.do anti-scrape, not base64)', () => {
    // Real-world pattern: sk-…删掉我… continues as hex body; must not truncate at CJK.
    const clean = 'sk-testonlyaaaaaaaabbbbbbbbccccccccddddddddeeeeeeee'
    const withWatermark =
      'sk-testonlyaaaaaaaabbbbbbbb' + '删掉我' + 'ccccccccddddddddeeeeeeee'
    const text = `openfly.cc
Sub2API - AI API Gateway
${withWatermark}

想测一下高并发是否稳定`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, clean)
    assert.equal(r.chat, 'https://openfly.cc')
  })

  it('parses newapi_channel_conn JSON with base64 key field', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const text = `{"_type":"newapi_channel_conn","key":"${b64}","url":"${SYNTH.endpointNewapi}"}
链接不能注册 欢迎佬们 帮忙测试`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointNewapi)
    assert.equal(r.anthropic, SYNTH.endpointNewapi)
    assert.equal(r.apiKey, SYNTH.skPlain)
    assert.ok(['json', 'mixed'].includes(r.source), `source=${r.source}`)
  })

  it('recovers endpoint when Discourse linkifies JSON url value to bare "url"', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const selectionText = `{"_type":"newapi_channel_conn","key":"${b64}","url":"url"}
链接不能注册`
    const enriched = enrichTextWithAnchorHrefs(selectionText, [
      { text: 'url', href: SYNTH.endpointNewapi },
    ])
    assert.ok(!/"url[：:]https?:\/\//.test(enriched), `corrupted JSON: ${enriched}`)
    assert.match(enriched, /https:\/\/newapi\.example\.invalid/)
    const r = parseShareText(enriched)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.skPlain)
    assert.equal(r.chat, SYNTH.endpointNewapi)
  })

  it('handles Discourse-wrapped newapi JSON (newline after colon, unquoted url)', () => {
    const b64 = base64Encode(SYNTH.skPlain)
    const text = `{"_type":"newapi_channel_conn","key":
"${b64}","url":
${SYNTH.endpointNewapi}"}
链接不能注册 欢迎佬们 帮忙测试

key base64`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointNewapi)
    assert.equal(r.apiKey, SYNTH.skPlain)
    assert.ok(!String(r.chat).includes('"'))
  })

  it('recovers tp- key from CJK-glued base64 (no whitespace boundary)', () => {
    // Pattern from real shares: base64 glued after Chinese prose, peels to tp-…
    const b64 = base64Encode(SYNTH.tp)
    const text = `自己买的这个都没咋用 之前一分钱续费的 最近使用的grok 丢出来给需要的佬友们用${b64}
目前还有额度

兼容 OpenAI 接口协议：

${SYNTH.endpointV1}

兼容 Anthropic 接口协议：

${SYNTH.endpointAnthropic}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.tp)
    assert.ok(r.chat || r.anthropic)
  })

  it('accepts plain / spaced base64 that peels to tp- keys', () => {
    const b64 = base64Encode(SYNTH.tp)
    const cases = [
      `${b64}\n${SYNTH.endpointV1}`,
      `佬友们用 ${b64}\n${SYNTH.endpointV1}`,
      `key: ${SYNTH.tp}\n${SYNTH.endpointV1}`,
    ]
    for (const text of cases) {
      const r = parseShareText(text)
      assert.ok(r, `expected parse for: ${text.slice(0, 40)}…`)
      assert.equal(r.apiKey, SYNTH.tp)
      assert.equal(r.chat, SYNTH.endpointV1)
    }
  })

  it('truncates oversized selections and still parses trailing config', () => {
    // Put the real config near the start so truncation keeps it; pad with prose after.
    const text =
      `url：${SYNTH.endpointV1}\nkey：${SYNTH.skAnt}\n` + '讨论内容填充'.repeat(20_000)
    assert.ok(text.length > 64 * 1024)
    const started = Date.now()
    const r = parseShareText(text)
    const elapsed = Date.now() - started
    assert.ok(elapsed < 2000, `parse took too long: ${elapsed}ms`)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointV1)
    assert.equal(r.apiKey, SYNTH.skAnt)
    assert.ok(r.warnings.some((w) => /选区过大|截断/.test(w)))
  })

  it('samples both ends of oversized selections and reports the omitted middle', () => {
    const text =
      '无关讨论内容'.repeat(20_000) + `\nurl：${SYNTH.endpointV1}\nkey：${SYNTH.skAnt}\n`

    assert.ok(text.length > 64 * 1024)
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)

    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointV1)
    assert.equal(r.apiKey, SYNTH.skAnt)
    assert.ok(r.warnings.some((w) => /开头和结尾|中间内容已省略/.test(w)))
  })

  it('keeps an oversized omitted-middle selection actionable', () => {
    const padding = '普通讨论内容'.repeat(7_000)
    const text =
      padding + `\nurl：${SYNTH.endpointV1}\nkey：${SYNTH.skAnt}\n` + padding

    assert.ok(text.length > 64 * 1024)
    assert.equal(looksLikeConfig(text), true)
    assert.equal(parseShareText(text), null)
  })

  it('bounds malformed JSON scanning at the maximum selection size', () => {
    const text = '{'.repeat(64 * 1024)
    const started = Date.now()
    const r = parseShareText(text)
    const elapsed = Date.now() - started

    assert.equal(r, null)
    assert.ok(elapsed < 1000, `malformed parse exceeded the 1s budget: ${elapsed}ms`)
  })

  it('parses Discourse onebox bare host + g2a_ key (no https scheme in selection)', () => {
    // linux.do onebox shows host text without scheme; key sits under 总结
    const text = `c
grok2api-v2.onrender.com
Grok2API
总结
${SYNTH.g2a}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.g2a)
    assert.equal(r.chat, 'https://grok2api-v2.onrender.com')
  })

  it('parses https URL + g2a_ key without labels', () => {
    const text = `https://grok2api-v2.onrender.com
Grok2API
${SYNTH.g2a}`
    assert.equal(looksLikeConfig(text), true)
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, 'https://grok2api-v2.onrender.com')
    assert.equal(r.apiKey, SYNTH.g2a)
  })
})

describe('enrichTextWithAnchorHrefs', () => {
  it('appends hrefs when visible link text has no URL', () => {
    const text = 'API Key xxx\nbase url'
    const out = enrichTextWithAnchorHrefs(text, [
      { text: 'base url', href: 'https://hidden.example.com/api' },
    ])
    assert.match(out, /https:\/\/hidden\.example\.com\/api/)
    assert.match(out, /base\s*url/i)
  })

  it('does not duplicate href already present in selection text', () => {
    const text = 'url：https://already.example.com\nkey：sk-xxx'
    const out = enrichTextWithAnchorHrefs(text, [
      { text: 'https://already.example.com', href: 'https://already.example.com' },
    ])
    const matches = out.match(/https:\/\/already\.example\.com/g) || []
    assert.equal(matches.length, 1)
  })

  it('skips non-http(s) and empty anchors', () => {
    const text = 'hello world enough chars here!!'
    const out = enrichTextWithAnchorHrefs(text, [
      { text: 'click', href: 'javascript:void(0)' },
      { text: 'x', href: '' },
      { text: 'mail', href: 'mailto:a@b.com' },
    ])
    assert.equal(out, text)
  })

  it('labels preferred: base url / url / endpoint anchors first', () => {
    const text = 'see also docs and base url'
    const out = enrichTextWithAnchorHrefs(text, [
      { text: 'docs', href: 'https://docs.example.com/readme' },
      { text: 'base url', href: 'https://api.example.com' },
    ])
    assert.match(out, /base\s*url\s*[:：]\s*https:\/\/api\.example\.com/i)
    assert.match(out, /https:\/\/docs\.example\.com\/readme/)
  })
})

describe('classifyEndpointProtocol', () => {
  it('classifies /v1-family paths as chat-only', () => {
    for (const url of [
      'https://api.relay.cn/v1',
      'https://api.relay.cn/v1/',
      'https://api.relay.cn/api/v3',
      'https://api.relay.cn:8443/api/v1beta',
    ]) {
      const c = classifyEndpointProtocol(url)
    }
    assert.equal(classifyEndpointProtocol('https://api.relay.cn/v1').chat, 'https://api.relay.cn/v1')
    assert.equal(classifyEndpointProtocol('https://api.relay.cn/v1').anthropic, null)
  })

  it('classifies /anthropic paths as anthropic base, stripping a trailing /v1', () => {
    assert.deepEqual(classifyEndpointProtocol('https://api.relay.cn/anthropic'), {
      chat: null,
      responses: null,
      anthropic: 'https://api.relay.cn/anthropic',
    })
    assert.equal(
      classifyEndpointProtocol('https://api.relay.cn/anthropic/v1').anthropic,
      'https://api.relay.cn/anthropic',
    )
  })

  it('gives a root-ish URL both chat and anthropic (relay usually speaks both)', () => {
    assert.deepEqual(classifyEndpointProtocol('https://api.relay.cn'), {
      chat: 'https://api.relay.cn',
      responses: null,
      anthropic: 'https://api.relay.cn',
    })
  })

  it('maps Volcengine Ark dual-protocol paths', () => {
    // /api/coding → anthropic root (path kept)
    assert.equal(
      classifyEndpointProtocol('https://ark.cn-beijing.volces.com/api/coding').anthropic,
      'https://ark.cn-beijing.volces.com/api/coding',
    )
    // /api/coding/v3 → chat keeps the v3 path, anthropic falls back to host root
    const v3 = classifyEndpointProtocol('https://ark.cn-beijing.volces.com/api/coding/v3')
    assert.equal(v3.chat, 'https://ark.cn-beijing.volces.com/api/coding/v3')
    assert.equal(v3.anthropic, 'https://ark.cn-beijing.volces.com')
  })

  it('returns empty for forum links and non-http(s) schemes', () => {
    assert.deepEqual(classifyEndpointProtocol('https://linux.do/t/topic/1'), {
      chat: null,
      responses: null,
      anthropic: null,
    })
    assert.deepEqual(classifyEndpointProtocol('ftp://x.example'), {
      chat: null,
      responses: null,
      anthropic: null,
    })
  })
})

describe('suggestPresetLinks', () => {
  it('suggests the official preset when the share URL is the vendor base', () => {
    const s = suggestPresetLinks(
      '任意标题',
      { chat: 'https://api.openai.com/v1', responses: null, anthropic: null },
      SYNTH.skAnt,
    )
    assert.ok(s.some((x) => x.id === 'openai'), `got ${JSON.stringify(s)}`)
  })

  it('suggests by topic title mention but not for relay-worded titles', () => {
    const none = { chat: null, responses: null, anthropic: null }
    const s1 = suggestPresetLinks('分享一个 anthropic 官方 key', none, SYNTH.skAnt)
    assert.ok(s1.some((x) => x.id === 'anthropic'))

    const s2 = suggestPresetLinks('某某中转站 openai 线路', none, SYNTH.skAnt)
    assert.equal(s2.some((x) => x.id === 'openai'), false)

    const s3 = suggestPresetLinks('随便聊聊', none, SYNTH.skAnt)
    assert.equal(s3.length, 0)
  })

  it('requires an api key before suggesting anything', () => {
    const none = { chat: null, responses: null, anthropic: null }
    assert.equal(suggestPresetLinks('anthropic 官方', none, null).length, 0)
  })
})

describe('selectCandidate', () => {
  it('switches protocol URLs/apiKey among mixed multi-pair candidates', () => {
    const text = `
      url1 ${SYNTH.endpointA}
      url2 ${SYNTH.endpointB}
      key1 ${SYNTH.skAntA}
      key2 ${SYNTH.skAntB}
    `
    const r = parseShareText(text)
    assert.ok(r)
    assert.ok(r.candidates && r.candidates.length >= 2, `candidates=${r.candidates?.length}`)
    const second = selectCandidate(r, 1)
    assert.equal(second.candidateIndex, 1)
    assert.ok(hasAnyUrl(second))
    assert.ok(second.apiKey)
    assert.ok([SYNTH.skAntA, SYNTH.skAntB].includes(second.apiKey))
  })

  it('defaults to same-block URL/key pairs instead of crossed best fields', () => {
    // Grouped blocks: URL1+KEY1 then URL2+KEY2 — default must not be URL2×KEY1
    const text = `
url：${SYNTH.endpointA}
key：${SYNTH.skAntA}

url：${SYNTH.endpointB}
key：${SYNTH.skAntB}
`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointA)
    assert.equal(r.apiKey, SYNTH.skAntA)
  })
})

describe('labeled key hygiene', () => {
  it('rejects Chinese placeholder text after key labels', () => {
    for (const text of [
      `API Key：请联系群主获取完整密钥后填写\nBase URL ${SYNTH.endpoint}`,
      `密钥：请自行填写\n地址：${SYNTH.endpoint}`,
      `key: your-key-here-please\nurl: ${SYNTH.endpoint}`,
    ]) {
      const r = parseShareText(text)
      assert.ok(r, `expected parse for endpoint in: ${text.slice(0, 30)}`)
      assert.equal(r.chat, SYNTH.endpoint)
      assert.equal(r.apiKey, null, `should not treat prose as key: ${r.apiKey}`)
    }
  })

  it('rejects URL values labeled as key', () => {
    const text = `key：https://evil.example.invalid/steal\nurl：${SYNTH.endpoint}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpoint)
    assert.ok(
      r.apiKey == null || !/^https?:\/\//i.test(r.apiKey),
      `apiKey must not be a URL: ${r.apiKey}`,
    )
    // Prefer no key at all over stealing the url as key
    assert.notEqual(r.apiKey, 'https://evil.example.invalid/steal')
  })
})

describe('bare host email peel', () => {
  it('does not treat email domains as bare API hosts', () => {
    const text = `admin@mail.example.com\n${SYNTH.g2a}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.g2a)
    assert.equal(hasAnyUrl(r), false)
  })

  it('still accepts genuine bare onebox hosts with keys', () => {
    const text = `grok2api-v2.onrender.com\n${SYNTH.g2a}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, 'https://grok2api-v2.onrender.com')
    assert.equal(r.apiKey, SYNTH.g2a)
  })
})

describe('deeplink finalize', () => {
  it('strips trailing punctuation from deeplink URLs via finalizeResult', () => {
    const link = `magpie://import?name=X&chat=${encodeURIComponent(
      'https://api.example.com/v1.',
    )}&key=${SYNTH.skAntDeeplink}`
    const r = parseShareText(link)
    assert.ok(r)
    assert.equal(r.source, 'deeplink')
    assert.equal(r.chat, 'https://api.example.com/v1')
    assert.equal(r.apiKey, SYNTH.skAntDeeplink)
  })

  it('strips trailing quotes from deeplink URLs', () => {
    const link = `magpie://import?name=X&chat=${encodeURIComponent(
      'https://api.example.com/v1"',
    )}&key=${SYNTH.skAntDeeplink}`
    const r = parseShareText(link)
    assert.ok(r)
    assert.equal(r.chat, 'https://api.example.com/v1')
  })
})

describe('buildDeeplink · magpie rules', () => {
  const base = {
    name: 'T',
    preset: null,
    region: null,
    chat: 'https://api.example.invalid/v1',
    responses: null,
    anthropic: null,
    apiKey: SYNTH.skAnt,
    models: [],
  }

  it('builds an import link', () => {
    const link = buildDeeplink(base, {})
    assert.match(link, /^magpie:\/\/import\?/)
    const u = new URL(link)
    assert.equal(u.searchParams.get('name'), 'T')
    assert.equal(u.searchParams.get('chat'), 'https://api.example.invalid/v1')
    assert.ok(u.searchParams.get('key'))
  })

  it('uses preset instead of name when present', () => {
    const link = buildDeeplink({ ...base, preset: 'deepseek' }, {})
    const u = new URL(link)
    assert.equal(u.searchParams.get('preset'), 'deepseek')
    assert.equal(u.searchParams.has('name'), false)
    // preset replaces the URL requirement entirely — chat still carried is fine
  })

  it('throws without any base URL (no preset)', () => {
    assert.throws(
      () => buildDeeplink({ ...base, chat: null, responses: null, anthropic: null }, {}),
      /base URL/,
    )
  })

  it('validates endpoint URLs: query/fragment/credentials rejected', () => {
    for (const chat of [
      'https://user:pass@relay.example.invalid/v1',
      'https://relay.example.invalid/v1?token=x',
      'https://relay.example.invalid/v1#frag',
      'ftp://relay.example.invalid/v1',
      'not a url',
    ]) {
      assert.throws(
        () => buildDeeplink({ ...base, chat }, {}),
        /chat 地址已阻止|地址/,
        `chat=${chat}`,
      )
    }
  })

  it('allows http only for local/lAN hosts (magpie rule), blocks otherwise', () => {
    assert.doesNotThrow(() =>
      buildDeeplink({ ...base, chat: 'http://127.0.0.1:8080/v1' }, {}),
    )
    assert.doesNotThrow(() =>
      buildDeeplink({ ...base, chat: 'http://192.168.1.10:3000/v1' }, {}),
    )
    assert.throws(
      () => buildDeeplink({ ...base, chat: 'http://relay.example.invalid/v1' }, {}),
      /非本机|https/,
    )
  })

  it('rejects oversized or control-character keys (magpie limits)', () => {
    assert.throws(
      () => buildDeeplink({ ...base, apiKey: 'sk-' + 'k'.repeat(5000) }, {}),
      /apiKey|4096|控制字符/,
    )
    assert.throws(
      () => buildDeeplink({ ...base, apiKey: 'sk-a\nb' }, {}),
      /apiKey|控制字符/,
    )
  })

  it('carries models as a comma list, deduped and capped', () => {
    const models = []
    for (let i = 0; i < 40; i++) models.push(`model-${i}`)
    const link = buildDeeplink({ ...base, models }, {})
    const u = new URL(link)
    const carried = u.searchParams.get('models').split(',')
    assert.equal(carried.length, 24, 'capped at MAX_DEEPLINK_MODELS')
    assert.equal(carried[0], 'model-0')
  })

  it('enforces the final deep-link limit for every parameter source', () => {
    const cases = [
      { ...base, name: 'N'.repeat(MAX_DEEPLINK_LEN) },
      {
        ...base,
        chat: `https://relay.example.invalid/${'e'.repeat(MAX_DEEPLINK_LEN)}`,
      },
      { ...base, apiKey: `sk-${'k'.repeat(MAX_DEEPLINK_LEN)}` },
      {
        ...base,
        providerParams: { region: 'r'.repeat(MAX_DEEPLINK_LEN) },
      },
      {
        ...base,
        name: 'n'.repeat(2700),
        apiKey: `sk-${'k'.repeat(2700)}`,
        models: Array.from({ length: 24 }, (_, i) => 'm'.repeat(200) + i),
      },
    ]

    for (const input of cases) {
      assert.throws(() => buildDeeplink(input, {}), /8.?000|过长|长度/)
    }
    assert.ok(buildDeeplink(base, {}).length < MAX_DEEPLINK_LEN)
  })

  it('MAX_DEEPLINK_LEN is a finite conservative cap', () => {
    assert.equal(typeof MAX_DEEPLINK_LEN, 'number')
    assert.ok(MAX_DEEPLINK_LEN >= 2000 && MAX_DEEPLINK_LEN <= 32000)
  })
})

describe('maskKey', () => {
  it('masks middle of key', () => {
    const m = maskKey('sk-ant-api03-abcdefghijklmnop')
    assert.ok(m.includes('****'))
    assert.ok(!m.includes('abcdefghijklmnop'))
  })
})

describe('extractModels integration', () => {
  it('detects model ids from share prose and merges with parse result models', () => {
    const text = `模型设置    gpt-5.5，gpt-5.6-sol，claude系列均会转发到grok4.5
Base URL    ${SYNTH.endpoint}
API Key     ${SYNTH.skPlain}`
    const r = parseShareText(text)
    assert.ok(r)
    const detected = extractModels(text).models
    assert.ok(detected.includes('gpt-5.5'))
    assert.ok(detected.includes('grok-4.5'))
    const merged = Array.from(new Set([...(r.models || []), ...detected]))
    const link = buildDeeplink({ ...r, models: merged }, {})
    const u = new URL(link)
    assert.ok(u.searchParams.get('models').includes('gpt-5.5'))
  })
})

describe('regression · unquoted field=value base64 wrapper (#1)', () => {
  it('unwraps unquoted api_key=sk-… fragment decoded from a JSON key field', () => {
    // The v1.2.9 unwrap only handled quoted `"FIELD": "value"` fragments. A blob
    // decoding to unquoted `api_key=sk-…` must yield the bare key too — never the
    // whole fragment (which would silently break the generated deeplink).
    const key = SYNTH.skPlain
    const b64 = base64Encode(`api_key=${key}`)
    const share = JSON.stringify({ url: SYNTH.endpointV1, key: b64 })
    const r = parseShareText(share)
    assert.ok(r)
    assert.equal(r.apiKey, key)
    assert.equal(r.chat, SYNTH.endpointV1)
  })

  it('unwraps unquoted field=value fragments via toml/env and labeled paths', () => {
    const key = SYNTH.skPlain
    for (const field of ['api_key', 'OPENAI_API_KEY', 'token']) {
      const b64 = base64Encode(`${field}=${key}`)
      const toml = parseShareText(`base_url = "https://ricktoken.example.net"\napi_key = "${b64}"`)
      assert.ok(toml, `toml field ${field} should parse`)
      assert.equal(toml.apiKey, key, `toml field ${field}`)

      const labeled = parseShareText(`key（base64）：${b64}\nbase_url = "https://ricktoken.example.net"`)
      assert.ok(labeled, `labeled field ${field} should parse`)
      assert.equal(labeled.apiKey, key, `labeled field ${field}`)
    }
  })

  it('never carries a field= wrapper into the deeplink key', () => {
    const key = SYNTH.skPlain
    const b64 = base64Encode(`api_key=${key}`)
    const share = JSON.stringify({ url: SYNTH.endpointV1, key: b64 })
    const r = parseShareText(share)
    assert.ok(r)
    const link = buildDeeplink(r, {})
    const qs = new URLSearchParams(link.slice(link.indexOf('?') + 1))
    assert.equal(qs.get('key'), key)
  })
})

describe('regression · forum links are not API endpoints (#2)', () => {
  it('does not recover a linux.do topic link as endpoint for key-only JSON shares', () => {
    const text = `{"key":"${SYNTH.skAnt}","name":"x"} 详见 https://linux.do/t/topic/123456`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.skAnt)
    assert.equal(hasAnyUrl(r), false)
    assert.ok(r.warnings.some((w) => /base URL/i.test(w)))
  })

  it('does not use linux.do links as mixed-path endpoint candidates', () => {
    // Whole-post selection: topic link + key but no real API URL → URL stays null.
    const text = `佬友们自取\n${SYNTH.skAnt}\n原帖 https://linux.do/t/topic/123456 欢迎反馈`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, SYNTH.skAnt)
    for (const c of r.candidates || []) {
      assert.ok(
        !c.chat || !/linux\.do/.test(c.chat),
        `candidate chat ${c.chat}`,
      )
      assert.ok(
        !c.anthropic || !/linux\.do/.test(c.anthropic),
        `candidate anthropic ${c.anthropic}`,
      )
    }
    assert.equal(hasAnyUrl(r), false)
  })

  it('still accepts a real endpoint alongside a linux.do topic link', () => {
    const text = `url：${SYNTH.endpointV1}\nkey：${SYNTH.skPlain}\n原帖 https://linux.do/t/topic/123456`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, SYNTH.endpointV1)
    assert.equal(r.apiKey, SYNTH.skPlain)
  })
})

describe('regression · candidate sync + warnings survival (#4 #5)', () => {
  it('keeps the stitched endpoint on ALL candidate pairs, not just the active one (#4)', () => {
    // Two bare keys + a base64 blob that only carries base_url: the merge stitches
    // endpoint from the blob and key from the mixed scan. Switching candidates in
    // the confirm card must not drop the stitched endpoint.
    const k1 = SYNTH.skAntA
    const k2 = SYNTH.skAntB
    const b64 = base64Encode('base_url=https://hidden.example.invalid/v1')
    const text = `${k1}\n${k2}\n${b64}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, 'https://hidden.example.invalid/v1')
    assert.ok((r.candidates?.length || 0) >= 2, 'expected multi candidates')
    for (const c of r.candidates) {
      assert.equal(
        c.chat,
        'https://hidden.example.invalid/v1',
        'every pair inherits stitched endpoint',
      )
    }
    const alt = selectCandidate(r, 1)
    assert.equal(alt.apiKey, k2)
    assert.equal(alt.chat, 'https://hidden.example.invalid/v1')
  })

  it('preserves the multi-candidate summary warning through selectCandidate (#5)', () => {
    const text = `url：${SYNTH.endpointV1}\nkey：${SYNTH.skPlain}\n备用 ${SYNTH.skAntA}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.ok((r.candidates?.length || 0) > 1)
    assert.ok(r.warnings.some((w) => /候选/.test(w)), 'mixed parser should emit candidate summary')
    const alt = selectCandidate(r, 1)
    assert.ok(
      alt.warnings.some((w) => /候选/.test(w)),
      `summary must survive selectCandidate, got ${JSON.stringify(alt.warnings)}`,
    )
  })

  it('preserves parser warnings through the merge/stitch path (#5)', () => {
    const k1 = SYNTH.skAntA
    const k2 = SYNTH.skAntB
    const b64 = base64Encode('base_url=https://hidden.example.invalid/v1')
    const text = `${k1}\n${k2}\n${b64}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.ok(
      r.warnings.some((w) => /候选/.test(w)),
      `candidate summary must survive merge, got ${JSON.stringify(r.warnings)}`,
    )
  })

  it('still recomputes field-derived warnings for the new active pair (#5 sanity)', () => {
    // Switching to a key-only pair must DROP the now-false "endpoint missing"
    // warning only when the pair actually has an endpoint; here the stitched
    // endpoint exists, so the endpoint-missing warning must stay gone.
    const text = `url：${SYNTH.endpointV1}\nkey：${SYNTH.skPlain}\n备用 ${SYNTH.skAntA}`
    const r = parseShareText(text)
    assert.ok(r)
    const alt = selectCandidate(r, 1)
    assert.ok(!alt.warnings.some((w) => /未识别到 base URL/.test(w)))
  })
})

describe('regression · parser edge fixes (#6–#9)', () => {
  it('keeps # inside quoted env values instead of comment-stripping (#7)', () => {
    // A quoted value is literal: OPENAI_API_KEY="sk-abc #tail" must not truncate
    // at the #. (Whitespace inside the key is normalized away downstream.)
    const text = `OPENAI_BASE_URL=${SYNTH.endpointV1}\nOPENAI_API_KEY="sk-test-only-abcdef123456 #literal"`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.apiKey, 'sk-test-only-abcdef123456#literal')
  })

  it('keeps balanced parentheses in endpoint paths (#9)', () => {
    const text = `url：https://api.example.invalid/v1(beta)\nkey：${SYNTH.skPlain}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, 'https://api.example.invalid/v1(beta)')
  })

  it('still strips an unbalanced prose paren after a URL (#9 sanity)', () => {
    const text = `(配置 https://api.example.invalid/v1)\nkey：${SYNTH.skPlain}`
    const r = parseShareText(text)
    assert.ok(r)
    assert.equal(r.chat, 'https://api.example.invalid/v1')
  })
})

/** A parse result is usable when at least one protocol URL survived. */
function hasAnyUrl(result) {
  return Boolean(result && (result.chat || result.responses || result.anthropic))
}
