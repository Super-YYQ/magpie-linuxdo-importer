import { parseShareText, maskKey, base64Encode } from '../userscript/lib/core.mjs'

// Synthetic only — generate base64 at runtime, never print full apiKey.
const expectedKey = 'sk-test-only-000000000000000000000000'
const b64 = base64Encode(expectedKey)
const endpoint = 'https://api.example.invalid'

const variants = {
  original_newlines: `配置项    值
Base URL    ${endpoint}
额度查询页    打开网站后输入 key 可以查询使用额度记录
模型设置    gpt-5.5，gpt-5.6-sol，claude系列均会转发到grok4.5
API Key（Base64，请自行解码）
${b64}
如果想自己稳定`,

  single_space_baseurl: `Base URL ${endpoint}
API Key（Base64，请自行解码）
${b64}`,

  tabs: `Base URL\t${endpoint}
API Key（Base64，请自行解码）\t${b64}`,

  all_one_line: `Base URL ${endpoint} 额度查询页 打开网站后输入 key 可以查询 API Key（Base64，请自行解码） ${b64}`,

  no_space_after_label: `API Key（Base64，请自行解码）${b64}
Base URL ${endpoint}`,

  zwsp: `Base URL​​  ${endpoint}\nAPI Key（Base64，请自行解码）\n​` + b64,

  crlf: `Base URL    ${endpoint}\r\nAPI Key（Base64，请自行解码）\r\n${b64}`,

  code_fence: '```\nBase URL: ' + endpoint + '\nAPI Key（Base64，请自行解码）\n' + b64 + '\n```',

  // Discourse often inserts spaces into long tokens when selecting
  spaced_b64: `Base URL ${endpoint}
API Key（Base64，请自行解码）
${b64.slice(0, 20)} ${b64.slice(20)}`,

  soft_hyphen: `Base URL ${endpoint}
API Key（Base64，请自行解码）
${b64.slice(0, 16)}­${b64.slice(16)}`,
}

let fail = 0
for (const [name, t] of Object.entries(variants)) {
  const r = parseShareText(t)
  // A root-ish URL is classified as both chat and anthropic — either counts.
  const ok =
    r &&
    (r.chat === endpoint || r.anthropic === endpoint) &&
    r.apiKey === expectedKey
  if (!ok) fail++
  console.log(
    (ok ? 'OK ' : 'FAIL') +
      ' ' +
      name +
      ' -> ' +
      JSON.stringify(
        r
          ? {
              chat: r.chat,
              anthropic: r.anthropic,
              apiKey: maskKey(r.apiKey),
              source: r.source,
              warnings: r.warnings,
            }
          : null,
      ),
  )
}
process.exit(fail ? 1 : 0)
