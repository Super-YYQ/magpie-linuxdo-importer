/**
 * Pure parse / classify / deeplink helpers for the magpie linux.do importer.
 * Used by Node tests and inlined into the Tampermonkey userscript.
 */

const MIN_SELECTION_LEN = 20
/** Hard caps so adversarial / huge selections cannot freeze the tab. */
const MAX_SELECTION_LEN = 64 * 1024
const MAX_DECODED_LEN = 64 * 1024
const MAX_JSON_OBJECTS = 16
const MAX_URLS = 8
const MAX_KEYS = 8
const MAX_CANDIDATES = 12
const MAX_DEEPLINK_MODELS = 24
const SELECTION_OMISSION_MARKER = '\n\n[选区中间内容已省略]\n\n'
const OVERSIZED_SELECTION_WARNING = '选区过大，已取开头和结尾片段解析；中间内容已省略'

const ENV_URL_KEYS = [
  'ANTHROPIC_BASE_URL',
  'ANTHROPIC_API_BASE',
  'CLAUDE_BASE_URL',
  'OPENAI_BASE_URL',
  'OPENAI_API_BASE',
  'CODEX_BASE_URL',
  'BASE_URL',
  'API_BASE_URL',
]

const ENV_KEY_KEYS = [
  'ANTHROPIC_AUTH_TOKEN',
  'ANTHROPIC_API_KEY',
  'ANTHROPIC_API_TOKEN',
  'CLAUDE_API_KEY',
  'OPENAI_API_KEY',
  'OPENAI_AUTH_TOKEN',
  'CODEX_API_KEY',
  'API_KEY',
  'APIKEY',
  'AUTH_TOKEN',
  'TOKEN',
]
const RISKY_ENV_NAMES = new Set([
  'NODE_OPTIONS',
  'BASH_ENV',
  'ENV',
  'LD_PRELOAD',
  'LD_LIBRARY_PATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'PATH',
  'PATHEXT',
  'PYTHONPATH',
  'NODE_PATH',
  'CLASSPATH',
  'SHELL',
  'COMSPEC',
  'PROMPT_COMMAND',
  'GIT_SSH_COMMAND',
])

// Balanced single-level paren groups are allowed in paths (e.g. /v1(beta));
// a lone ')' from surrounding prose still terminates the match.
const URL_RE = /https?:\/\/(?:\([^\s"'`<>，。；、）)\]}]*\)|[^\s"'`<>，。；、）)\]}])+/gi
// Discourse onebox / paste often drops the scheme: grok2api-v2.onrender.com
// Require a multi-label host + common TLD.
// Reject emails and host suffixes peeled from them:
//   admin@mail.example.com  — (?<!@) alone still matches "example.com" after the dot.
// Also refuse a match that continues a larger label (prev char is word / "." / "@" / "-").
const BARE_HOST_RE =
  /(?<![@.\w-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|dev|app|ai|cc|me|co|info|xyz|top|tech|cloud|run|site|online|pro|page|link|live|tv|us|uk|cn|jp|de|fr|ru|br|in|au|ca|nl|se|no|fi|pl|cz|ch|at|be|es|it|pt|kr|tw|hk|sg|my|id|ph|vn|th|edu|gov)(?:\/[^\s"'`<>，。；、）)\]}]*)?/gi
// Allow short CJK / non-ASCII runs mid-key (linux.do anti-scrape watermarks like
// 「删掉我」「去除文中」). Lookahead requires the key body to continue in ASCII so
// trailing Chinese prose is not swallowed. sanitizeApiKey strips the watermark later.
const SK_KEY_BODY = '(?:[A-Za-z0-9_\\-]|[^\\x00-\\x7F]{1,12}(?=[A-Za-z0-9_\\-]))'
const SK_ANT_RE = new RegExp(`sk-ant-${SK_KEY_BODY}{10,}`, 'g')
const SK_RE = new RegExp(`sk-${SK_KEY_BODY}{16,}`, 'g')
const BEARER_RE = /Bearer\s+([A-Za-z0-9_\-.]{16,})/gi
// CJK / fullwidth punct count as token boundaries — linux.do often glues base64 after Chinese prose
const B64_BOUNDARY_L = '(?:^|[\\s"\'`：:，。；、！？]|(?<=[一-鿿]))'
const B64_BOUNDARY_R = '(?:$|[\\s"\'`，。；、！？]|(?=[一-鿿]))'
const BASE64_RE = new RegExp(`${B64_BOUNDARY_L}([A-Za-z0-9+/]{40,}={0,2})${B64_BOUNDARY_R}`, 'g')
// Accept both magpie://import?... and magpie:import?... (no authority slashes)
const DEEPLINK_RE = /magpie:(?:\/\/)?[^\s"'`<>]+/gi
// magpie import-link parameters that carry a provider description. Known but
// NOT here: website/keys/icon — a share text can offer them, but magpie only
// accepts https pages/pictures from the vendor itself, so a forum paste is not
// a trustworthy source and they are dropped at parse time.
const SAFE_PROVIDER_PARAM_NAMES = new Set([
  'catalog',
  'region',
  'id',
])
const RISKY_PROVIDER_PARAM_NAMES = new Set([
  'website',
  'keys',
  'icon',
])
const CONSUMED_PROVIDER_PARAM_NAMES = new Set([
  'preset',
  'name',
  'chat',
  'responses',
  'anthropic',
  'key',
  'models',
])
// Known API key prefixes (sk-/g2a_/tp- token-plan, plus rare vendor tags).
// ark- = Volcengine 方舟 (ark.cn-beijing.volces.com / api.volcengine.com):
// base64-shared key decodes to `ark-<uuid>-<suffix>`. Listed here so decoded
// bodies are accepted as keys and bare ark- tokens light the import button.
// xai- = xAI Grok; gsk_ = Groq; pplx- = Perplexity; r8_ = Replicate;
// hf_ = HuggingFace; fw_ = Fireworks. oc_sk_ = OpenCode-style key. These carry a delimiter (-/_)
// specific enough to avoid false matches (cross-checked vs gitleaks/n8n/pipelock).
const KEY_PREFIX_RE = /^(sk-ant-|sk-|g2a_|tp-|nk-|pk-|rk-|ark-|xai-|gsk_|pplx-|r8_|hf_|fw_|oc_sk_)/i
const KEY_PREFIX_BODY_RE = /^(sk-ant-|sk-|g2a_|tp-|nk-|pk-|rk-|ark-|xai-|gsk_|pplx-|r8_|hf_|fw_|oc_sk_|Bearer\s)/i
const VENDOR_KEY_RE = /\b(?:g2a_|tp-|nk-|pk-|rk-|ark-|xai-|gsk_|pplx-|r8_|hf_|fw_|oc_sk_)[A-Za-z0-9_\-]{8,}\b/g

// magpie presets a linux.do share plausibly matches — a small subset of
// `magpie presets`, used only to SUGGEST preset links (never auto-filled:
// relay shares differ from vendor endpoints). Keyed by official base URLs
// (chat URL → preset) and by relay-ish names for the topic-title path.
// https://github.com/yetone/magpie internal/provider/presets.go
const MAGPIE_PRESETS = [
  { id: 'anthropic', name: 'Anthropic', anthropic: 'https://api.anthropic.com' },
  { id: 'openai', name: 'OpenAI', chat: 'https://api.openai.com/v1' },
  {
    id: 'deepseek',
    name: 'DeepSeek',
    chat: 'https://api.deepseek.com/v1',
    alsoChat: ['https://api.deepseek.com'],
  },
  { id: 'moonshot', name: 'Kimi', chat: 'https://api.moonshot.cn/v1' },
  { id: 'xai', name: 'xAI', chat: 'https://api.x.ai/v1' },
  { id: 'mistral', name: 'Mistral', chat: 'https://api.mistral.ai/v1' },
  { id: 'groq', name: 'Groq', chat: 'https://api.groq.com/openai/v1' },
  { id: 'stepfun', name: 'StepFun', chat: 'https://api.stepfun.ai/v1' },
  { id: 'stepfun-cn', name: 'StepFun (China)', chat: 'https://api.stepfun.com/v1' },
  { id: 'zhipu', name: 'Zhipu GLM', chat: 'https://open.bigmodel.cn/api/paas/v4' },
  { id: 'zai', name: 'Z.ai', chat: 'https://api.z.ai/api/paas/v4' },
  {
    id: 'volcengine',
    name: 'Volcengine Ark',
    chat: 'https://ark.cn-beijing.volces.com/api/v3',
  },
  { id: 'openrouter', name: 'OpenRouter', chat: 'https://openrouter.ai/api/v1' },
  { id: 'siliconflow', name: 'SiliconFlow', chat: 'https://api.siliconflow.cn/v1' },
  { id: 'together', name: 'Together AI', chat: 'https://api.together.xyz/v1' },
  { id: 'fireworks', name: 'Fireworks', chat: 'https://api.fireworks.ai/inference/v1' },
  { id: 'modelscope', name: 'ModelScope', chat: 'https://api-inference.modelscope.cn/v1' },
  { id: '302ai', name: '302.AI', chat: 'https://api.302.ai/v1' },
]

/**
 * Preset ids whose link only needs the key: magpie already knows endpoints.
 * Suggested for copy only — a relay share must still use its own URLs.
 * @typedef {{ id: string, name: string, reason: string }} PresetSuggestion
 */

/**
 * Match a share's endpoint or the topic title against known magpie presets.
 * Never returns a suggestion for relay-looking hosts (a relay of DeepSeek
 * models is NOT the DeepSeek preset).
 * @param {string} topicTitle
 * @param {{ chat?: string|null, responses?: string|null, anthropic?: string|null }} endpoints
 * @param {string|null} [apiKey]
 * @returns {PresetSuggestion[]}
 */
export function suggestPresetLinks(topicTitle, endpoints, apiKey) {
  const out = []
  const seen = new Set()
  const urls = [endpoints?.chat, endpoints?.responses, endpoints?.anthropic]
    .map((u) => (u ? normalizeBareHostUrl(u) : null))
    .filter(Boolean)

  for (const preset of MAGPIE_PRESETS) {
    if (seen.has(preset.id)) continue
    const official = [preset.chat, preset.anthropic, ...(preset.alsoChat || [])]
      .map((u) => (u ? trimUrl(u) : null))
      .filter(Boolean)
    const hit = urls.some((u) => official.includes(trimUrl(u)))
    if (hit) {
      seen.add(preset.id)
      out.push({
        id: preset.id,
        name: preset.name,
        reason: 'endpoint 与官方地址一致',
      })
      continue
    }
    // Topic-title path: explicit vendor mention, no relay wording, and the
    // share actually carries a key (a preset link without a key is pointless).
    const title = String(topicTitle || '')
    const relayWording = /中转|relay|转发|代理站|公益站|镜像|转售|共享站/i.test(title)
    if (apiKey && !relayWording && vendorMentionedIn(title, preset)) {
      seen.add(preset.id)
      out.push({
        id: preset.id,
        name: preset.name,
        reason: '主题标题提到官方厂商',
      })
    }
  }
  return out
}

/** Vendor names/topics that suggest a preset without naming its id. */
const PRESET_NAME_HINTS = {
  anthropic: /\banthropic\b|\bclaude\s*(?:api|官方)/i,
  openai: /\bopenai\b|\bgpt\s*(?:api|官方)/i,
  deepseek: /\bdeepseek\b|\b深度求索\b/i,
  moonshot: /\bmoonshot\b|\bkimi\b/i,
  xai: /\bxai\b|\bgrok\s*(?:api|官方)/i,
  mistral: /\bmistral\b/i,
  groq: /\bgroq\b/i,
  stepfun: /\bstepfun\b|阶跃星辰|阶跃/i,
  'stepfun-cn': /阶跃\s*(?:国内|中国|cn)/i,
  zhipu: /\bzhipu\b|智谱|\bglm\b/i,
  zai: /\bz\.?ai\b/i,
  volcengine: /\bvolcengine\b|火山引擎|火山方舟/i,
  openrouter: /\bopenrouter\b/i,
  siliconflow: /\bsiliconflow\b|硅基流动/i,
  together: /\btogether\s*ai\b/i,
  fireworks: /\bfireworks\s*ai\b/i,
  modelscope: /\bmodelscope\b|魔搭/i,
  '302ai': /\b302\.?ai\b/i,
}

function vendorMentionedIn(title, preset) {
  const hint = PRESET_NAME_HINTS[preset.id]
  if (!hint) return false
  return hint.test(title)
}

/**
 * @typedef {{ chat: string|null, responses: string|null, anthropic: string|null }} ProtocolEndpoints
 * @typedef {{ chat: string|null, responses: string|null, anthropic: string|null }} CandidatePair
 * @typedef {'deeplink'|'base64'|'json'|'env'|'toml'|'mixed'} SourceKind
 * @typedef {{
 *   name: string,
 *   preset: string|null,
 *   region: string|null,
 *   chat: string|null,
 *   responses: string|null,
 *   anthropic: string|null,
 *   apiKey: string|null,
 *   models: string[],
 *   source: SourceKind,
 *   confidence: number,
 *   candidateCount: number,
 *   candidateIndex: number,
 *   candidates: CandidatePair[],
 *   warnings: string[],
 *   deeplink?: string|null,
 *   providerParams?: Record<string, string>|null
 * }} ParseResult
 */

/**
 * @param {string} text
 * @returns {ParseResult|null}
 */
export function parseShareText(text) {
  if (text == null) return null
  let raw = normalizeShareText(text)
  if (raw.length < MIN_SELECTION_LEN) return null
  const sampled = sampleSelection(raw)
  raw = sampled.text
  const oversized = sampled.oversized

  let cleaned = repairBrokenBase64(stripMarkdownFences(raw))

  // 1. Existing magpie import links (try every match; first valid one wins)
  const deeplinks = extractDeeplinks(cleaned)
  for (const deep of deeplinks) {
    const fromLink = parseDeeplink(deep)
    if (fromLink) {
      fromLink.deeplink = deep
      if (oversized) {
        fromLink.warnings = [...(fromLink.warnings || []), OVERSIZED_SELECTION_WARNING]
      }
      // Same cleanUrl / key normalize path as mixed/json/env results
      return finalizeResult(fromLink, cleaned)
    }
  }
  // Non-import / malformed: strip all so mixed path cannot harvest secrets from querystrings
  if (deeplinks.length) cleaned = stripAllDeeplinks(cleaned)

  // 2–6. Prefer complete (endpoint+key) results; otherwise stitch partial hits.
  // Partial JSON from Discourse linkify must not block mixed/base64 key recovery.
  const b64 = tryParseBase64(cleaned)
  const json = tryParseJson(cleaned)
  const toml = tryParseTomlLike(cleaned)
  const env = tryParseEnv(cleaned)
  const mixed = tryParseMixed(cleaned)
  const parsed = mergeParseResults([b64, json, toml, env, mixed]) || tryParseStandaloneKey(cleaned)
  const result = finalizeResult(parsed, cleaned)
  if (result && oversized) {
    result.warnings = [...(result.warnings || []), OVERSIZED_SELECTION_WARNING]
  }
  return result
}

/**
 * Prefer a result that has both endpoint+key; otherwise stitch the best fields together.
 * @param {Array<ParseResult|null|undefined>} candidates
 * @returns {ParseResult|null}
 */
function mergeParseResults(candidates) {
  const list = candidates.filter(Boolean)
  if (list.length === 0) return null

  const hasAnyEndpoint = (r) => Boolean(r.chat || r.responses || r.anthropic)
  const complete = list
    .filter((r) => hasAnyEndpoint(r) && r.apiKey)
    .sort((a, b) => (b.confidence || 0) - (a.confidence || 0))
  if (complete[0]) return complete[0]

  let best = { ...list[0] }
  for (const r of list) {
    if (!hasAnyEndpoint(best) && hasAnyEndpoint(r)) {
      best.chat = r.chat
      best.responses = r.responses
      best.anthropic = r.anthropic
    }
    if (!best.apiKey && r.apiKey) best.apiKey = r.apiKey
    // Stitch models like other fields: keep the longest non-empty list seen.
    const bestModels = Array.isArray(best.models) ? best.models : []
    const rModels = Array.isArray(r.models) ? r.models : []
    if (rModels.length > bestModels.length) best.models = rModels
    if (
      (!best.name || String(best.name).startsWith('linuxdo-')) &&
      r.name &&
      !String(r.name).startsWith('linuxdo-')
    ) {
      best.name = r.name
    }
    if ((r.candidates?.length || 0) > (best.candidates?.length || 0)) {
      best.candidates = r.candidates
      best.candidateIndex = r.candidateIndex || 0
      best.candidateCount = r.candidates.length
    }
    if ((r.confidence || 0) > (best.confidence || 0)) {
      best.source = r.source
      best.confidence = r.confidence
      best.candidateCount = Math.max(best.candidateCount || 1, r.candidateCount || 1)
      best.preset = r.preset != null ? r.preset : best.preset
    }
  }
  // Keep candidate pairs in sync with the stitched top-level fields. Partial
  // pairs (key-only / endpoint-only) must inherit the stitched fields too —
  // otherwise selectCandidate re-applies a stale pair and wipes a field merged
  // from a different parser (e.g. base64 key fragment + env base_url line).
  if (best.candidates?.length) {
    const idx = Math.max(0, Math.min(best.candidateIndex || 0, best.candidates.length - 1))
    best.candidateIndex = idx
    best.candidates = best.candidates.map((c) => ({
      chat: c.chat ?? best.chat,
      responses: c.responses ?? best.responses,
      anthropic: c.anthropic ?? best.anthropic,
      apiKey: c.apiKey ?? best.apiKey,
    }))
  }
  // Parser-generated notes (multi-candidate summary, oversized selection, prefix
  // hint) survive; field-derived warnings are recomputed on the stitched fields.
  const carried = []
  for (const r of list) {
    for (const w of r.warnings || []) {
      if (!isFieldDerivedWarning(w)) carried.push(w)
    }
  }
  best.warnings = Array.from(new Set([...carried, ...buildWarnings(best)]))
  best.confidence = scoreFields(best)
  return hasAnyEndpoint(best) || best.apiKey ? best : null
}

/**
 * Strip Discourse/selection noise that breaks key/base64 matching.
 * @param {string} text
 */
export function normalizeShareText(text) {
  return String(text)
    // ZWSP/ZWNJ/ZWJ, BOM, soft-hyphen, word-joiner
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, '')
    // nbsp / narrow nbsp / figure space
    .replace(/[\u00A0\u202F\u2007]/g, ' ')
    // smart / curly quotes \u2192 ASCII (Discourse / paste noise)
    .replace(/[\u201C\u201D\u201E\u201F\u2033\u2036]/g, '"')
    .replace(/[\u2018\u2019\u201A\u201B\u2032\u2035]/g, "'")
    .replace(/\r\n?/g, '\n')
    .trim()
}

/**
 * Merge real URLs from selected <a href> into selection text.
 * Discourse often shows link text as "base url" while the real endpoint only lives in href;
 * window.getSelection().toString() drops those hrefs.
 *
 * @param {string} text - selection.toString()
 * @param {Array<{text?: string, href?: string}>} anchors
 * @returns {string}
 */
export function enrichTextWithAnchorHrefs(text, anchors) {
  const base = text == null ? '' : String(text)
  if (!anchors || anchors.length === 0) return base

  // Cleaned forms of every URL already in the selection. Anchors whose href
  // differs only by stripped trailing punctuation are caught by the
  // existing.has(cleaned) / base.includes(cleaned) checks below.
  const existing = new Set(matchAll(base, URL_RE).map(cleanUrl))

  /** @type {Array<{label: string, href: string, preferred: boolean}>} */
  const toAdd = []
  for (const a of anchors) {
    if (!a) continue
    const href = unwrapHref(a.href)
    if (!href || !/^https?:\/\//i.test(href)) continue
    const cleaned = cleanUrl(href)
    if (!cleaned || existing.has(cleaned) || base.includes(cleaned)) {
      if (cleaned) existing.add(cleaned)
      continue
    }
    const label = String(a.text || '').trim().replace(/\s+/g, ' ')
    const preferred = isUrlLinkLabel(label)
    toAdd.push({ label, href: cleaned, preferred })
    existing.add(cleaned)
  }

  if (toAdd.length === 0) return base

  // Prefer labeled base-url anchors first
  toAdd.sort((a, b) => Number(b.preferred) - Number(a.preferred))

  let out = base
  const appended = []
  for (const item of toAdd) {
    if (item.preferred && item.label) {
      // Replace bare labels like "base url" with "base url\uFF1Ahttps://..." for labeled extract.
      // Do NOT replace inside JSON quotes \u2014 Discourse often linkifies the JSON key/value
      // "url", and rewriting `"url"` \u2192 `url\uFF1Ahttps://...` corrupts the object and drops fields.
      const labelRe = new RegExp(
        `(?<!["'\\w./])(${escapeRegExp(item.label)})(?![\\w"'])(?!\\s*[:\uFF1A=]\\s*https?:)`,
        'i',
      )
      if (labelRe.test(out)) {
        out = out.replace(labelRe, `$1\uFF1A${item.href}`)
        continue
      }
      appended.push(`${item.label}\uFF1A${item.href}`)
    } else {
      appended.push(item.href)
    }
  }
  if (appended.length) out = `${out}\n${appended.join('\n')}`
  return out
}

/** Visible link labels that usually stand for the API base URL on linux.do shares. */
function isUrlLinkLabel(label) {
  if (!label) return false
  const s = label.trim()
  if (
    /^(?:url|base\s*url|base[_-]?url|endpoint|api\s*base|api[_-]?base|host|\u5730\u5740|\u63A5\u53E3|\u94FE\u63A5)(?:\b|[\uFF08(]|\d|$)/i.test(
      s,
    )
  ) {
    return true
  }
  // "base url 2", "Base URL", etc.
  if (/base\s*url|endpoint|base[_-]?url/i.test(s) && s.length <= 40) return true
  return false
}

/**
 * Normalize anchor href: keep http(s), unwrap common click-trackers / nested URLs.
 * @param {string|null|undefined} href
 * @returns {string|null}
 */
function unwrapHref(href) {
  if (!href) return null
  let h = String(href).trim()
  if (!h) return null
  // ignore non-navigational schemes
  if (/^(javascript|mailto|tel|data|#):/i.test(h)) return null
  // nested https inside tracking / redirect URLs
  try {
    const m = h.match(/https?:\/\/[^\s"'<>]+/i)
    if (m) {
      // if the whole thing is already http(s), prefer parsing query redirects
      if (/^https?:\/\//i.test(h)) {
        try {
          const u = new URL(h)
          for (const key of ['url', 'u', 'target', 'redirect', 'to', 'link', 'dest']) {
            const v = u.searchParams.get(key)
            if (v && /^https?:\/\//i.test(v)) return cleanUrl(v)
          }
        } catch {
          /* keep */
        }
        return cleanUrl(h)
      }
      return cleanUrl(m[0])
    }
  } catch {
    /* keep */
  }
  return null
}

/**
 * Re-join base64 tokens broken by spaces/newlines if the join decodes to a key.
 * @param {string} text
 */
export function repairBrokenBase64(text) {
  // spaces inside an otherwise base64-ish run
  let out = text.replace(
    /(?:^|[\s"'`])((?:[A-Za-z0-9+/_-]{6,}={0,2}[\s\u00AD]+){1,}[A-Za-z0-9+/_-]{6,}={0,2})(?=$|[\s"'`])/gm,
    (full, group) => {
      const prefix = full.slice(0, full.length - group.length)
      const joined = group.replace(/[\s\u00AD]+/g, '')
      if (joined.length < 24) return full
      try {
        const d = base64Decode(joined).trim()
        if (KEY_PREFIX_RE.test(d) && !/\s/.test(d) && d.length >= 8) {
          return prefix + joined
        }
      } catch {
        /* keep */
      }
      return full
    },
  )
  // adjacent pure-base64 lines
  out = out.replace(
    /(^|\n)([A-Za-z0-9+/_-]{12,}={0,2})\n([A-Za-z0-9+/_-]{12,}={0,2})(?=\n|$)/gm,
    (full, lead, a, b) => {
      const joined = a + b
      try {
        const d = base64Decode(joined).trim()
        if (KEY_PREFIX_RE.test(d) && !/\s/.test(d)) return `${lead}${joined}`
      } catch {
        /* keep */
      }
      return full
    },
  )
  return out
}

/**
 * Single exit for apiKey: decode body (b64/hex/watermark) + optional vendor prefix from prose.
 * Intermediate parsers should pass raw tokens; finalize always runs this once.
 * @param {string|null|undefined} raw
 * @param {string} [shareText]
 * @returns {string|null|undefined}
 */
function normalizeApiKey(raw, shareText = '') {
  if (raw == null || raw === '') return raw
  let decoded = decodeKeyBody(raw)
  // Last-resort unwrap: a decoded body that is still a labeled fragment
  // (field=value / "field": "value") must never be imported verbatim as the key.
  if (decoded && !hasKeyPrefix(decoded) && !lookLikeKeyValue(decoded)) {
    const unwrapped = extractKeyFromWrapper(decoded)
    if (unwrapped) decoded = unwrapped
  }
  return applyKeyPrefixHints(decoded, shareText)
}

/** Final pass: normalize keys/endpoints once, clamp confidence. */
function finalizeResult(result, text = '') {
  if (!result) return null

  const beforeKey = result.apiKey
  const fixKey = (k) => (k ? normalizeApiKey(k, text) : k)

  if (result.apiKey) result.apiKey = fixKey(result.apiKey)
  for (const proto of ['chat', 'responses', 'anthropic']) {
    if (result[proto]) {
      result[proto] = cleanUrl(normalizeShareText(result[proto]))
      if (result[proto] && !/^https?:\/\//i.test(result[proto])) result[proto] = null
    }
  }

  if (result.candidates?.length) {
    result.candidates = result.candidates.map((c) => ({
      chat: c.chat ? cleanUrl(normalizeShareText(c.chat)) : c.chat,
      responses: c.responses ? cleanUrl(normalizeShareText(c.responses)) : c.responses,
      anthropic: c.anthropic ? cleanUrl(normalizeShareText(c.anthropic)) : c.anthropic,
      apiKey: fixKey(c.apiKey),
    }))
    const i = Math.max(0, Math.min(result.candidateIndex || 0, result.candidates.length - 1))
    result.candidateIndex = i
    result.apiKey = result.candidates[i].apiKey
    result.chat = result.candidates[i].chat ?? null
    result.responses = result.candidates[i].responses ?? null
    result.anthropic = result.candidates[i].anthropic ?? null
  }

  if (result.apiKey && beforeKey) {
    const bodyOnly = decodeKeyBody(beforeKey)
    if (hasKeyPrefix(result.apiKey) && bodyOnly && !hasKeyPrefix(bodyOnly) && result.apiKey !== bodyOnly) {
      const prefix = (result.apiKey.match(KEY_PREFIX_RE) || [])[1] || 'sk-'
      const note = `已根据文案补上 ${prefix} 前缀`
      if (!result.warnings) result.warnings = []
      if (!result.warnings.includes(note)) result.warnings.push(note)
    }
  }

  if (typeof result.confidence === 'number') {
    result.confidence = Math.min(1, Math.max(0, result.confidence))
  }
  result.warnings = Array.from(
    new Set([...(result.warnings || []), ...buildWarnings(result)]),
  )
  return result
}

/** @returns {'sk-ant-'|'sk-'|'g2a_'|null} */
function detectKeyPrefixHint(text) {
  const t = String(text || '')
  if (!t) return null
  if (
    /sk-ant-[\s_-]*前缀|前缀[\s\S]{0,10}sk-ant-|prefix[\s:：=]*sk-ant-|(?:加|补|带|加上|补上)[\s\S]{0,8}sk-ant-/i.test(
      t,
    )
  ) {
    return 'sk-ant-'
  }
  if (/g2a_[\s_-]*前缀|前缀[\s\S]{0,10}g2a_|prefix[\s:：=]*g2a_/i.test(t)) return 'g2a_'
  if (
    /(?:别忘了|记得|需要|请|务必|别漏)[\s\S]{0,20}sk-[\s_-]*前缀|sk-[\s_-]*前缀|前缀[\s\S]{0,10}sk-(?!ant)|prefix[\s:：=]*sk-(?!ant)|(?:加|补|带|加上|补上)[\s\S]{0,6}sk-(?!ant)/i.test(
      t,
    )
  ) {
    return 'sk-'
  }
  return null
}

function applyKeyPrefixHints(key, text) {
  if (!key) return key
  let k = String(key).trim()
  if (!k) return k
  if (KEY_PREFIX_BODY_RE.test(k)) {
    return sanitizeApiKey(k.replace(/^Bearer\s*/i, ''))
  }
  const prefix = detectKeyPrefixHint(text)
  if (!prefix) return k
  if (k.length < 8 || k.length > 512) return k
  if (!/^[A-Za-z0-9_+\-./]+$/.test(k) || /^https?:\/\//i.test(k)) return k
  return prefix + k
}

/**
 * @param {string} text
 */
export function looksLikeConfig(text) {
  if (!text || text.trim().length < MIN_SELECTION_LEN) return false
  const sampled = sampleSelection(normalizeShareText(text))
  let t = repairBrokenBase64(sampled.text)
  // Import deeplink → yes. Non-import magpie link → strip and keep scanning for
  // ordinary endpoint/key shares that may follow (do not hard-return false).
  const deeplinks = extractDeeplinks(t)
  if (deeplinks.some((d) => Boolean(parseDeeplink(d)))) return true
  if (deeplinks.length) t = stripAllDeeplinks(t)
  if (/ANTHROPIC_|OPENAI_|CODEX_|BASE_URL|API_KEY|apiKey|baseUrl|endpoint|Base\s*URL/i.test(t))
    return true
  if (/sk-ant-|sk-[A-Za-z0-9]{16,}/.test(t)) return true
  // Vendor keys (g2a_ Grok2API, tp- token-plan, …) alone are enough to light the button
  if (hasVendorKey(t)) return true
  if (/https?:\/\//i.test(t) && /sk-|Bearer\s+/i.test(t)) return true
  // bare host (no scheme) + any known key shape — Discourse onebox paste
  if (hasBareHost(t) && (/sk-|Bearer\s+/i.test(t) || hasVendorKey(t))) return true
  // labeled shares: url： / key： / 密钥： / API Key（...）
  if (
    /(?:url|base[_-]?url|base\s*url|endpoint|key|api[_-]?key|api\s*key|token|密钥|地址|接口)/i.test(
      t,
    )
  ) {
    if (/https?:\/\//i.test(t) || hasBareHost(t)) return true
    // Bare-token fallback: require a key-shaped token (lookLikeKeyValue), not any
    // 16+ alnum run — plain chat ("我没token用了" + emoji短码 like
    // ":backhand_index_pointing_left:") must not light the button.
    if (hasKeyShapedToken(t)) return true
  }
  // url + base64-ish token (key often base64-encoded on linux.do)
  if (/https?:\/\//i.test(t) && /[A-Za-z0-9+/]{32,}={0,2}/.test(t)) return true
  // standalone base64 only if it decodes to a key or config-shaped text (avoid AAAA… noise)
  if (hasUsefulBase64Blob(t)) return true
  // A deliberately selected single token may be a prefix-less relay key.
  if (standaloneKeyCandidate(t)) return true
  if (
    t.includes('{') &&
    t.includes('}') &&
    /"(?:apiKey|api_key|baseUrl|endpoint|base_url)"\s*:/.test(t)
  ) {
    return true
  }
  // Oversized selections stay actionable even when the only configuration is
  // in the omitted middle. The confirmation flow can then explain that the
  // user must select a smaller block instead of silently hiding the trigger.
  if (sampled.oversized) return true
  return false
}

/** Accept a single selected token as a low-confidence key candidate. */
function tryParseStandaloneKey(text) {
  const apiKey = standaloneKeyCandidate(text)
  if (!apiKey) return null
  return emptyResult({
    apiKey,
    confidence: scoreFields({ apiKey }),
    candidates: [{ chat: null, responses: null, anthropic: null, apiKey }],
    warnings: ['仅根据单独选中的字符串识别为可能的 Key，请核对'],
  })
}

function standaloneKeyCandidate(text) {
  const token = String(text || '').trim()
  if (token.length < 32 || token.length > 512 || /\s/.test(token)) return null
  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(token)) return null

  // Treat canonical base64 as encoded content first. Encoded prose must not
  // become a key merely because the encoded bytes look random.
  if (token.length >= 40 && token.length % 4 !== 1) {
    try {
      const decoded = base64Decode(token)
      const normalized = token.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')
      if (base64Encode(decoded).replace(/=+$/, '') === normalized) {
        if (hasKeyPrefix(decoded) || looksLikeStandaloneKeyBody(decoded)) return decoded
        return null
      }
    } catch {
      /* not text base64 */
    }
  }
  return looksLikeStandaloneKeyBody(token) ? token : null
}

function looksLikeStandaloneKeyBody(value) {
  const s = String(value || '')
  if (s.length < 32 || s.length > 256 || !/^[A-Za-z0-9_-]+$/.test(s)) return false
  if (/^[0-9a-f-]+$/i.test(s) || /(?:your|please|example|xxxx|todo|changeme)/i.test(s)) return false
  if (new Set(s).size < 8) return false
  return /[A-Za-z]/.test(s) && /\d/.test(s)
}

/**
 * True when text contains a plausible bare hostname (no scheme).
 * @param {string} text
 */
function hasBareHost(text) {
  BARE_HOST_RE.lastIndex = 0
  return BARE_HOST_RE.test(text)
}

/**
 * True when text contains a known vendor-prefixed key (g2a_/tp-/ark-/…).
 * Resets the shared /g regex lastIndex before testing — looksLikeConfig can be
 * called repeatedly on different selections, and a stray lastIndex from a prior
 * early-return would otherwise make the same token toggle true/false.
 * @param {string} text
 */
function hasVendorKey(text) {
  VENDOR_KEY_RE.lastIndex = 0
  return VENDOR_KEY_RE.test(text)
}

/**
 * True when some 16+ alnum token in text is key-shaped (lookLikeKeyValue),
 * so labeled shares with a real-looking key light the button but plain chat
 * with a stray long word / emoji shortcode does not.
 * @param {string} text
 */
function hasKeyShapedToken(text) {
  const re = /[A-Za-z0-9_+\-/]{16,}={0,2}/g
  let m
  while ((m = re.exec(text)) !== null) {
    if (lookLikeKeyValue(m[0])) return true
  }
  return false
}

/**
 * True when a URL points at the linux.do forum itself. Topic/post links are
 * never provider endpoints — recovering them as one produces a garbage
 * deeplink with no warning, so they are filtered at collection time.
 * @param {string} u
 */
function isForumEndpoint(u) {
  try {
    const host = new URL(String(u || '')).hostname.toLowerCase()
    return host === 'linux.do' || host.endsWith('.linux.do')
  } catch {
    return false
  }
}

/**
 * Classify a share URL into magpie's protocol base URLs.
 * chat/responses bases end in /v1 (OpenAI style); anthropic is the root.
 * A root-ish URL gets BOTH chat (as typed) and anthropic (root) so magpie
 * can serve whichever protocol the relay actually speaks.
 * @param {string} url
 * @returns {ProtocolEndpoints}
 */
export function classifyEndpointProtocol(url) {
  const empty = { chat: null, responses: null, anthropic: null }
  let u
  try {
    u = new URL(String(url || '').trim())
  } catch {
    return empty
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return empty
  if (isForumEndpoint(u.toString())) return empty

  const path = (u.pathname || '/').replace(/\/+$/, '')

  // Volcengine Ark: /api/coding is the Anthropic root, /api/coding/v3 the
  // OpenAI-style base — same host, distinguished by path only.
  if (/volces\.com/i.test(u.hostname)) {
    if (/\/api\/coding\/v3$/i.test(path)) {
      return { chat: u.toString(), responses: null, anthropic: rootOf(u) }
    }
    if (/\/api\/(?:coding|plan)(?:\/anthropic)?$/i.test(path)) {
      return { chat: null, responses: null, anthropic: stripTrailingSlash(u.toString()) }
    }
  }

  // Anthropic-style path segment → anthropic base. magpie appends
  // /v1/messages itself, so a relay path like /anthropic/v1 must strip the
  // trailing /v1: anthropic base = the part before it.
  if (/\/anthropic(\/v\d+[a-z0-9]*)?$/i.test(path)) {
    const anthropic = stripTrailingSlash(u.toString()).replace(/\/v\d+[a-z0-9]*$/i, '')
    return { chat: null, responses: null, anthropic }
  }

  // OpenAI-style base: path ends in /v1 (or /v2, /v3, /v1beta/openai…)
  if (/\/v\d+[a-z0-9]*(?:\/openai)?$/i.test(path) || /\/v\d+$/i.test(path)) {
    return { chat: u.toString(), responses: null, anthropic: null }
  }

  // Root-ish URL (no meaningful path): a relay usually speaks both.
  if (path === '' || path === '/') {
    const base = stripTrailingSlash(u.toString())
    return { chat: base, responses: null, anthropic: base }
  }
  // Unknown path shape: keep it as chat base verbatim; user can adjust in magpie.
  return { chat: stripTrailingSlash(u.toString()), responses: null, anthropic: null }
}

/** Root of a URL: scheme + host (+port), no path. */
function rootOf(u) {
  return `${u.protocol}//${u.host}`
}

function stripTrailingSlash(s) {
  return String(s).replace(/\/+$/, '')
}

/** Comparison form of a URL for preset matching: lowercase, no trailing slash. */
function trimUrl(u) {
  return stripTrailingSlash(String(u || '').trim().toLowerCase())
}

/** Ensure an endpoint has a scheme (bare onebox hosts → https). */
function normalizeBareHostUrl(u) {
  const s = String(u || '').trim()
  if (!s) return null
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return s
  if (/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}/i.test(s)) return `https://${s}`
  return null
}

/**
 * Collect http(s) URLs plus bare hosts normalized to https://.
 * Skips hosts already covered by a full URL match, and forum self-links.
 * @param {string} text
 * @returns {string[]}
 */
function collectEndpoints(text) {
  const full = matchAll(text, URL_RE)
    .map(cleanUrl)
    .filter((u) => isHttpUrl(u) && !isForumEndpoint(u))
  const bare = matchAll(text, BARE_HOST_RE)
    .map((h) => normalizeBareHost(h))
    .filter(Boolean)
  // Drop bare hosts already present as full URLs (or as their host part)
  const covered = new Set()
  for (const u of full) {
    covered.add(u.toLowerCase())
    try {
      covered.add(new URL(u).host.toLowerCase())
    } catch {
      /* ignore */
    }
  }
  const bareUrls = []
  for (const h of bare) {
    const hostOnly = h.replace(/^https?:\/\//i, '').split('/')[0].toLowerCase()
    if (covered.has(h.toLowerCase()) || covered.has(hostOnly)) continue
    // Skip if this "host" is actually inside an already-matched full URL string
    if (full.some((u) => u.toLowerCase().includes(hostOnly))) continue
    if (isForumEndpoint(h)) continue
    bareUrls.push(h)
    covered.add(hostOnly)
  }
  return unique([...full, ...bareUrls])
}

/**
 * @param {string} host
 * @returns {string|null}
 */
function normalizeBareHost(host) {
  let h = cleanUrl(String(host || ''))
  if (!h) return null
  // Reject if it already has a scheme (URL_RE handles those)
  if (/^[a-z][a-z0-9+.-]*:/i.test(h)) return null
  // Reject email-like leftovers
  if (h.includes('@')) return null
  // Must look like host.tld[/path]
  if (!/^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(?:\/\S*)?$/i.test(h)) return null
  return `https://${h}`
}

/**
 * True when a base64-ish token decodes to an API key or config-like payload.
 * Prevents long random A-Z runs from lighting the import button.
 * @param {string} text
 */
function hasUsefulBase64Blob(text) {
  const hasEndpoint = /https?:\/\//i.test(text)
  const hasDecodeHint = /(?:base\s*64|64\s*解|解密|解码|加密|自行\s*解)/i.test(text)
  const re = new RegExp(`${B64_BOUNDARY_L}([A-Za-z0-9+/]{40,}={0,2})${B64_BOUNDARY_R}`, 'g')
  let m
  while ((m = re.exec(text)) !== null) {
    const token = m[1]
    if (token.startsWith('sk-') || token.startsWith('http')) continue
    try {
      const decoded = base64Decode(token).trim()
      if (!decoded || decoded.length < 8) continue
      const ascii = decoded.replace(/[^\x20-\x7E]/g, '').replace(/\s+/g, '')
      if (KEY_PREFIX_RE.test(ascii) && ascii.length >= 8 && ascii.length <= 512) {
        return true
      }
      // Prefix-less vendor token (StepFun/Mistral) under endpoint+decode-hint context
      if (
        hasEndpoint &&
        hasDecodeHint &&
        ascii.length >= 24 &&
        ascii.length <= 512 &&
        /^[A-Za-z0-9_+-]+$/.test(ascii)
      ) {
        return true
      }
      if (
        /[{=\n:]/.test(decoded) &&
        (/https?:\/\//.test(decoded) || /API|KEY|BASE|endpoint|baseUrl/i.test(decoded))
      ) {
        return true
      }
    } catch {
      /* ignore */
    }
  }
  return false
}

/** Conservative cap for custom-protocol URLs (Windows / browsers / desktop apps). */
export const MAX_DEEPLINK_LEN = 8000

/**
 * magpie import deeplink. magpie parses this itself (provider.ParseImport):
 * base URLs go in per protocol (chat/responses end in /v1, anthropic is the
 * root), models is a comma list, and a preset can replace the URLs entirely.
 *
 * @param {ParseResult} result
 * @param {{ includeRiskyParams?: boolean }} [options]
 * @returns {string}
 */
export function buildDeeplink(result, options) {
  if (!result) throw new Error('no parse result')

  const preset = result.preset || null
  const params = new URLSearchParams()
  if (preset) {
    params.set('preset', preset)
  } else {
    params.set('name', result.name || defaultName())
    let urlCount = 0
    for (const proto of ['chat', 'responses', 'anthropic']) {
      const value = result[proto]
      if (!value) continue
      const policy = inspectEndpoint(value)
      if (!policy.valid) {
        throw new Error(`${proto} 地址已阻止：${policy.error}`)
      }
      params.set(proto, value)
      urlCount++
    }
    if (urlCount === 0) {
      throw new Error('缺少 base URL：请提供 chat / responses / anthropic 至少一个')
    }
  }

  if (result.apiKey) {
    if (result.apiKey.length > 4096 || /[\x00-\x1f\x7f]/.test(result.apiKey)) {
      throw new Error('apiKey 形态异常（过长或含控制字符），magpie 会拒绝此深链')
    }
    params.set('key', result.apiKey)
  }

  if (result.providerParams && typeof result.providerParams === 'object') {
    for (const [name, value] of Object.entries(result.providerParams)) {
      if (
        value != null &&
        (SAFE_PROVIDER_PARAM_NAMES.has(name) || options?.includeRiskyParams === true)
      ) {
        params.set(name, String(value))
      }
    }
  }

  const models = (result.models || []).filter(Boolean).slice(0, MAX_DEEPLINK_MODELS)
  if (models.length) params.set('models', models.join(','))

  const deeplink = `magpie://import?${params.toString()}`
  if (deeplink.length > MAX_DEEPLINK_LEN) {
    const error = new Error(
      `深链过长（${deeplink.length} 字符，安全上限 ${MAX_DEEPLINK_LEN}）；请缩短字段或减少模型`,
    )
    error.code = 'DEEPLINK_TOO_LONG'
    error.length = deeplink.length
    throw error
  }
  return deeplink
}

/**
 * Disclose optional import-link parameter names without exposing values.
 * Safe metadata (catalog/region/id) is retained automatically; website/keys/icon
 * and unknown parameters require an explicit inclusion choice at the UI boundary.
 * @param {Record<string, unknown>|null|undefined} providerParams
 */
export function describeProviderParams(providerParams) {
  if (!providerParams || typeof providerParams !== 'object') return null
  const fields = Object.keys(providerParams)
  const safeFields = fields.filter((name) => SAFE_PROVIDER_PARAM_NAMES.has(name))
  const riskyFields = fields.filter((name) => RISKY_PROVIDER_PARAM_NAMES.has(name))
  const unknownFields = fields.filter(
    (name) =>
      !SAFE_PROVIDER_PARAM_NAMES.has(name) && !RISKY_PROVIDER_PARAM_NAMES.has(name),
  )
  const riskReasons = []
  if (riskyFields.length) riskReasons.push(`高风险深链参数：${riskyFields.join('、')}`)
  if (unknownFields.length) riskReasons.push(`未知深链参数：${unknownFields.join('、')}`)
  return {
    fields,
    safeFields,
    riskyFields,
    unknownFields,
    risky: riskReasons.length > 0,
    riskReasons,
  }
}

/**
 * @param {string} key
 * @returns {string}
 */
export function maskKey(key) {
  if (!key) return ''
  if (key.length <= 12) return '*'.repeat(Math.min(key.length, 8))
  return `${key.slice(0, 8)}****${key.slice(-4)}`
}

/**
 * Switch result to another endpoint/apiKey candidate pair (from mixed multi-match).
 * @param {ParseResult} result
 * @param {number} index
 * @returns {ParseResult}
 */
export function selectCandidate(result, index) {
  if (!result) return result
  const list = result.candidates
  if (!list || list.length === 0) return result
  const i = Math.max(0, Math.min(Number(index) || 0, list.length - 1))
  const pair = list[i]
  const next = {
    ...result,
    chat: pair.chat ?? null,
    responses: pair.responses ?? null,
    anthropic: pair.anthropic ?? null,
    apiKey: pair.apiKey,
    candidateIndex: i,
    candidateCount: list.length,
  }
  // Parser-generated notes (multi-candidate summary, oversized selection, prefix
  // hint) carry over; field-derived warnings are recomputed for the new pair.
  const carried = (result.warnings || []).filter((w) => !isFieldDerivedWarning(w))
  next.warnings = Array.from(new Set([...carried, ...buildWarnings(next)]))
  next.confidence = scoreFields(next)
  if (typeof next.confidence === 'number') {
    next.confidence = Math.min(1, Math.max(0, next.confidence))
  }
  return next
}

// ─── internals ───────────────────────────────────────────────

function defaultName() {
  const d = new Date()
  const pad = (n) => String(n).padStart(2, '0')
  return `linuxdo-${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}`
}

function stripMarkdownFences(text) {
  return text
    .replace(/^```[a-zA-Z0-9]*\s*\n?/gm, '')
    .replace(/```$/gm, '')
    .trim()
}

function emptyResult(partial) {
  return {
    name: defaultName(),
    preset: null,
    region: null,
    chat: null,
    responses: null,
    anthropic: null,
    apiKey: null,
    models: [],
    source: 'mixed',
    confidence: 0,
    candidateCount: 1,
    candidateIndex: 0,
    candidates: [],
    warnings: [],
    deeplink: null,
    providerParams: null,
    ...partial,
  }
}

/**
 * @param {string} text
 * @returns {string[]}
 */
function extractDeeplinks(text) {
  if (!text) return []
  const re = new RegExp(DEEPLINK_RE.source, 'gi')
  const out = []
  let m
  while ((m = re.exec(text)) !== null) {
    if (m[0]) out.push(m[0])
  }
  return out
}

/**
 * Remove every magpie: deeplink token so subsequent parsers cannot
 * harvest secrets from non-import query strings.
 * @param {string} text
 */
function stripAllDeeplinks(text) {
  return String(text || '').replace(new RegExp(DEEPLINK_RE.source, 'gi'), ' ')
}

/**
 * @param {string} link
 * @returns {ParseResult|null}
 */
function parseDeeplink(link) {
  try {
    // Only import links. Manual parse: URL() may not like custom schemes.
    const raw = String(link || '').trim()
    if (!/^magpie:/i.test(raw)) return null
    // Accept magpie://import?... / magpie:import?... / magpie:///import?...
    const pathPart = raw.replace(/^magpie:\/\//i, '').replace(/^magpie:/i, '')
    const qIndex = pathPart.indexOf('?')
    if (qIndex < 0) return null
    const path = pathPart.slice(0, qIndex).replace(/^\/+/, '').replace(/\/+$/, '')
    if (!/^import$/i.test(path)) return null
    const qs = pathPart.slice(qIndex + 1)
    const params = new URLSearchParams(qs)
    const preset = params.get('preset') || null
    const name = params.get('name') || (preset ? preset : defaultName())
    const apiKey = params.get('key') || null
    const chat = params.get('chat') || null
    const responses = params.get('responses') || null
    const anthropic = params.get('anthropic') || null
    const models = (params.get('models') || '')
      .split(',')
      .map((m) => m.trim())
      .filter(Boolean)
    const providerParams = Object.create(null)
    for (const [paramName, value] of params) {
      if (!CONSUMED_PROVIDER_PARAM_NAMES.has(paramName)) {
        providerParams[paramName] = value
      }
    }
    const confidence = preset || chat || responses || anthropic || apiKey ? 0.95 : 0.5
    if (!preset && !chat && !responses && !anthropic && !apiKey) return null
    return emptyResult({
      name,
      preset,
      region: params.get('region') || null,
      chat,
      responses,
      anthropic,
      apiKey,
      models,
      providerParams: Object.keys(providerParams).length ? providerParams : null,
      source: 'deeplink',
      confidence,
    })
  } catch {
    return null
  }
}

function tryParseBase64(text) {
  BASE64_RE.lastIndex = 0
  let best = null
  let m
  while ((m = BASE64_RE.exec(text)) !== null) {
    const token = m[1]
    if (token.length < 40) continue
    // skip if looks like a normal url fragment or key
    if (token.startsWith('sk-')) continue
    let decoded
    try {
      decoded = base64Decode(token)
    } catch {
      continue
    }
    if (!decoded || decoded.length < 10) continue
    // must look like text config
    if (!/[{=\n:]/.test(decoded) && !/https?:\/\//.test(decoded) && !/API|KEY|BASE/i.test(decoded)) {
      continue
    }
    // parse decoded without re-running base64 on itself forever
    const inner =
      tryParseJson(decoded) ||
      tryParseTomlLike(decoded) ||
      tryParseEnv(decoded) ||
      tryParseMixed(decoded)
    if (inner && (hasAnyProtocol(inner) || inner.apiKey)) {
      inner.source = 'base64'
      inner.confidence = Math.min(1, (inner.confidence || 0.6) + 0.1)
      if (!best || inner.confidence > best.confidence) best = inner
    }
  }
  return best
}

function tryParseJson(text) {
  const objects = extractJsonObjects(text)
  let best = null
  for (const objStr of objects) {
    let obj
    try {
      obj = JSON.parse(objStr)
    } catch {
      continue
    }
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) continue
    const fields = pickProviderFields(obj)
    if (!fields.endpoint && !fields.apiKey) continue
    // Discourse may turn "url" value into bare link text "url" — recover real https from surrounding text
    if (!fields.endpoint) {
      const urls = unique(matchAll(text, URL_RE).map(cleanUrl)).filter((u) => isHttpUrl(u))
      const recovered = pickBestUrl(urls, text)
      if (recovered) fields.endpoint = recovered
    }
    const protocols = classifyEndpointProtocol(fields.endpoint || '')
    const r = emptyResult({
      name: fields.name || defaultName(),
      ...protocols,
      apiKey: fields.apiKey,
      models: fields.models || [],
      source: 'json',
      confidence: scoreFields({ ...fields, ...protocols }),
      warnings: buildWarnings({ ...fields, ...protocols }),
    })
    if (!best || r.confidence > best.confidence) best = r
  }

  // Broken / partial JSON (smart quotes, missing braces): still pull "key"/"url" string fields
  if (!best || (!best.apiKey && !hasAnyProtocol(best))) {
    const loose = extractJsonishFields(text)
    if (loose.hit && (loose.endpoint || loose.apiKey)) {
      const fields = {
        name: loose.name || defaultName(),
        endpoint: loose.endpoint,
        apiKey: loose.apiKey,
      }
      const protocols = classifyEndpointProtocol(fields.endpoint || '')
      const r = emptyResult({
        name: fields.name,
        ...protocols,
        apiKey: fields.apiKey,
        source: 'json',
        confidence: scoreFields({ ...fields, ...protocols }) * 0.95,
        warnings: buildWarnings({ ...fields, ...protocols }),
      })
      if (!best || r.confidence > best.confidence) best = r
    }
  }
  return best
}

/** True when a parse result carries at least one protocol base URL. */
function hasAnyProtocol(result) {
  return Boolean(result && (result.chat || result.responses || result.anthropic))
}

/**
 * Regex fallback for provider-like JSON when JSON.parse fails (newapi_channel_conn shares, etc.).
 * Only fires when quoted JSON field names are present — never steal plain env/mixed shares.
 * Tolerates newlines after `:` and unquoted http(s) url values (Discourse linkify).
 * @param {string} text
 */
function extractJsonishFields(text) {
  const result = { endpoint: null, apiKey: null, name: null, hit: false }

  // Must look like JSON-ish (brace + quoted key) before we try loose extraction
  if (
    !text.includes('{') ||
    !/["'](?:key|apiKey|api_key|url|baseUrl|base_url|endpoint)["']\s*:/i.test(text)
  ) {
    return result
  }

  // "url": "https://..." OR "url":\nhttps://... (unquoted after Discourse linkify)
  const urlField = text.match(
    /["'](?:url|baseUrl|base_url|endpoint|api_base)["']\s*:\s*(?:["'](https?:\/\/[^"']+)["']|(https?:\/\/[^\s"'`<>，。；、}\]]+))/i,
  )
  if (urlField) {
    result.endpoint = cleanUrl(urlField[1] || urlField[2])
    result.hit = true
  }

  // "key": "c2st..." allowing newline between colon and value
  const keyField = text.match(
    /["'](?:key|apiKey|api_key|token|secret|auth_token)["']\s*:\s*["']?\s*([A-Za-z0-9+/_-]{16,}={0,2})["']?/i,
  )
  if (keyField) {
    result.apiKey = maybeDecodeKey(keyField[1])
    result.hit = true
  }

  const nameField = text.match(/["'](?:name|title|provider|_type|type)["']\s*:\s*["']([^"']+)["']/i)
  if (nameField) result.name = nameField[1]

  // Only recover free-floating https when we already hit a JSON key field
  // (Discourse may have turned the url value into bare link text "url")
  if (result.hit && !result.endpoint) {
    const urls = unique(matchAll(text, URL_RE).map(cleanUrl)).filter((u) => isHttpUrl(u))
    result.endpoint = pickBestUrl(urls, text)
  }
  return result
}

function extractJsonObjects(text) {
  const limit = Math.min(text.length, MAX_SELECTION_LEN)
  const stack = []
  const pairs = []
  let inStr = false
  let esc = false

  for (let i = 0; i < limit; i++) {
    const c = text[i]
    if (inStr) {
      if (esc) {
        esc = false
      } else if (c === '\\') {
        esc = true
      } else if (c === '"') {
        inStr = false
      } else if (c === '\n' || c === '\r') {
        // Raw line breaks are invalid inside JSON strings. Recover here so an
        // earlier malformed fragment cannot hide a later valid object.
        inStr = false
      }
      continue
    }

    if (c === '"' && stack.length > 0) {
      inStr = true
      continue
    }
    if (c === '{') {
      stack.push(i)
    } else if (c === '}' && stack.length > 0) {
      const start = stack.pop()
      if (i - start + 1 <= MAX_DECODED_LEN) {
        pairs.push({ start, end: i + 1 })
      }
    }
  }

  // Closing order lists nested pairs before their enclosing pair. Walking it
  // backwards therefore sees each maximal pair first; one interval comparison
  // removes its nested pairs without a sort or suffix rescan.
  const maximalReversed = []
  let currentOuter = null
  for (let i = pairs.length - 1; i >= 0; i--) {
    const pair = pairs[i]
    if (!currentOuter || pair.end <= currentOuter.start) {
      maximalReversed.push(pair)
      currentOuter = pair
    }
  }
  return maximalReversed
    .reverse()
    .slice(0, MAX_JSON_OBJECTS)
    .map((pair) => text.slice(pair.start, pair.end))
}

function stripStructuredEnvNames(s) {
  return String(s || '').replace(/\b(?:ANTHROPIC|CLAUDE|OPENAI|CODEX)_[A-Z0-9_]+\b/gi, ' ')
}

function sampleSelection(text) {
  const raw = String(text || '')
  if (raw.length <= MAX_SELECTION_LEN) return { text: raw, oversized: false }

  const contentBudget = MAX_SELECTION_LEN - SELECTION_OMISSION_MARKER.length
  const headLength = Math.ceil(contentBudget / 2)
  const tailLength = contentBudget - headLength
  return {
    text:
      raw.slice(0, headLength) +
      SELECTION_OMISSION_MARKER +
      raw.slice(raw.length - tailLength),
    oversized: true,
  }
}

function isHttpUrl(value) {
  return typeof value === 'string' && /^https?:\/\//i.test(value.trim())
}

function inspectEndpoint(value) {
  if (value == null || String(value).trim() === '') {
    return { valid: true, warning: null, error: null }
  }
  let url
  try {
    url = new URL(String(value).trim())
  } catch {
    return { valid: false, warning: null, error: '不是有效 URL' }
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { valid: false, warning: null, error: '仅支持 HTTP(S) 协议' }
  }
  if (!url.hostname) {
    return { valid: false, warning: null, error: 'URL 缺少主机名' }
  }
  if (url.username || url.password) {
    return { valid: false, warning: null, error: 'URL 不得包含用户名或密码凭据' }
  }
  if (url.search || url.hash) {
    return { valid: false, warning: null, error: 'base URL 不得携带 query 或 fragment' }
  }
  // magpie refuses plain http outside this machine / the local network outright,
  // so block it here instead of shipping a link the app will reject.
  if (url.protocol === 'http:' && !isLocalNetworkHostname(url.hostname)) {
    return {
      valid: false,
      warning: null,
      error: '非本机 HTTP 地址：magpie 仅接受 https（或本机/局域网 http）',
    }
  }
  return { valid: true, warning: null, error: null }
}

function isLoopbackHostname(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
  if (host === 'localhost' || host.endsWith('.localhost')) return true
  if (host === '::1' || host === '0:0:0:0:0:0:0:1') return true
  return /^127(?:\.\d{1,3}){0,3}$/.test(host)
}

/** http is acceptable to this machine, the loopback, private ranges and *.local. */
function isLocalNetworkHostname(hostname) {
  const host = String(hostname || '')
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .replace(/\.$/, '')
  if (isLoopbackHostname(host)) return true
  if (host.endsWith('.local')) return true
  // IPv4 private ranges: 10.x / 192.168.x / 172.16–31.x
  if (/^10\.\d{1,3}(\.\d{1,3}){0,2}$/.test(host)) return true
  if (/^192\.168\.\d{1,3}(\.\d{1,3})?$/.test(host)) return true
  if (/^172\.(1[6-9]|2\d|3[01])\.\d{1,3}(\.\d{1,3})?$/.test(host)) return true
  return false
}

function pickProviderFields(obj) {
  const name = firstString(obj, ['name', 'title', 'label', 'provider', 'providerName', '_type', 'type'])
  let endpoint = firstString(obj, [
    'endpoint',
    'baseUrl',
    'base_url',
    'baseURL',
    'api_base',
    'apiBase',
    'url',
    'host',
  ])
  // Discourse may turn JSON "url" value into visible link text "url" — not a real endpoint
  if (endpoint && !isHttpUrl(endpoint)) endpoint = null

  const apiKey = firstString(obj, [
    'apiKey',
    'api_key',
    'key',
    'token',
    'authToken',
    'auth_token',
    'secret',
    'access_token',
  ])
  // nested env style
  const env = obj.env || obj.environment || obj.settings || null
  let ep = endpoint
  let key = apiKey
  if (env && typeof env === 'object') {
    ep = ep || firstString(env, ENV_URL_KEYS.map((k) => k).concat(['baseUrl', 'endpoint']))
    if (ep && !isHttpUrl(ep)) ep = null
    // also case-insensitive scan
    if (!ep) ep = scanObjectForUrl(env)
    if (!key) key = firstString(env, ENV_KEY_KEYS.concat(['apiKey', 'key']))
    if (!key) key = scanObjectForKey(env)
  }
  if (!ep) ep = scanObjectForUrl(obj)
  if (!key) key = scanObjectForKey(obj)

  // magpie models list: string, comma string, or array of model ids.
  let models = []
  const rawModels = obj.models ?? obj.model
  if (typeof rawModels === 'string') {
    models = rawModels.split(',').map((m) => m.trim()).filter(Boolean)
  } else if (Array.isArray(rawModels)) {
    models = rawModels.map((m) => String(m).trim()).filter(Boolean)
  }
  return { name, endpoint: ep, apiKey: key, models }
}

function firstString(obj, keys) {
  for (const k of keys) {
    if (obj[k] != null && String(obj[k]).trim()) return String(obj[k]).trim()
  }
  // case-insensitive
  const lowerMap = {}
  for (const [k, v] of Object.entries(obj)) {
    lowerMap[k.toLowerCase()] = v
  }
  for (const k of keys) {
    const v = lowerMap[k.toLowerCase()]
    if (v != null && String(v).trim()) return String(v).trim()
  }
  return null
}

function scanObjectForUrl(obj) {
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && /^https?:\/\//i.test(v.trim())) {
      if (/url|base|endpoint|host|api/i.test(k)) return v.trim()
    }
  }
  for (const v of Object.values(obj)) {
    if (typeof v === 'string' && /^https?:\/\//i.test(v.trim())) return v.trim()
  }
  return null
}

function scanObjectForKey(obj) {
  // Exact field names only — avoid matching monkey_token / description etc.
  const exact = new Set([
    'apikey',
    'api_key',
    'key',
    'token',
    'authtoken',
    'auth_token',
    'secret',
    'access_token',
    'authorization',
  ])
  for (const [k, v] of Object.entries(obj)) {
    if (typeof v === 'string' && exact.has(String(k).toLowerCase()) && v.trim().length >= 8) {
      return v.trim()
    }
  }
  for (const v of Object.values(obj)) {
    if (typeof v === 'string' && KEY_PREFIX_BODY_RE.test(v.trim())) {
      return sanitizeApiKey(v.trim().replace(/^Bearer\s+/i, ''))
    }
  }
  return null
}

function tryParseTomlLike(text) {
  const endpoint =
    matchQuotedAssignment(text, ['base_url', 'baseUrl', 'endpoint', 'api_base', 'url']) || null
  const apiKey =
    matchQuotedAssignment(text, ['api_key', 'apiKey', 'key', 'token', 'auth_token', 'secret']) || null
  if (!endpoint && !apiKey) return null
  // require at least one assignment-style line to distinguish from mixed
  if (!/^\s*[\w.]+\s*=\s*.+/m.test(text) && !endpoint) return null
  if (!/=\s*["']?/.test(text)) return null

  const name = matchQuotedAssignment(text, ['name', 'title']) || defaultName()
  const fields = { name, endpoint, apiKey, ...classifyEndpointProtocol(endpoint || '') }
  return emptyResult({
    name,
    ...classifyEndpointProtocol(endpoint || ''),
    apiKey,
    source: 'toml',
    confidence: scoreFields(fields),
    warnings: buildWarnings(fields),
  })
}

function matchQuotedAssignment(text, keys) {
  for (const key of keys) {
    const re = new RegExp(
      `(?:^|[\\s;])${escapeRegExp(key)}\\s*=\\s*(?:"([^"]+)"|'([^']+)'|(\\S+))`,
      'im',
    )
    const m = text.match(re)
    if (m) return (m[1] || m[2] || m[3] || '').trim()
  }
  return null
}

function tryParseEnv(text) {
  const map = parseEnvMap(text)
  if (Object.keys(map).length === 0) return null

  let endpoint = null
  let apiKey = null
  for (const k of ENV_URL_KEYS) {
    if (map[k]) {
      endpoint = map[k]
      break
    }
  }
  for (const k of ENV_KEY_KEYS) {
    if (map[k]) {
      apiKey = map[k]
      break
    }
  }
  // fuzzy
  if (!endpoint) {
    for (const [k, v] of Object.entries(map)) {
      if (/BASE_URL|API_BASE|ENDPOINT/i.test(k) && /^https?:\/\//i.test(v)) {
        endpoint = v
        break
      }
    }
  }
  if (!apiKey) {
    for (const [k, v] of Object.entries(map)) {
      if (/API_KEY|AUTH_TOKEN|TOKEN|SECRET/i.test(k) && v.length >= 8) {
        apiKey = v
        break
      }
    }
  }

  if (!endpoint && !apiKey) return null

  const fields = { name: defaultName(), endpoint, apiKey, ...classifyEndpointProtocol(endpoint || '') }
  return emptyResult({
    name: defaultName(),
    ...classifyEndpointProtocol(endpoint || ''),
    apiKey,
    source: 'env',
    confidence: scoreFields(fields) + 0.05,
    warnings: buildWarnings(fields),
  })
}

function parseEnvMap(text) {
  const map = {}
  const lines = text.split(/\r?\n/)
  for (const line of lines) {
    const trimmed = line.trim()
    if (!trimmed || trimmed.startsWith('#')) continue
    // KEY=value or export KEY=value
    const m = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
    if (!m) continue
    let val = m[2].trim()
    if (
      val.length >= 2 &&
      ((val.startsWith('"') && val.endsWith('"')) ||
        (val.startsWith("'") && val.endsWith("'")))
    ) {
      // Quoted values are literal — a '#' inside them is content, not a comment.
      val = val.slice(1, -1)
    } else {
      // strip trailing inline comments loosely (unquoted values only)
      val = val.replace(/\s+#.*$/, '').trim()
    }
    if (val) map[m[1]] = val
  }
  // also allow single-line KEY=value KEY2=value
  if (Object.keys(map).length === 0) {
    const re = /([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([^\s]+)/g
    let m
    while ((m = re.exec(text)) !== null) {
      if (ENV_URL_KEYS.includes(m[1]) || ENV_KEY_KEYS.includes(m[1]) || /URL|KEY|TOKEN/i.test(m[1])) {
        map[m[1]] = m[2].replace(/^["']|["']$/g, '')
      }
    }
  }
  return map
}

function tryParseMixed(text) {
  const labeled = extractLabeledFields(text)

  const urls = unique([
    ...collectEndpoints(text),
    ...(labeled.endpoint ? [labeled.endpoint] : []),
  ])
    .filter((u) => isHttpUrl(u))
    .slice(0, MAX_URLS)

  const keys = unique([
    ...matchAll(text, SK_ANT_RE),
    ...matchAll(text, SK_RE),
    ...matchAllGroups(text, BEARER_RE, 1),
    ...extractLooseKeys(text),
    ...extractBase64DecodedKeys(text),
    ...(labeled.apiKey ? [labeled.apiKey] : []),
  ])
    .map((k) => maybeDecodeKey(k))
    .filter((k) => k && (hasKeyPrefix(k) || lookLikeKeyValue(k)))

  const apiKeys = unique(keys).slice(0, MAX_KEYS)

  if (urls.length === 0 && apiKeys.length === 0) return null

  const candidates = buildCandidatePairs(urls, apiKeys, text, labeled)
  if (candidates.length === 0) return null

  const best = candidates[0]

  const fields = {
    name: labeled.name || defaultName(),
    chat: best.chat,
    responses: best.responses,
    anthropic: best.anthropic,
    apiKey: best.apiKey,
  }
  const candidateCount = candidates.length
  const warnings = buildWarnings(fields)
  if (candidateCount > 1) {
    warnings.push(
      `检测到 ${urls.length} 个 URL、${apiKeys.length} 个 key，共 ${candidateCount} 组候选（可在确认卡切换）`,
    )
  }

  const confidence = scoreFields(fields) * (candidateCount > 1 ? 0.9 : 1)
  if (!hasAnyProtocol(fields) && !fields.apiKey) return null

  return emptyResult({
    name: fields.name,
    chat: best.chat,
    responses: best.responses,
    anthropic: best.anthropic,
    apiKey: best.apiKey,
    source: 'mixed',
    confidence: labeled.hit ? Math.min(1, confidence + 0.1) : confidence,
    candidateCount,
    candidateIndex: 0,
    candidates,
    warnings,
  })
}

/**
 * Rank endpoint×key pairs for mixed shares. Labeled fields pin when present.
 * Prefer same-line / adjacent-line pairs over independent “best URL × best key”.
 * Each raw share URL is classified into magpie's protocol endpoints when the
 * pair becomes the active candidate (classifyEndpointProtocol at consume time).
 * @param {string[]} urls
 * @param {string[]} apiKeys
 * @param {string} text
 * @param {{ endpoint?: string|null, apiKey?: string|null }} labeled
 * @returns {CandidatePair[]}
 */
function buildCandidatePairs(urls, apiKeys, text, labeled) {
  const preferredUrl = labeled.endpoint || null
  const preferredKey = labeled.apiKey ? decodeKeyBody(labeled.apiKey) : null

  const urlLocs = locateValues(text, urls)
  const keyLocs = locateValues(text, apiKeys)

  /** @type {CandidatePair[]} */
  const pairs = []
  const seen = new Set()
  const add = (endpoint, apiKey) => {
    if (pairs.length >= MAX_CANDIDATES) return false
    const id = `${endpoint || ''}\0${apiKey || ''}`
    if (seen.has(id)) return true
    seen.add(id)
    const protos = classifyEndpointProtocol(endpoint || '')
    pairs.push({
      chat: protos.chat,
      responses: protos.responses,
      anthropic: protos.anthropic,
      apiKey: apiKey || null,
    })
    return pairs.length < MAX_CANDIDATES
  }

  if (urls.length && apiKeys.length) {
    // 1) Labeled pair if both present
    if (preferredUrl && preferredKey) add(preferredUrl, preferredKey)

    // 2) Same-line / adjacent-line proximity pairs (sorted by distance)
    /** @type {Array<{u: string, k: string, dist: number}>} */
    const prox = []
    for (const u of urlLocs) {
      for (const k of keyLocs) {
        const dist = locationDistance(u, k)
        prox.push({ u: u.value, k: k.value, dist })
      }
    }
    prox.sort((a, b) => a.dist - b.dist)
    for (const p of prox) {
      if (!add(p.u, p.k)) break
    }

    // 3) Zip by document order as a soft fallback
    const n = Math.max(urls.length, apiKeys.length)
    for (let i = 0; i < n && pairs.length < MAX_CANDIDATES; i++) {
      add(urls[i] || urls[0], apiKeys[i] || apiKeys[0])
    }

    // 4) Full cartesian only when proximity+zip left us with almost nothing
    //    (avoids flooding the UI with crossed URL×key noise).
    if (pairs.length < 2) {
      outer: for (const u of urls) {
        for (const k of apiKeys) {
          if (!add(u, k)) break outer
        }
      }
    }
  } else if (urls.length === 0) {
    for (const k of apiKeys) {
      if (!add(null, k)) break
    }
  } else {
    for (const u of urls) {
      if (!add(u, null)) break
    }
  }

  const bestUrl = preferredUrl || (proxBestUrl(urlLocs, keyLocs) || pickBestUrl(urls, text))
  const bestKey = preferredKey || (proxBestKey(urlLocs, keyLocs) || pickBestKey(apiKeys))

  pairs.sort((a, b) => {
    const sa = scorePair(a, bestUrl, bestKey, text, urlLocs, keyLocs)
    const sb = scorePair(b, bestUrl, bestKey, text, urlLocs, keyLocs)
    return sb - sa
  })

  return pairs.slice(0, MAX_CANDIDATES)
}

/**
 * @typedef {{ value: string, index: number, line: number }} LocatedValue
 */

/**
 * @param {string} text
 * @param {string[]} values
 * @returns {LocatedValue[]}
 */
function locateValues(text, values) {
  /** @type {LocatedValue[]} */
  const out = []
  const src = String(text || '')
  for (const value of values) {
    if (!value) continue
    const idx = src.indexOf(value)
    if (idx < 0) {
      out.push({ value, index: Number.MAX_SAFE_INTEGER, line: Number.MAX_SAFE_INTEGER })
      continue
    }
    const line = src.slice(0, idx).split(/\r?\n/).length - 1
    out.push({ value, index: idx, line })
  }
  return out
}

/**
 * @param {LocatedValue} a
 * @param {LocatedValue} b
 */
function locationDistance(a, b) {
  if (a.line === Number.MAX_SAFE_INTEGER || b.line === Number.MAX_SAFE_INTEGER) return 1e9
  const lineDist = Math.abs(a.line - b.line)
  if (lineDist === 0) return 0
  // adjacent lines slightly worse than same line; farther grows quickly
  return lineDist * 10 + Math.abs(a.index - b.index) / 1000
}

function proxBestUrl(urlLocs, keyLocs) {
  if (!urlLocs.length) return null
  if (!keyLocs.length) return urlLocs[0].value
  let best = null
  let bestD = Infinity
  for (const u of urlLocs) {
    for (const k of keyLocs) {
      const d = locationDistance(u, k)
      if (d < bestD) {
        bestD = d
        best = u.value
      }
    }
  }
  return best
}

function proxBestKey(urlLocs, keyLocs) {
  if (!keyLocs.length) return null
  if (!urlLocs.length) return keyLocs[0].value
  let best = null
  let bestD = Infinity
  for (const u of urlLocs) {
    for (const k of keyLocs) {
      const d = locationDistance(u, k)
      if (d < bestD) {
        bestD = d
        best = k.value
      }
    }
  }
  return best
}

/**
 * @param {CandidatePair} pair
 * @param {string|null} preferredUrl
 * @param {string|null} preferredKey
 * @param {string} text
 * @param {LocatedValue[]} [urlLocs]
 * @param {LocatedValue[]} [keyLocs]
 */
function scorePair(pair, preferredUrl, preferredKey, text, urlLocs, keyLocs) {
  let s = 0
  const pairUrl = pair.chat || pair.anthropic || pair.responses
  if (pairUrl && pair.apiKey) s += 2
  if (preferredUrl && pairUrl === preferredUrl) s += 3
  if (preferredKey && pair.apiKey === preferredKey) s += 3

  // Proximity boost: same/adjacent lines beat independent “best” fields
  if (pairUrl && pair.apiKey && urlLocs && keyLocs) {
    const u = urlLocs.find((x) => x.value === pairUrl)
    const k = keyLocs.find((x) => x.value === pair.apiKey)
    if (u && k) {
      const d = locationDistance(u, k)
      if (d === 0) s += 4
      else if (d <= 10) s += 3
      else if (d <= 30) s += 1.5
      else if (d < 1e8) s += 0.5
    }
  }

  if (pairUrl) {
    const lower = pairUrl.toLowerCase()
    if (/api\.|anthropic|openai|proxy|relay/.test(lower)) s += 1
    // demote billing / docs / dashboard style URLs
    if (/usage|billing|dashboard|docs\.|status\.|github\.com|linux\.do/.test(lower)) s -= 2
  }
  if (pair.apiKey) {
    if (pair.apiKey.startsWith('sk-ant-')) s += 2
    else if (pair.apiKey.startsWith('sk-')) s += 1
    else if (/^(?:g2a_|tp-|ark-|xai-|gsk_|pplx-|r8_|hf_|fw_)/i.test(pair.apiKey)) s += 1
  }
  // slight preference for shorter path endpoints (often the real base)
  if (pairUrl) {
    try {
      const path = new URL(pairUrl).pathname || '/'
      if (path === '/' || path === '/v1' || path === '/v1/') s += 0.5
    } catch {
      /* ignore */
    }
  }
  void text
  return s
}

// Shared label matchers (one source of truth for table / colon / glued forms)
const LABEL_KEY_RE =
  /^(?:api\s*key|api[_-]?key|key|token|secret|auth[_-]?token|密钥)(?:\b|[（(]|$)/i
const LABEL_URL_RE =
  /^(?:url|base\s*url|base[_-]?url|endpoint|api\s*base|api[_-]?base|host|地址|接口|链接)(?:\b|[（(]|$)/i
const LABEL_NAME_RE = /^(?:name|名称|名字)(?:\b|[（(]|$)/i
const LABEL_ANY_RE =
  /^(url|base\s*url|base[_-]?url|endpoint|api\s*base|api[_-]?base|host|地址|接口|链接|key|api\s*key|api[_-]?key|token|secret|auth[_-]?token|密钥|name|名称|名字)/i
const LABEL_KEY_PREFIX_RE =
  /^(?:api\s*key|api[_-]?key|key|token|secret|auth[_-]?token|密钥)(?:\s*[（(][^）)]*[）)])?\s*[:：]?\s*/i
// Looser than LABEL_KEY_PREFIX_RE: matches a line that merely *starts* with a key
// label word and may carry a trailing descriptor (e.g. "API-Key Base64",
// "密钥（Base64，请自行解码）"). Used to trigger readFollowingKey for the
// "label-line + newline + token" two-line shape that the strict prefix+$ test misses.
const LABEL_KEY_HEAD_RE =
  /^(?:api\s*key|api[_-]?key|key|token|secret|auth[_-]?token|密钥)(?=\s|\b|[（(])/i

function labelKind(label) {
  const s = String(label || '').toLowerCase().replace(/\s+/g, '')
  if (/url|base|endpoint|host|地址|接口|链接/.test(s)) return 'url'
  if (/key|token|secret|auth|密钥/.test(s)) return 'key'
  if (/name|名称|名字/.test(s)) return 'name'
  return null
}

function stripLabeledValue(value) {
  let v = String(value || '').trim()
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1).trim()
  }
  return v.replace(/[，。；、！？]+$/g, '')
}

/**
 * Labeled "key：" values must look like real tokens — not Chinese placeholders
 * ("请联系群主…"), not http(s) URLs, not short English filler ("your-key-here").
 * Encoded bodies (base64 / hex) and known vendor prefixes stay accepted.
 */
function lookLikeKeyValue(v) {
  if (!v) return false
  const s = String(v).trim()
  if (!s || s.length > 512) return false
  if (/^https?:\/\//i.test(s) || /\s/.test(s)) return false
  // Real keys may briefly contain CJK watermarks only when they already have a
  // vendor prefix (sanitizeApiKey strips them later). Placeholder Chinese prose
  // without a prefix must never become apiKey.
  if (KEY_PREFIX_BODY_RE.test(s)) {
    const stripped = s.replace(/[^\x20-\x7E]/g, '')
    return stripped.length >= 8 && stripped.length <= 512
  }
  if (/[^\x20-\x7E]/.test(s)) return false
  // classic base64 (padding or long alphabet)
  if (/^[A-Za-z0-9+/]+={1,2}$/.test(s) && s.length >= 20) return true
  if (/^[A-Za-z0-9+/]{32,}$/.test(s)) return true
  // url-safe / underscore bodies (no multi-word English filler)
  if (/^[A-Za-z0-9_-]{32,}={0,2}$/.test(s) && !/(?:your|please|example|xxxx|todo|changeme)/i.test(s)) {
    return true
  }
  // hex-encoded key body
  if (/^[0-9a-fA-F]{24,}$/.test(s) && s.length % 2 === 0) return true
  return false
}

function assignLabeledField(result, kind, value) {
  if (!kind || value == null || value === '') return
  if (kind === 'url') {
    // First labeled URL wins — later pairs become candidates via mixed scan
    if (result.endpoint) return
    const u = (String(value).match(URL_RE) || [])[0]
    if (u) result.endpoint = cleanUrl(u)
    else if (/^https?:\/\//i.test(value)) result.endpoint = cleanUrl(value)
    else return
  } else if (kind === 'key') {
    if (result.apiKey) return
    const raw = String(value).replace(/\s+/g, '')
    // Never treat a URL as an apiKey (common mis-label / copy-paste)
    if (/^https?:\/\//i.test(raw) || !lookLikeKeyValue(raw)) return
    // raw token — finalizeResult runs normalizeApiKey once
    result.apiKey = raw
  } else if (kind === 'name') {
    if (result.name) return
    result.name = String(value).trim()
  }
  result.hit = true
}

function joinBase64Continuations(lines, from, start, hardCap) {
  let next = start
  let k = from
  while (k < hardCap && /^[A-Za-z0-9+/_-]{8,}={0,2}$/.test(lines[k].trim())) {
    next += lines[k].trim()
    k++
  }
  return next.replace(/\s+/g, '')
}

function readFollowingKey(lines, afterIdx) {
  for (let j = afterIdx; j < Math.min(afterIdx + 4, lines.length); j++) {
    let next = lines[j].trim()
    if (!next) continue
    if (LABEL_URL_RE.test(next) || LABEL_KEY_RE.test(next) || LABEL_NAME_RE.test(next)) break
    next = next.replace(LABEL_KEY_PREFIX_RE, '')
    next = joinBase64Continuations(lines, j + 1, next, Math.min(afterIdx + 5, lines.length))
    if (lookLikeKeyValue(next) && !/^https?:\/\//i.test(next)) return next
  }
  return null
}

/**
 * Labeled / table shares. Stores raw key tokens; normalizeApiKey in finalizeResult.
 */
function extractLabeledFields(text) {
  const result = { endpoint: null, apiKey: null, name: null, hit: false }
  const lines = text.split(/\r?\n/)

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim()
    if (!line) continue

    const keyGlued = line.match(
      new RegExp(LABEL_KEY_PREFIX_RE.source + '([A-Za-z0-9+/_-]{16,}={0,2})\s*$', 'i'),
    )
    if (keyGlued && !result.apiKey) {
      assignLabeledField(result, 'key', keyGlued[1])
      continue
    }

    if (new RegExp(LABEL_KEY_PREFIX_RE.source + '$', 'i').test(line) && !result.apiKey) {
      const v = readFollowingKey(lines, i + 1)
      if (v) assignLabeledField(result, 'key', v)
      continue
    }

    // Label-line carrying a trailing descriptor ("API-Key Base64", "密钥（Base64）")
    // followed by a newline + token. Same readFollowingKey path; v == null means the
    // value is on the same line (handled by glued/labeled below), so do NOT continue.
    if (LABEL_KEY_HEAD_RE.test(line) && !result.apiKey) {
      const v = readFollowingKey(lines, i + 1)
      if (v) {
        assignLabeledField(result, 'key', v)
        continue
      }
    }

    const labeled = line.match(
      new RegExp(LABEL_ANY_RE.source + '\s*(?:[:：=]\s*|\s{2,})(.+)$', 'i'),
    )
    if (labeled) {
      const kind = labelKind(labeled[1])
      let value = stripLabeledValue(labeled[2])
      if (kind === 'key' && (!lookLikeKeyValue(value) || /base64|解码|自行/i.test(value))) {
        value = readFollowingKey(lines, i + 1) || value
      }
      if (value && !(kind === 'key' && /base64|解码|自行/i.test(value) && !lookLikeKeyValue(value))) {
        assignLabeledField(result, kind, value)
      }
      continue
    }
  }

  if (!result.endpoint) {
    const m = text.match(
      /(?:url|base[_-]?url|base\s*url|endpoint|地址|接口)\s*[:：]\s*(https?:\/\/[^\s，。；]+)/i,
    )
    if (m) assignLabeledField(result, 'url', m[1])
  }
  if (!result.apiKey) {
    const m = text.match(
      /(?:key|api[_-]?key|api\s*key|token|密钥)\s*[:：]\s*([A-Za-z0-9_+\-/=]{8,})/i,
    )
    if (m) assignLabeledField(result, 'key', m[1])
  }

  return result
}

/**
 * A base64-shared "key" may itself decode to a labeled fragment rather than a
 * bare token — e.g. ` "OPENAI_API_KEY": "sk-..."` or `api_key=sk-...`. Peel the
 * wrapper and return the inner key value. Returns null when no key-shaped value
 * is present (caller keeps the original string).
 * @param {string} text
 * @returns {string|null}
 */
function extractKeyFromWrapper(text) {
  const t = String(text || '').trim()
  if (!t || t.length > 1024) return null
  // Labeled fragment: "field": "value"  /  'field': 'value'  /  field=value
  // Value quotes are optional — unquoted field=value bodies are common when the
  // share base64-encodes an env-style line.
  const kv = t.match(
    /["']?[A-Za-z_][A-Za-z0-9_]*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-./+=]{8,})["']?/,
  )
  const candidate = kv ? kv[1] : null
  if (!candidate) return null
  const decoded = hasKeyPrefix(candidate) ? candidate : decodeKeyBody(candidate)
  if (hasKeyPrefix(decoded)) return sanitizeApiKey(decoded)
  return null
}

/**
 * Decode b64/hex + strip CJK watermark; no prefix hints.
 * Supports nested base64 (e.g. "\u4FE9\u6B21base64" \u2192 outer b64 \u2192 inner b64 \u2192 sk-\u2026).
 * Caps depth so random blobs do not loop forever.
 */
function decodeKeyBody(value) {
  if (!value) return value
  let v = String(value)
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, '')
    .replace(/[\s\u00A0]+/g, '')
    .trim()
  if (KEY_PREFIX_BODY_RE.test(v)) {
    return sanitizeApiKey(v.replace(/^Bearer\s*/i, ''))
  }

  // Hex first (even length long enough)
  if (/^[0-9a-fA-F]{24,}$/.test(v) && v.length % 2 === 0) {
    try {
      const decoded = sanitizeApiKey(hexDecode(v).trim())
      if (isDecodableKeyBody(decoded) && (hasKeyPrefix(decoded) || decoded.length < v.length)) {
        return peelBase64Layers(decoded)
      }
    } catch {
      /* base64 next */
    }
  }

  const peeled = peelBase64Layers(v)
  // The peeled result may be a labeled wrapper ("OPENAI_API_KEY": "sk-…") that
  // itself carries the real key — unwrap it before handing back a non-key string.
  if (!hasKeyPrefix(peeled)) {
    const unwrapped = extractKeyFromWrapper(peeled)
    if (unwrapped) return unwrapped
  }
  return peeled
}

/** Peel nested base64 (e.g. 俩次base64) until sk-/g2a_/tp- or layers stop. */
function peelBase64Layers(value, maxDepth = 4) {
  let v = String(value || '').trim()
  if (!v) return v
  if (hasKeyPrefix(v)) return sanitizeApiKey(v)

  for (let depth = 0; depth < maxDepth; depth++) {
    if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(v) || v.length < 16) break
    let decoded
    try {
      decoded = base64Decode(v).trim()
    } catch {
      break
    }
    if (!decoded || decoded === v) break
    const cleaned = sanitizeApiKey(decoded)
    if (hasKeyPrefix(cleaned) && isDecodableKeyBody(cleaned)) {
      return cleaned
    }
    // Decoded text may be a labeled fragment ("OPENAI_API_KEY": "sk-…") rather
    // than a bare key — such text has spaces/quotes, so isDecodableKeyBody is
    // false and none of the branches below fire. Unwrap the inner key first.
    const unwrapped = extractKeyFromWrapper(decoded)
    if (unwrapped) return unwrapped
    // Intermediate pure base64 → peel again
    if (
      isDecodableKeyBody(cleaned) &&
      /^[A-Za-z0-9+/_-]+={0,2}$/.test(cleaned) &&
      cleaned.length >= 16 &&
      cleaned.length < v.length
    ) {
      v = cleaned
      continue
    }
    if (isDecodableKeyBody(cleaned) && (cleaned.includes('_') || cleaned.length < v.length)) {
      return cleaned
    }
    break
  }
  return v
}
function maybeDecodeKey(value) {
  return decodeKeyBody(value)
}

function hasKeyPrefix(s) {
  return KEY_PREFIX_RE.test(s)
}

function isDecodableKeyBody(decoded) {
  return (
    !!decoded &&
    decoded.length >= 8 &&
    decoded.length <= 512 &&
    /^[\x20-\x7E]+$/.test(decoded) &&
    !/\s/.test(decoded) &&
    /[A-Za-z0-9]/.test(decoded)
  )
}

function hexDecode(hex) {
  const h = String(hex).replace(/[^0-9a-fA-F]/g, '')
  if (h.length % 2 !== 0) throw new Error('bad hex')
  if (typeof Buffer !== 'undefined') return Buffer.from(h, 'hex').toString('utf8')
  const bytes = new Uint8Array(h.length / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(h.substr(i * 2, 2), 16)
  if (typeof TextDecoder !== 'undefined') return new TextDecoder('utf-8').decode(bytes)
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i])
  return s
}

/**
 * Strip non-ASCII watermarks (e.g. CJK anti-scrape) from API keys.
 * @param {string} key
 * @returns {string}
 */
function sanitizeApiKey(key) {
  if (!key) return key
  let k = String(key)
    .replace(/[\u200B-\u200D\uFEFF\u00AD\u2060]/g, '')
    .trim()
  if (/^[\x20-\x7E]+$/.test(k) && !/\s/.test(k)) {
    return k.replace(/\s+/g, '')
  }
  const stripped = k.replace(/[^\x20-\x7E]/g, '').replace(/\s+/g, '')
  if (stripped.length >= 8 && stripped.length <= 512 && KEY_PREFIX_RE.test(stripped)) {
    return stripped
  }
  return k
}

/** Non-sk tokens after key labels, or base64 after "base64：" / "俩次base64" style notes. */
function extractLooseKeys(text) {
  const out = []
  const vendor = text.match(VENDOR_KEY_RE)
  if (vendor) out.push(...vendor)

  // key：… / 密钥：… / base64：… / 两次base64：…
  const afterLabel = text.match(
    /(?:key|api[_-]?key|api\s*key|token|密钥|(?:俩|两|二)?次?\s*base\s*64|base\s*64)\s*[:：]\s*([A-Za-z0-9+/_-]{20,}={0,2})/gi,
  )
  if (afterLabel) {
    for (const chunk of afterLabel) {
      const m = chunk.match(/[:：]\s*([A-Za-z0-9+/_-]{20,}={0,2})/)
      if (m) {
        const raw = m[1]
        // Drop English/CJK placeholders before decode (e.g. your-key-here-please)
        if (!lookLikeKeyValue(raw) && !KEY_PREFIX_BODY_RE.test(raw)) continue
        const decoded = decodeKeyBody(raw)
        if (decoded && (hasKeyPrefix(decoded) || lookLikeKeyValue(decoded))) out.push(decoded)
      }
    }
  }
  return out
}

/**
 * Standalone base64 tokens that peel to sk- / g2a_ / tp- keys (incl. double base64).
 */
function extractBase64DecodedKeys(text) {
  const out = []
  // Context gates for accepting prefix-less decoded tokens (StepFun / Mistral /
  // Cohere style random-string keys): only when the share clearly carries an
  // endpoint URL AND a base64/decode hint, so arbitrary base64 noise (image
  // hashes, encoded snippets) is not harvested as keys.
  const hasEndpoint = /https?:\/\//i.test(text)
  const hasDecodeHint = /(?:base\s*64|64\s*解|解密|解码|加密|自行\s*解)/i.test(text)
  const consider = (token) => {
    if (!token || token.startsWith('sk-') || token.startsWith('http')) return
    const decoded = decodeKeyBody(token)
    if (!decoded || decoded === token) return
    if (hasKeyPrefix(decoded)) {
      out.push(decoded)
      return
    }
    // Prefix-less vendor token: require endpoint + decode hint + key-like shape,
    // so a lone base64 blob without context is never mistaken for a key.
    if (hasEndpoint && hasDecodeHint && lookLikeKeyValue(decoded) && decoded.length >= 24) {
      out.push(decoded)
    }
  }

  for (const line of text.split(/\r?\n/)) {
    const t = line.trim()
    // whole line, or "label：TOKEN" on one line
    if (/^[A-Za-z0-9+/_-]{24,}={0,2}$/.test(t)) {
      consider(t)
      continue
    }
    // CJK-glued: …佬友们用dHAt… (no whitespace before base64)
    const cjkGlued = t.match(
      /(?:[一-鿿]|[\s"'`：:，。；、！？])([A-Za-z0-9+/]{32,}={0,2})\s*$/,
    )
    if (cjkGlued) consider(cjkGlued[1])
    const labeled = t.match(
      /(?:key|api[_-]?key|token|密钥|base\s*64|(?:俩|两|二)?次?\s*base\s*64)\s*[:：]\s*([A-Za-z0-9+/_-]{24,}={0,2})\s*$/i,
    )
    if (labeled) consider(labeled[1])
  }

  const re = new RegExp(`${B64_BOUNDARY_L}([A-Za-z0-9+/]{32,}={0,2})${B64_BOUNDARY_R}`, 'gm')
  let m
  while ((m = re.exec(text)) !== null) consider(m[1])
  return unique(out)
}

function pickBestUrl(urls, text) {
  // Forum self-links are never provider endpoints (same rule as collectEndpoints).
  const usable = urls.filter((u) => !isForumEndpoint(u))
  if (usable.length === 0) return null
  const scored = usable.map((u) => {
    let s = 0
    const lower = u.toLowerCase()
    if (/anthropic|claude/.test(lower)) s += 3
    if (/openai|codex/.test(lower)) s += 2
    if (/api\./.test(lower)) s += 1
    if (/127\.0\.0\.1|localhost/.test(lower)) s += 1 // local proxy common
    // demote billing / docs / dashboard style URLs (parity with scorePair)
    if (/usage|billing|dashboard|docs\.|status\.|github\.com|linux\.do/.test(lower)) s -= 2
    // proximity to key words in original text
    if (new RegExp(`(?:BASE_URL|endpoint|baseUrl)[^\\n]{0,40}${escapeRegExp(u.slice(0, 30))}`, 'i').test(text)) {
      s += 2
    }
    return { u, s }
  })
  scored.sort((a, b) => b.s - a.s)
  return scored[0].u
}

function pickBestKey(keys) {
  if (keys.length === 0) return null
  const scored = keys.map((k) => {
    let s = k.length / 100
    if (k.startsWith('sk-ant-')) s += 3
    else if (k.startsWith('sk-')) s += 2
    else if (/^(?:g2a_|tp-|ark-|xai-|gsk_|pplx-|r8_|hf_|fw_)/i.test(k)) s += 2
    else if (/^[A-Za-z0-9+/]+={1,2}$/.test(k) && k.length >= 24) s += 0.5 // raw b64
    return { k, s }
  })
  scored.sort((a, b) => b.s - a.s)
  return maybeDecodeKey(scored[0].k)
}

function cleanUrl(u) {
  const s = String(u || '')
    .trim()
    // leading quotes left over from prose / JSON fragments
    .replace(/^["'`]+/, '')
    // trailing JSON / prose punctuation, parens excluded (handled below)
    .replace(/[.,;:!?」』】"'`]+$/g, '')
  return stripUnbalancedTrailingParens(s)
}

/**
 * Drop trailing ')' / '）' only while they are unmatched by an opening paren
 * inside the URL, so parenthesised path segments survive but a prose paren
 * around the whole URL does not leak in.
 * @param {string} s
 */
function stripUnbalancedTrailingParens(s) {
  let out = s
  while (/[)）]$/.test(out)) {
    const opens = (out.match(/[(（]/g) || []).length
    const closes = (out.match(/[)）]/g) || []).length
    if (closes <= opens) break
    out = out.slice(0, -1)
  }
  return out
}

function scoreFields(fields) {
  let s = 0.3
  if (hasAnyProtocol(fields)) s += 0.35
  if (fields.apiKey) {
    s += 0.35
    // Weak / non-prefixed tokens should not read as "100% confidence"
    const k = String(fields.apiKey)
    if (!KEY_PREFIX_RE.test(k) && !KEY_PREFIX_BODY_RE.test(k)) {
      s -= 0.25
    }
  }
  return Math.min(1, Math.max(0, s))
}

/**
 * True for warnings produced by buildWarnings (derived from the current
 * endpoint/apiKey fields). Parser-generated notes — multi-candidate summary,
 * oversized-selection marker, "已根据文案补上前缀" — are NOT field-derived and
 * must survive selectCandidate / mergeParseResults, which recompute field
 * warnings from scratch.
 * @param {string} w
 */
function isFieldDerivedWarning(w) {
  return (
    /^未识别到 (?:API Key|base URL)/.test(w) ||
    /^(?:chat|responses|anthropic) 地址已阻止/.test(w) ||
    /^apiKey /.test(w)
  )
}

function buildWarnings(fields) {
  const w = []
  const hasUrl = hasAnyProtocol(fields)
  if (hasUrl && !fields.apiKey) w.push('未识别到 API Key，仍可尝试导入')
  if (!hasUrl && fields.apiKey) w.push('未识别到 base URL，仍可尝试导入')
  for (const proto of ['chat', 'responses', 'anthropic']) {
    if (!fields[proto]) continue
    const endpointPolicy = inspectEndpoint(fields[proto])
    if (!endpointPolicy.valid) w.push(`${proto} 地址已阻止：${endpointPolicy.error}`)
    else if (endpointPolicy.warning) w.push(endpointPolicy.warning)
  }
  if (fields.apiKey) {
    const k = String(fields.apiKey)
    if (/^https?:\/\//i.test(k)) {
      w.push('apiKey 看起来像 URL，请核对')
    } else if (!KEY_PREFIX_RE.test(k) && !KEY_PREFIX_BODY_RE.test(k) && k.length < 24) {
      w.push('apiKey 形态较弱，请核对后再导入')
    }
  }
  return w
}

function matchAll(text, re) {
  const out = []
  const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')
  let m
  while ((m = r.exec(text)) !== null) out.push(m[0])
  return out
}

function matchAllGroups(text, re, group) {
  const out = []
  const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')
  let m
  while ((m = r.exec(text)) !== null) out.push(m[group])
  return out
}

function unique(arr) {
  return [...new Set(arr.filter(Boolean))]
}

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

export function base64Encode(str) {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(str, 'utf8').toString('base64')
  }
  // browser
  return btoa(unescape(encodeURIComponent(str)))
}

export function base64Decode(b64) {
  // normalize url-safe
  let s = String(b64 || '').replace(/-/g, '+').replace(/_/g, '/')
  // Reject oversized tokens before allocating decoded buffers
  if (s.length * 0.75 > MAX_DECODED_LEN) {
    throw new Error('base64 payload too large')
  }
  const pad = s.length % 4
  if (pad) s += '='.repeat(4 - pad)
  let out
  if (typeof Buffer !== 'undefined') {
    out = Buffer.from(s, 'base64').toString('utf8')
  } else {
    out = decodeURIComponent(escape(atob(s)))
  }
  if (out.length > MAX_DECODED_LEN) throw new Error('decoded payload too large')
  return out
}

export { MIN_SELECTION_LEN, MAX_SELECTION_LEN, MAX_CANDIDATES }
