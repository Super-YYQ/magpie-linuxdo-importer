/**
 * Extract model names from share text for the magpie import link.
 * Used by Node tests and inlined into the Tampermonkey userscript.
 *
 * magpie takes a comma-separated models list covering every agent, so unlike
 * the CC Switch flow there is no per-app preference: every detected id goes
 * into the link and the app lists what the provider serves.
 */

/**
 * @typedef {{
 *   models: string[]
 * }} ModelResult
 */

/**
 * Ordered specific → general. Overlaps are resolved by keeping the longest
 * match at each span (e.g. claude-sonnet-4.5 wins over claude-sonnet-4).
 * @type {RegExp[]}
 */
const MODEL_RES = [
  // Claude (longer / more specific first). Full ids with date or minor:
  //   claude-sonnet-4-20250514, claude-opus-4-1, claude-haiku-4.5
  /claude-3\.7-sonnet(?:-\d{8})?/gi,
  /claude-3\.5-sonnet(?:-\d{8})?/gi,
  /claude-3-sonnet(?:-\d{8})?/gi,
  /claude-3\.5-haiku(?:-\d{8})?/gi,
  /claude-3-haiku(?:-\d{8})?/gi,
  /claude-3-opus(?:-\d{8})?/gi,
  /claude-(?:haiku|sonnet|opus|fable|mythos)-\d+(?:(?:[.-]\d{1,2})(?:-\d{8})?|-\d{8})?(?![a-z0-9.-])/gi,
  /\bclaude-sonnet\b/gi,
  /\bclaude-haiku\b/gi,
  /\bclaude-opus\b/gi,
  // OpenAI — generic gpt-5 line covers gpt-5/5.1/5-pro/5.1-codex/5.5/5.6-sol…
  /gpt-5(?:\.\d+)?(?:-(?:pro|codex|mini|nano|sol|chat))?(?![a-z0-9.-])/gi,
  /gpt-4\.1(?:-(?:mini|nano))?(?![a-z0-9.-])/gi,
  /gpt-4\.?5[a-z-]*(?:turbo|preview)?/gi,
  /gpt-4o(?:-mini|-preview)?/gi,
  /gpt-4-turbo(?:-preview)?/gi,
  /gpt-4-vision(?:-preview)?/gi,
  /gpt-4(?:-\d{4})?(?![a-z0-9.])/gi,
  /gpt-3\.5-turbo(?:-\d{4})?/gi,
  /\bo[34](?:-(?:mini|pro))?\b/gi,
  /\bo1(?:-mini|-preview)?\b/gi,
  // Grok — accept "Grok4.5" / "grok4.5" (no hyphen)
  /(?<![a-z0-9])grok[-_]?4\.5(?![0-9])/gi,
  /(?<![a-z0-9])grok[-_]?3\.5(?![0-9])/gi,
  /(?<![a-z0-9])grok[-_]?4(?![0-9.])/gi,
  /(?<![a-z0-9])grok[-_]?3(?![0-9.])/gi,
  /(?<![a-z0-9])grok-beta\b/gi,
  /(?<![a-z0-9])grok-2\b/gi,
  // Gemini
  /gemini-2\.5-(?:pro|flash)/gi,
  /gemini-2\.0-(?:flash|pro)/gi,
  /gemini-1\.5-(?:pro|flash)/gi,
  /gemini-pro/gi,
  /gemini-flash/gi,
  // Chinese vendors common on linux.do relay shares (智谱 / 阿里 / Moonshot / 字节)
  /\bglm-\d+(?:\.\d+)?(?:-(?:air|flash|plus))?/gi,
  /\bqwen\d+(?:\.\d+)?(?:-[a-z0-9]+(?:-[a-z0-9]+)?)?/gi,
  /\bqwq-?\d+(?:\.\d+)?(?:-[a-z0-9]+)?/gi,
  /\bkimi-(?:k\d+(?:\.\d+)?|\d+(?:\.\d+)?)/gi,
  /\bdoubao-(?:seed-)?\d+(?:\.\d+)?(?:-(?:pro|lite|flash|thinking))?/gi,
  // DeepSeek — require full minor when present so deepseek-v3.2 is not truncated
  /deepseek-v3(?:\.\d+)?/gi,
  /deepseek-r\d+(?:\.\d+)?/gi,
  /deepseek-coder(?:-v2)?/gi,
  /deepseek-chat/gi,
]

/**
 * @param {string} text
 * @returns {ModelResult}
 */
export function extractModels(text) {
  if (!text) {
    return { models: [] }
  }

  // Mask secrets / long base64 so tokens like "...o3..." inside keys never become models.
  // Do NOT use a class that includes "-" — that erases real model ids such as
  // claude-sonnet-4-20250514 (length ≥ 24 with hyphens).
  const scanText = String(text)
    .replace(/[A-Za-z0-9+/]{24,}={0,2}/g, ' ')
    .replace(/[A-Za-z0-9_]{32,}={0,2}/g, ' ')
    .replace(/\bsk-(?:ant-)?[A-Za-z0-9_-]{8,}\b/gi, ' ')
    .replace(/\b(?:g2a_|tp-|nk-|pk-|rk-)[A-Za-z0-9_-]{8,}\b/gi, ' ')

  /** @type {Array<{start: number, end: number, value: string}>} */
  const spans = []
  for (const re of MODEL_RES) {
    const r = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')
    let m
    while ((m = r.exec(scanText)) !== null) {
      const value = normalizeModelId(m[0])
      if (!value) continue
      spans.push({ start: m.index, end: m.index + m[0].length, value })
    }
  }

  // Prefer longer matches; drop spans fully contained in a longer one
  spans.sort((a, b) => b.end - b.start - (a.end - a.start) || a.start - b.start)
  /** @type {Array<{start: number, end: number, value: string}>} */
  const kept = []
  for (const s of spans) {
    const contained = kept.some((k) => s.start >= k.start && s.end <= k.end)
    if (!contained) kept.push(s)
  }

  // Stable unique list in document order
  kept.sort((a, b) => a.start - b.start)
  const models = []
  const seen = new Set()
  for (const s of kept) {
    if (seen.has(s.value)) continue
    seen.add(s.value)
    models.push(s.value)
  }

  return { models }
}

/**
 * Normalize informal spellings to stable model ids.
 * e.g. Grok4.5 / grok4.5 → grok-4.5; gpt5.5 → gpt-5.5 (when matched that way)
 * @param {string} raw
 * @returns {string}
 */
function normalizeModelId(raw) {
  let m = String(raw || '').toLowerCase().trim()
  // Grok: "Grok4.5" / "grok4.5" / "grok_4.5" → "grok-4.5"
  m = m.replace(/^grok[_-]?(\d)/, 'grok-$1')
  // gpt5.5 → gpt-5.5 when hyphen missing
  m = m.replace(/^gpt(\d)/, 'gpt-$1')
  return m
}
