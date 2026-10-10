/**
 * UI + integration entry for the Tampermonkey userscript.
 * Built with esbuild (IIFE) via scripts/build.mjs.
 */
import {
  parseShareText,
  looksLikeConfig,
  buildDeeplink,
  maskKey,
  selectCandidate,
  enrichTextWithAnchorHrefs,
  describeProviderParams,
  suggestPresetLinks,
  MAX_DEEPLINK_LEN,
  MAX_SELECTION_LEN,
} from './lib/core.mjs'
import { extractModels } from './lib/model-extractor.mjs'

/* global GM_setClipboard, GM_notification, __SCRIPT_VERSION__ */
// Replaced at build time by scripts/build.mjs (esbuild define).
const SCRIPT_VERSION = __SCRIPT_VERSION__

const ROOT_ID = 'mp-ld-root'
const Z = 2147483000

let lastSelectionText = ''
let hideTimer = null
let scrollRaf = 0
/** Memoized looksLikeConfig verdict for the current selection text. */
let lastConfigCheck = { text: null, ok: false }
let currentResult = null
let currentTopicTitle = ''
let currentPresetSuggestions = []
/** Model ids the user kept selected in the confirm card (null = auto). */
let selectedModels = null
/** Risky or unknown optional import-link parameters always require opt-in. */
let includeRiskyParams = false
let currentDeeplink = null
let deeplinkError = null
let previouslyFocused = null

function ensureRoot() {
  let host = document.getElementById(ROOT_ID)
  if (host) return host.shadowRoot
  host = document.createElement('div')
  host.id = ROOT_ID
  host.style.all = 'initial'
  host.style.position = 'fixed'
  host.style.zIndex = String(Z)
  host.style.top = '0'
  host.style.left = '0'
  host.style.width = '0'
  host.style.height = '0'
  document.documentElement.appendChild(host)
  const shadow = host.attachShadow({ mode: 'open' })
  const style = document.createElement('style')
  style.textContent = CSS_TEXT
  shadow.appendChild(style)
  return shadow
}

const CSS_TEXT = `
  :host { all: initial; }
  * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif; }
  .mp-btn {
    position: fixed;
    z-index: ${Z};
    padding: 8px 14px;
    border: none;
    border-radius: 999px;
    background: #228be6;
    color: #fff;
    font-size: 12px;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 4px 16px rgba(0,0,0,.28);
    display: none;
    white-space: nowrap;
  }
  .mp-btn:hover { background: #1c7ed6; }
  .mp-btn.show { display: inline-flex; align-items: center; gap: 6px; }
  .mp-overlay {
    position: fixed; inset: 0; background: rgba(0,0,0,.45);
    z-index: ${Z + 1}; display: none; align-items: center; justify-content: center;
    padding: 16px;
  }
  .mp-overlay.show { display: flex; }
  .mp-card {
    width: min(400px, 100%);
    max-height: calc(100vh - 32px); overflow-y: auto;
    background: #2c2e33;
    color: #e9ecef;
    border-radius: 12px;
    border: 1px solid #373a40;
    box-shadow: 0 12px 40px rgba(0,0,0,.45);
    padding: 16px;
  }
  .mp-card h2 { margin: 0 0 6px; font-size: 15px; font-weight: 650; color: #fff; }
  .mp-meta { font-size: 12px; color: #adb5bd; margin-bottom: 12px; line-height: 1.5; }
  .mp-fields {
    background: #1a1b1e; border-radius: 8px; padding: 10px 12px;
    font-size: 12px; line-height: 1.65; margin-bottom: 12px;
    word-break: break-all;
  }
  .mp-fields .k { color: #868e96; margin-right: 6px; }
  .mp-copy-key {
    display: inline-flex; align-items: center; justify-content: center;
    width: 22px; height: 22px; margin-left: 4px; padding: 4px; vertical-align: middle;
    border: none; border-radius: 4px; background: transparent; color: #adb5bd;
    cursor: pointer;
  }
  .mp-copy-key:hover:not(:disabled) { background: #373a40; color: #fff; }
  .mp-copy-key:focus-visible { outline: 2px solid #228be6; outline-offset: 2px; }
  .mp-copy-key:disabled { opacity: .4; cursor: not-allowed; }
  .mp-preset-suggestions, .mp-url-help {
    display: none; margin: -2px 0 12px; font-size: 11px; line-height: 1.5;
    color: #adb5bd;
  }
  .mp-preset-suggestions.show, .mp-url-help.show { display: block; }
  .mp-preset-row { border-top: 1px solid #495057; margin-top: 7px; padding-top: 7px; }
  .mp-preset-row strong { display: block; color: #e9ecef; font-size: 12px; }
  .mp-preset-row code { display: block; overflow-wrap: anywhere; color: #ced4da; }
  .mp-copy-preset {
    border: 1px solid #495057; border-radius: 6px; padding: 4px 8px;
    margin-top: 4px; background: #373a40; color: #fff; cursor: pointer;
  }
  .mp-copy-preset:hover { background: #495057; }
  .mp-copy-preset:focus-visible { outline: 2px solid #228be6; outline-offset: 2px; }
  .mp-warn {
    font-size: 11px; color: #fcc419; margin: -4px 0 12px; line-height: 1.45;
  }
  .mp-row {
    display: flex; align-items: center; gap: 8px; margin-bottom: 10px;
    font-size: 12px;
  }
  .mp-row label { color: #adb5bd; white-space: nowrap; }
  .mp-row select {
    flex: 1; min-width: 0;
    background: #1a1b1e; color: #e9ecef; border: 1px solid #495057;
    border-radius: 6px; padding: 6px 8px; font-size: 12px;
  }
  .mp-cand {
    display: none; align-items: center; gap: 8px; margin-bottom: 10px;
    font-size: 12px; color: #ced4da;
  }
  .mp-cand.show { display: flex; }
  .mp-cand button {
    border: 1px solid #495057; background: #373a40; color: #fff;
    border-radius: 6px; padding: 4px 10px; font-size: 12px; cursor: pointer;
  }
  .mp-cand button:disabled { opacity: .4; cursor: not-allowed; }
  .mp-cand .mp-cand-label { flex: 1; text-align: center; color: #adb5bd; }
  .mp-opt {
    display: none; align-items: flex-start; gap: 8px; margin: -2px 0 12px;
    font-size: 12px; color: #ced4da; line-height: 1.45;
  }
  .mp-opt.show { display: flex; }
  .mp-opt input { margin-top: 2px; }
  .mp-opt .mp-opt-meta { color: #868e96; font-size: 11px; margin-top: 2px; }
  .mp-actions { display: flex; gap: 8px; flex-wrap: wrap; }
  .mp-actions button {
    flex: 1; min-width: 90px; border-radius: 8px; padding: 9px 10px;
    font-size: 12px; cursor: pointer; border: 1px solid transparent;
  }
  .mp-btn-cancel { background: transparent; border-color: #495057 !important; color: #adb5bd; }
  .mp-btn-copy { background: #495057; color: #fff; }
  .mp-btn-open { background: #40c057; color: #fff; font-weight: 600; }
  .mp-btn-open:disabled { opacity: .45; cursor: not-allowed; }
  .mp-toast {
    position: fixed; left: 50%; bottom: 28px; transform: translateX(-50%);
    background: #212529; color: #fff; padding: 10px 16px; border-radius: 8px;
    font-size: 12px; z-index: ${Z + 2}; opacity: 0; pointer-events: none;
    transition: opacity .2s ease; max-width: min(420px, 92vw); text-align: center;
    box-shadow: 0 6px 20px rgba(0,0,0,.35);
  }
  .mp-toast.show { opacity: 1; }
  .mp-err {
    color: #ff6b6b; font-size: 13px; padding: 8px 0 12px; line-height: 1.5;
  }
`

function getUi() {
  const shadow = ensureRoot()
  let btn = shadow.getElementById('btn')
  let overlay = shadow.getElementById('overlay')
  let toast = shadow.getElementById('toast')
  if (!btn) {
    btn = document.createElement('button')
    btn.id = 'btn'
    btn.className = 'mp-btn'
    btn.type = 'button'
    btn.textContent = '导入 magpie'
    btn.addEventListener('mousedown', (e) => e.preventDefault())
    btn.addEventListener('click', onImportClick)
    shadow.appendChild(btn)

    overlay = document.createElement('div')
    overlay.id = 'overlay'
    overlay.className = 'mp-overlay'
    overlay.innerHTML = `
      <div class="mp-card" role="dialog" aria-modal="true" aria-labelledby="dialog-title" aria-describedby="warn err" tabindex="-1">
        <h2 id="dialog-title">导入到 magpie</h2>
        <div class="mp-meta" id="meta"></div>
        <div class="mp-err" id="err" role="alert" aria-live="assertive" style="display:none"></div>
        <div class="mp-fields" id="fields"></div>
        <div class="mp-preset-suggestions" id="preset-suggestions"></div>
        <div class="mp-url-help" id="url-help"></div>
        <div class="mp-cand" id="cand">
          <button type="button" id="cand-prev" aria-label="上一组候选">‹</button>
          <span class="mp-cand-label" id="cand-label">候选 1/1</span>
          <button type="button" id="cand-next" aria-label="下一组候选">›</button>
        </div>
        <div class="mp-row" id="model-row" style="display:none">
          <label for="model-select">models</label>
          <select id="model-select" multiple size="4"></select>
        </div>
        <label class="mp-opt" id="provider-opt">
          <input type="checkbox" id="include-provider-params" />
          <span>
            <span>携带风险/未知附加参数</span>
            <div class="mp-opt-meta" id="provider-meta"></div>
          </span>
        </label>
        <div class="mp-warn" id="warn" role="status" aria-live="polite"></div>
        <div class="mp-actions">
          <button type="button" class="mp-btn-cancel" id="cancel">取消</button>
          <button type="button" class="mp-btn-copy" id="copy">复制深链</button>
          <button type="button" class="mp-btn-open" id="open">打开导入</button>
        </div>
      </div>
    `
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeCard()
    })
    shadow.appendChild(overlay)

    toast = document.createElement('div')
    toast.id = 'toast'
    toast.className = 'mp-toast'
    toast.setAttribute('role', 'status')
    toast.setAttribute('aria-live', 'polite')
    shadow.appendChild(toast)

    shadow.getElementById('cancel').addEventListener('click', closeCard)
    shadow.getElementById('copy').addEventListener('click', () => copyDeeplink(true))
    shadow.getElementById('open').addEventListener('click', openImport)
    shadow.getElementById('preset-suggestions').addEventListener('click', (event) => {
      const button = event.target.closest('button[data-preset-id]')
      if (button) copyPresetLink(button.dataset.presetId)
    })
    shadow.getElementById('cand-prev').addEventListener('click', () => shiftCandidate(-1))
    shadow.getElementById('cand-next').addEventListener('click', () => shiftCandidate(1))
    shadow.getElementById('model-select').addEventListener('change', onModelSelect)
    shadow
      .getElementById('include-provider-params')
      .addEventListener('change', onIncludeProviderParamsChange)
  }
  return { shadow, btn, overlay, toast }
}

function showToast(msg, ms = 2800) {
  const { toast } = getUi()
  toast.textContent = msg
  toast.classList.add('show')
  clearTimeout(showToast._t)
  showToast._t = setTimeout(() => toast.classList.remove('show'), ms)
}

function getSelectionText() {
  const sel = window.getSelection()
  if (!sel || sel.isCollapsed) return ''
  const plain = String(sel.toString() || '').trim()
  if (!plain) return ''
  const anchors = collectAnchorsInSelection(sel)
  return String(enrichTextWithAnchorHrefs(plain, anchors) || plain).trim()
}

function getTopicTitle() {
  const heading = document.querySelector('#topic-title .fancy-title, #topic-title h1, h1.fancy-title')
  return String(heading?.textContent || document.title || '').trim()
}

/**
 * @param {Selection} sel
 * @returns {Array<{text: string, href: string}>}
 */
function collectAnchorsInSelection(sel) {
  const out = []
  if (!sel || sel.rangeCount === 0) return out
  const seen = new Set()
  for (let i = 0; i < sel.rangeCount; i++) {
    const range = sel.getRangeAt(i)
    const root = range.commonAncestorContainer
    const rootEl =
      root.nodeType === 1 /* ELEMENT_NODE */ ? root : root.parentElement
    if (!rootEl) continue

    let nearest = rootEl.closest ? rootEl.closest('a[href]') : null
    if (!nearest && rootEl.tagName === 'A' && rootEl.getAttribute('href')) {
      nearest = rootEl
    }
    if (nearest) pushAnchor(nearest, out, seen)

    const candidates = rootEl.querySelectorAll
      ? rootEl.querySelectorAll('a[href]')
      : []
    for (const a of candidates) {
      if (!rangeIntersectsNode(range, a)) continue
      pushAnchor(a, out, seen)
    }

    for (const boundary of [range.startContainer, range.endContainer]) {
      const el =
        boundary.nodeType === 1 ? boundary : boundary.parentElement
      if (!el) continue
      const a = el.closest ? el.closest('a[href]') : null
      if (a) pushAnchor(a, out, seen)
    }
  }
  return out
}

function pushAnchor(a, out, seen) {
  if (!a || !a.getAttribute) return
  const href = a.href || a.getAttribute('href') || ''
  if (!href) return
  const key = href + '|' + (a.textContent || '').trim()
  if (seen.has(key)) return
  seen.add(key)
  out.push({
    text: String(a.textContent || '').replace(/\s+/g, ' ').trim(),
    href: String(href),
  })
}

function rangeIntersectsNode(range, node) {
  if (!range || !node) return false
  try {
    if (typeof range.intersectsNode === 'function') {
      return range.intersectsNode(node)
    }
  } catch {
    /* fall through */
  }
  try {
    const nodeRange = document.createRange()
    nodeRange.selectNode(node)
    return (
      range.compareBoundaryPoints(Range.END_TO_START, nodeRange) < 0 &&
      range.compareBoundaryPoints(Range.START_TO_END, nodeRange) > 0
    )
  } catch {
    return false
  }
}

function getSelectionRect() {
  const sel = window.getSelection()
  if (!sel || sel.rangeCount === 0) return null
  const range = sel.getRangeAt(0)
  const rect = range.getBoundingClientRect()
  if (!rect || (rect.width === 0 && rect.height === 0)) return null
  return rect
}

function positionButton(rect) {
  const { btn } = getUi()
  const top = Math.min(window.innerHeight - 48, Math.max(8, rect.bottom + 8))
  const left = Math.min(window.innerWidth - 140, Math.max(8, rect.left + rect.width / 2 - 60))
  btn.style.top = `${top}px`
  btn.style.left = `${left}px`
}

function updateSelectionUi() {
  const text = getSelectionText()
  lastSelectionText = text
  const { btn } = getUi()
  if (!text || !checkLooksLikeConfig(text)) {
    btn.classList.remove('show')
    return
  }
  const rect = getSelectionRect()
  if (!rect) {
    btn.classList.remove('show')
    return
  }
  positionButton(rect)
  btn.classList.add('show')
}

/** looksLikeConfig runs ~15 regexes over up to 64 KiB — memoize per text. */
function checkLooksLikeConfig(text) {
  if (text === lastConfigCheck.text) return lastConfigCheck.ok
  const ok = looksLikeConfig(text)
  lastConfigCheck = { text, ok }
  return ok
}

function scheduleUpdate() {
  clearTimeout(hideTimer)
  hideTimer = setTimeout(updateSelectionUi, 120)
}

function onImportClick(e) {
  e.preventDefault()
  e.stopPropagation()
  previouslyFocused = e.currentTarget
  const text = lastSelectionText || getSelectionText()
  currentTopicTitle = getTopicTitle()
  const { btn } = getUi()
  btn.classList.remove('show')

  const result = parseShareText(text)
  if (!result) {
    openErrorCard(
      text.length > MAX_SELECTION_LEN
        ? '选区过大，配置可能位于未解析的中间部分。请缩小选区，只保留一个完整配置块后重试。'
        : '未识别到 API 配置。请选中包含 base URL / API Key / magpie 深链 / Base64 配置 的文本。',
    )
    return
  }
  currentResult = applyDetectedModels(result, text)
  selectedModels = null
  includeRiskyParams = false
  rebuildDeeplink()
  renderCard(currentResult)
}

/**
 * Merge models extracted from the share text into the parse result.
 * Models already carried by the result (magpie deeplink models= / JSON models
 * field) come first; detected ids are appended without duplicates.
 * @param {object} result
 * @param {string} sourceText
 */
function applyDetectedModels(result, sourceText) {
  const detected = extractModels(sourceText || lastSelectionText || '').models || []
  const existing = Array.isArray(result.models) ? result.models : []
  const seen = new Set()
  const models = []
  for (const m of [...existing, ...detected]) {
    const id = String(m || '').trim()
    if (!id || seen.has(id)) continue
    seen.add(id)
    models.push(id)
  }
  return { ...result, models }
}

function openErrorCard(msg) {
  const { overlay, shadow } = getUi()
  shadow.getElementById('meta').textContent = ''
  shadow.getElementById('fields').style.display = 'none'
  currentPresetSuggestions = []
  shadow.getElementById('preset-suggestions').classList.remove('show')
  shadow.getElementById('preset-suggestions').innerHTML = ''
  shadow.getElementById('url-help').classList.remove('show')
  shadow.getElementById('warn').textContent = ''
  shadow.getElementById('cand').classList.remove('show')
  shadow.getElementById('model-row').style.display = 'none'
  shadow.getElementById('provider-opt').classList.remove('show')
  shadow.getElementById('include-provider-params').checked = false
  shadow.getElementById('provider-meta').textContent = ''
  includeRiskyParams = false
  deeplinkError = null
  const err = shadow.getElementById('err')
  err.style.display = 'block'
  err.textContent = msg
  shadow.getElementById('open').disabled = true
  shadow.getElementById('copy').disabled = true
  showDialog(overlay, shadow.getElementById('cancel'))
}

function renderCard(result) {
  const { overlay, shadow } = getUi()
  const err = shadow.getElementById('err')
  const blockingMessage = deeplinkError?.message || ''
  err.style.display = blockingMessage ? 'block' : 'none'
  err.textContent = blockingMessage
  shadow.getElementById('fields').style.display = 'block'

  const conf = Math.round((result.confidence || 0) * 100)
  const modelCount = result.models?.length || 0
  const candCount = result.candidates?.length || result.candidateCount || 1
  const candIdx = (result.candidateIndex || 0) + 1
  const ver =
    typeof SCRIPT_VERSION !== 'undefined' && SCRIPT_VERSION ? String(SCRIPT_VERSION) : 'dev'
  shadow.getElementById('meta').textContent =
    `识别：${result.source} · 置信度 ${conf}%` +
    (candCount > 1 ? ` · 候选 ${candIdx}/${candCount}` : '') +
    (modelCount ? ` · 模型×${modelCount}` : '') +
    ` · v${ver}`

  const providerInfo = result.providerParams
    ? describeProviderParams(result.providerParams)
    : null

  const chatUrl = result.chat || '—'
  const responsesUrl = result.responses || '—'
  const anthropicUrl = result.anthropic || '—'
  const fields = shadow.getElementById('fields')
  fields.innerHTML = `
    <div><span class="k">name</span>${escapeHtml(result.name || '')}${result.preset ? ` <span class="k">preset</span>${escapeHtml(result.preset)}` : ''}</div>
    <div><span class="k">chat</span>${escapeHtml(chatUrl)}</div>
    <div><span class="k">responses</span>${escapeHtml(responsesUrl)}</div>
    <div><span class="k">anthropic</span>${escapeHtml(anthropicUrl)}</div>
    <div><span class="k">key</span>${escapeHtml(maskKey(result.apiKey || '') || '—')}<button type="button" class="mp-copy-key" id="copy-key" aria-label="复制 Key" title="复制完整 Key"${result.apiKey ? '' : ' disabled'}>
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">
        <rect x="9" y="9" width="13" height="13" rx="2" />
        <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
      </svg>
    </button></div>
    <div><span class="k">models</span>${escapeHtml(formatModelsLine(result))}</div>
    ${
      providerInfo
        ? `<div><span class="k">附加参数</span>${escapeHtml(
            providerInfo.fields.slice(0, 12).join('、'),
          )}${providerInfo.fields.length > 12 ? '…' : ''}</div>`
        : ''
    }
  `

  shadow.getElementById('copy-key').addEventListener('click', copyApiKey)

  currentPresetSuggestions = suggestPresetLinks(
    currentTopicTitle,
    { chat: result.chat, responses: result.responses, anthropic: result.anthropic },
    result.apiKey,
  )
  const presetBox = shadow.getElementById('preset-suggestions')
  const urlHelp = shadow.getElementById('url-help')
  if (currentPresetSuggestions.length) {
    presetBox.classList.add('show')
    presetBox.innerHTML = `
      检测到官方厂商 preset；预设链接只携带 Key，地址由 magpie 内置。
      ${currentPresetSuggestions.map(({ id, name, reason }) => `
        <div class="mp-preset-row">
          <strong>${escapeHtml(name)}（${escapeHtml(id)}）</strong>
          <code>magpie://import?preset=${escapeHtml(id)}&key=…</code>
          <button type="button" class="mp-copy-preset" data-preset-id="${escapeHtml(id)}" aria-label="复制 ${escapeHtml(name)} preset 链接">复制链接</button>
          <div>${escapeHtml(reason)}</div>
        </div>
      `).join('')}
      复制不会自动打开；深链仍以卡片内容为准。
    `
    urlHelp.classList.remove('show')
    urlHelp.textContent = ''
  } else {
    presetBox.classList.remove('show')
    presetBox.innerHTML = ''
    const needsUrl = Boolean(result.apiKey && !result.chat && !result.responses && !result.anthropic)
    urlHelp.classList.toggle('show', needsUrl)
    urlHelp.textContent = needsUrl
      ? '只凭 Key 无法生成导入深链：magpie 需要至少一个 base URL（或 preset）。请从原帖补充地址，或复制 Key 手动添加。'
      : ''
  }

  const providerOpt = shadow.getElementById('provider-opt')
  const includeProviderCb = shadow.getElementById('include-provider-params')
  const providerMeta = shadow.getElementById('provider-meta')
  if (providerInfo?.risky) {
    providerOpt.classList.add('show')
    includeProviderCb.checked = includeRiskyParams
    providerMeta.textContent = [
      providerInfo.riskyFields.length
        ? `高风险：${providerInfo.riskyFields.slice(0, 6).join('、')}`
        : '',
      providerInfo.unknownFields.length
        ? `未知：${providerInfo.unknownFields.slice(0, 6).join('、')}`
        : '',
    ]
      .filter(Boolean)
      .join(' · ')
  } else {
    providerOpt.classList.remove('show')
    includeProviderCb.checked = false
    providerMeta.textContent = ''
  }

  const candEl = shadow.getElementById('cand')
  if (candCount > 1 && result.candidates && result.candidates.length > 1) {
    candEl.classList.add('show')
    shadow.getElementById('cand-label').textContent = `候选 ${candIdx}/${candCount}`
    shadow.getElementById('cand-prev').disabled = (result.candidateIndex || 0) <= 0
    shadow.getElementById('cand-next').disabled =
      (result.candidateIndex || 0) >= result.candidates.length - 1
  } else {
    candEl.classList.remove('show')
  }

  const modelRow = shadow.getElementById('model-row')
  const modelSelect = shadow.getElementById('model-select')
  if (modelCount > 1) {
    modelRow.style.display = 'flex'
    const chosen = selectedModels || result.models
    modelSelect.innerHTML = result.models
      .map(
        (m) =>
          `<option value="${escapeHtml(m)}"${chosen.includes(m) ? ' selected' : ''}>${escapeHtml(m)}</option>`,
      )
      .join('')
  } else {
    modelRow.style.display = 'none'
    modelSelect.innerHTML = ''
  }

  const warn = shadow.getElementById('warn')
  const warnings = [...(result.warnings || [])]
  if (modelCount === 1) warnings.push('已自动填入检测到的唯一模型')
  else if (modelCount > 1) warnings.push(`检测到 ${modelCount} 个模型，全部携带；可在下方多选框调整`)
  if (providerInfo?.risky) {
    warnings.push(
      `风险/未知附加参数默认不携带（${providerInfo.riskReasons.join('；')}）`,
    )
  }
  if (currentDeeplink && currentDeeplink.length > MAX_DEEPLINK_LEN * 0.85) {
    warnings.push(
      `深链较长（${currentDeeplink.length} 字符），若无法唤起请减少字段后重试`,
    )
  }
  warn.textContent = warnings.join('；')

  const blocked = !currentDeeplink
  shadow.getElementById('open').disabled = blocked
  shadow.getElementById('copy').disabled = blocked
  showDialog(overlay, blocked ? shadow.getElementById('cancel') : shadow.getElementById('open'))
}

function formatModelsLine(result) {
  const models = result.models || []
  if (!models.length) return '—（magpie 将自行获取模型列表）'
  const preview = models.slice(0, 3).join('、')
  return models.length > 3 ? `${preview}… 共 ${models.length} 个` : preview
}

function shiftCandidate(delta) {
  if (!currentResult || typeof selectCandidate !== 'function') return
  const list = currentResult.candidates
  if (!list || list.length < 2) return
  const next = selectCandidate(currentResult, (currentResult.candidateIndex || 0) + delta)
  currentResult = next
  selectedModels = null
  rebuildDeeplink()
  renderCard(currentResult)
}

function onModelSelect(e) {
  const options = Array.from(e.target?.selectedOptions || [])
  selectedModels = options.map((o) => o.value).filter(Boolean)
  if (currentResult) {
    currentResult = { ...currentResult, models: selectedModels.slice() }
    rebuildDeeplink()
    renderCard(currentResult)
  }
}

function onIncludeProviderParamsChange(e) {
  includeRiskyParams = !!(e.target && e.target.checked)
  rebuildDeeplink()
  if (currentResult) renderCard(currentResult)
}

function rebuildDeeplink() {
  currentDeeplink = null
  deeplinkError = null
  if (!currentResult) return
  try {
    currentDeeplink = buildDeeplink(currentResult, {
      includeRiskyParams,
    })
  } catch (e) {
    currentDeeplink = null
    deeplinkError = e instanceof Error ? e : new Error(String(e || '无法生成深链'))
  }
}

function showDialog(overlay, preferredFocus) {
  const wasOpen = overlay.classList.contains('show')
  if (!wasOpen && !previouslyFocused) {
    const { shadow } = getUi()
    previouslyFocused = shadow.activeElement || document.activeElement
  }
  overlay.classList.add('show')
  if (!wasOpen) {
    requestAnimationFrame(() => {
      const card = overlay.querySelector('.mp-card')
      const target =
        preferredFocus && !preferredFocus.disabled ? preferredFocus : card
      if (target && typeof target.focus === 'function') target.focus()
    })
  }
}

function closeCard() {
  const { overlay } = getUi()
  if (!overlay.classList.contains('show')) return
  overlay.classList.remove('show')
  const restore = previouslyFocused
  previouslyFocused = null
  if (restore?.id === 'btn') updateSelectionUi()
  if (restore && restore.isConnected && typeof restore.focus === 'function') {
    requestAnimationFrame(() => restore.focus())
  }
}

function copyText(text) {
  if (typeof GM_setClipboard === 'function') {
    GM_setClipboard(text, 'text')
    return Promise.resolve(true)
  }
  if (navigator.clipboard && navigator.clipboard.writeText) {
    return navigator.clipboard.writeText(text).then(() => true).catch(() => false)
  }
  try {
    const ta = document.createElement('textarea')
    ta.value = text
    ta.style.position = 'fixed'
    ta.style.left = '-9999px'
    document.body.appendChild(ta)
    ta.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(ta)
    return Promise.resolve(ok)
  } catch {
    return Promise.resolve(false)
  }
}

async function copyApiKey() {
  const apiKey = currentResult?.apiKey
  if (!apiKey) {
    showToast('未识别到可复制的 Key')
    return
  }
  try {
    const ok = await copyText(apiKey)
    showToast(ok ? 'Key 已复制到剪贴板' : 'Key 复制失败，请重试')
  } catch {
    showToast('Key 复制失败，请重试')
  }
}

/**
 * Copy a `magpie://import?preset=<id>&key=<key>` link for a suggested preset.
 * Never opened automatically — the card stays authoritative.
 * @param {string} presetId
 */
async function copyPresetLink(presetId) {
  const apiKey = currentResult?.apiKey
  const params = new URLSearchParams({ preset: presetId })
  if (apiKey) params.set('key', apiKey)
  const link = `magpie://import?${params.toString()}`
  try {
    const ok = await copyText(link)
    showToast(ok ? 'preset 链接已复制' : 'preset 链接复制失败，请重试')
  } catch {
    showToast('preset 链接复制失败，请重试')
  }
}

function copyDeeplink(fromBtn) {
  if (!currentDeeplink) {
    showToast(deeplinkError?.message || '无法生成深链：缺少 base URL 或 preset')
    return
  }
  copyText(currentDeeplink).then((ok) => {
    showToast(ok ? '深链已复制到剪贴板' : '复制失败，请手动复制')
    if (fromBtn && typeof GM_notification === 'function') {
      try {
        GM_notification({ title: 'magpie Importer', text: '深链已复制', timeout: 2000 })
      } catch (_) {}
    }
  })
}

function openImport() {
  rebuildDeeplink()
  if (!currentDeeplink) {
    showToast(deeplinkError?.message || '无法生成深链')
    return
  }

  const link = currentDeeplink
  const a = document.createElement('a')
  a.href = link
  a.style.display = 'none'
  document.body.appendChild(a)
  try {
    a.click()
  } catch (_) {
    try {
      window.location.href = link
    } catch (_) {}
  }
  setTimeout(() => a.remove(), 0)

  // Do NOT auto-copy the deeplink (contains key). Use「复制深链」if protocol fails.
  showToast('已尝试打开 magpie。若无反应，请点「复制深链」并确认已安装 magpie', 4200)
}

// Entity strings are built via charCode so literal `&xxx;` sequences in the
// source never round-trip through anything that decodes HTML entities.
const HTML_AMP = String.fromCharCode(38)
const HTML_ESCAPE_MAP = {
  '&': HTML_AMP + 'amp;',
  '<': HTML_AMP + 'lt;',
  '>': HTML_AMP + 'gt;',
  '"': HTML_AMP + 'quot;',
  "'": HTML_AMP + '#39;',
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => HTML_ESCAPE_MAP[c])
}

function onKeydown(e) {
  const { overlay, shadow } = getUi()
  if (!overlay.classList.contains('show')) return
  if (e.key === 'Escape') {
    e.preventDefault()
    closeCard()
    return
  }
  if (e.key !== 'Tab') return

  const focusable = Array.from(
    overlay.querySelectorAll(
      'button:not([disabled]), select:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
    ),
  ).filter((element) => element.getClientRects().length > 0)
  if (!focusable.length) {
    e.preventDefault()
    overlay.querySelector('.mp-card')?.focus()
    return
  }
  const active = shadow.activeElement
  const index = focusable.indexOf(active)
  if (e.shiftKey && index <= 0) {
    e.preventDefault()
    focusable[focusable.length - 1].focus()
  } else if (!e.shiftKey && (index < 0 || index === focusable.length - 1)) {
    e.preventDefault()
    focusable[0].focus()
  }
}

function init() {
  document.addEventListener('selectionchange', scheduleUpdate)
  document.addEventListener('mouseup', scheduleUpdate)
  document.addEventListener('keyup', scheduleUpdate)
  document.addEventListener('keydown', onKeydown)
  window.addEventListener('scroll', () => {
    const { btn } = getUi()
    if (!btn.classList.contains('show') || scrollRaf) return
    // Scrolling never changes the selection text — only reposition the button,
    // throttled to one rAF tick.
    scrollRaf = requestAnimationFrame(() => {
      scrollRaf = 0
      const rect = getSelectionRect()
      if (rect) positionButton(rect)
      else btn.classList.remove('show')
    })
  }, true)
  getUi()
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init)
} else {
  init()
}
