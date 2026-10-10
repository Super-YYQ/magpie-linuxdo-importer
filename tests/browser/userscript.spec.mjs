import { test, expect } from '@playwright/test'
import fs from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const userscriptPath = path.resolve(
  here,
  '../../userscript/magpie-linuxdo-importer.user.js',
)

async function installUserscript(page, shareText, topicTitle = '') {
  await page.setContent(
    '<main><h1 id="topic-title"><span class="fancy-title"></span></h1><p id="share"></p></main>',
  )
  await page.evaluate(() => {
    window.__copiedDeeplinks = []
    window.__openedDeeplinks = []
    window.GM_setClipboard = (text) => window.__copiedDeeplinks.push(text)
    window.GM_notification = () => {}
    HTMLAnchorElement.prototype.click = function () {
      if (String(this.href).startsWith('magpie:')) {
        window.__openedDeeplinks.push(this.href)
        return
      }
      HTMLElement.prototype.click.call(this)
    }
  })
  await page.locator('#share').evaluate((element, text) => {
    element.textContent = text
  }, shareText)
  await page
    .locator('#topic-title .fancy-title')
    .evaluate((element, title) => {
      element.textContent = title
      document.title = title
    }, topicTitle)
  await page.addScriptTag({ content: await fs.readFile(userscriptPath, 'utf8') })
}

async function selectShare(page) {
  await page.locator('#share').evaluate((element) => {
    const range = document.createRange()
    range.selectNodeContents(element)
    const selection = window.getSelection()
    selection.removeAllRanges()
    selection.addRange(range)
    document.dispatchEvent(new Event('selectionchange', { bubbles: true }))
    element.dispatchEvent(new MouseEvent('mouseup', { bubbles: true }))
  })
}

async function shadowState(page) {
  return page.locator('#mp-ld-root').evaluate((host) => {
    const root = host.shadowRoot
    return {
      activeId: root.activeElement?.id || null,
      overlayOpen: root.getElementById('overlay').classList.contains('show'),
    }
  })
}

test('copies the complete decoded API key while keeping it masked in the dialog', async ({
  page,
}) => {
  const apiKey = 'sk-ant-api03-TESTONLY-copy-key-browser-fixture'
  const encodedKey = Buffer.from(apiKey).toString('base64')
  await installUserscript(
    page,
    `base_url = "https://relay.example.invalid/v1"\nkey（base64）：${encodedKey}`,
  )
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()
  const fields = root.locator('#fields')
  await expect(fields).toContainText('****')
  await expect(fields).not.toContainText(apiKey)
  expect(await page.evaluate(() => window.__copiedDeeplinks)).toEqual([])

  const copyKey = root.getByRole('button', { name: '复制 Key', exact: true })
  await expect(copyKey).toBeVisible()
  await copyKey.click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks))
    .toEqual([apiKey])
  await expect(root.locator('#toast')).toHaveText('Key 已复制到剪贴板')
  await expect(fields).not.toContainText(apiKey)
  expect(await page.evaluate(() => window.__openedDeeplinks)).toEqual([])
})

test('recognizes a lone encoded key and explains the missing URL', async ({ page }) => {
  const apiKey = 'oc_sk_TESTONLY0000000000000000000000000000'
  const encodedKey = Buffer.from(apiKey).toString('base64')
  await installUserscript(page, encodedKey, '普通中转站分享')
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await expect(root.locator('#btn')).toBeVisible()
  await root.locator('#btn').click()
  await expect(root.locator('#fields')).toContainText('chat—')
  await expect(root.locator('#fields')).not.toContainText(apiKey)

  const urlHelp = root.locator('#url-help')
  await expect(urlHelp).toBeVisible()
  await expect(urlHelp).toContainText('只凭 Key 无法生成导入深链')
  await root.getByRole('button', { name: '复制 Key', exact: true }).click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks))
    .toEqual([apiKey])
  // No URL → no import link can be opened or copied
  await expect(root.locator('#copy')).toBeDisabled()
  await expect(root.locator('#open')).toBeDisabled()
  expect(await page.evaluate(() => window.__openedDeeplinks)).toEqual([])
})

test('suggests a preset link when the topic title names the official vendor', async ({
  page,
}) => {
  const apiKey = 'sk-ant-api03-deeplinkkey'
  await installUserscript(page, apiKey, '分享一个 anthropic 官方 key')
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()

  const suggestions = root.locator('#preset-suggestions')
  await expect(suggestions).toBeVisible()
  await expect(suggestions).toContainText('anthropic')
  await root
    .getByRole('button', { name: '复制 Anthropic preset 链接' })
    .click()
  const copied = await page.evaluate(() => window.__copiedDeeplinks)
  expect(copied).toHaveLength(1)
  expect(copied[0]).toMatch(/^magpie:\/\/import\?preset=anthropic&key=/)
  expect(copied[0]).toContain(encodeURIComponent(apiKey))

  // The confirm card still shows the key-only state: no URL was invented.
  await expect(root.locator('#fields')).toContainText('chat—')
  expect(await page.evaluate(() => window.__openedDeeplinks)).toEqual([])
})

test('does not suggest presets for relay-worded titles', async ({ page }) => {
  const apiKey = 'sk-ant-api03-deeplinkkey'
  await installUserscript(page, apiKey, '某某中转站 openai 线路')
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()
  await expect(root.locator('#preset-suggestions')).toBeHidden()
})

test('copies the current candidate API key after switching candidates', async ({ page }) => {
  const firstKey = 'sk-ant-api03-TESTONLY-candidate-first-1111'
  const secondKey = 'sk-ant-api03-TESTONLY-candidate-second-2222'
  await installUserscript(
    page,
    `https://relay.example.invalid/v1\n${firstKey}\n${secondKey}`,
  )
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()
  const copyKey = root.getByRole('button', { name: '复制 Key', exact: true })
  await copyKey.click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks))
    .toEqual([firstKey])

  await root.getByRole('button', { name: '下一组候选' }).click()
  await expect(root.locator('#cand-label')).toHaveText('候选 2/2')
  await copyKey.click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks))
    .toEqual([firstKey, secondKey])

  await root.getByRole('button', { name: '上一组候选' }).click()
  await copyKey.click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks))
    .toEqual([firstKey, secondKey, firstKey])
})

test('disables API key copying when a later selection has no key', async ({ page }) => {
  await installUserscript(page, 'sk-ant-api03-TESTONLY-previous-key-fixture')
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()
  await expect(
    root.getByRole('button', { name: '复制 Key', exact: true }),
  ).toBeEnabled()
  await root.locator('#cancel').click()
  await page.locator('#share').click()
  await expect(root.locator('#btn')).toBeHidden()

  await page.locator('#share').evaluate((element) => {
    element.textContent = 'OPENAI_BASE_URL=https://relay.example.invalid/v1'
  })
  await selectShare(page)
  await root.locator('#btn').click()
  await expect(
    root.getByRole('button', { name: '复制 Key', exact: true }),
  ).toBeDisabled()
  expect(await page.evaluate(() => window.__copiedDeeplinks)).toEqual([])
})

test('reports API key clipboard failures without claiming success', async ({ page }) => {
  await installUserscript(page, 'sk-ant-api03-TESTONLY-clipboard-failure-fixture')
  await page.evaluate(() => {
    window.GM_setClipboard = () => {
      throw new Error('Clipboard unavailable in this fixture')
    }
  })
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()
  await root.getByRole('button', { name: '复制 Key', exact: true }).click()
  await expect(root.locator('#toast')).toHaveText('Key 复制失败，请重试')
  expect(await page.evaluate(() => window.__copiedDeeplinks)).toEqual([])
})

test('runs the critical userscript import flow in Chromium', async ({ page }) => {
  const config = JSON.stringify({
    name: 'Browser fixture',
    env: {
      ANTHROPIC_BASE_URL: 'https://relay.example.invalid/v1',
      ANTHROPIC_AUTH_TOKEN: 'sk-ant-api03-TESTONLY-browser-fixture',
    },
    notes: '也支持 gpt-5.5 与 claude-sonnet-4-6',
  })
  await installUserscript(page, config)
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  const trigger = root.locator('#btn')
  await expect(trigger).toBeVisible()
  await trigger.click()

  const dialog = root.getByRole('dialog', { name: '导入到 magpie' })
  await expect(dialog).toBeVisible()
  await expect(root.locator('#fields')).toContainText('claude-sonnet-4-6')
  await expect.poll(async () => (await shadowState(page)).activeId).toBe('open')
  await page.keyboard.press('Tab')
  await expect.poll(async () => (await shadowState(page)).activeId).toBe('copy-key')
  await page.keyboard.press('Tab')
  // multi-model select is visible when more than one model is detected
  await expect(root.locator('#model-select')).toBeVisible()
  await expect.poll(async () => (await shadowState(page)).activeId).toBe(
    'model-select',
  )
  await page.keyboard.press('Shift+Tab')
  await expect.poll(async () => (await shadowState(page)).activeId).toBe('copy-key')
  await page.keyboard.press('Shift+Tab')
  await expect.poll(async () => (await shadowState(page)).activeId).toBe('open')

  await root.locator('#copy').click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks.length))
    .toBe(1)
  const copied = await page.evaluate(() => window.__copiedDeeplinks[0])
  expect(copied).toMatch(/^magpie:\/\/import\?/)
  const params = new URLSearchParams(copied.slice(copied.indexOf('?') + 1))
  expect(params.get('name')).toBe('Browser fixture')
  expect(params.get('chat')).toBe('https://relay.example.invalid/v1')
  expect(params.has('key')).toBe(true)
  expect(params.get('models')).toContain('claude-sonnet-4-6')
  expect(params.get('models')).toContain('gpt-5.5')

  await root.locator('#open').click()
  await expect
    .poll(() => page.evaluate(() => window.__openedDeeplinks.length))
    .toBe(1)
  const opened = await page.evaluate(() => window.__openedDeeplinks[0])
  expect(opened).toMatch(/^magpie:\/\/import\?/)

  await page.keyboard.press('Escape')
  await expect(dialog).toBeHidden()
  await expect.poll(async () => (await shadowState(page)).activeId).toBe('btn')
})

test('requires opt-in before risky provider parameters are carried', async ({ page }) => {
  const params = new URLSearchParams({
    name: 'Risky fixture',
    chat: 'https://relay.example.invalid/v1',
    key: 'sk-ant-api03-TESTONLY-overlong-browser-fixture',
    website: 'https://vendor.example.invalid',
    keys: 'https://vendor.example.invalid/keys',
  })
  await installUserscript(page, `magpie://import?${params}`)
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()

  // risky params are disclosed and off by default
  await expect(root.locator('#provider-opt')).toBeVisible()
  await expect(root.locator('#provider-meta')).toContainText('website')
  await root.locator('#copy').click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks.length))
    .toBe(1)
  const defaultLink = await page.evaluate(() => window.__copiedDeeplinks[0])
  expect(defaultLink).not.toContain('website=')
  expect(defaultLink).not.toContain('keys=')

  await root.locator('#include-provider-params').check()
  await root.locator('#copy').click()
  await expect
    .poll(() => page.evaluate(() => window.__copiedDeeplinks.length))
    .toBe(2)
  const optedIn = await page.evaluate(() => window.__copiedDeeplinks[1])
  expect(optedIn).toContain('website=')
  expect(optedIn).toContain('keys=')
})

test('shows an actionable error instead of copying or opening an overlong link', async ({
  page,
}) => {
  const params = new URLSearchParams({
    name: 'N'.repeat(8_000),
    chat: 'https://relay.example.invalid/v1',
    key: 'sk-ant-api03-TESTONLY-overlong-browser-fixture',
  })
  await installUserscript(page, `magpie://import?${params}`)
  await selectShare(page)

  const root = page.locator('#mp-ld-root')
  await root.locator('#btn').click()

  await expect(root.locator('#err')).toContainText('深链过长')
  await expect(root.locator('#copy')).toBeDisabled()
  await expect(root.locator('#open')).toBeDisabled()
  expect(await page.evaluate(() => window.__copiedDeeplinks)).toEqual([])
  expect(await page.evaluate(() => window.__openedDeeplinks)).toEqual([])
})
