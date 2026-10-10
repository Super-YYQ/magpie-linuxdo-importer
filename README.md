# Magpie Importer for linux.do

在 [linux.do](https://linux.do) 选中分享的 API 地址、Key 或配置文本，脚本会在浏览器本地解析内容，并生成 [magpie](https://github.com/yetone/magpie) 的导入深链（`magpie://import?...`），确认后一键导入。确认卡中的 Key 保持脱敏，也可以点击复制图标获取当前候选的完整 Key。

**[安装用户脚本](https://raw.githubusercontent.com/Super-YYQ/magpie-linuxdo-importer/release/userscript/magpie-linuxdo-importer.user.js)** · [最新 Release](https://github.com/Super-YYQ/magpie-linuxdo-importer/releases/latest) · [反馈问题](https://github.com/Super-YYQ/magpie-linuxdo-importer/issues)

## 快速开始

### 安装

1. 在 Chrome、Edge 或 Firefox 中安装 [Tampermonkey](https://www.tampermonkey.net/)。
2. 安装并至少运行一次 [magpie](https://github.com/yetone/magpie)，让系统注册 `magpie://` 协议。
3. 打开上方的“安装用户脚本”链接，由 Tampermonkey 接管安装；也可以从 [GitHub Releases](https://github.com/Super-YYQ/magpie-linuxdo-importer/releases) 下载 `.user.js` 文件。
4. 访问 [linux.do](https://linux.do)，选中帖子中的一段配置文本。

安装脚本和自动更新地址指向 `release` 分支；`main` 分支只保存源码、测试和文档。

### 使用

1. 选中含 API 地址、Key 或配置块的文本。
2. 点击蓝色悬浮按钮 **“导入 magpie”**。
3. 在确认卡中核对 name、chat / responses / anthropic 地址、脱敏 Key 和模型。存在多组 URL/Key 时，使用 **‹ / ›** 切换候选。
4. 按需调整模型列表，以及是否携带风险附加参数。
5. 选择操作：

| 操作 | 效果 |
| --- | --- |
| Key 旁的复制图标 | 复制当前候选的完整 Key，界面仍保持脱敏；支持鼠标和键盘操作 |
| preset 建议旁的“复制链接” | 仅在分享地址或主题标题对应官方厂商时显示；复制 `magpie://import?preset=...&key=...`，不自动打开 |
| 复制深链 | 复制当前导入链接，供手动使用 |
| 打开导入 | 尝试唤起 magpie，不会自动写入剪贴板 |
| 取消或 `Escape` | 关闭确认卡 |

未识别到 Key 时，复制图标不可用。复制成功或失败都会显示提示。preset 建议只是提示：预设端点来自 magpie 内置列表，与中转站实际地址可能不同，深链始终以确认卡内容为准。

## 支持范围

脚本只在 `linux.do` 和 `www.linux.do` 生效。magpie 是统一网关：一个导入即可覆盖所有支持的 agent，无需选择目标应用。

### 分享格式

| 格式 | 示例或处理方式 |
| --- | --- |
| magpie 深链 | `magpie://import?...`；其他 action（如 `magpie://install`）不会误触发 |
| JSON | `baseUrl` / `endpoint` 配合 `apiKey`，可带 `models` 列表 |
| 环境变量 | `ANTHROPIC_BASE_URL`、`ANTHROPIC_AUTH_TOKEN`、`OPENAI_*` 等 |
| TOML / 键值文本 | `base_url = "..."`、`api_key = "..."` |
| Base64 | 编码后的配置、Key 或 Key 字段片段；支持部分多层编码形式 |
| 混排与表格 | 中文说明、URL、Key 混排，以及 `url：` / `key：`、标签和值分行等形式 |

可识别 `sk-`、`sk-ant-`、`g2a_`、`tp-`、`ark-`、`xai-`、`gsk_`、`pplx-`、`r8_`、`hf_`、`fw_`、`oc_sk_` 等常见 Key 前缀。单独选中的长随机串也会作为待核对的 Key 候选，支持明文或 Base64；从一大段文字中提取无固定前缀的 Base64 Key 时仍要求地址、解码提示等上下文，以减少误判。

### 地址与协议

magpie 的深链按协议区分地址：`chat`（OpenAI Chat Completions，通常以 `/v1` 结尾）、`responses`（OpenAI Responses）和 `anthropic`（Messages 根路径）。脚本会按分享地址自动分类：

| 分享地址形态 | 分类结果 |
| --- | --- |
| `https://relay.example.com/v1` | 仅 chat |
| `https://relay.example.com/anthropic`（含 `/anthropic/v1`） | 仅 anthropic（去掉尾部 `/v1`） |
| `https://relay.example.com`（根路径） | 同时作为 chat 和 anthropic，由 magpie 按需使用 |
| 火山方舟 `/api/coding` 与 `/api/coding/v3` | 分别识别为 anthropic 与 chat，互为补充 |

地址要求与 magpie 一致：仅接受 HTTPS，HTTP 只允许本机与局域网（localhost、`*.local`、回环及内网 IP）；带查询参数、锚点或账号密码的地址会被阻止。

### 模型列表

| 文本内容 | 行为 |
| --- | --- |
| 识别到一个或多个模型 | 全部进入深链 `models` 参数（逗号列表），可在确认卡多选框中调整 |
| 只有“支持所有模型”等描述 | 不填入模型，由 magpie 自行获取模型列表 |

已识别的模型 ID 会保留日期和版本信息，例如 `claude-sonnet-4-5-20250929`。模型来自选中文本，脚本不会访问供应商接口查询模型列表。

## 解析示例

以下示例全部使用合成数据，不包含可用密钥。

### 环境变量

```text
ANTHROPIC_BASE_URL=https://relay.example.invalid
ANTHROPIC_AUTH_TOKEN=sk-ant-api03-TESTONLY-readme-fixture
```

### JSON

```json
{
  "name": "Example Relay",
  "baseUrl": "https://relay.example.invalid/v1",
  "apiKey": "sk-ant-api03-TESTONLY-readme-fixture",
  "models": ["claude-sonnet-4-20250514", "gpt-5.1"]
}
```

### 全角标签与 Base64 Key

```text
url：https://relay.example.invalid/v1
key（Base64）：c2stYW50LWFwaTAzLVRFU1RPTkxZLXJlYWRtZS1maXh0dXJl
```

## 隐私与安全

- **本地解析**：不上传或在线验证 Key，也不监听剪贴板内容。
- **脱敏显示**：确认卡隐藏 Key 中间部分；只有主动点击复制图标或“复制深链”时，才会写入剪贴板。
- **参数检查**：风险深链参数（`website`、`keys`、`icon`）和未知参数默认不携带，需要显式勾选才进入深链。
- **地址校验**：仅接受 HTTPS（本机/局域网 HTTP 除外）；带凭据、查询参数或锚点的地址会被阻止，与 magpie 的校验规则一致。
- **长度限制**：选区超过 64 KiB 时只解析开头和结尾，并提示中间内容已省略。最终深链最多 8,000 个字符，超限时不能复制或打开。
- **保密建议**：导入前核对地址和配置来源；截图、Issue 和提交记录中不要包含真实 Key。

## 常见问题

### 选中文字后没有出现按钮

确认脚本已启用，并且当前页面属于支持站点。尽量完整选中地址、Key 或配置块，不要只选说明文字。

### Key 显示为 `****`，怎样复制原值？

点击 Key 旁的复制图标。

### 点击“打开导入”没有反应

确认已安装并运行过 magpie，且系统已经注册 `magpie://` 协议。也可以点击“复制深链”，再将链接粘贴到地址栏尝试打开。

### 只有 Key，没有地址

magpie 的导入需要至少一个 base URL 或 preset。脚本会提示“只凭 Key 无法生成导入深链”，此时可以从原帖补充地址，或复制 Key 到 magpie 中手动添加；若主题标题明确提到官方厂商，也可以复制 preset 链接。

### 提示深链过长

缩小选区、缩短输入字段或减少模型后重试。

### 模型没有识别出来

确认选中文本包含具体且已支持的模型 ID。有多个候选模型时，可以在确认卡的多选框中调整。

## 本地开发

项目要求 **Node.js 18 或更高版本**。

```bash
npm ci
npx playwright install chromium
npm run check
```

| 命令 | 用途 |
| --- | --- |
| `npm test` | 运行解析器、模型提取、发布守卫单元测试及格式变体验证 |
| `npm run test:browser` | 先构建，再运行 Chromium 交互测试 |
| `npm run build` | 将源码打包为单文件油猴脚本 |
| `npm run check` | 运行完整的单元与浏览器检查 |

本地构建产物为 `userscript/magpie-linuxdo-importer.user.js`，已被 Git 忽略。修改源码后需重新构建，再安装到 Tampermonkey 验证。

### 目录结构

| 路径 | 职责 |
| --- | --- |
| [`userscript/ui-main.js`](userscript/ui-main.js) | 选区识别、确认卡、复制和导入交互 |
| [`userscript/lib/core.mjs`](userscript/lib/core.mjs) | 配置解析、归一化、协议分类、风险检查和深链构建 |
| [`userscript/lib/model-extractor.mjs`](userscript/lib/model-extractor.mjs) | 模型 ID 提取 |
| [`scripts/build.mjs`](scripts/build.mjs) | 打包脚本、注入版本及安装更新地址 |
| [`scripts/release-guard.mjs`](scripts/release-guard.mjs) | 版本比较和发布产物哈希检查 |
| [`tests/`](tests/) | 单元、格式变体和浏览器回归测试 |
| [`.github/workflows/`](.github/workflows/) | CI 与标签触发的发布工作流 |

## 发布说明

| 分支 | 内容 |
| --- | --- |
| `main` | 源码、测试和文档；普通推送只触发 CI |
| `release` | 正式安装脚本，由发布工作流维护，也是 Tampermonkey 的更新来源 |

只更新源码或文档时，提交并推送 `main` 即可，不需要发布标签。正式发版流程如下：

1. 同步更新 `package.json` 和 `package-lock.json` 中的版本号。
2. 运行 `npm run check`，将通过验证的改动提交并推送到 `main`。
3. 为该提交创建 `v<版本号>` 标签并推送；标签必须与包版本一致。
4. 等待 [Release 工作流](.github/workflows/release.yml) 完成，核对 GitHub Release 附件和 `release` 分支脚本。

发布流程先以只读权限测试和构建，再通过版本及 SHA-256 守卫发布。它会阻止版本降级，以及用不同内容覆盖同一版本。

## 许可证

[MIT License](LICENSE) · © 2026 Magpie Importer Contributors

本项目代码与文档由 AI 辅助编写，请审查后使用。
