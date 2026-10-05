# Chick Zone

**在线体验：https://chickchat.cc.cd** ｜ 一个部署在 Cloudflare Workers + D1 上的轻量个人社区站。单文件 Worker，复制粘贴即可运行。

> 不想自己部署？直接来站点看看：<https://chickchat.cc.cd>

## 功能一览

- 聊天大厅（10 秒轮询增量同步、撤回、图片消息、@机器人）
- 帖子 / 评论 / 点赞 / 撤回 / 置顶
- 网址导航（分类筛选、提交审核）
- 用户主页（头像、签名、等级徽章、统计）
- 私聊（分栏显示、引用、图片、未读提醒，限额制）
- 赞助等级 + 荣誉墙（进度条、上榜授权）
- 签到 / 抽奖 / 积分
- AI 内容审核（发布前拦截 + 举报异步复核）
- AI 群友「会看心情说话」，@它可触发回复
- 管理面板（统计/用户/帖子/消息/举报/赞助/网址/搜索/图片/AI 十个模块）
- 站长专用投稿 API（读写，给 AI 工具/自动化用）
- SEO：动态 sitemap.xml、robots.txt、IndexNow 推送
- 防滥用：Turnstile 人机验证、限流、自动清理、警告累计 3 次自动禁言

## 部署前置

需要：Cloudflare 账号、Node.js 18+、wrangler CLI（`npm install -g wrangler`）

## 环境变量（重点）

| 变量名 | 必填 | 类型 | 作用 | 去哪拿 |
|---|---|---|---|---|
| `DB` | ✅ | D1 绑定 | 数据库，**绑定名必须叫 DB** | `wrangler d1 create` 创建后填 database_id |
| `SECRET` | ✅ | Secret | 会话 token 签名、验证码；不设置服务器直接 500 | 自己随便生成一串长随机字符 |
| `ADMIN_KEY` | ✅ | Secret | 注册站长时填的密钥（只用于第一个站长注册） | 自己设一个强密码 |
| `TURNSTILE_SITE_KEY` | 可选 | 明文/Secret | 人机验证前端 key | Cloudflare Dashboard → Turnstile |
| `TURNSTILE_SECRET` | 可选 | Secret | 人机验证服务端校验；**不设置 = 跳过人机验证**（开发期方便） | 同上 |
| `AI_KEY` | 可选 | Secret | DeepSeek API Key（内容审核 / 机器人 / 赞助截图识别）；不设置 = 所有 AI 功能关闭 | platform.deepseek.com |
| `AI_BASE` | 可选 | 明文 | AI 接口地址，默认 `https://api.deepseek.com` | — |
| `AI_MODEL` | 可选 | 明文 | 文本模型，默认 `deepseek-chat` | — |
| `AI_DAILY_LIMIT` | 可选 | 明文 | 每日 AI 调用上限，默认 `100` | — |
| `BOT_ENABLED` | 可选 | 明文 | `1` 开启 AI 机器人，`0` 关闭，默认开 | — |
| `INDEXNOW_KEY` | 可选 | 明文 | IndexNow 推送密钥（Bing/Yandex 快速收录） | 自己生成一串随机 hex |
| `BAIDU_TOKEN` | 可选 | Secret | 百度搜索推送 token | 百度搜索资源平台 |

## 部署步骤

```bash
npm install -g wrangler
wrangler login

# 1. 建数据库（记下输出的 database_id，填进 wrangler.toml）
wrangler d1 create chickzone-db

# 2. 填好 wrangler.toml 里的 database_id

# 3. 添加密钥（按提示输入值）
wrangler secret put SECRET
wrangler secret put ADMIN_KEY
wrangler secret put AI_KEY          # 可选
wrangler secret put TURNSTILE_SECRET # 可选

# 4. 部署
wrangler deploy
```

## 首次使用

1. 打开站点首页
2. 点「没有账号？注册一个」
3. 注册时**站长密钥**一栏填 `ADMIN_KEY` 的值 → 该账号成为站长（role=2）
4. 站长进「我的 → 管理面板」可管理一切；其他用户注册不带该密钥，就是普通用户

## 常见报错

| 报错 | 原因 |
|---|---|
| 401 请先登录 | 未登录或 token 过期（重新登录） |
| 403 无权限 | 权限不够（如普通用户操作管理功能）或被禁言 |
| 403 服务器未绑定 D1 | 变量名不是 `DB` |
| 429 过于频繁 | 触发限流，等一会儿 |
| 500 服务器未设置 SECRET | 环境变量 SECRET 没添加 |

## 自定义

- **站点名**：worker.js 配置区的 `SITE_NAME`
- **收款码**：worker.js 配置区的 `PAY_ALIPAY` / `PAY_WECHAT`（填图片的 data URL）
- **AI 模型 / 开关**：环境变量 `AI_MODEL` / `BOT_ENABLED`
- **违禁词库**：worker.js 里的 `BAD` 对象（分 1/2/3 三级）

## 目录结构

```
chickzone/
├── worker.js      # 后端 + 前端（单文件，前端内嵌于 HTML_MODERN 模板字符串）
├── wrangler.toml  # 部署配置模板
├── README.md
├── LICENSE        # MIT
└── .gitignore     # 已挡掉 .dev.vars / .env 等
```

## License

MIT
