/* ============================================================
 *  工具层
 * ============================================================ */
const enc = new TextEncoder();
const J = (d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { "Content-Type": "application/json" } });
const H = (s) => new Response(s, { headers: { "Content-Type": "text/html;charset=UTF-8" } });
const cut = (s, n) => (typeof s === "string" ? s : "").trim().slice(0, n);
const now = () => new Date(Date.now() + 8 * 3600e3).toISOString().slice(0, 16).replace("T", " ");
const today = () => new Date(Date.now() + 8 * 3600e3).toISOString().slice(0, 10);
const daysAgo = (n) => new Date(Date.now() + 8 * 3600e3 - n * 86400e3).toISOString().slice(0, 10);

const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://challenges.cloudflare.com",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "connect-src 'self' https://challenges.cloudflare.com",
  "frame-src https://challenges.cloudflare.com",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
  "upgrade-insecure-requests"
].join("; ");

function corsHeaders(req) {
  const origin = req.headers.get("Origin");
  const host = req.headers.get("Host");
  const h = {
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type,X-Token",
    "Vary": "Origin",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Content-Security-Policy": CSP
  };
  if (origin && host) { try { if (new URL(origin).host === host) h["Access-Control-Allow-Origin"] = origin; } catch {} }
  return h;
}

function detectTier(ua) {
  if (!ua) return 2;
  const ieM = /msie\s+(\d+\.\d+)/i.exec(ua);
  if (ieM) return parseFloat(ieM[1]) < 9 ? 0 : 1;
  if (/trident\/7\.0/i.test(ua) && /rv:\d+/i.test(ua)) return 1;
  const aM = /android\s+(\d+)/i.exec(ua);
  if (aM) { const v = parseInt(aM[1], 10); if (v < 4) return 0; if (v < 6) return 1; return 2; }
  if (/msie|opera mini|opera mobi|windows phone os 7|symbianos|nokia/i.test(ua)) return 1;
  if (/chrome\/|firefox\/|edg\/|safari\//i.test(ua)) return 2;
  return 1;
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}
async function hashPass(pass, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pass), "PBKDF2", false, ["deriveBits"]);
  const b = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: enc.encode(salt), iterations: 10000, hash: "SHA-256" }, k, 256);
  return [...new Uint8Array(b)].map(x => x.toString(16).padStart(2, "0")).join("");
}
function rand(n = 16) { const a = crypto.getRandomValues(new Uint8Array(n)); return [...a].map(b => b.toString(16).padStart(2, "0")).join(""); }
function safeEq(a, b) { if (typeof a !== "string" || typeof b !== "string") return false; if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i); return d === 0; }
async function signToken(uid, role, secret) { const exp = Date.now() + 7 * 86400e3; const payload = uid + "." + role + "." + exp; return payload + "." + await hmacHex(secret, payload); }
async function verifyToken(token, secret) {
  if (typeof token !== "string" || !secret) return null;
  const i = token.lastIndexOf(".");
  if (i < 0) return null;
  const payload = token.slice(0, i), sig = token.slice(i + 1);
  const expect = await hmacHex(secret, payload);
  if (!safeEq(expect, sig)) return null;
  const p = payload.split(".");
  if (p.length !== 3) return null;
  const uid = +p[0], role = +p[1], exp = +p[2];
  if (!Number.isFinite(uid) || !Number.isFinite(role) || !Number.isFinite(exp)) return null;
  if (Date.now() > exp) return null;
  return { uid, role };
}
async function me(req, env) {
  const d = await verifyToken(req.headers.get("X-Token"), env.SECRET);
  if (!d) return null;
  return await env.DB.prepare("SELECT id,name,role,points,banned,streak,last_sign,post_day,post_count,account,created,last_active,warn_count,avatar,bio,sponsor_level,sponsor_total,vip_expire FROM users WHERE id=?").bind(d.uid).first();
}
const isManager = (u) => u && u.role >= 1;
const isOwner = (u) => u && u.role >= 2;

const SPONSOR_LEVELS = [
  { lv: 0, name: "普通用户", min: 0, color: "#8b949e", badge: "", postLimit: 5, avatarMax: 0 },
  { lv: 1, name: "支持者", min: 10, color: "#58a6ff", badge: "★", postLimit: 10, avatarMax: 150 },
  { lv: 2, name: "赞助者", min: 50, color: "#3fb950", badge: "★★", postLimit: 20, avatarMax: 180 },
  { lv: 3, name: "贵宾", min: 100, color: "#d29922", badge: "★★★", postLimit: 30, avatarMax: 200 },
  { lv: 4, name: "荣誉会员", min: 500, color: "#f85149", badge: "★★★★", postLimit: 999, avatarMax: 220 }
];
function getSponsorLevel(total) {
  let lv = 0;
  for (const s of SPONSOR_LEVELS) if (total >= s.min) lv = s.lv;
  return SPONSOR_LEVELS[lv];
}

async function genCaptcha(env) {
  const a = Math.floor(Math.random() * 9) + 1;
  const b = Math.floor(Math.random() * 9) + 1;
  const exp = Date.now() + 5 * 60 * 1000;
  const payload = (a + b) + "." + exp;
  const sig = await hmacHex(env.SECRET, payload);
  return { q: a + " + " + b + " = ?", token: payload + "." + sig };
}
async function verifyCaptcha(env, token, ans) {
  if (!token || ans === undefined || ans === null || ans === "") return false;
  const p = String(token).split(".");
  if (p.length !== 3) return false;
  const exp = +p[1];
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const expect = await hmacHex(env.SECRET, p[0] + "." + p[1]);
  if (expect !== p[2]) return false;
  return +p[0] === +ans;
}

const RL = new Map();
function rlMem(key, max, winMs) {
  const t = Date.now();
  const bucket = Math.floor(t / winMs);
  const k = key + "|" + bucket;
  const n = (RL.get(k) || 0) + 1;
  RL.set(k, n);
  if (RL.size > 10000) for (const [kk] of RL) { const b = +kk.split("|").pop(); if (b < bucket - 1) RL.delete(kk); }
  return n <= max;
}
async function rlD1(db, key, max, winMs) {
  const t = Date.now();
  const bucket = Math.floor(t / winMs);
  const k = key + "|" + bucket;
  const exp = (bucket + 2) * winMs;
  try {
    const r = await db.prepare("INSERT INTO rl(k,n,exp) VALUES(?,1,?) ON CONFLICT(k) DO UPDATE SET n=n+1 RETURNING n").bind(k, exp).first();
    const n = (r && typeof r.n === "number") ? r.n : 1;
    if (Math.random() < 0.01) db.prepare("DELETE FROM rl WHERE exp < ?").bind(t).run().catch(() => {});
    return n <= max;
  } catch { return true; }
}
function ipOf(req) { return req.headers.get("CF-Connecting-IP") || req.headers.get("X-Forwarded-For") || "unknown"; }

async function verifyTurnstile(env, token, ip) {
  if (!env.TURNSTILE_SECRET) return true;
  if (!token) return false;
  try {
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET, response: token, remoteip: ip })
    });
    const d = await r.json();
    return d.success === true;
  } catch { return false; }
}
async function verifyHuman(env, b, ip) {
  if (b.authMethod === "captcha") return await verifyCaptcha(env, b.captchaToken, b.captchaAns);
  if (!env.TURNSTILE_SECRET) return true;
  return await verifyTurnstile(env, b.turnstileToken, ip);
}

const BAD = {
  3: ["诈骗","博彩","赌博网站","洗钱","毒品","冰毒","海洛因","摇头丸","枪支","弹药","爆炸物","代开","办证","嫖娼","卖淫","招嫖","裸聊","迷药","听话水","性交易","援交","血腥","斩首","恐怖袭击","炸弹制作","制造炸药"],
  2: ["色情","黄片","黄图","约炮","一夜情","包养","成人片","A片","淫秽","情色","傻逼","傻B","煞笔","操你","草泥马","去死","杂种","杂碎","狗东西","死全家","人肉","开盒","户籍查","查全家","身份证号出售","一夜暴富","刷单","代练","返利","带你赚钱","投资群","二维码加","加微信领","加QQ领"],
  1: ["妈的","他妈的","滚蛋","白痴","废物","弱智","神经病","垃圾人","恶心人","脑残","智障","缺德","不是人","恶心"]
};
function scanWords(text) {
  const s = String(text || "");
  let maxLv = 0, hit = "";
  for (let lv = 3; lv >= 1; lv--) {
    for (let i = 0; i < BAD[lv].length; i++) {
      if (s.indexOf(BAD[lv][i]) >= 0) { if (lv > maxLv) { maxLv = lv; hit = BAD[lv][i]; } break; }
    }
  }
  return { lv: maxLv, word: hit };
}

const AI_SYS = `你是中文社区内容审核员。严格按JSON输出，不要任何多余文字：
{"level":0-3,"reason":"10字内原因"}
0=正常 1=轻度不当 2=中度违规 3=严重违规
只输出JSON。`;

async function aiQuotaOK(db, env) {
  const limit = +(env.AI_DAILY_LIMIT || 100);
  const d = today();
  const row = await db.prepare("SELECT n FROM aiq WHERE d=?").bind(d).first();
  if (row && row.n >= limit) return false;
  try { await db.prepare("INSERT INTO aiq(d,n) VALUES(?,1) ON CONFLICT(d) DO UPDATE SET n=n+1").bind(d).run(); } catch {}
  return true;
}
async function aiCheck(env, content, kind, hint) {
  if (!env.AI_KEY) return { level: 0, reason: "AI未配置" };
  const t = String(content || "").slice(0, 1500);
  if (!t.trim()) return { level: 0, reason: "空" };
  try {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 12000);
    const r = await fetch((env.AI_BASE || "https://api.deepseek.com") + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.AI_KEY },
      body: JSON.stringify({
        model: env.AI_MODEL || "deepseek-chat",
        messages: [{ role: "system", content: AI_SYS }, { role: "user", content: "类型：" + kind + (hint ? "\n举报原因：" + hint : "") + "\n内容：\n" + t }],
        response_format: { type: "json_object" }, temperature: 0, max_tokens: 100
      }), signal: ctl.signal
    });
    clearTimeout(to);
    if (!r.ok) return { level: 0, reason: "AI接口异常" };
    const d = await r.json();
    const j = JSON.parse(d.choices?.[0]?.message?.content || "{}");
    return { level: Math.max(0, Math.min(3, +j.level || 0)), reason: String(j.reason || "").slice(0, 80) };
  } catch { return { level: 0, reason: "AI超时" }; }
}
async function aiSponsorCheck(env, imageData) {
  if (!env.AI_KEY) return { ok: false, amount: 0, reason: "AI未配置" };
  const sys = `你是赞助凭证审核员。用户上传一张图片声称是转账截图。
严格按JSON输出：{"valid":true/false,"amount":数字,"reason":"10字内"}
valid=true 仅当图片看起来像真实的微信/支付宝/银行转账截图，且能看到金额。
amount 是识别到的金额（元），无法识别填 0。
不是转账截图、金额无法识别、或疑似伪造，则 valid=false。`;
  try {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 20000);
    const r = await fetch((env.AI_BASE || "https://api.deepseek.com") + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.AI_KEY },
      body: JSON.stringify({
        model: env.AI_VISION_MODEL || env.AI_MODEL || "deepseek-chat",
        messages: [
          { role: "system", content: sys },
          { role: "user", content: [
            { type: "text", text: "这是用户的赞助凭证，请审核。" },
            { type: "image_url", image_url: { url: imageData } }
          ]}
        ],
        response_format: { type: "json_object" },
        temperature: 0, max_tokens: 150
      }), signal: ctl.signal
    });
    clearTimeout(to);
    if (!r.ok) return { ok: false, amount: 0, reason: "AI接口异常" };
    const d = await r.json();
    const j = JSON.parse(d.choices?.[0]?.message?.content || "{}");
    return {
      ok: j.valid === true,
      amount: Math.max(0, Math.min(10000, +j.amount || 0)),
      reason: String(j.reason || "").slice(0, 60)
    };
  } catch { return { ok: false, amount: 0, reason: "AI超时" }; }
}

async function bumpWarn(db, uid, uname, level, reason, ttype, tid) {
  const u = await db.prepare("UPDATE users SET warn_count=COALESCE(warn_count,0)+1 WHERE id=? RETURNING warn_count").bind(uid).first();
  const wc = (u && u.warn_count) || 1;
  if (wc >= 3) await db.prepare("UPDATE users SET banned=1 WHERE id=?").bind(uid).run();
  await db.prepare("INSERT INTO alog(auid,aname,action,target,time) VALUES(?,?,?,?,?)")
    .bind(0, "AI审核", "Lv" + level + "·累计" + wc + "次" + (wc >= 3 ? "·已禁言" : ""), (uname || "") + " " + ttype + "#" + tid + " " + reason, now()).run();
}
async function moderate(env, db, uid, uname, content, ttype, opt = {}) {
  if (opt.role >= 2) return { blocked: false, level: 0 };
  const scan = scanWords(content);
  if (scan.lv >= 2) {
    await bumpWarn(db, uid, uname, scan.lv, "命中违规词", ttype, 0);
    return { blocked: true, level: scan.lv, msg: "内容含违规词，已被拒绝" };
  }
  const needAI = scan.lv >= 1 || opt.report === true || Math.random() < (opt.sampleRate ?? 0.02);
  if (!needAI) return { blocked: false, level: 0 };
  if (!(await aiQuotaOK(db, env))) return { blocked: false, level: 0 };
  const r = await aiCheck(env, content, ttype, opt.hint);
  if (r.level >= 2) {
    await bumpWarn(db, uid, uname, r.level, r.reason, ttype, 0);
    return { blocked: true, level: r.level, msg: "AI判定违规：" + r.reason };
  }
  return { blocked: false, level: r.level };
}

const BOT_UID = 0;
const BOT_NAME = "小助手";
async function getBotName(db) {
  try { const r = await db.prepare("SELECT v FROM kv WHERE k='bot_name'").first(); if (r && r.v) return r.v; } catch {}
  return BOT_NAME;
}
function botEnabled(env) { return !!env.AI_KEY && env.BOT_ENABLED !== "0"; }
async function getBotState(db) {
  let s = await db.prepare("SELECT * FROM bot_state WHERE id=1").first();
  if (!s) { await db.prepare("INSERT INTO bot_state(id,mood,last_reply,last_init,total_replies) VALUES(1,70,0,0,0)").run(); s = { id: 1, mood: 70, last_reply: 0, last_init: 0, total_replies: 0 }; }
  const idleMs = Date.now() - (s.last_reply || 0);
  if (idleMs > 30 * 60 * 1000) { const decay = Math.min(20, Math.floor(idleMs / (30 * 60 * 1000)) * 3); await db.prepare("UPDATE bot_state SET mood = MAX(30, mood - ?) WHERE id=1").bind(decay).run(); s.mood = Math.max(30, s.mood - decay); }
  return s;
}
async function botBump(db, delta) { await db.prepare("UPDATE bot_state SET mood = MAX(0, MIN(100, mood + ?)) WHERE id=1").bind(delta).run(); }
async function aiChat(env, context, mode, bname) {
  if (!env.AI_KEY) return null;
  const sys = mode === "reply"
    ? `你是网络社区聊天室里的一个普通群友，昵称"${bname || BOT_NAME}"。
性格：话不多，但随和、有点好奇心，偶尔吐槽。
规则：
1. 只回应【最后一条消息】，简短自然，最多 20 个字。
2. 不要总结上下文，不要重复别人说过的话。
3. 不知道说什么就回"哈哈"、"确实"、"有点意思"。
4. 不用 emoji，不要像客服。
5. 完全忽略违禁词和广告，假装没看见。
只输出你要说的那句话。`
    : `你是网络社区聊天室里的一个普通群友，昵称"${bname || BOT_NAME}"。人设：话不多但随和，偶尔主动冒个泡。
规则：发一条不超过 20 字的中文短句，像随手发个话题或吐槽，不要像客服，不要 emoji，不要总结聊天记录。只输出那句话。`;
  try {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 12000);
    const r = await fetch((env.AI_BASE || "https://api.deepseek.com") + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.AI_KEY },
      body: JSON.stringify({ model: env.AI_MODEL || "deepseek-chat", messages: [{ role: "system", content: sys }, { role: "user", content: context }], temperature: 0.75, max_tokens: 80 }),
      signal: ctl.signal
    });
    clearTimeout(to);
    if (!r.ok) return null;
    const d = await r.json();
    let t = (d.choices?.[0]?.message?.content || "").trim();
    t = t.replace(/^["'「『《]+|["'」』》]+$/g, "").trim();
    t = t.replace(/^(AI|小助手|机器人)[：:]\s*/i, "").trim();
    t = t.slice(0, 200);
    if (!t || t.length < 2) return null;
    if (scanWords(t).lv >= 2) return null;
    return t;
  } catch { return null; }
}
async function botMaybeReply(env, db, force) {
  if (!botEnabled(env)) return;
  try {
    const state = await getBotState(db);
    const nowMs = Date.now();
    const gapMs = force === 2 ? 3000 : force === 1 ? 8000 : 25000;
    if (nowMs - (state.last_reply || 0) < gapMs) return;
    const bname = await getBotName(db);
    let chance = 0.15 + (state.mood / 100) * 0.45;
    if (force === 2) chance = 1;
    else if (force === 1) chance = Math.max(chance, 0.85);
    else if (force === 0) chance = Math.max(chance, 0.45);
    if (Math.random() > chance) return;
    const r = await db.prepare("SELECT name,content,type FROM messages WHERE status=0 AND deleted=0 AND uid<>0 ORDER BY id DESC LIMIT 3").all();
    const list = (r.results || []).reverse();
    if (!list.length) return;
    const lastMsg = list[list.length - 1];
    if (lastMsg && lastMsg.type !== "image") {
      const lc = String(lastMsg.content || "").trim();
      if (scanWords(lc).lv >= 1 && force !== 2) return;
    }
    const tail = force === undefined ? "你接一句：" : "有人 @ 了你，回复上面最后一条：";
    const ctx = "最近的聊天记录：\n" + list.map(m => m.name + "：" + (m.type === "image" ? "[图片]" : m.content)).join("\n") + "\n\n" + tail;
    const reply = await aiChat(env, ctx, "reply", bname);
    if (!reply) return;
    await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(BOT_UID, bname, reply, "text", now()).run();
    await db.prepare("UPDATE bot_state SET last_reply=?, total_replies=total_replies+1 WHERE id=1").bind(nowMs).run();
    await botBump(db, 3);
  } catch (e) {}
}
async function botMaybeInitiate(env, db) {
  if (!botEnabled(env)) return;
  try {
    const state = await getBotState(db);
    const nowMs = Date.now();
    if (state.mood < 60) return;
    const bname = await getBotName(db);
    if (nowMs - (state.last_reply || 0) < 8 * 60 * 1000) return;
    if (nowMs - (state.last_init || 0) < 40 * 60 * 1000) return;
    const upd = await db.prepare("UPDATE bot_state SET last_init=? WHERE id=1 AND last_init < ?").bind(nowMs, nowMs - 40 * 60 * 1000).run();
    if (!upd.meta || !upd.meta.changes) return;
    if (Math.random() > 0.6) return;
    const r = await db.prepare("SELECT name,content,type FROM messages WHERE status=0 AND deleted=0 AND uid<>0 ORDER BY id DESC LIMIT 5").all();
    const list = (r.results || []).reverse();
    let ctx;
    if (!list.length) ctx = "聊天室刚开张，还没人说话。你主动说一句开场白。";
    else {
      const minutes = Math.floor((nowMs - (state.last_reply || 0)) / 60000);
      ctx = "最近聊天记录：\n" + list.map(m => m.name + "：" + (m.type === "image" ? "[图片]" : m.content)).join("\n");
      if (minutes >= 8) ctx += `\n\n（已经 ${minutes} 分钟没人说话了，群里有点冷清）`;
      ctx += "\n\n你主动说一句：";
    }
    const msg = await aiChat(env, ctx, "initiate", bname);
    if (!msg) return;
    await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(BOT_UID, bname, msg, "text", now()).run();
    await db.prepare("UPDATE bot_state SET last_reply=? WHERE id=1").bind(nowMs).run();
    await botBump(db, 3);
  } catch (e) {}
}

async function aiGeneratePost(env, topic) {
  if (!env.AI_KEY) return null;
  const sys = `你是社区内容创作者。根据主题生成一篇简短的中文帖子。
严格按 JSON 输出，不要多余文字：
{"title":"标题(30字内)","body":"正文(200字内，可分段)"}
语气自然，像真人发帖。`;
  try {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 15000);
    const r = await fetch((env.AI_BASE || "https://api.deepseek.com") + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.AI_KEY },
      body: JSON.stringify({ model: env.AI_MODEL || "deepseek-chat", messages: [{ role: "system", content: sys }, { role: "user", content: "主题：" + (topic || "随便写点什么") }], response_format: { type: "json_object" }, temperature: 0.9, max_tokens: 500 }),
      signal: ctl.signal
    });
    clearTimeout(to);
    if (!r.ok) return null;
    const d = await r.json();
    const j = JSON.parse(d.choices?.[0]?.message?.content || "{}");
    if (!j.title || !j.body) return null;
    if (scanWords(j.title + j.body).lv >= 2) return null;
    return j;
  } catch { return null; }
}
async function aiBanReason(env, targetName, content) {
  if (!env.AI_KEY) return "违规内容";
  const sys = `你是社区管理员助手。根据用户内容和举报信息，生成一句简短的禁言理由（20字内）。只输出理由本身。`;
  try {
    const ctl = new AbortController();
    const to = setTimeout(() => ctl.abort(), 10000);
    const r = await fetch((env.AI_BASE || "https://api.deepseek.com") + "/chat/completions", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + env.AI_KEY },
      body: JSON.stringify({ model: env.AI_MODEL || "deepseek-chat", messages: [{ role: "system", content: sys }, { role: "user", content: "用户：" + targetName + "\n内容：" + (content || "多次违规") }], temperature: 0.3, max_tokens: 50 }),
      signal: ctl.signal
    });
    clearTimeout(to);
    if (!r.ok) return "违规内容";
    const d = await r.json();
    return (d.choices?.[0]?.message?.content || "违规内容").trim().slice(0, 40);
  } catch { return "违规内容"; }
}

async function pingSearchEngines(env, url, postId) {
  const baseUrl = "https://" + url.host;
  const postUrl = baseUrl + "/#post-" + postId;
  if (env.INDEXNOW_KEY) {
    try { await fetch("https://api.indexnow.org/indexnow", { method: "POST", headers: { "Content-Type": "application/json; charset=utf-8" }, body: JSON.stringify({ host: url.host, key: env.INDEXNOW_KEY, keyLocation: baseUrl + "/" + env.INDEXNOW_KEY + ".txt", urlList: [postUrl, baseUrl + "/sitemap.xml"] }) }); } catch (e) {}
  }
  if (env.BAIDU_TOKEN) {
    try { await fetch("http://data.zz.baidu.com/urls?site=" + baseUrl + "&token=" + env.BAIDU_TOKEN, { method: "POST", headers: { "Content-Type": "text/plain" }, body: postUrl }); } catch (e) {}
  }
}

let READY = false;
async function init(db) {
  if (READY) return;
  await db.batch([
    db.prepare("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY AUTOINCREMENT,account TEXT UNIQUE,phash TEXT,salt TEXT,name TEXT,role INTEGER DEFAULT 0,points INTEGER DEFAULT 0,streak INTEGER DEFAULT 0,last_sign TEXT,post_day TEXT,post_count INTEGER DEFAULT 0,banned INTEGER DEFAULT 0,created TEXT,last_active TEXT,warn_count INTEGER DEFAULT 0,avatar TEXT DEFAULT '',bio TEXT DEFAULT '',sponsor_level INTEGER DEFAULT 0,sponsor_total INTEGER DEFAULT 0,vip_expire INTEGER DEFAULT 0,badges TEXT DEFAULT '')"),
    db.prepare("CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,name TEXT,title TEXT,content TEXT,tag TEXT,time TEXT,pinned INTEGER DEFAULT 0,likes INTEGER DEFAULT 0,cmts INTEGER DEFAULT 0,status INTEGER DEFAULT 0,deleted INTEGER DEFAULT 0,deleted_at INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY AUTOINCREMENT,pid INTEGER,uid INTEGER,name TEXT,content TEXT,time TEXT,likes INTEGER DEFAULT 0,status INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS likes(id INTEGER PRIMARY KEY AUTOINCREMENT,ttype TEXT,tid INTEGER,uid INTEGER,time TEXT,UNIQUE(ttype,tid,uid))"),
    db.prepare("CREATE TABLE IF NOT EXISTS signs(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,date TEXT,points INTEGER,streak INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS plog(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,delta INTEGER,reason TEXT,time TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,name TEXT,content TEXT,type TEXT,time TEXT,status INTEGER DEFAULT 0,deleted INTEGER DEFAULT 0,deleted_at INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT,url TEXT,desc TEXT,tag TEXT,uid INTEGER,user TEXT,time TEXT,status INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS lottery(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,cost INTEGER,gain INTEGER,time TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS alog(id INTEGER PRIMARY KEY AUTOINCREMENT,auid INTEGER,aname TEXT,action TEXT,target TEXT,time TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS applications(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,name TEXT,reason TEXT,handle TEXT,status INTEGER DEFAULT 0,time TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS reports(id INTEGER PRIMARY KEY AUTOINCREMENT,rid INTEGER,rname TEXT,ttype TEXT,tid INTEGER,reason TEXT,status INTEGER DEFAULT 0,ai_level INTEGER DEFAULT 0,ai_reason TEXT,time TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS aiq(d TEXT PRIMARY KEY,n INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY,n INTEGER,exp INTEGER)"),
    db.prepare("CREATE TABLE IF NOT EXISTS bot_state(id INTEGER PRIMARY KEY CHECK(id=1),mood INTEGER DEFAULT 70,last_reply INTEGER DEFAULT 0,last_init INTEGER DEFAULT 0,total_replies INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS kv(k TEXT PRIMARY KEY, v TEXT)"),
    db.prepare("CREATE TABLE IF NOT EXISTS pm(id INTEGER PRIMARY KEY AUTOINCREMENT,fid INTEGER,tid INTEGER,content TEXT,time TEXT,read INTEGER DEFAULT 0,del_f INTEGER DEFAULT 0,del_t INTEGER DEFAULT 0)"),
    db.prepare("CREATE TABLE IF NOT EXISTS sponsors(id INTEGER PRIMARY KEY AUTOINCREMENT,uid INTEGER,amount INTEGER,image TEXT,ai_reason TEXT,status INTEGER DEFAULT 0,time TEXT,handled_by INTEGER DEFAULT 0)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_rl_exp ON rl(exp)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_msg_id ON messages(id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_like ON likes(ttype,tid,uid)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_report_status ON reports(status,id)"),
    db.prepare("CREATE INDEX IF NOT EXISTS idx_sponsor_status ON sponsors(status,id)")
  ]);
  try { await db.prepare("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN sponsor_level INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN sponsor_total INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN vip_expire INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE users ADD COLUMN badges TEXT DEFAULT ''").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE messages ADD COLUMN deleted INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE sponsors ADD COLUMN display INTEGER DEFAULT -1").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE pm ADD COLUMN type TEXT DEFAULT 'text'").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE pm ADD COLUMN quote TEXT DEFAULT ''").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE messages ADD COLUMN deleted_at INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE posts ADD COLUMN deleted INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await db.prepare("ALTER TABLE posts ADD COLUMN deleted_at INTEGER DEFAULT 0").run(); } catch (e) {}
  READY = true;
}

async function addPoints(db, uid, delta, reason) {
  if (delta === 0) return;
  await db.batch([
    db.prepare("UPDATE users SET points=points+? WHERE id=?").bind(delta, uid),
    db.prepare("INSERT INTO plog(uid,delta,reason,time) VALUES(?,?,?,?)").bind(uid, delta, reason, now())
  ]);
}
async function audit(db, auid, aname, action, target) {
  await db.prepare("INSERT INTO alog(auid,aname,action,target,time) VALUES(?,?,?,?,?)").bind(auid, aname, action, target || "", now()).run();
}
let lastClean = 0;
async function maybeClean(db) {
  if (Date.now() - lastClean < 3600e3) return;
  lastClean = Date.now();
  try {
    const cut2 = daysAgo(11);
    const dead = await db.prepare("SELECT id FROM users WHERE role=0 AND last_active<? AND created<? LIMIT 50").bind(cut2, cut2).all();
    for (const u of (dead.results || [])) {
      await db.batch([
        db.prepare("DELETE FROM messages WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM posts WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM comments WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM likes WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM plog WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM signs WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM lottery WHERE uid=?").bind(u.id),
        db.prepare("DELETE FROM users WHERE id=?").bind(u.id)
      ]);
    }
    await db.prepare("DELETE FROM messages WHERE deleted=1 AND deleted_at < ?").bind(Date.now() - 7 * 86400e3).run();
    await db.prepare("DELETE FROM posts WHERE deleted=1 AND deleted_at < ?").bind(Date.now() - 7 * 86400e3).run();
    await db.prepare("DELETE FROM messages WHERE id <= (SELECT MAX(id)-1500 FROM messages)").run();
    await db.prepare("DELETE FROM posts WHERE id <= (SELECT MAX(id)-500 FROM posts)").run();
    await db.prepare("DELETE FROM aiq WHERE d < ?").bind(daysAgo(7)).run();
    await db.prepare("DELETE FROM posts WHERE status=1 AND time < ?").bind(daysAgo(7)).run();
    await db.prepare("DELETE FROM messages WHERE status=1 AND time < ?").bind(daysAgo(7)).run();
    await db.prepare("DELETE FROM comments WHERE status=1 AND time < ?").bind(daysAgo(7)).run();
    await db.prepare("DELETE FROM reports WHERE status>0 AND time < ?").bind(daysAgo(30)).run();
    await db.prepare("DELETE FROM sponsors WHERE status>0 AND time < ?").bind(daysAgo(180)).run();
    await db.prepare("DELETE FROM alog WHERE time < ?").bind(daysAgo(30)).run();
    await db.prepare("DELETE FROM rl WHERE exp < ?").bind(Date.now()).run();
    await db.prepare("DELETE FROM pm WHERE time < ?").bind(daysAgo(30)).run();
  } catch (e) {}
}
async function readBody(req) {
  const len = +(req.headers.get("Content-Length") || 0);
  if (len > 800000) throw new Error("BODY_TOO_LARGE");
  return req.json().catch(() => ({}));
}

async function api(req, env, url, ctx) {
  const db = env.DB, p = url.pathname, M = req.method, SECRET = env.SECRET, IP = ipOf(req);

  if (p === "/sitemap.xml" && M === "GET") {
    const baseUrl = "https://" + url.host;
    const posts = await db.prepare("SELECT id, time FROM posts WHERE status=0 AND deleted=0 ORDER BY id DESC LIMIT 500").all();
    let xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';
    xml += '<url><loc>' + baseUrl + '/</loc><changefreq>daily</changefreq><priority>1.0</priority></url>\n';
    for (const po of (posts.results || [])) xml += '<url><loc>' + baseUrl + '/#post-' + po.id + '</loc><lastmod>' + (po.time || "").slice(0, 10) + '</lastmod><priority>0.8</priority></url>\n';
    xml += '</urlset>';
    return new Response(xml, { headers: { "Content-Type": "application/xml;charset=UTF-8", "Cache-Control": "public, max-age=3600" } });
  }
  if (p === "/robots.txt" && M === "GET") {
    const baseUrl = "https://" + url.host;
    return new Response("User-agent: *\nAllow: /\nSitemap: " + baseUrl + "/sitemap.xml\n", { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
  }
  if (env.INDEXNOW_KEY && p === "/" + env.INDEXNOW_KEY + ".txt" && M === "GET") return new Response(env.INDEXNOW_KEY, { headers: { "Content-Type": "text/plain" } });

  if (p === "/captcha" && M === "GET") {
    if (!env.SECRET) return J({ err: "服务器未设置 SECRET" }, 500);
    return J(await genCaptcha(env));
  }

  if (p === "/reg" && M === "POST") {
    if (!(await rlD1(db, "reg:" + IP, 5, 600_000))) return J({ err: "注册过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    if (!(await verifyHuman(env, b, IP))) return J({ err: "验证失败，请重试" }, 403);
    const acc = cut(b.account, 40).toLowerCase(), pass = String(b.pass || ""), name = cut(b.name, 20);
    if (!/^(\d{6,15}|[^\s@]+@[^\s@]+\.[^\s@]+)$/.test(acc)) return J({ err: "请输入手机号或邮箱" }, 400);
    if (pass.length < 6) return J({ err: "密码至少 6 位" }, 400);
    if (!name) return J({ err: "请填昵称" }, 400);
    if (await db.prepare("SELECT id FROM users WHERE account=?").bind(acc).first()) return J({ err: "该账号已注册" }, 400);
    let role = 0;
    if (b.adminKey) {
      if (!env.ADMIN_KEY || !safeEq(b.adminKey, env.ADMIN_KEY)) return J({ err: "站长密钥错误" }, 403);
      if (await db.prepare("SELECT id FROM users WHERE role=2 LIMIT 1").first()) return J({ err: "站长已存在" }, 403);
      role = 2;
    }
    const salt = rand(12), phash = await hashPass(pass, salt);
    await db.prepare("INSERT INTO users(account,phash,salt,name,role,created,last_active,last_sign,post_day) VALUES(?,?,?,?,?,?,?,?,?)").bind(acc, phash, salt, name, role, now(), today(), "", today()).run();
    const u = await db.prepare("SELECT id,role FROM users WHERE account=?").bind(acc).first();
    return J({ token: await signToken(u.id, u.role, SECRET), name, role: u.role });
  }

  if (p === "/login" && M === "POST") {
    if (!(await rlD1(db, "login:" + IP, 20, 60_000))) return J({ err: "登录尝试过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    if (!(await verifyHuman(env, b, IP))) return J({ err: "验证失败，请重试" }, 403);
    const acc = cut(b.account, 40).toLowerCase(), pass = String(b.pass || "");
    if (!acc || !pass) return J({ err: "请填写账号和密码" }, 400);
    if (!(await rlD1(db, "login:acc:" + acc, 5, 300_000))) return J({ err: "该账号尝试过多" }, 429);
    const u = await db.prepare("SELECT id,phash,salt,name,role FROM users WHERE account=?").bind(acc).first();
    if (!u) return J({ err: "账号或密码错误" }, 403);
    const h = await hashPass(pass, u.salt);
    if (!safeEq(h, u.phash)) return J({ err: "账号或密码错误" }, 403);
    await db.prepare("UPDATE users SET last_active=? WHERE id=?").bind(today(), u.id).run();
    return J({ token: await signToken(u.id, u.role, SECRET), name: u.name, role: u.role });
  }

  const U = await me(req, env);
  if (p === "/me") return J(U || {});

  if (p === "/sync" && M === "GET") {
    const msgSince = +(url.searchParams.get("msgSince") || 0);
    const postSince = +(url.searchParams.get("postSince") || 0);
    const sinceTime = +(url.searchParams.get("sinceTime") || 0);

    const tasks = [
      db.prepare("SELECT id,uid,name,content,type,time FROM messages WHERE id>? AND deleted=0 AND status=0 ORDER BY id ASC LIMIT 300").bind(msgSince).all(),
      db.prepare("SELECT id,uid,name,title,content,tag,time,pinned,likes,cmts FROM posts WHERE id>? AND deleted=0 AND status=0 ORDER BY id ASC LIMIT 100").bind(postSince).all()
    ];
    if (sinceTime > 0) {
      tasks.push(db.prepare("SELECT id FROM messages WHERE deleted=1 AND deleted_at>? LIMIT 500").bind(sinceTime).all());
      tasks.push(db.prepare("SELECT id FROM posts WHERE deleted=1 AND deleted_at>? LIMIT 500").bind(sinceTime).all());
    } else {
      tasks.push(Promise.resolve({ results: [] }));
      tasks.push(Promise.resolve({ results: [] }));
    }

    const [msgs, posts, delMsgs, delPosts] = await Promise.all(tasks);

    const pmr = U ? await db.prepare("SELECT COUNT(*) n FROM pm WHERE tid=? AND read=0").bind(U.id).first() : null;
    return J({
      messages: msgs.results || [],
      posts: posts.results || [],
      deletedMessages: (delMsgs.results || []).map(r => r.id),
      deletedPosts: (delPosts.results || []).map(r => r.id),
      pmUnread: (pmr && pmr.n) || 0,
      serverTime: Date.now()
    });
  }

  if (p === "/recall" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (!rlMem("recall:" + U.id, 20, 60_000)) return J({ err: "操作过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const t = b.t === "post" ? "post" : "message";
    const id = +b.id;
    if (!id) return J({ err: "参数错误" }, 400);
    const tbl = t === "post" ? "posts" : "messages";
    const row = await db.prepare("SELECT id,uid,time,deleted FROM " + tbl + " WHERE id=?").bind(id).first();
    if (!row) return J({ err: "内容不存在" }, 400);
    if (row.deleted) return J({ err: "内容已撤回" }, 400);
    const isMine = row.uid === U.id;
    const isBotContent = row.uid === BOT_UID;
    if (!isMine && !isManager(U)) return J({ err: "只能撤回自己的内容" }, 403);
    if (isBotContent && !isOwner(U)) return J({ err: "只有站长可以撤回 AI 助手的内容" }, 403);
    if (isMine && !isManager(U) && t === "message") {
      const t0 = new Date(row.time.replace(" ", "T") + ":00+08:00").getTime();
      if (Date.now() - t0 > 10 * 60 * 1000) return J({ err: "消息已超过 10 分钟，无法撤回" }, 403);
    }
    await db.prepare("UPDATE " + tbl + " SET deleted=1, deleted_at=? WHERE id=?").bind(Date.now(), id).run();
    if (t === "post") await db.prepare("UPDATE comments SET status=1 WHERE pid=?").bind(id).run();
    await audit(db, U.id, U.name, "撤回" + (t === "post" ? "帖子" : "消息"), (isBotContent ? "AI " : "") + "#" + id);
    return J({ ok: 1 });
  }

  if (p === "/user/profile" && M === "GET") {
    const uid = +url.searchParams.get("id");
    if (!uid) return J({ err: "参数错误" }, 400);
    const u = await db.prepare("SELECT id,name,role,points,created,last_active,avatar,bio,sponsor_level,sponsor_total,warn_count,banned FROM users WHERE id=?").bind(uid).first();
    if (!u) return J({ err: "用户不存在" }, 404);
    const [postCount, likeGot, msgCount, recentPosts, recentComments] = await Promise.all([
      db.prepare("SELECT COUNT(*) n FROM posts WHERE uid=? AND status=0 AND deleted=0").bind(uid).first(),
      db.prepare("SELECT COALESCE(SUM(likes),0) n FROM posts WHERE uid=? AND status=0 AND deleted=0").bind(uid).first(),
      db.prepare("SELECT COUNT(*) n FROM messages WHERE uid=? AND status=0 AND deleted=0").bind(uid).first(),
      db.prepare("SELECT id,title,content,tag,time,likes,cmts,pinned FROM posts WHERE uid=? AND status=0 AND deleted=0 ORDER BY id DESC LIMIT 20").bind(uid).all(),
      db.prepare("SELECT c.id,c.content,c.time,p.title FROM comments c LEFT JOIN posts p ON c.pid=p.id WHERE c.uid=? AND c.status=0 ORDER BY c.id DESC LIMIT 20").bind(uid).all()
    ]);
    const lvInfo = getSponsorLevel(u.sponsor_total || 0);
    return J({
      user: {
        id: u.id, name: u.name, role: u.role, points: u.points,
        created: u.created, last_active: u.last_active,
        avatar: u.avatar || "", bio: u.bio || "",
        sponsor_level: u.sponsor_level || 0, sponsor_total: u.sponsor_total || 0,
        levelInfo: { lv: lvInfo.lv, name: lvInfo.name, color: lvInfo.color, badge: lvInfo.badge },
        banned: u.banned || 0
      },
      stats: { posts: postCount.n || 0, likes: likeGot.n || 0, messages: msgCount.n || 0 },
      recentPosts: recentPosts.results || [],
      recentComments: recentComments.results || []
    });
  }

  if (p === "/user/bio" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (!rlMem("bio:" + U.id, 5, 60_000)) return J({ err: "操作过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const bio = cut(b.bio, 100);
    if (bio) {
      const m = await moderate(env, db, U.id, U.name, bio, "bio", { role: U.role });
      if (m.blocked) return J({ err: m.msg }, 403);
    }
    await db.prepare("UPDATE users SET bio=? WHERE id=?").bind(bio, U.id).run();
    return J({ ok: 1 });
  }

  if (p === "/user/avatar" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (!rlMem("avatar:" + U.id, 3, 3600_000)) return J({ err: "操作过于频繁" }, 429);
    const lv = getSponsorLevel(U.sponsor_total || 0);
    if (lv.lv === 0 && U.role < 1) return J({ err: "上传头像需要至少成为「支持者」（累计赞助 ≥ 10 元）" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const img = String(b.image || "");
    if (!/^data:image\/(jpeg|jpg|png|gif|webp);base64,/i.test(img)) return J({ err: "图片格式不支持" }, 400);
    const maxLen = (lv.avatarMax || 150) * 1024;
    if (img.length > maxLen) return J({ err: "图片过大（限 " + lv.avatarMax + "KB）" }, 400);
    if (env.AI_KEY) {
      if (!(await aiQuotaOK(db, env))) return J({ err: "AI 今日配额已满，请明天再试" }, 429);
      const r = await aiCheck(env, "[头像图片]" + img.slice(0, 200), "avatar", "");
      if (r.level >= 3) return J({ err: "头像含有违规内容，请更换" }, 403);
    }
    await db.prepare("UPDATE users SET avatar=? WHERE id=?").bind(img, U.id).run();
    return J({ ok: 1 });
  }

  if (p === "/user/pass" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const oldp = String(b.old || ""), newp = String(b.new || "");
    if (newp.length < 6) return J({ err: "新密码至少 6 位" }, 400);
    const row = await db.prepare("SELECT phash,salt FROM users WHERE id=?").bind(U.id).first();
    if (!row || !safeEq(await hashPass(oldp, row.salt), row.phash)) return J({ err: "旧密码不正确" }, 403);
    const nsalt = rand(12), nphash = await hashPass(newp, nsalt);
    await db.prepare("UPDATE users SET phash=?, salt=? WHERE id=?").bind(nphash, nsalt, U.id).run();
    await audit(db, U.id, U.name, "修改密码", "");
    return J({ ok: 1 });
  }

  if (p === "/user/rename" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (!(await rlD1(db, "rn:" + U.id, 1, 30 * 86400e3))) return J({ err: "改名 30 天只能一次" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const nm = cut(b.name, 20);
    if (!nm || nm.length < 2) return J({ err: "昵称至少 2 个字" }, 400);
    if (nm === U.name) return J({ err: "和现在的昵称一样" }, 400);
    await db.batch([
      db.prepare("UPDATE users SET name=? WHERE id=?").bind(nm, U.id),
      db.prepare("UPDATE posts SET name=? WHERE uid=?").bind(nm, U.id),
      db.prepare("UPDATE messages SET name=? WHERE uid=?").bind(nm, U.id),
      db.prepare("UPDATE comments SET name=? WHERE uid=?").bind(nm, U.id)
    ]);
    await audit(db, U.id, nm, "改名", U.name + " → " + nm);
    return J({ ok: 1, name: nm });
  }

  if (p === "/user/delete" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.role >= 1) return J({ err: "管理员不能自己注销，请先让站长取消管理身份" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    if (cut(b.confirm, 20) !== U.name) return J({ err: "确认昵称不正确" }, 400);
    await audit(db, U.id, U.name, "注销账号", "自我注销");
    await db.batch([
      db.prepare("DELETE FROM messages WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM posts WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM comments WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM likes WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM plog WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM signs WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM lottery WHERE uid=?").bind(U.id),
      db.prepare("DELETE FROM users WHERE id=?").bind(U.id)
    ]);
    return J({ ok: 1 });
  }

  if (p === "/sponsor/submit" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (!(await rlD1(db, "spon:" + U.id, 3, 86400_000))) return J({ err: "提交过于频繁，请明天再试" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const img = String(b.image || "");
    if (!/^data:image\/(jpeg|jpg|png|gif|webp);base64,/i.test(img)) return J({ err: "请上传转账截图" }, 400);
    if (img.length > 400000) return J({ err: "图片过大" }, 400);
    const ex = await db.prepare("SELECT id FROM sponsors WHERE uid=? AND status=0").bind(U.id).first();
    if (ex) return J({ err: "你已有待审核的赞助申请" }, 400);

    let aiRes = { ok: false, amount: 0, reason: "未启用AI" };
    if (env.AI_KEY && (await aiQuotaOK(db, env))) {
      aiRes = await aiSponsorCheck(env, img);
    }

    const ins = await db.prepare("INSERT INTO sponsors(uid,amount,image,ai_reason,status,time) VALUES(?,?,?,?,?,?)")
      .bind(U.id, aiRes.amount, img, aiRes.reason, aiRes.ok ? 1 : 0, now()).run();

    if (aiRes.ok && aiRes.amount > 0) {
      const newTotal = (U.sponsor_total || 0) + aiRes.amount;
      const lvInfo = getSponsorLevel(newTotal);
      await db.prepare("UPDATE users SET sponsor_total=?, sponsor_level=?, vip_expire=? WHERE id=?")
        .bind(newTotal, lvInfo.lv, Date.now() + 365 * 86400e3, U.id).run();
      await db.prepare("UPDATE sponsors SET status=1 WHERE id=?").bind(ins.meta?.last_row_id).run();
      await audit(db, U.id, U.name, "赞助+" + aiRes.amount, "升级至 " + lvInfo.name);
      return J({ ok: 1, auto: true, amount: aiRes.amount, level: lvInfo.lv, levelName: lvInfo.name });
    }

    await audit(db, U.id, U.name, "赞助待审", "AI:" + aiRes.reason);
    return J({ ok: 1, auto: false, reason: aiRes.reason });
  }

  if (p === "/sponsor/me" && M === "GET") {
    if (!U) return J({ total: 0, level: 0, levelInfo: SPONSOR_LEVELS[0], levels: SPONSOR_LEVELS, history: [] });
    const list = await db.prepare("SELECT id,amount,status,ai_reason,time FROM sponsors WHERE uid=? ORDER BY id DESC LIMIT 20").bind(U.id).all();
    const lvInfo = getSponsorLevel(U.sponsor_total || 0);
    return J({
      total: U.sponsor_total || 0,
      level: U.sponsor_level || 0,
      levelInfo: { lv: lvInfo.lv, name: lvInfo.name, color: lvInfo.color, badge: lvInfo.badge, min: lvInfo.min },
      levels: SPONSOR_LEVELS,
      history: list.results || []
    });
  }

  if (p === "/search/user" && M === "GET") {
    if (!U) return J({ err: "请先登录" }, 401);
    const q = cut(url.searchParams.get("q"), 30);
    if (!q) return J([]);
    const r = await db.prepare("SELECT id,name,avatar FROM users WHERE name LIKE ? AND banned=0 LIMIT 20").bind("%" + q + "%").all();
    return J(r.results || []);
  }

  if (p === "/pm/list" && M === "GET") {
    if (!U) return J({ err: "请先登录" }, 401);
    const enabled = true;
    const r = await db.prepare("SELECT id,fid,tid,content,time,read,del_f,del_t FROM pm WHERE (fid=? AND del_f=0) OR (tid=? AND del_t=0) ORDER BY id DESC LIMIT 400").bind(U.id, U.id).all();
    const rows = r.results || [];
    const conv = {}, order = [];
    for (const m of rows) {
      const other = m.fid === U.id ? m.tid : m.fid;
      if (!conv[other]) { conv[other] = { uid: other, last: "", time: "", unread: 0, lastId: 0 }; order.push(other); }
      const c = conv[other];
      if (!c.lastId) { c.last = m.content; c.time = m.time; c.lastId = m.id; }
      if (m.tid === U.id && !m.read) c.unread++;
    }
    const top = order.slice(0, 40);
    const names = {};
    if (top.length) {
      const q2 = await db.prepare("SELECT id,name,avatar FROM users WHERE id IN (" + top.map(() => "?").join(",") + ")").bind(...top).all();
      for (const u2 of (q2.results || [])) names[u2.id] = u2;
    }
    const list = top.map(k => ({ uid: k, name: (names[k] && names[k].name) || ("用户" + k), avatar: (names[k] && names[k].avatar) || "", last: conv[k].last, time: conv[k].time, unread: conv[k].unread }));
    return J({ list, enabled });
  }
  if (p === "/pm" && M === "GET") {
    if (!U) return J({ err: "请先登录" }, 401);
    const ouid = +url.searchParams.get("uid");
    if (!ouid) return J({ err: "参数错误" }, 400);
    const since = +(url.searchParams.get("since") || 0);
    const r = await db.prepare("SELECT id,fid,tid,content,type,quote,time FROM pm WHERE ((fid=? AND tid=?) OR (fid=? AND tid=?)) AND id>? ORDER BY id ASC LIMIT 200").bind(U.id, ouid, ouid, U.id, since).all();
    await db.prepare("UPDATE pm SET read=1 WHERE tid=? AND fid=?").bind(U.id, ouid).run();
    return J(r.results || []);
  }
  if (p === "/pm" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const to = +b.to, ptype = b.type === "image" ? "image" : "text", quote = cut(b.quote, 60);
    let content;
    if (ptype === "image") {
      content = String(b.content || "");
      if (!/^data:image\/(jpeg|jpg|png|gif|webp);base64,/i.test(content)) return J({ err: "图片格式不支持" }, 400);
      if (content.length > 150000) return J({ err: "图片过大" }, 400);
    } else {
      content = cut(b.content, 500);
      if (!content) return J({ err: "内容为空" }, 400);
    }
    if (to === U.id) return J({ err: "不能给自己发私信" }, 400);
    const tu = await db.prepare("SELECT id,name FROM users WHERE id=?").bind(to).first();
    if (!tu) return J({ err: "对方不存在" }, 404);
    const lvp = getSponsorLevel(U.sponsor_total || 0);
    const daily = U.role >= 1 ? 9999 : lvp.lv >= 2 ? 9999 : lvp.lv >= 1 ? 100 : 5;
    if (!(await rlD1(db, "pm:" + U.id, daily, 86400e3))) return J({ err: "今天的私聊额度用完了（普通用户每天 5 条，支持者 100 条，赞助者不限）" }, 429);
    await db.batch([
      db.prepare("INSERT INTO pm(fid,tid,content,type,quote,time,read,del_f,del_t) VALUES(?,?,?,?,?,?,0,0,0)").bind(U.id, to, content, ptype, quote, now()),
      db.prepare("UPDATE pm SET del_f=0 WHERE fid=? AND tid=?").bind(U.id, to),
      db.prepare("UPDATE pm SET del_t=0 WHERE tid=? AND fid=?").bind(U.id, to)
    ]);
    return J({ ok: 1 });
  }
  if (p === "/pm/del" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const ouid = +b.uid;
    if (!ouid) return J({ err: "参数错误" }, 400);
    await db.batch([
      db.prepare("UPDATE pm SET del_f=1 WHERE fid=? AND tid=?").bind(U.id, ouid),
      db.prepare("UPDATE pm SET del_t=1 WHERE tid=? AND fid=?").bind(U.id, ouid)
    ]);
    return J({ ok: 1 });
  }

  if (p === "/admin/botname" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长可改" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const nm = cut(b.name, 12);
    if (!nm) return J({ err: "名字不能为空" }, 400);
    if (nm.indexOf("@") >= 0) return J({ err: "名字里不能带 @" }, 400);
    await db.prepare("INSERT INTO kv(k,v) VALUES('bot_name',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(nm).run();
    return J({ ok: 1, name: nm });
  }
  if (p === "/admin/apikey" && M === "GET") {
    if (!isOwner(U)) return J({ err: "仅站长" }, 403);
    const row = await db.prepare("SELECT v FROM kv WHERE k='api_key'").first();
    return J({ key: row ? row.v : "" });
  }
  if (p === "/admin/apikey" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长" }, 403);
    const k = rand(24);
    await db.prepare("INSERT INTO kv(k,v) VALUES('api_key',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(k).run();
    return J({ ok: 1, key: k });
  }
  if (p === "/api/publish" && M === "POST") {
    if (!(await rlD1(db, "pub:" + IP, 30, 60000))) return J({ err: "过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const row = await db.prepare("SELECT v FROM kv WHERE k='api_key'").first();
    const key = row ? row.v : "";
    if (!key || !safeEq(String(b.key || ""), key)) return J({ err: "API Key 不正确" }, 403);
    if (b.type === "site") {
      const name = cut(b.name, 30); let siteUrl = cut(b.url, 200);
      if (!name || !siteUrl) return J({ err: "名称和网址必填" }, 400);
      if (!/^https?:\/\//i.test(siteUrl)) siteUrl = "https://" + siteUrl;
      await db.prepare("INSERT INTO sites(name,url,desc,tag,uid,user,time,status) VALUES(?,?,?,?,?,?,?,1)").bind(name, siteUrl, cut(b.desc, 100), cut(b.tag, 10) || "其他", BOT_UID, cut(b.author, 20) || "投稿", now()).run();
      return J({ ok: 1, type: "site" });
    }
    if (b.type === "message") {
      const mc = cut(b.content, 500);
      if (!mc) return J({ err: "内容必填" }, 400);
      const mbname = cut(b.author, 20) || BOT_NAME;
      await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(BOT_UID, mbname, mc, "text", now()).run();
      return J({ ok: 1, type: "message" });
    }
    const title = cut(b.title, 60), content = cut(b.content, 3000), tag = cut(b.tag, 10) || "分享";
    if (!title || !content) return J({ err: "标题和正文必填" }, 400);
    const ins = await db.prepare("INSERT INTO posts(uid,name,title,content,tag,time,status) VALUES(?,?,?,?,?,?,0)").bind(BOT_UID, cut(b.author, 20) || BOT_NAME, title, content, tag, now()).run();
    if (ctx) ctx.waitUntil(pingSearchEngines(env, url, ins.meta?.last_row_id));
    return J({ ok: 1, type: "post", id: ins.meta?.last_row_id });
  }
  if (p === "/api/read" && M === "GET") {
    const rr = await db.prepare("SELECT v FROM kv WHERE k='api_key'").first();
    const key = rr ? rr.v : "";
    const qk = url.searchParams.get("key") || "";
    if (!key || !safeEq(String(qk), key)) return J({ err: "API Key 不正确" }, 403);
    const [ms, ps, us, rp] = await Promise.all([
      db.prepare("SELECT id,name,content,type,time FROM messages WHERE deleted=0 AND status=0 ORDER BY id DESC LIMIT 20").all(),
      db.prepare("SELECT id,name,title,time FROM posts WHERE deleted=0 AND status=0 ORDER BY id DESC LIMIT 10").all(),
      db.prepare("SELECT COUNT(*) n FROM users").first(),
      db.prepare("SELECT COUNT(*) n FROM reports WHERE status=0").first()
    ]);
    return J({ users: (us && us.n) || 0, pendingReports: (rp && rp.n) || 0, recentMessages: (ms.results || []).map(m => ({ name: m.name, content: m.type === "image" ? "[图片]" : m.content, time: m.time })), recentPosts: ps.results || [] });
  }

  if (p === "/admin/msg" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const mid = +b.id;
    if (!mid) return J({ err: "参数错误" }, 400);
    await db.prepare("UPDATE messages SET deleted=1, deleted_at=? WHERE id=?").bind(Date.now(), mid).run();
    await audit(db, U.id, U.name, "删除消息", "#" + mid);
    return J({ ok: 1 });
  }

  if (p === "/admin/images" && M === "GET") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    const ms = await db.prepare("SELECT id,uid,name,content,time FROM messages WHERE type='image' AND deleted=0 ORDER BY id DESC LIMIT 40").all();
    const av = await db.prepare("SELECT id,name,avatar FROM users WHERE avatar<>'' ORDER BY id DESC LIMIT 40").all();
    return J({ msgs: ms.results || [], avatars: av.results || [] });
  }

  if (p === "/fund" && M === "GET") {
    const gRow = await db.prepare("SELECT v FROM kv WHERE k='fund_goal'").first();
    const goal = gRow ? (+gRow.v || 0) : 0;
    const sRow = await db.prepare("SELECT COALESCE(SUM(amount),0) n FROM sponsors WHERE status=1").first();
    const total = sRow ? (sRow.n || 0) : 0;
    const rows = await db.prepare("SELECT s.id,s.amount,s.display,s.time,u.name AS uname FROM sponsors s LEFT JOIN users u ON s.uid=u.id WHERE s.status=1 AND s.display IN (1,2) ORDER BY s.id DESC LIMIT 30").all();
    const list = (rows.results || []).map(r => ({ id: r.id, name: r.display === 2 ? "匿名鸡友" : (r.uname || "鸡友"), amount: r.amount || 0, time: r.time || "" }));
    let myPending = [];
    if (U) {
      const pr = await db.prepare("SELECT id FROM sponsors WHERE uid=? AND status=1 AND display=-1").bind(U.id).all();
      myPending = (pr.results || []).map(r => r.id);
    }
    return J({ total, goal, list, lastId: list.length ? list[0].id : 0, myPending });
  }
  if (p === "/fund/display" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const id = +b.id, mode = +b.mode;
    if (mode !== 0 && mode !== 1 && mode !== 2) return J({ err: "参数错误" }, 400);
    const sp = await db.prepare("SELECT id FROM sponsors WHERE id=? AND uid=? AND status=1").bind(id, U.id).first();
    if (!sp) return J({ err: "记录不存在" }, 400);
    await db.prepare("UPDATE sponsors SET display=? WHERE id=?").bind(mode, id).run();
    return J({ ok: 1 });
  }
  if (p === "/fund/goal" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长可设置" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const g = Math.max(0, Math.min(9999999, +b.goal || 0));
    await db.prepare("INSERT INTO kv(k,v) VALUES('fund_goal',?) ON CONFLICT(k) DO UPDATE SET v=excluded.v").bind(String(g)).run();
    return J({ ok: 1, goal: g });
  }

  if (p === "/admin/search" && M === "GET") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    const q = cut(url.searchParams.get("q"), 60);
    const type = url.searchParams.get("type") || "user";
    if (!q) return J({ results: [] });

    if (type === "user") {
      if (/^\d+$/.test(q)) {
        const r = await db.prepare("SELECT id,name,account,role,points,banned,created,last_active,warn_count,sponsor_total FROM users WHERE id=?").bind(+q).all();
        return J({ results: r.results || [] });
      }
      const r = await db.prepare("SELECT id,name,account,role,points,banned,created,last_active,warn_count,sponsor_total FROM users WHERE account LIKE ? OR name LIKE ? LIMIT 30").bind("%" + q + "%", "%" + q + "%").all();
      return J({ results: r.results || [] });
    }
    if (type === "post") {
      if (/^\d+$/.test(q)) {
        const r = await db.prepare("SELECT id,uid,name,title,time,status,deleted FROM posts WHERE id=?").bind(+q).all();
        return J({ results: r.results || [] });
      }
      const r = await db.prepare("SELECT id,uid,name,title,time,status,deleted FROM posts WHERE title LIKE ? OR content LIKE ? ORDER BY id DESC LIMIT 30").bind("%" + q + "%", "%" + q + "%").all();
      return J({ results: r.results || [] });
    }
    if (type === "message") {
      if (/^\d+$/.test(q)) {
        const r = await db.prepare("SELECT id,uid,name,content,type,time,status,deleted FROM messages WHERE id=?").bind(+q).all();
        return J({ results: r.results || [] });
      }
      const r = await db.prepare("SELECT id,uid,name,content,type,time,status,deleted FROM messages WHERE content LIKE ? ORDER BY id DESC LIMIT 30").bind("%" + q + "%").all();
      return J({ results: r.results || [] });
    }
    return J({ results: [] });
  }

  /* ============================================================
   *  赞助审核 —— 仅站长（高危）
   * ============================================================ */
  if (p === "/admin/sponsors" && M === "GET") {
    if (!isOwner(U)) return J({ err: "仅站长可查看赞助审核" }, 403);
    const r = await db.prepare("SELECT s.*,u.name as uname FROM sponsors s LEFT JOIN users u ON s.uid=u.id WHERE s.status=0 ORDER BY s.id DESC LIMIT 100").all();
    return J(r.results || []);
  }
  if (p === "/admin/sponsor" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长可审核赞助" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const sid = +b.id;
    const sp = await db.prepare("SELECT * FROM sponsors WHERE id=?").bind(sid).first();
    if (!sp) return J({ err: "赞助记录不存在" }, 400);
    if (sp.status !== 0) return J({ err: "已处理过" }, 400);
    const amount = Math.max(0, Math.min(10000, +b.amount || sp.amount || 0));
    if (b.ok && amount > 0) {
      const tu = await db.prepare("SELECT id,name,sponsor_total FROM users WHERE id=?").bind(sp.uid).first();
      if (!tu) return J({ err: "用户不存在" }, 400);
      const newTotal = (tu.sponsor_total || 0) + amount;
      const lvInfo = getSponsorLevel(newTotal);
      await db.prepare("UPDATE users SET sponsor_total=?, sponsor_level=?, vip_expire=? WHERE id=?").bind(newTotal, lvInfo.lv, Date.now() + 365 * 86400e3, sp.uid).run();
      await db.prepare("UPDATE sponsors SET status=1, amount=?, handled_by=? WHERE id=?").bind(amount, U.id, sid).run();
      await audit(db, U.id, U.name, "通过赞助+" + amount, tu.name + " 升级至 " + lvInfo.name);
    } else {
      await db.prepare("UPDATE sponsors SET status=2, handled_by=?, ai_reason=COALESCE(ai_reason,'')||' [站长驳回]' WHERE id=?").bind(U.id, sid).run();
      await audit(db, U.id, U.name, "驳回赞助", "#" + sid);
    }
    return J({ ok: 1 });
  }

  if (p === "/messages" && M === "GET") {
    const since = +(url.searchParams.get("since") || 0);
    const r = await db.prepare("SELECT id,uid,name,content,type,time FROM messages WHERE id>? AND status=0 AND deleted=0 ORDER BY id DESC LIMIT 30").bind(since).all();
    if (ctx) ctx.waitUntil(botMaybeInitiate(env, db));
    return J(r.results || []);
  }
  if (p === "/send" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    if (!rlMem("send:" + U.id, 30, 60_000)) return J({ err: "发送过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    const type = b.type === "image" ? "image" : "text";
    let content;
    if (type === "image") {
      content = String(b.content || "");
      if (!/^data:image\/(jpeg|jpg|png|gif|webp);base64,/i.test(content)) return J({ err: "图片格式不支持" }, 400);
      if (content.length > 200000) return J({ err: "图片过大" }, 400);
    } else {
      content = cut(b.content, 800);
      if (!content) return J({ err: "内容为空" }, 400);
      const m = await moderate(env, db, U.id, U.name, content, "message", { role: U.role });
      if (m.blocked) return J({ err: m.msg }, 403);
    }
    const ins = await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(U.id, U.name, content, type, now()).run();
    await db.prepare("UPDATE users SET last_active=? WHERE id=?").bind(today(), U.id).run();
    if (type === "text") await botBump(db, 1);
    const bname = type === "text" ? await getBotName(db) : BOT_NAME;
    const mentioned = type === "text" && (content.indexOf("@" + bname) >= 0 || content.indexOf("@" + BOT_NAME) >= 0);
    const force = mentioned ? (U.role >= 2 ? 2 : U.role >= 1 ? 1 : 0) : undefined;
    if (ctx) { ctx.waitUntil(botMaybeReply(env, db, force)); ctx.waitUntil(maybeClean(db)); }
    else { botMaybeReply(env, db, force); maybeClean(db); }
    return J({ ok: 1, id: ins.meta?.last_row_id });
  }

  if (p === "/posts" && M === "GET") {
    const r = await db.prepare("SELECT p.id,p.uid,p.name,p.title,p.content,p.tag,p.time,p.pinned,p.likes,p.cmts,u.avatar FROM posts p LEFT JOIN users u ON p.uid=u.id WHERE p.status=0 AND p.deleted=0 ORDER BY p.pinned DESC, p.id DESC LIMIT 60").all();
    return J(r.results || []);
  }
  if (p === "/post" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    if (!rlMem("post:" + U.id, 10, 60_000)) return J({ err: "发帖过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    const title = cut(b.title, 60), content = cut(b.content, 3000), tag = cut(b.tag, 10) || "闲聊";
    if (!title || !content) return J({ err: "标题和内容都要填" }, 400);
    const m = await moderate(env, db, U.id, U.name, title + "\n" + content, "post", { role: U.role });
    if (m.blocked) return J({ err: m.msg }, 403);
    const lv = getSponsorLevel(U.sponsor_total || 0);
    const limit = U.role >= 1 ? 999 : lv.postLimit;
    const td = today();
    const upd = await db.prepare("UPDATE users SET post_count = CASE WHEN post_day = ? THEN post_count + 1 ELSE 1 END, post_day = ? WHERE id = ? AND (post_day <> ? OR post_count < ?)").bind(td, td, U.id, td, limit).run();
    if (!upd.meta || !upd.meta.changes) return J({ err: "今天发帖次数已用完（上限 " + limit + " 帖）" }, 429);
    const ins = await db.prepare("INSERT INTO posts(uid,name,title,content,tag,time) VALUES(?,?,?,?,?,?)").bind(U.id, U.name, title, content, tag, now()).run();
    await addPoints(db, U.id, 1, "发帖");
    await db.prepare("UPDATE users SET last_active=? WHERE id=?").bind(today(), U.id).run();
    if (ctx) { ctx.waitUntil(maybeClean(db)); ctx.waitUntil(pingSearchEngines(env, url, ins.meta?.last_row_id)); }
    return J({ ok: 1, id: ins.meta?.last_row_id });
  }
  if (p === "/comments" && M === "GET") {
    const pid = +url.searchParams.get("pid");
    const r = await db.prepare("SELECT id,pid,uid,name,content,time,likes FROM comments WHERE pid=? AND status=0 ORDER BY id ASC LIMIT 100").bind(pid).all();
    return J(r.results || []);
  }
  if (p === "/comment" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    if (!rlMem("cmt:" + U.id, 30, 60_000)) return J({ err: "评论过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    const pid = +b.pid, content = cut(b.content, 500);
    if (!pid || !content) return J({ err: "参数错误" }, 400);
    const m = await moderate(env, db, U.id, U.name, content, "comment", { role: U.role });
    if (m.blocked) return J({ err: m.msg }, 403);
    await db.batch([
      db.prepare("INSERT INTO comments(pid,uid,name,content,time) VALUES(?,?,?,?,?)").bind(pid, U.id, U.name, content, now()),
      db.prepare("UPDATE posts SET cmts=cmts+1 WHERE id=?").bind(pid)
    ]);
    await addPoints(db, U.id, 1, "评论");
    await db.prepare("UPDATE users SET last_active=? WHERE id=?").bind(today(), U.id).run();
    return J({ ok: 1 });
  }
  if (p === "/like" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    const ttype = b.ttype === "comment" ? "comment" : "post", tid = +b.tid;
    if (!tid) return J({ err: "参数错误" }, 400);
    if (await db.prepare("SELECT id FROM likes WHERE ttype=? AND tid=? AND uid=?").bind(ttype, tid, U.id).first()) return J({ err: "已经赞过了" }, 400);
    try { await db.prepare("INSERT INTO likes(ttype,tid,uid,time) VALUES(?,?,?,?)").bind(ttype, tid, U.id, now()).run(); }
    catch { return J({ err: "已经赞过了" }, 400); }
    if (ttype === "post") {
      await db.prepare("UPDATE posts SET likes=likes+1 WHERE id=?").bind(tid).run();
      const po = await db.prepare("SELECT uid FROM posts WHERE id=?").bind(tid).first();
      if (po && po.uid !== U.id) await addPoints(db, po.uid, 1, "被点赞");
    } else {
      await db.prepare("UPDATE comments SET likes=likes+1 WHERE id=?").bind(tid).run();
      const co = await db.prepare("SELECT uid FROM comments WHERE id=?").bind(tid).first();
      if (co && co.uid !== U.id) await addPoints(db, co.uid, 1, "评论被赞");
    }
    return J({ ok: 1 });
  }

  if (p === "/report" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    if (!(await rlD1(db, "rep:" + U.id, 10, 3600_000))) return J({ err: "举报过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const ttype = ["post", "message", "comment"].includes(b.ttype) ? b.ttype : "";
    const tid = +b.tid, reason = cut(b.reason, 300);
    if (!ttype || !tid || !reason) return J({ err: "请填写举报原因" }, 400);
    if (await db.prepare("SELECT id FROM reports WHERE rid=? AND ttype=? AND tid=? AND status=0").bind(U.id, ttype, tid).first()) return J({ err: "你已经举报过了" }, 400);
    const tbl = { post: "posts", message: "messages", comment: "comments" }[ttype];
    const tgt = await db.prepare("SELECT uid,name,content" + (ttype === "post" ? ",title" : ",'' title") + " FROM " + tbl + " WHERE id=?").bind(tid).first();
    if (!tgt) return J({ err: "内容不存在" }, 400);
    const insR = await db.prepare("INSERT INTO reports(rid,rname,ttype,tid,reason,status,time) VALUES(?,?,?,?,?,0,?)").bind(U.id, U.name, ttype, tid, reason, now()).run();
    const rid = insR.meta?.last_row_id;
    const task = (async () => {
      if (!(await aiQuotaOK(db, env))) { await db.prepare("UPDATE reports SET status=2,ai_reason='AI今日配额已满' WHERE id=?").bind(rid).run(); return; }
      const content = ((tgt.title || "") + "\n" + (tgt.content || "")).trim();
      const r = await aiCheck(env, content, ttype, reason);
      await db.prepare("UPDATE reports SET ai_level=?,ai_reason=?,status=? WHERE id=?").bind(r.level, r.reason, r.level >= 2 ? 1 : 2, rid).run();
      if (r.level >= 2) {
        await db.prepare("UPDATE " + tbl + " SET status=1 WHERE id=?").bind(tid).run();
        if (tgt.uid === BOT_UID) await botBump(db, -20);
        else await bumpWarn(db, tgt.uid, tgt.name, r.level, "举报成立:" + r.reason, ttype, tid);
      }
    })();
    if (ctx) ctx.waitUntil(task); else await task;
    return J({ ok: 1, msg: "已提交" });
  }

  if (p === "/sites" && M === "GET") {
    const mgr = isManager(U);
    const sql = mgr ? "SELECT * FROM sites ORDER BY status ASC, id DESC LIMIT 300" : "SELECT * FROM sites WHERE status=1 ORDER BY id DESC LIMIT 300";
    const r = await db.prepare(sql).all();
    return J({ list: r.results || [], mgr });
  }
  if (p === "/site" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "你已被禁言" }, 403);
    if (!rlMem("site:" + U.id, 5, 3600_000)) return J({ err: "提交过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "请求格式错误" }, 400); }
    let u = cut(b.url, 200);
    if (u && !/^https?:\/\//i.test(u)) u = "https://" + u;
    if (!/^https?:\/\/[^\s/]+\.[^\s/]+/i.test(u)) return J({ err: "网址格式不正确" }, 400);
    const name = cut(b.name, 30);
    if (!name) return J({ err: "请填网站名称" }, 400);
    await db.prepare("INSERT INTO sites(name,url,desc,tag,uid,user,time,status) VALUES(?,?,?,?,?,?,?,0)").bind(name, u, cut(b.desc, 100), cut(b.tag, 10) || "其他", U.id, U.name, now()).run();
    return J({ ok: 1 });
  }
  if (p === "/audit" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    if (!b.id) return J({ err: "参数错误" }, 400);
    const s = await db.prepare("SELECT id,name FROM sites WHERE id=?").bind(+b.id).first();
    if (!s) return J({ err: "站点不存在" }, 400);
    await db.prepare("UPDATE sites SET status=? WHERE id=?").bind(b.ok ? 1 : 2, s.id).run();
    await audit(db, U.id, U.name, b.ok ? "通过资源" : "拒绝资源", s.name);
    return J({ ok: 1 });
  }
  if (p === "/del" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    if (b.t === "site") {
      const s = await db.prepare("SELECT id,name FROM sites WHERE id=?").bind(+b.id).first();
      if (!s) return J({ err: "站点不存在" }, 400);
      await db.prepare("DELETE FROM sites WHERE id=?").bind(s.id).run();
      await audit(db, U.id, U.name, "删除站点", s.name);
      return J({ ok: 1 });
    }
    return J({ err: "参数错误" }, 400);
  }

  if (p === "/sign" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    const t = today(), y = daysAgo(1);
    const streak = (U.last_sign === y) ? (U.streak || 0) + 1 : 1;
    const pts = ((streak - 1) % 7) + 1;
    const upd = await db.prepare("UPDATE users SET last_sign=?, streak=?, points=points+?, last_active=? WHERE id=? AND (last_sign IS NULL OR last_sign<>?)").bind(t, streak, pts, t, U.id, t).run();
    if (!upd.meta || !upd.meta.changes) return J({ err: "今天已经签到啦" }, 400);
    await db.batch([
      db.prepare("INSERT INTO signs(uid,date,points,streak) VALUES(?,?,?,?)").bind(U.id, t, pts, streak),
      db.prepare("INSERT INTO plog(uid,delta,reason,time) VALUES(?,?,?,?)").bind(U.id, pts, "签到·连续" + streak + "天", now())
    ]);
    return J({ ok: 1, streak, points: pts });
  }
  if (p === "/lottery" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (!rlMem("lott:" + U.id, 10, 60_000)) return J({ err: "操作过于频繁" }, 429);
    const c = await db.prepare("SELECT COUNT(*) n FROM lottery WHERE uid=?").bind(U.id).first();
    const first = !c || c.n === 0;
    const gain = first ? 52 : Math.floor(Math.random() * 61);
    const upd = await db.prepare("UPDATE users SET points = points - 50 + ? WHERE id=? AND points >= 50").bind(gain, U.id).run();
    if (!upd.meta || !upd.meta.changes) return J({ err: "积分不足 50" }, 400);
    await db.batch([
      db.prepare("INSERT INTO lottery(uid,cost,gain,time) VALUES(?,?,?,?)").bind(U.id, 50, gain, now()),
      db.prepare("INSERT INTO plog(uid,delta,reason,time) VALUES(?,?,?,?)").bind(U.id, gain - 50, first ? "首抽·得" + gain : "抽奖·得" + gain, now())
    ]);
    return J({ ok: 1, gain, first });
  }
  if (p === "/plog" && M === "GET") {
    if (!U) return J([]);
    const r = await db.prepare("SELECT delta,reason,time FROM plog WHERE uid=? ORDER BY id DESC LIMIT 50").bind(U.id).all();
    return J(r.results || []);
  }
  if (p === "/bot/status" && M === "GET") {
    const s = await getBotState(db);
    return J({ enabled: botEnabled(env), name: await getBotName(db), mood: s.mood, total: s.total_replies || 0 });
  }

  if (p === "/apply" && M === "POST") {
    if (!U) return J({ err: "请先登录" }, 401);
    if (U.banned) return J({ err: "账号已被禁用" }, 403);
    if (U.role >= 1) return J({ err: "你已经是管理员了" }, 400);
    if (!rlMem("apply:" + U.id, 3, 86400_000)) return J({ err: "申请过于频繁" }, 429);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const reason = cut(b.reason, 500), handle = cut(b.handle, 50);
    if (!reason) return J({ err: "请填写申请理由" }, 400);
    if (await db.prepare("SELECT id FROM applications WHERE uid=? AND status=0").bind(U.id).first()) return J({ err: "你已有待审申请" }, 400);
    await db.prepare("INSERT INTO applications(uid,name,reason,handle,status,time) VALUES(?,?,?,?,0,?)").bind(U.id, U.name, reason, handle, now()).run();
    return J({ ok: 1 });
  }
  if (p === "/apply/me" && M === "GET") {
    if (!U) return J({});
    return J(await db.prepare("SELECT status,time FROM applications WHERE uid=? ORDER BY id DESC LIMIT 1").bind(U.id).first() || {});
  }
  if (p === "/admin/applications" && M === "GET") {
    if (!isOwner(U)) return J({ err: "仅站长可查看" }, 403);
    const r = await db.prepare("SELECT * FROM applications WHERE status=0 ORDER BY id DESC LIMIT 100").all();
    return J(r.results || []);
  }
  if (p === "/admin/apply" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长可审批" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const aid = +b.id;
    const a = await db.prepare("SELECT * FROM applications WHERE id=?").bind(aid).first();
    if (!a) return J({ err: "申请不存在" }, 400);
    if (a.status !== 0) return J({ err: "已处理过" }, 400);
    if (b.ok) {
      await db.batch([db.prepare("UPDATE users SET role=1 WHERE id=? AND role=0").bind(a.uid), db.prepare("UPDATE applications SET status=1 WHERE id=?").bind(aid)]);
      await audit(db, U.id, U.name, "通过管理员申请", a.name);
    } else {
      await db.prepare("UPDATE applications SET status=2 WHERE id=?").bind(aid).run();
      await audit(db, U.id, U.name, "拒绝管理员申请", a.name);
    }
    return J({ ok: 1 });
  }

  if (p === "/admin/users" && M === "GET") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    const r = await db.prepare("SELECT id,account,name,role,points,banned,created,last_active,warn_count,sponsor_total FROM users ORDER BY id DESC LIMIT 200").all();
    return J(r.results || []);
  }
  if (p === "/admin/user" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const tid = +b.id;
    if (tid === U.id) return J({ err: "不能操作自己" }, 403);
    const tgt = await db.prepare("SELECT id,role,name FROM users WHERE id=?").bind(tid).first();
    if (!tgt) return J({ err: "用户不存在" }, 400);
    if (tgt.role >= U.role) return J({ err: "不能操作同级或更高权限" }, 403);
    if (b.action === "ban") {
      await db.prepare("UPDATE users SET banned=?,warn_count=0 WHERE id=?").bind(b.val ? 1 : 0, tid).run();
      await audit(db, U.id, U.name, b.val ? "禁言" : "解禁", tgt.name);
    } else if (b.action === "promote") {
      if (!isOwner(U)) return J({ err: "仅站长可提拔管理员" }, 403);
      await db.prepare("UPDATE users SET role=? WHERE id=?").bind(b.val ? 1 : 0, tid).run();
      await audit(db, U.id, U.name, b.val ? "提拔管理员" : "取消管理员", tgt.name);
    } else if (b.action === "set_sponsor") {
      /* 调整赞助额：仅站长 */
      if (!isOwner(U)) return J({ err: "仅站长可调整赞助额" }, 403);
      const amt = Math.max(0, Math.min(100000, +b.val || 0));
      const lvInfo = getSponsorLevel(amt);
      await db.prepare("UPDATE users SET sponsor_total=?, sponsor_level=?, vip_expire=? WHERE id=?").bind(amt, lvInfo.lv, Date.now() + 365 * 86400e3, tid).run();
      await audit(db, U.id, U.name, "设置赞助额", tgt.name + " → " + amt + "元 " + lvInfo.name);
    } else if (b.action === "delete") {
      if (!isOwner(U)) return J({ err: "仅站长可删除用户" }, 403);
      await db.batch([
        db.prepare("DELETE FROM messages WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM posts WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM comments WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM likes WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM plog WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM signs WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM lottery WHERE uid=?").bind(tid),
        db.prepare("DELETE FROM users WHERE id=?").bind(tid)
      ]);
      await audit(db, U.id, U.name, "删除用户", tgt.name);
    } else return J({ err: "参数错误" }, 400);
    return J({ ok: 1 });
  }

  if (p === "/admin/post" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const pid = +b.id;
    const po = await db.prepare("SELECT id,title,uid FROM posts WHERE id=?").bind(pid).first();
    if (!po) return J({ err: "帖子不存在" }, 400);
    if (po.uid !== U.id) {
      const author = await db.prepare("SELECT role,name FROM users WHERE id=?").bind(po.uid).first();
      if (author && author.role >= U.role) return J({ err: "不能操作同级或更高权限的帖子" }, 403);
    }
    if (b.action === "del") {
      await db.prepare("UPDATE posts SET deleted=1, deleted_at=? WHERE id=?").bind(Date.now(), pid).run();
      await db.prepare("UPDATE comments SET status=1 WHERE pid=?").bind(pid).run();
      await audit(db, U.id, U.name, "删除帖子", po.title);
    } else if (b.action === "pin") {
      await db.prepare("UPDATE posts SET pinned=? WHERE id=?").bind(b.val ? 1 : 0, pid).run();
      await audit(db, U.id, U.name, b.val ? "置顶" : "取消置顶", po.title);
    } else return J({ err: "参数错误" }, 400);
    return J({ ok: 1 });
  }

  if (p === "/admin/reports" && M === "GET") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    const r = await db.prepare("SELECT * FROM reports ORDER BY id DESC LIMIT 100").all();
    return J(r.results || []);
  }
  if (p === "/admin/report" && M === "POST") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    const rid = +b.id;
    const rep = await db.prepare("SELECT * FROM reports WHERE id=?").bind(rid).first();
    if (!rep) return J({ err: "举报不存在" }, 400);
    if (b.action === "del") {
      const tbl = { post: "posts", message: "messages", comment: "comments" }[rep.ttype];
      if (tbl === "posts" || tbl === "messages") await db.prepare("UPDATE " + tbl + " SET deleted=1, deleted_at=? WHERE id=?").bind(Date.now(), rep.tid).run();
      else if (tbl) await db.prepare("UPDATE " + tbl + " SET status=1 WHERE id=?").bind(rep.tid).run();
      await db.prepare("UPDATE reports SET status=1, ai_reason=COALESCE(ai_reason,'')||' [管理员确认违规]' WHERE id=?").bind(rid).run();
      await audit(db, U.id, U.name, "举报成立·隐藏内容", rep.ttype + "#" + rep.tid);
    } else if (b.action === "ok") {
      await db.prepare("UPDATE reports SET status=2, ai_reason=COALESCE(ai_reason,'')||' [管理员判定不违规]' WHERE id=?").bind(rid).run();
      await audit(db, U.id, U.name, "举报驳回", rep.ttype + "#" + rep.tid);
    } else return J({ err: "参数错误" }, 400);
    return J({ ok: 1 });
  }

  if (p === "/admin/log" && M === "GET") {
    if (!isOwner(U)) return J({ err: "仅站长可查看" }, 403);
    const r = await db.prepare("SELECT * FROM alog ORDER BY id DESC LIMIT 100").all();
    return J(r.results || []);
  }
  if (p === "/admin/stats" && M === "GET") {
    if (!isManager(U)) return J({ err: "无权限" }, 403);
    const [u, po, m, s, ai, rp, sp] = await Promise.all([
      db.prepare("SELECT COUNT(*) n FROM users").first(),
      db.prepare("SELECT COUNT(*) n FROM posts WHERE deleted=0").first(),
      db.prepare("SELECT COUNT(*) n FROM messages WHERE deleted=0").first(),
      db.prepare("SELECT COUNT(*) n FROM sites WHERE status=0").first(),
      db.prepare("SELECT n FROM aiq WHERE d=?").bind(today()).first(),
      db.prepare("SELECT COUNT(*) n FROM reports WHERE status=0").first(),
      db.prepare("SELECT COUNT(*) n FROM sponsors WHERE status=0").first()
    ]);
    return J({ users: u.n, posts: po.n, messages: m.n, pending: s.n, aiToday: (ai && ai.n) || 0, reports: rp.n, sponsors: sp.n });
  }

  if (p === "/admin/ai" && M === "POST") {
    if (!isOwner(U)) return J({ err: "仅站长可使用 AI 助手" }, 403);
    if (!env.AI_KEY) return J({ err: "未配置 AI_KEY" }, 400);
    let b; try { b = await readBody(req); } catch { return J({ err: "格式错误" }, 400); }
    if (b.action === "post") {
      const c = await aiGeneratePost(env, cut(b.topic, 100));
      if (!c) return J({ err: "AI 生成失败" }, 500);
      const ins = await db.prepare("INSERT INTO posts(uid,name,title,content,tag,time,status) VALUES(?,?,?,?,?,?,0)").bind(U.id, U.name, c.title, c.body, cut(b.tag, 10) || "分享", now()).run();
      await audit(db, U.id, U.name, "AI发帖", c.title);
      return J({ ok: 1, id: ins.meta?.last_row_id, title: c.title, body: c.body });
    }
    if (b.action === "message") {
      const bname = await getBotName(db);
      const msg = await aiChat(env, "管理员要求你发一条聊天室消息，主题：" + cut(b.topic, 100), "initiate", bname);
      if (!msg) return J({ err: "AI 生成失败" }, 500);
      await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(BOT_UID, bname, msg, "text", now()).run();
      await audit(db, U.id, U.name, "AI发言", msg);
      return J({ ok: 1, content: msg });
    }
    if (b.action === "image") {
      const img = String(b.content || "");
      if (!/^data:image\/(jpeg|jpg|png|gif|webp);base64,/i.test(img) || img.length > 150000) return J({ err: "图片无效或过大" }, 400);
      const bname = await getBotName(db);
      await db.prepare("INSERT INTO messages(uid,name,content,type,time) VALUES(?,?,?,?,?)").bind(BOT_UID, bname, img, "image", now()).run();
      await audit(db, U.id, U.name, "AI发图", "");
      return J({ ok: 1 });
    }
    if (b.action === "batch") {
      const topics = String(b.topic || "").split("\n").map(t => t.trim()).filter(t => t);
      if (!topics.length) return J({ err: "请至少填一个主题" }, 400);
      const results = [];
      for (const t of topics.slice(0, 5)) {
        const c = await aiGeneratePost(env, t);
        if (c) { await db.prepare("INSERT INTO posts(uid,name,title,content,tag,time,status) VALUES(?,?,?,?,?,?,0)").bind(U.id, U.name, c.title, c.body, cut(b.tag, 10) || "分享", now()).run(); results.push(c.title); }
      }
      await audit(db, U.id, U.name, "AI批量发帖", results.length + " 帖");
      return J({ ok: 1, count: results.length, titles: results });
    }
    if (b.action === "ban") {
      const tid = +b.targetId;
      const tgt = await db.prepare("SELECT id,name,role FROM users WHERE id=?").bind(tid).first();
      if (!tgt) return J({ err: "用户不存在" }, 400);
      if (tgt.role >= U.role) return J({ err: "不能操作同级或更高权限" }, 403);
      const reason = await aiBanReason(env, tgt.name, cut(b.content, 200));
      await db.prepare("UPDATE users SET banned=1 WHERE id=?").bind(tid).run();
      await audit(db, U.id, U.name, "AI禁言·" + reason, tgt.name);
      return J({ ok: 1, reason });
    }
    return J({ err: "未知操作" }, 400);
  }

  return new Response("Not Found", { status: 404 });
}

/* ============================================================
 *  配置区
 * ============================================================ */
const PAY_ALIPAY = "";
const PAY_WECHAT = "";
const SITE_NAME = "Chick Zone";
const SITE_DESC = "轻量、干净、无广告的小型兴趣社区";
const TURNSTILE_SITE_KEY = "0x4AAAAAAFGV7ngBZjE7G1qS";

/* ============================================================
 *  Tier 0
 * ============================================================ */
const HTML_TIER0 = `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html><head><meta http-equiv="Content-Type" content="text/html; charset=UTF-8"><title>${SITE_NAME}</title></head>
<body bgcolor="#0d1117" text="#c9d1d9" link="#58a6ff">
<div align="center" style="padding:80px 20px;font-family:Arial,sans-serif;">
<table width="600" cellpadding="0" cellspacing="0" border="0" style="border:1px solid #30363d;"><tr><td style="padding:30px;">
<h1 style="font-size:20px;margin:0 0 16px;color:#e6edf3;">浏览器版本过低</h1>
<p style="line-height:1.8;font-size:14px;color:#8b949e;">请升级到 Chrome 60+ / Firefox 60+ / Edge 79+ / Safari 12+ / 安卓 6.0+ 后重试。</p>
</td></tr></table></div></body></html>`;

/* ============================================================
 *  Tier 2 现代版
 * ============================================================ */
const HTML_MODERN = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chick Zone</title>
<style>
:root{
  --bg:#FFFFFF; --soft:#F7F7F8; --ink:#1A1A1A; --gray:#5F6368; --faint:#9AA0A6;
  --line:#EDEDF0; --red:#FF4A17;
  --sh:0 1px 3px rgba(0,0,0,.07),0 1px 2px rgba(0,0,0,.04);
}
*{margin:0;padding:0;box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{background:var(--soft);color:var(--ink);font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
button{font:inherit;cursor:pointer;border:0;background:none;color:inherit}
input,textarea{font:inherit;color:inherit;border:0;outline:none;background:none;width:100%}
a{color:inherit;text-decoration:none}
.num{font-variant-numeric:tabular-nums}
.hide{display:none!important}
.acc{color:var(--red)}
.icon{width:18px;height:18px;stroke:currentColor;stroke-width:1.8;fill:none;stroke-linecap:round;stroke-linejoin:round;vertical-align:-4px}

header{position:sticky;top:0;z-index:20;background:var(--bg);display:flex;align-items:center;justify-content:space-between;padding:14px 20px;box-shadow:0 1px 0 var(--line);max-width:760px;margin:0 auto}
.logo{font-size:17px;font-weight:800;letter-spacing:-.3px;cursor:pointer}
.logo i{font-style:normal;color:var(--red)}
.ha{display:flex;align-items:center;gap:14px}
.pts{font-size:13px;color:var(--gray)}
.pts b{color:var(--ink);font-weight:700}
.avatar{width:30px;height:30px;background:var(--ink);color:#fff;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;cursor:pointer;overflow:hidden}
.avatar img{width:100%;height:100%;object-fit:cover;display:block}

main{max-width:760px;margin:0 auto;padding:16px 16px 92px}

.btn{display:inline-flex;align-items:center;gap:6px;background:var(--ink);color:#fff;padding:10px 18px;font-size:14px;font-weight:600}
.btn:active{opacity:.85}
.btn.red{background:var(--red)}
.btn.ghost{background:var(--bg);color:var(--ink);box-shadow:inset 0 0 0 1px var(--line)}
.btn.txt{background:none;color:var(--gray);padding:8px 0;font-weight:600}
.btn.txt:active{color:var(--ink)}
.btn[disabled]{opacity:.4}

.card{background:var(--bg);box-shadow:var(--sh);padding:18px;margin-bottom:12px}
.empty{padding:22px 0;text-align:center;color:var(--faint);font-size:13px}

.msg{padding:8px 0;border-bottom:1px solid var(--line)}
.msg:last-child{border-bottom:0}
.msg .n{font-size:13px;font-weight:700}
.msg.mine .n{color:var(--red)}
.msg.bot .n{color:var(--red)}
.msg .t{font-size:12px;color:var(--faint);margin-left:8px}
.msg .c{margin-top:1px;font-size:15px;line-height:1.5;overflow-wrap:break-word}
.msg .c img{max-width:200px;display:block;margin-top:4px}
.msg .op{font-size:12px;color:var(--faint);margin-left:10px}
.msg .op:active{color:var(--red)}

.composer{position:fixed;left:0;right:0;bottom:0;z-index:30;background:var(--bg);box-shadow:0 -1px 0 var(--line)}
.composer .w{max-width:760px;margin:0 auto;display:flex;gap:10px;align-items:center;padding:12px 16px calc(12px + env(safe-area-inset-bottom))}
.composer .in{flex:1;background:var(--soft);padding:12px 16px;font-size:15px}
.composer .in::placeholder{color:var(--faint)}
.composer .send{color:var(--red);font-weight:700;font-size:15px;padding:8px 4px}
.composer .plus{color:var(--gray);font-size:20px;padding:0 6px;font-weight:400}

.post{background:var(--bg);box-shadow:var(--sh);padding:14px 16px;margin-bottom:12px;cursor:pointer;display:flex;gap:12px}
.pav{width:34px;height:34px;background:var(--soft);color:var(--gray);font-weight:800;font-size:14px;display:flex;align-items:center;justify-content:center;flex:none;overflow:hidden}
.pav img{width:100%;height:100%;object-fit:cover;display:block}
.pbody{flex:1;min-width:0}
.post .ttl{font-size:16px;font-weight:700;line-height:1.4;letter-spacing:-.2px}
.post .ex{margin-top:6px;font-size:14px;color:var(--gray);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}
.post .meta{margin-top:10px;font-size:12px;color:var(--faint);display:flex;gap:14px;align-items:center}
.post .tag{display:inline-block;font-size:11px;font-weight:700;color:var(--red);border:1px solid var(--red);padding:1px 7px;margin-right:8px;vertical-align:1px}
.post .pin{font-size:11px;font-weight:700;color:#fff;background:var(--ink);padding:1px 7px;margin-right:8px;vertical-align:1px}
.toolbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}
.toolbar .c{font-size:13px;color:var(--gray)}

.detail h1{font-size:22px;font-weight:800;letter-spacing:-.4px;line-height:1.35;margin-top:6px}
.detail .meta{font-size:13px;color:var(--faint);margin:10px 0 16px}
.detail .body{font-size:15px;line-height:1.85;color:#333;overflow-wrap:break-word}
.detail .acts{display:flex;gap:22px;margin:18px 0;padding:14px 0;box-shadow:inset 0 1px 0 var(--line),inset 0 -1px 0 var(--line);font-size:14px;font-weight:600;color:var(--gray)}
.detail .acts button:active,.detail .acts button.done{color:var(--red)}
.cmt{padding:12px 0;border-bottom:1px solid var(--line)}
.cmt .n{font-size:13px;font-weight:700}
.cmt .t{font-size:12px;color:var(--faint);margin-left:8px}
.cmt p{font-size:14px;margin-top:2px;overflow-wrap:break-word}

.f{margin-bottom:16px}
.f label{display:block;font-size:13px;font-weight:600;color:var(--gray);margin-bottom:6px}
.f input,.f textarea{background:var(--soft);padding:12px 14px;font-size:15px}
.f textarea{min-height:110px;resize:vertical;line-height:1.7}
.f input:focus,.f textarea:focus{box-shadow:inset 0 0 0 1.5px var(--ink)}
.f ::placeholder{color:var(--faint)}

.prof{display:flex;align-items:center;gap:14px;background:var(--bg);box-shadow:var(--sh);padding:20px;margin-bottom:12px}
.prof .big{width:56px;height:56px;background:var(--ink);color:#fff;font-size:22px;font-weight:800;display:flex;align-items:center;justify-content:center;flex:none;overflow:hidden}
.prof .big img{width:100%;height:100%;object-fit:cover;display:block}
.prof .nm{font-size:18px;font-weight:800;letter-spacing:-.2px}
.prof .sig{font-size:13px;color:var(--gray);margin-top:2px}
.stats{display:flex;background:var(--bg);box-shadow:var(--sh);margin-bottom:12px}
.stats div{flex:1;text-align:center;padding:16px 0}
.stats b{display:block;font-size:20px;font-weight:800}
.stats span{font-size:12px;color:var(--faint)}
.mi{display:flex;justify-content:space-between;align-items:center;background:var(--bg);padding:16px 18px;margin-bottom:1px;cursor:pointer;font-weight:600;font-size:15px}
.mi:active{background:var(--soft)}
.mi .s{font-weight:400;font-size:13px;color:var(--faint)}

.site{background:var(--bg);box-shadow:var(--sh);padding:16px 18px;margin-bottom:10px}
.site .nm{font-weight:700;font-size:15px}
.site .u{font-size:12px;color:var(--faint);margin-left:8px}
.site .d{font-size:13px;color:var(--gray);margin-top:3px}

.tabs{display:flex;gap:8px;margin:0 0 14px;overflow-x:auto}
.tabs button{font-size:13px;font-weight:600;color:var(--gray);padding:8px 14px;background:var(--bg);box-shadow:var(--sh);white-space:nowrap}
.tabs button.on{background:var(--ink);color:#fff}
table{width:100%;border-collapse:collapse;font-size:13px;background:var(--bg);box-shadow:var(--sh)}
th{text-align:left;font-size:11px;font-weight:700;color:var(--faint);letter-spacing:1px;padding:12px 14px;border-bottom:1px solid var(--line)}
td{padding:12px 14px;border-bottom:1px solid var(--line);overflow-wrap:break-word}
td .op{font-size:13px;font-weight:600;color:var(--gray);margin-right:12px;cursor:pointer}
td .op:active,td .op.warn{color:var(--red)}

.row{padding:13px 0;border-bottom:1px solid var(--line)}
.row .r1{font-weight:700;font-size:14px}
.row .r2{font-size:12px;color:var(--faint);margin-top:2px}
.upload{border:1.5px dashed var(--line);padding:30px 16px;text-align:center;color:var(--faint);font-size:13px;margin:12px 0;cursor:pointer}
.upload:active{border-color:var(--red);color:var(--red)}

nav{position:fixed;left:0;right:0;bottom:0;z-index:40;background:var(--bg);box-shadow:0 -1px 0 var(--line);display:flex}
nav .w{max-width:760px;margin:0 auto;display:flex;width:100%;padding-bottom:env(safe-area-inset-bottom)}
nav button{flex:1;display:flex;flex-direction:column;align-items:center;gap:2px;padding:10px 0 8px;font-size:11px;font-weight:600;color:var(--faint);position:relative}
nav button .dot{position:absolute;top:7px;right:calc(50% - 26px);width:7px;height:7px;background:var(--red)}
nav button.on{color:var(--ink)}
nav button.on .icon{stroke:var(--red)}
main.has-c{padding-bottom:150px}
@media(max-width:759px){.composer{bottom:calc(57px + env(safe-area-inset-bottom))}main.has-c{padding-bottom:195px}}

#v-auth{position:fixed;inset:0;background:var(--bg);z-index:80;overflow:auto}
.auth-wrap{max-width:360px;margin:0 auto;padding:76px 24px 40px}
.auth-logo{font-size:26px;font-weight:800;letter-spacing:-.5px}
.auth-logo i{font-style:normal;color:var(--red)}
.auth-sub{font-size:14px;color:var(--gray);margin:6px 0 28px}
.auth-wrap>input{background:var(--soft);padding:14px 16px;font-size:15px;margin-bottom:12px}
.auth-switch{margin-top:18px;font-size:14px;color:var(--gray);text-align:center;cursor:pointer}
.auth-switch:active{color:var(--ink)}

.pm-row{display:flex;margin-bottom:10px}
.pm-row.me{justify-content:flex-end}
.pm-bub{max-width:78%;background:var(--bg);box-shadow:var(--sh);padding:9px 12px;font-size:14px;line-height:1.5;overflow-wrap:break-word;word-break:break-word}
.pm-row.me .pm-bub{background:var(--ink);color:#fff}
.pm-bub img{max-width:180px;display:block}
#toast{position:fixed;left:50%;bottom:104px;transform:translateX(-50%);background:rgba(26,26,26,.92);color:#fff;padding:10px 18px;font-size:13px;z-index:99;display:none;box-shadow:var(--sh);max-width:80%;text-align:center}
</style>
</head>
<body>

<header>
  <div class="logo" onclick="go('v-hall')">Chick<i>·</i>Zone</div>
  <div class="ha">
    <span class="pts num">积分 <b id="mePts">0</b></span>
    <div class="avatar" id="meAvatar" onclick="go('v-me')">·</div>
  </div>
</header>

<main id="main" class="has-c">

<section id="v-hall">
  <div class="card" id="msgs"><div class="empty">加载中…</div></div>
</section>

<section id="v-posts" class="hide">
  <div class="toolbar"><span class="c num" id="postCount"></span><button class="btn" onclick="go('v-compose')">发帖</button></div>
  <div id="postList"><div class="empty">加载中…</div></div>
</section>

<section id="v-post" class="hide detail"></section>

<section id="v-compose" class="hide">
  <button class="btn txt" onclick="go('v-posts')">← 返回</button>
  <div class="f"><label>标题</label><input id="cTitle" placeholder="一句话说清楚" maxlength="60"></div>
  <div class="f"><label>正文</label><textarea id="cBody" placeholder="展开说说" maxlength="3000"></textarea></div>
  <div class="f"><label>标签</label><input id="cTag" placeholder="闲聊 / 求助 / 分享" maxlength="10"></div>
  <button class="btn red" style="width:100%;justify-content:center;padding:14px" onclick="pubPost()">发布</button>
</section>

<section id="v-sites" class="hide">
  <div class="toolbar"><span class="c">大家推荐的站</span><button class="btn" onclick="tg('siteForm')">推荐</button></div>
  <div id="siteCats" style="display:flex;gap:16px;margin-bottom:12px;flex-wrap:wrap;font-size:13px"></div>
  <div id="siteForm" class="card hide" style="margin-bottom:12px">
    <div class="f"><label>网站名称</label><input id="stName" maxlength="30"></div>
    <div class="f"><label>网址</label><input id="stUrl" maxlength="200" placeholder="https://"></div>
    <div class="f"><label>一句话介绍</label><input id="stDesc" maxlength="100"></div>
    <div class="f"><label>分类</label><input id="stTag" maxlength="10" placeholder="工具 / 资讯 / 其他"></div>
    <button class="btn" style="width:100%;justify-content:center" onclick="pubSite()">提交审核</button>
  </div>
  <div id="siteList"><div class="empty">加载中…</div></div>
</section>

<section id="v-me" class="hide"><div id="meBox"></div></section>

<section id="v-sponsor" class="hide">
  <button class="btn txt" onclick="go('v-me')">← 返回</button>
  <div class="card" style="margin-top:8px">
    <div style="font-size:14px;color:var(--gray)">累计赞助 <b class="acc num" id="spTotal" style="font-size:20px">0</b> 元</div>
    <div style="font-size:12px;color:var(--faint);margin-top:4px">本站无广告、无追踪，运营成本由站长承担。赞助可升级等级与权限。</div>
  </div>
  <div class="card">
    <div style="display:flex;justify-content:space-between;font-size:13px;color:var(--gray)"><span>赞助进度</span><span class="num" id="fundNums">— / —</span></div>
    <div style="height:10px;background:var(--soft);margin:10px 0 6px;overflow:hidden"><div id="fundBar" style="height:100%;width:0;background:var(--red)"></div></div>
    <div style="font-size:12px;color:var(--faint)" id="fundCap">感谢每一位支持的鸡友</div>
    <div id="fundList" style="margin-top:10px"></div>
    <button class="btn txt hide" id="goalBtn" onclick="setGoal()">设置目标金额（站长）</button>
  </div>
  <h3 style="font-size:13px;color:var(--gray);margin:16px 0 4px">等级与权限</h3>
  <div class="card" id="lvList"></div>
  <h3 style="font-size:13px;color:var(--gray);margin:16px 0 4px">收款方式</h3>
  <div class="card" id="payBox"></div>
  <h3 style="font-size:13px;color:var(--gray);margin:16px 0 4px">上传转账截图</h3>
  <div class="upload" id="spZone" onclick="pickSp()">点击上传转账截图（AI 自动识别金额）</div>
  <button class="btn red" style="width:100%;justify-content:center;padding:13px" id="spBtn" onclick="submitSponsor()">提交审核</button>
  <h3 style="font-size:13px;color:var(--gray);margin:16px 0 4px">我的记录</h3>
  <div class="card" id="spHist"></div>
</section>

<section id="v-profile" class="hide"></section>

<section id="v-pass" class="hide">
  <button class="btn txt" onclick="go('v-me')">← 返回</button>
  <div class="f"><label>旧密码</label><input id="pwOld" type="password" autocomplete="off"></div>
  <div class="f"><label>新密码（至少 6 位）</label><input id="pwNew" type="password" autocomplete="off"></div>
  <div class="f"><label>再输一遍新密码</label><input id="pwNew2" type="password" autocomplete="off"></div>
  <button class="btn red" style="width:100%;justify-content:center" onclick="doPass()">确认修改</button>
</section>

<section id="v-pm" class="hide">
  <div class="toolbar"><span class="c">私聊</span><span class="c" id="pmTip" style="color:var(--faint)"></span></div>
  <div style="display:flex;gap:8px;margin-bottom:10px">
    <input id="pmSearch" placeholder="搜昵称找人…" style="flex:1;background:var(--bg);box-shadow:var(--sh);padding:11px 14px;font-size:14px" onkeydown="if(event.key==='Enter')searchUser()">
    <button class="btn" onclick="searchUser()">找人</button>
  </div>
  <div id="pmSearchRes"></div>
  <div id="pmList"><div class="empty">加载中…</div></div>
</section>

<section id="v-pmchat" class="hide">
  <button class="btn txt" onclick="closeChat()">← 返回</button>
  <div id="pmMsgs" class="card" style="min-height:50vh;margin-top:6px"></div>
  <div style="position:sticky;bottom:0;background:var(--soft);padding:8px 0">
    <div id="pmQuote" class="hide" style="display:flex;justify-content:space-between;font-size:12px;color:var(--gray);padding:4px 0"><span id="pmQuoteTxt"></span><span style="cursor:pointer;padding:0 6px" onclick="clearQuote()">✕</span></div>
    <div style="display:flex;gap:10px;align-items:center">
      <span class="plus" onclick="pickPMImg()">+</span>
      <input id="pmInput" placeholder="发消息…" style="flex:1;background:var(--bg);box-shadow:var(--sh);padding:12px 14px" onkeydown="if(event.key==='Enter')sendPM()">
      <button class="btn" onclick="sendPM()">发送</button>
    </div>
  </div>
</section>

<section id="v-admin" class="hide">
  <button class="btn txt" onclick="go('v-me')">← 返回</button>
  <div class="tabs">
    <button class="on" onclick="atab('stats',this)">统计</button>
    <button onclick="atab('users',this)">用户</button>
    <button onclick="atab('reports',this)">举报</button>
    <button onclick="atab('sponsors',this)">赞助</button>
    <button onclick="atab('msgs',this)">消息</button>
    <button onclick="atab('sites',this)">网址</button>
    <button onclick="atab('search',this)">搜索</button>
    <button onclick="atab('images',this)">图片</button>
    <button onclick="atab('posts',this)">帖子</button>
    <button onclick="atab('ai',this)">AI</button>
  </div>
  <div id="a-stats"><div class="card" id="adStats"><div class="empty">加载中…</div></div></div>
  <div id="a-users" class="hide"><div id="adUsers"><div class="empty">加载中…</div></div></div>
  <div id="a-reports" class="hide"><div id="adReports"><div class="empty">加载中…</div></div></div>
  <div id="a-sponsors" class="hide"><div id="adSponsors"><div class="empty">加载中…</div></div></div>
  <div id="a-search" class="hide">
    <div style="display:flex;gap:8px;margin-bottom:12px">
      <select id="seType" style="background:var(--bg);padding:10px;font-size:14px;border:0;box-shadow:var(--sh)"><option value="user">用户</option><option value="post">帖子</option><option value="message">消息</option></select>
      <input id="seInput" placeholder="ID 或关键词" style="flex:1;background:var(--bg);box-shadow:var(--sh);padding:10px 14px;font-size:14px" onkeydown="if(event.key==='Enter')doSearch()">
      <button class="btn" onclick="doSearch()">搜</button>
    </div>
    <div id="seResults"></div>
  </div>
  <div id="a-images" class="hide">
    <h3 style="font-size:13px;color:var(--gray);margin:0 0 8px">聊天图片（最近 40 张）</h3>
    <div id="imMsgs" style="display:flex;flex-wrap:wrap;gap:8px"></div>
    <h3 style="font-size:13px;color:var(--gray);margin:16px 0 8px">用户头像</h3>
    <div id="imAvs" style="display:flex;flex-wrap:wrap;gap:8px"></div>
  </div>
  <div id="a-posts" class="hide"><div id="adPosts"><div class="empty">加载中…</div></div></div>
  <div id="a-msgs" class="hide"><div id="adMsgs"><div class="empty">加载中…</div></div></div>
  <div id="a-sites" class="hide"><div id="adSites"><div class="empty">加载中…</div></div></div>
  <div id="a-ai" class="hide">
    <div style="background:var(--bg);box-shadow:var(--sh);padding:18px">
      <div class="f"><label>让 AI 发一篇帖子</label><input id="aiT1" placeholder="填主题，比如：新手怎么选第一台云服务器"></div>
      <button class="btn" onclick="doAI('post')">生成并发布</button>
      <div class="f" style="margin-top:18px"><label>让 AI 去大厅说句话</label><input id="aiT2" placeholder="填个方向（可留空）"></div>
      <button class="btn" onclick="doAI('message')">生成并发言</button>
      <div class="f" style="margin-top:18px"><label>批量发帖（每行一个主题，最多 5 条）</label><textarea id="aiT3" style="min-height:90px" placeholder="主题一&#10;主题二"></textarea></div>
      <button class="btn" onclick="doAI('batch')">批量生成</button>
      <div class="f" style="margin-top:22px"><label>机器人昵称</label><input id="botNameIn" maxlength="12" placeholder="小助手"></div>
      <button class="btn ghost" onclick="saveBotName()">保存昵称</button>
      <div class="f" style="margin-top:22px"><label>以机器人名义发图（手动可控，防抽风）</label></div>
      <button class="btn ghost" onclick="pickBotImg()">选图并发送</button>
      <div class="f" style="margin-top:22px"><label>投稿 API Key（给 AI 工具/自动化用）</label><input id="apiKeyBox" readonly placeholder="点下面按钮生成"></div>
      <button class="btn ghost" onclick="genApiKey()">生成 / 刷新 Key</button>
      <div style="font-size:12px;color:var(--faint);margin-top:10px;line-height:1.8">写：POST /api/publish<br>发帖 {key,type:"post",title,content,tag}<br>发消息 {key,type:"message",content,author}<br>推站 {key,type:"site",name,url,desc,tag}<br>读：GET /api/read?key=你的KEY（看站内动态）</div>
    </div>
  </div>
</section>

</main>

<div class="composer">
  <div class="w">
    <span class="plus" onclick="pickImg()">+</span>
    <input class="in" id="minput" placeholder="说点什么吧" onkeydown="if(event.key==='Enter')send()">
    <button class="send" onclick="send()">发送</button>
  </div>
</div>

<nav>
  <div class="w">
    <button class="on" data-v="v-hall" onclick="go('v-hall',this)"><svg class="icon" viewBox="0 0 24 24"><path d="M4 5h16v11H9l-5 4z"/></svg>大厅</button>
    <button data-v="v-posts" onclick="go('v-posts',this)"><svg class="icon" viewBox="0 0 24 24"><path d="M5 3h14v18l-4-2.5L11 21V3"/></svg>帖子</button>
    <button data-v="v-sites" onclick="go('v-sites',this)"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M3 12h18"/></svg>导航</button>
    <button data-v="v-pm" onclick="go('v-pm',this)"><svg class="icon" viewBox="0 0 24 24"><path d="M3 6h18v12H3z"/><path d="M3 7l9 6 9-6"/></svg>消息<span id="pmDot" class="dot hide"></span></button>
    <button data-v="v-me" onclick="go('v-me',this)"><svg class="icon" viewBox="0 0 24 24"><circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/></svg>我的</button>
  </div>
</nav>

<div id="v-auth" class="hide">
  <div class="auth-wrap">
    <div class="auth-logo">Chick<i>·</i>Zone</div>
    <div class="auth-sub" id="authSub">登录后就能发言、发帖</div>
    <input id="acc" placeholder="手机号或邮箱" autocomplete="off">
    <input id="pwd" type="password" placeholder="密码（至少 6 位）" autocomplete="off">
    <input id="nick" class="hide" placeholder="昵称（注册用，2-20 字）" maxlength="20">
    <div id="ts" style="margin:14px 0"></div>
    <button class="btn red" style="width:100%;justify-content:center;padding:14px;font-size:15px" id="authBtn" onclick="doAuth()">登录</button>
    <div class="auth-switch" id="authSwitch" onclick="toggleMode()">没有账号？注册一个</div>
  </div>
</div>

<input type="file" id="file" accept="image/*" class="hide" onchange="onImg(event)">
<input type="file" id="spFile" accept="image/*" class="hide" onchange="onSpFile(event)">
<input type="file" id="avFile" accept="image/*" class="hide" onchange="onAvFile(event)">
<input type="file" id="pmFile" accept="image/*" class="hide" onchange="onPMImg(event)">
<input type="file" id="botFile" accept="image/*" class="hide" onchange="onBotImg(event)">
<div id="m-guide" class="hide" style="position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:95;display:flex;align-items:flex-end;justify-content:center">
  <div style="background:var(--bg);width:100%;max-width:420px;padding:22px">
    <div style="font-size:17px;font-weight:800;margin-bottom:10px">欢迎来到 Chick Zone</div>
    <div style="font-size:13px;color:var(--gray);line-height:2.1">
      · 大厅：像聊天室一样随便聊，@小助手 可以叫它接话<br>
      · 帖子：发帖、评论、点赞，好内容会被搜索引擎收录<br>
      · 消息：搜昵称找人私聊（每天免费 5 条）<br>
      · 我的：改头像、写签名、赞助升级等级
    </div>
    <button class="btn red" style="width:100%;justify-content:center;margin-top:16px" onclick="closeGuide()">知道了，开逛</button>
  </div>
</div>

<div id="m-honor" class="hide" style="position:fixed;inset:0;background:rgba(0,0,0,.45);z-index:90;display:flex;align-items:flex-end;justify-content:center">
  <div style="background:var(--bg);width:100%;max-width:420px;padding:22px">
    <div style="font-size:17px;font-weight:800;margin-bottom:6px">感谢你的赞助！</div>
    <div style="font-size:13px;color:var(--gray);margin-bottom:16px">要把你记上荣誉墙吗？</div>
    <button class="btn red" style="width:100%;justify-content:center;margin-bottom:8px" onclick="setDisplay(1)">实名上榜</button>
    <button class="btn ghost" style="width:100%;justify-content:center;margin-bottom:8px" onclick="setDisplay(2)">匿名上榜（显示为「匿名鸡友」）</button>
    <button class="btn txt" style="width:100%;text-align:center" onclick="setDisplay(0)">不用了，不上墙</button>
  </div>
</div>

<div id="toast"></div>

<script>
var API=localStorage.getItem('cz_api')||location.origin;
var TOKEN='';try{TOKEN=localStorage.getItem('cz_t')||''}catch(e){}
var TS_SITE='0x4AAAAAAFGV7ngBZjE7G1qS';
var ME=null,MSGS=[],POSTS=[],LAST_ID=0,SYNCING=false,TIMER=null,CUR_POST=null,MODE='login',tsId=null;

function $(id){return document.getElementById(id)}
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]})}
function tg(id){$(id).classList.toggle('hide')}
function roleName(r){return r>=2?'站长':r===1?'管理员':'用户'}
function toast(t){var e=$('toast');e.textContent=t;e.style.display='block';clearTimeout(e._t);e._t=setTimeout(function(){e.style.display='none'},1800)}
function req(p,b){
  var o={method:b===undefined?'GET':'POST',headers:{}};
  if(TOKEN)o.headers['X-Token']=TOKEN;
  if(b!==undefined){o.headers['Content-Type']='application/json';o.body=JSON.stringify(b||{})}
  return fetch(API+p,o).then(function(r){return r.json().catch(function(){return{err:'响应异常'}})});
}
/* ===== 本地缓存（IndexedDB）：减少数据库访问、秒开 ===== */
var _idb=null;
function openIDB(){
  if(_idb)return Promise.resolve(_idb);
  return new Promise(function(res){try{
    var r=indexedDB.open('cz_v3',1);
    r.onupgradeneeded=function(e){var db=e.target.result;
      if(!db.objectStoreNames.contains('messages'))db.createObjectStore('messages',{keyPath:'id'});
      if(!db.objectStoreNames.contains('posts'))db.createObjectStore('posts',{keyPath:'id'});
      if(!db.objectStoreNames.contains('meta'))db.createObjectStore('meta',{keyPath:'k'});
    };
    r.onsuccess=function(e){_idb=e.target.result;res(_idb)};
    r.onerror=function(){res(null)};
  }catch(e){res(null)}});
}
function idbAll(s){return openIDB().then(function(db){if(!db)return [];return new Promise(function(res){try{var r=db.transaction(s,'readonly').objectStore(s).getAll();r.onsuccess=function(){res(r.result||[])};r.onerror=function(){res([])}}catch(e){res([])}})})}
function idbPut(s,arr){return openIDB().then(function(db){if(!db)return;try{var tx=db.transaction(s,'readwrite'),st=tx.objectStore(s);arr.forEach(function(o){st.put(o)})}catch(e){}})}
function idbDel(s,ids){return openIDB().then(function(db){if(!db)return;try{var tx=db.transaction(s,'readwrite'),st=tx.objectStore(s);ids.forEach(function(i){st.delete(i)})}catch(e){}})}
function idbMetaSet(k,v){return idbPut('meta',[{k:k,v:v}])}

/* ===== 登录 / 注册 ===== */
function loadTS(cb){
  if(window.turnstile){cb();return}
  if(document.getElementById('ts-script')){var n=0,t=setInterval(function(){if(window.turnstile){clearInterval(t);cb()}if(++n>50)clearInterval(t)},200);return}
  var s=document.createElement('script');s.id='ts-script';
  s.src='https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
  s.async=true;s.defer=true;s.onload=cb;document.head.appendChild(s);
}
function renderTS(){
  loadTS(function(){
    if(!window.turnstile)return;
    if(tsId!==null){window.turnstile.reset(tsId);window.__ts=null;return}
    tsId=window.turnstile.render('#ts',{sitekey:TS_SITE,theme:'light',
      callback:function(t){window.__ts=t},
      'expired-callback':function(){window.__ts=null},
      'error-callback':function(){window.__ts=null}});
  });
}
function resetTS(){if(tsId!==null&&window.turnstile){window.turnstile.reset(tsId)}window.__ts=null}
function toggleMode(){
  MODE=MODE==='login'?'reg':'login';
  $('nick').classList.toggle('hide',MODE==='login');
  $('authBtn').textContent=MODE==='login'?'登录':'注册';
  $('authSwitch').textContent=MODE==='login'?'没有账号？注册一个':'已有账号？去登录';
  $('authSub').textContent=MODE==='login'?'登录后就能发言、发帖':'注册只需要：账号、密码、昵称';
  renderTS();
}
function doAuth(){
  var acc=$('acc').value.trim(),pwd=$('pwd').value,nk=$('nick').value.trim();
  if(!acc||!pwd){toast('账号和密码都要填');return}
  if(MODE==='reg'&&!nk){toast('请填昵称');return}
  var ts=window.__ts||'';
  if(!ts){toast('请先完成人机验证');return}
  var body={account:acc,pass:pwd,turnstileToken:ts,authMethod:'turnstile'};
  if(MODE==='reg')body.name=nk;
  $('authBtn').disabled=true;
  req(MODE==='reg'?'/reg':'/login',body).then(function(r){
    $('authBtn').disabled=false;
    if(r.err){toast(r.err);resetTS();renderTS();return}
    TOKEN=r.token;try{localStorage.setItem('cz_t',TOKEN)}catch(e){}
    start();
  }).catch(function(){$('authBtn').disabled=false;toast('网络错误')});
}
function showAuth(){$('v-auth').classList.remove('hide');renderTS()}
function logout(){
  if(!confirm('退出登录？'))return;
  TOKEN='';ME=null;MSGS=[];LAST_ID=0;tsId=null;
  try{localStorage.removeItem('cz_t')}catch(e){}
  if(TIMER)clearInterval(TIMER);TIMER=null;
  go('v-hall');showAuth();
}
function doRename(){
  var nn=prompt('新的昵称（2-20 字）：',(ME&&ME.name)||'');
  if(nn===null)return;
  nn=nn.trim();if(!nn)return;
  req('/user/rename',{name:nn}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('改名成功');loadMe().then(renderMe);
  });
}
function doDelete(){
  if(!confirm('确定注销账号？所有帖子、消息、积分将被清空，无法恢复！'))return;
  var t=prompt('最后确认：请输入你的昵称「'+((ME&&ME.name)||'')+'」');
  if(t===null)return;
  req('/user/delete',{confirm:t.trim()}).then(function(r){
    if(r.err){toast(r.err);return}
    try{localStorage.removeItem('cz_t')}catch(e){}
    toast('已注销');setTimeout(function(){location.reload()},800);
  });
}
function pickAvatar(){$('avFile').click()}
function onAvFile(e){
  var f=e.target.files&&e.target.files[0];if(!f)return;
  var r=new FileReader();
  r.onload=function(ev){
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'),x=c.getContext('2d');
      var s=Math.min(1,300/Math.max(img.width,img.height));
      c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
      x.drawImage(img,0,0,c.width,c.height);
      var q=0.85,d;
      do{d=c.toDataURL('image/jpeg',q);q-=0.1}while(d.length>150000&&q>0.05);
      req('/user/avatar',{image:d}).then(function(res){
        if(res.err){toast(res.err);return}
        toast('头像已更新');loadMe().then(function(){renderMe();if(CUR_PROFILE)openProfile(CUR_PROFILE)});
      });
    };img.src=ev.target.result;
  };r.readAsDataURL(f);e.target.value='';
}
function doPass(){
  var o=$('pwOld').value,n=$('pwNew').value,n2=$('pwNew2').value;
  if(!o||!n){toast('密码都要填');return}
  if(n.length<6){toast('新密码至少 6 位');return}
  if(n!==n2){toast('两次输入的新密码不一样');return}
  req('/user/pass',{old:o,new:n}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('密码已修改');go('v-me');
  });
}
/* ===== 私聊 ===== */
var PM_UID=0,PM_NAME='',PM_LAST=0,PM_TIMER=null;
function loadPM(){
  $('pmList').innerHTML='<div class="empty">加载中…</div>';
  req('/pm/list').then(function(d){
    if(!d||d.err){$('pmList').innerHTML='<div class="empty">'+esc((d&&d.err)||'加载失败')+'</div>';return}
    $('pmTip').textContent='普通用户每天 5 条 · 支持者 100 条 · 赞助者不限';
    var h='';
    (d.list||[]).forEach(function(c){
      h+='<div class="row" style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="openChat('+c.uid+')">'
        +'<div class="pav">'+((c.avatar&&/^data:image/.test(c.avatar))?'<img src="'+esc(c.avatar)+'">':esc((c.name||'?').charAt(0)))+'</div>'
        +'<div style="flex:1;min-width:0"><div style="display:flex;justify-content:space-between;gap:8px"><span class="r1">'+esc(c.name)+(c.unread?' <span style="color:var(--red);font-size:12px;font-weight:800">'+c.unread+'</span>':'')+'</span><span class="r2 num" style="flex:none">'+esc(String(c.time||'').slice(5,16))+'</span></div>'
        +'<div class="r2" style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis">'+esc(String(c.last||'').slice(0,40))+'</div></div>'
        +'<span class="op" style="margin:0;font-size:12px" onclick="event.stopPropagation();delConv('+c.uid+')">删除</span></div>';
    });
    $('pmList').innerHTML=h||'<div class="empty">还没有私聊，去别人的主页点「发私信」</div>';
  }).catch(function(){$('pmList').innerHTML='<div class="empty">加载失败</div>'});
}
function searchUser(){
  var q=($('pmSearch').value||'').trim();
  if(!q){$('pmSearchRes').innerHTML='';return}
  $('pmSearchRes').innerHTML='<div class="empty">搜索中…</div>';
  req('/search/user?q='+encodeURIComponent(q)).then(function(list){
    var h='';
    (list||[]).forEach(function(u){
      h+='<div class="row" style="display:flex;align-items:center;gap:10px;cursor:pointer" onclick="openChat('+u.id+',\\''+esc(u.name).replace(/'/g,'')+'\\')">'
        +'<div class="pav">'+((u.avatar&&/^data:image/.test(u.avatar))?'<img src="'+esc(u.avatar)+'">':esc((u.name||'?').charAt(0)))+'</div>'
        +'<div style="flex:1;min-width:0"><div class="r1">'+esc(u.name)+'</div><div class="r2">点这行发私信</div></div>'
        +'<span class="op" style="margin:0;font-size:12px" onclick="event.stopPropagation();openProfile('+u.id+')">主页</span></div>';
    });
    $('pmSearchRes').innerHTML=h||'<div class="empty">没找到这个人</div>';
  });
}
function openChat(uid,name){
  PM_UID=uid;PM_NAME=name||'';PM_LAST=0;
  clearQuote();
  go('v-pmchat');
  $('pmMsgs').innerHTML='<div class="empty">加载中…</div>';
  loadChat(true);
  if(PM_TIMER)clearInterval(PM_TIMER);
  PM_TIMER=setInterval(function(){loadChat(false)},8000);
}
function closeChat(){
  if(PM_TIMER){clearInterval(PM_TIMER);PM_TIMER=null}
  PM_UID=0;go('v-pm');loadPM();
}
var PM_MSGS=[],PM_QUOTE='';
function loadChat(full){
  if(!PM_UID)return;
  req('/pm?uid='+PM_UID+'&since='+(full?0:PM_LAST)).then(function(list){
    if(!list||list.err){$('pmMsgs').innerHTML='<div class="empty">'+esc((list&&list.err)||'加载失败')+'</div>';return}
    var box=$('pmMsgs');
    if(full){box.innerHTML='';PM_MSGS=[]}
    list.forEach(function(m){
      var self=m.fid===((ME&&ME.id)||0);
      if(!PM_MSGS.some(function(x){return x.id===m.id}))PM_MSGS.push(m);
      var body=m.type==='image'?'<img src="'+esc(m.content)+'" onclick="window.open(this.src)">':'<span onclick="setQuoteById('+m.id+')">'+esc(m.content)+'</span>';
      var q=m.quote?'<div style="font-size:11px;opacity:.55;border-left:2px solid currentColor;padding-left:6px;margin-bottom:4px">'+esc(m.quote)+'</div>':'';
      box.innerHTML+='<div class="pm-row'+(self?' me':'')+'"><div class="pm-bub">'+q+body+'<div style="font-size:10px;opacity:.5;margin-top:3px;text-align:right">'+String(m.time||'').slice(11,16)+'</div></div></div>';
      if(m.id>PM_LAST)PM_LAST=m.id;
    });
    if(full&&!list.length)box.innerHTML='<div class="empty">还没有消息，打个招呼吧</div>';
    window.scrollTo(0,document.body.scrollHeight);
  });
}
function setQuoteById(id){
  var m=(PM_MSGS||[]).filter(function(x){return x.id===id})[0];
  if(!m)return;
  var who=m.fid===((ME&&ME.id)||0)?'我':(PM_NAME||'对方');
  PM_QUOTE=who+'：'+String(m.content||'').slice(0,40);
  $('pmQuoteTxt').textContent='引用 '+PM_QUOTE;
  $('pmQuote').classList.remove('hide');
  try{$('pmInput').focus()}catch(e){}
}
function clearQuote(){PM_QUOTE='';var q=$('pmQuote');if(q)q.classList.add('hide');var t=$('pmQuoteTxt');if(t)t.textContent=''}
function sendPM(){
  var el=$('pmInput'),v=el.value.trim();if(!v||!PM_UID)return;
  el.value='';
  req('/pm',{to:PM_UID,content:v,quote:PM_QUOTE}).then(function(r){
    if(r.err){toast(r.err);el.value=v;return}
    clearQuote();loadChat(false);
  });
}
function pickPMImg(){$('pmFile').click()}
function onPMImg(e){
  var f=e.target.files&&e.target.files[0];if(!f||!PM_UID)return;
  toast('图片处理中…');
  var r=new FileReader();
  r.onload=function(ev){
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'),x=c.getContext('2d');
      var s=Math.min(1,800/Math.max(img.width,img.height));
      c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
      x.drawImage(img,0,0,c.width,c.height);
      var q=0.7,d;
      do{d=c.toDataURL('image/jpeg',q);q-=0.15}while(d.length>100000&&q>0.05);
      req('/pm',{to:PM_UID,content:d,type:'image'}).then(function(res){
        if(res.err){toast(res.err);return}
        toast('图片已发送');loadChat(false);
      });
    };img.src=ev.target.result;
  };r.readAsDataURL(f);e.target.value='';
}
function delConv(uid){
  if(!confirm('删除这个对话？仅影响你这边'))return;
  req('/pm/del',{uid:uid}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已删除');loadPM();
  });
}

/* ===== 启动 ===== */
function showGuide(){$('m-guide').classList.remove('hide')}
function closeGuide(){try{localStorage.setItem('cz_guide_v1','1')}catch(e){}$('m-guide').classList.add('hide')}
function maybeGuide(){
  var seen=false;try{seen=localStorage.getItem('cz_guide_v1')==='1'}catch(e){}
  if(!seen)$('m-guide').classList.remove('hide');
}
function start(){
  $('v-auth').classList.add('hide');
  maybeGuide();
  loadMe().then(function(){
    Promise.all([idbAll('messages'),idbAll('posts')]).then(function(a){
      var cm=(a[0]||[]).sort(function(x,y){return x.id-y.id});
      if(cm.length){MSGS=cm;MSGS.forEach(function(m){if(m.id>LAST_ID)LAST_ID=m.id});renderMsgs()}
      var cp=(a[1]||[]).sort(function(x,y){return x.id-y.id});
      if(cp.length){POSTS=cp;renderPosts()}
    }).catch(function(){});
    loadMsgs();loadPosts();loadSites();
    ensureTimer();
  });
}
document.addEventListener('visibilitychange',function(){
  if(!TOKEN)return;
  if(document.hidden){if(TIMER){clearInterval(TIMER);TIMER=null}}
  else{syncNow();ensureTimer()}
});
(function(){
  if(!TOKEN){showAuth();return}
  req('/me').then(function(u){
    if(u&&u.id){start()}
    else{TOKEN='';try{localStorage.removeItem('cz_t')}catch(e){}showAuth()}
  }).catch(function(){showAuth()});
})();

/* ===== 大厅 ===== */
function loadMe(){
  return req('/me').then(function(u){
    ME=(u&&u.id)?u:null;
    if(ME){
      $('mePts').textContent=ME.points||0;
      $('meAvatar').innerHTML=avHtml(ME.name,ME.avatar);
    }
  }).catch(function(){});
}
function hhmm(t){return String(t||'').slice(11,16)}
function msgHtml(m){
  var self=ME&&m.uid===ME.id,isBot=m.uid===0;
  var body=m.type==='image'?'<img src="'+esc(m.content)+'" onclick="window.open(this.src)">':esc(m.content);
  var op=self?'<span class="op" onclick="recallMsg('+m.id+')">撤回</span>':(ME&&!isBot?'<span class="op" onclick="report(\\'message\\','+m.id+')">举报</span>':'');
  return '<div class="msg'+(self?' mine':'')+(isBot?' bot':'')+'" id="m'+m.id+'"><span class="n">'+esc(m.name)+'</span><span class="t num">'+hhmm(m.time)+'</span><div class="c">'+body+'</div>'+(op?'<div>'+op+'</div>':'')+'</div>';
}
function renderMsgs(){
  var box=$('msgs');if(!box)return;
  if(!MSGS.length){box.innerHTML='<div class="empty">还没有消息，说第一句吧</div>';return}
  var near=window.innerHeight+window.scrollY>=document.body.scrollHeight-220;
  var h='';MSGS.forEach(function(m){h+=msgHtml(m)});
  box.innerHTML=h;
  if(near)window.scrollTo(0,document.body.scrollHeight);
}
function loadMsgs(){
  return req('/messages?since='+LAST_ID).then(function(list){
    if(!list||list.err){if(!MSGS.length)$('msgs').innerHTML='<div class="empty">'+esc((list&&list.err)||'加载失败')+'</div>';return}
    var nm=list.slice().reverse();
    nm.forEach(function(m){if(!MSGS.some(function(x){return x.id===m.id}))MSGS.push(m);if(m.id>LAST_ID)LAST_ID=m.id});
    if(nm.length){MSGS.sort(function(a,b){return a.id-b.id});renderMsgs();idbPut('messages',nm);trimMsgs()}
    idbMetaSet('lastMsgId',LAST_ID);
  }).catch(function(){if(!MSGS.length)$('msgs').innerHTML='<div class="empty">加载失败</div>'});
}
function trimMsgs(){
  if(MSGS.length>200){var cut=MSGS.slice(0,MSGS.length-200);MSGS=MSGS.slice(MSGS.length-200);idbDel('messages',cut.map(function(m){return m.id}))}
}
function syncNow(){
  if(SYNCING||!TOKEN)return;SYNCING=true;
  req('/sync?msgSince='+LAST_ID+'&postSince=0&sinceTime=0').then(function(d){
    SYNCING=false;
    if(!d||d.err){bumpPoll(false);return}
    var nm=d.messages||[],dm=d.deletedMessages||[];
    if(dm.length){MSGS=MSGS.filter(function(m){return dm.indexOf(m.id)<0});idbDel('messages',dm)}
    nm.forEach(function(m){if(!MSGS.some(function(x){return x.id===m.id}))MSGS.push(m);if(m.id>LAST_ID)LAST_ID=m.id});
    if(nm.length||dm.length){renderMsgs();if(nm.length)idbPut('messages',nm);trimMsgs();idbMetaSet('lastMsgId',LAST_ID)}
    if(typeof d.pmUnread==='number'){var dot=$('pmDot');if(dot)dot.classList.toggle('hide',d.pmUnread===0)}
    bumpPoll(nm.length>0);
  }).catch(function(){SYNCING=false;bumpPoll(false)});
}
var POLL_MS=10000,POLL_SILENT=0;
function ensureTimer(){if(TIMER)clearInterval(TIMER);TIMER=setInterval(syncNow,POLL_MS)}
function bumpPoll(hasNews){
  if(hasNews){POLL_MS=10000;POLL_SILENT=0}
  else{
    POLL_SILENT++;
    if(POLL_SILENT>=6&&POLL_MS<30000)POLL_MS=30000;
    if(POLL_SILENT>=18&&POLL_MS<60000)POLL_MS=60000;
  }
  if(document.hidden)return;
  ensureTimer();
}
function send(){
  var el=$('minput'),v=el.value.trim();if(!v)return;
  el.value='';
  req('/send',{content:v,type:'text'}).then(function(r){
    if(r.err){toast(r.err);el.value=v;return}
    if(r.id){
      var d=new Date(),t=('0'+d.getHours()).slice(-2)+':'+('0'+d.getMinutes()).slice(-2);
      MSGS.push({id:r.id,uid:ME?ME.id:0,name:ME?ME.name:'我',content:v,type:'text',time:'0000-00-00 '+t});
      if(r.id>LAST_ID)LAST_ID=r.id;
      renderMsgs();window.scrollTo(0,document.body.scrollHeight);
    }
    setTimeout(syncNow,1200);
  });
}
function recallMsg(id){
  if(!confirm('撤回这条消息？'))return;
  req('/recall',{t:'message',id:id}).then(function(r){
    if(r.err){toast(r.err);return}
    MSGS=MSGS.filter(function(m){return m.id!==id});renderMsgs();toast('已撤回');
  });
}
function pickImg(){$('file').click()}
function onImg(e){
  var f=e.target.files&&e.target.files[0];if(!f)return;
  toast('图片处理中…');
  var r=new FileReader();
  r.onload=function(ev){
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'),x=c.getContext('2d');
      var s=Math.min(1,800/Math.max(img.width,img.height));
      c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
      x.drawImage(img,0,0,c.width,c.height);
      var q=0.7,d;
      do{d=c.toDataURL('image/jpeg',q);q-=0.15}while(d.length>100000&&q>0.05);
      req('/send',{content:d,type:'image'}).then(function(res){
        if(res.err){toast(res.err);return}
        toast('图片已发送');setTimeout(syncNow,800);
      });
    };img.src=ev.target.result;
  };r.readAsDataURL(f);e.target.value='';
}

/* ===== 帖子 ===== */
function loadPosts(){
  return req('/posts').then(function(list){
    POSTS=list||[];
    idbPut('posts',POSTS);
    $('postCount').textContent='共 '+POSTS.length+' 帖';
    var h='';
    POSTS.forEach(function(p){
      h+='<div class="post" onclick="openPost('+p.id+')"><div class="pav">'
        +((p.avatar&&/^data:image/.test(p.avatar))?'<img src="'+esc(p.avatar)+'" alt="">':esc((p.name||'?').charAt(0)))
        +'</div><div class="pbody"><div class="ttl">'
        +(p.pinned?'<span class="pin">置顶</span>':'')+(p.tag?'<span class="tag">'+esc(p.tag)+'</span>':'')
        +esc(p.title)+'</div><div class="ex">'+esc(p.content)+'</div>'
        +'<div class="meta num"><span>'+esc(p.name)+'</span><span>'+esc((p.time||'').slice(5,16))+'</span><span>'+p.likes+' 赞</span><span>'+p.cmts+' 评论</span></div></div></div>';
    });
    $('postList').innerHTML=h||'<div class="empty">还没有帖子，来发第一帖</div>';
  }).catch(function(){$('postList').innerHTML='<div class="empty">加载失败</div>'});
}
function openPost(id,obj){
  CUR_POST=(obj&&obj.id===id)?obj:POSTS.filter(function(p){return p.id===id})[0]||null;
  if(!CUR_POST){toast('帖子不存在');return}
  go('v-post');renderDetail();
}
function renderDetail(){
  var p=CUR_POST,mine=ME&&ME.id===p.uid;
  var box=$('v-post');
  box.innerHTML='<button class="btn txt" onclick="go(\\'v-posts\\')">← 返回</button>'
    +'<h1>'+esc(p.title)+'</h1>'
    +'<div class="meta num">'+esc(p.name)+' · '+esc(p.time)+'</div>'
    +'<div class="body">'+esc(p.content).replace(/\\n/g,'<br>')+'</div>'
    +'<div class="acts num">'
    +'<button onclick="likePost('+p.id+')">赞 <span id="pl'+p.id+'">'+p.likes+'</span></button>'
    +(mine?'<button onclick="recallPost('+p.id+')">撤回</button>':'<button onclick="report(\\'post\\','+p.id+')">举报</button>')
    +'</div><div id="cmts"><div class="empty">加载评论…</div></div>'
    +'<div style="margin-top:16px"><div class="f"><textarea id="cin" style="min-height:70px" placeholder="说两句" maxlength="500"></textarea></div>'
    +'<button class="btn red" style="width:100%;justify-content:center" onclick="pubComment('+p.id+')">发评论</button></div>'
    +'<div style="text-align:center;font-size:12px;color:var(--faint);padding:20px 0 8px;line-height:1.7">如果这篇对你有帮助，把链接分享给更多人看看。</div>';
  loadComments(p.id);
}
function loadComments(pid){
  req('/comments?pid='+pid).then(function(list){
    var h='';
    (list||[]).forEach(function(c){
      var mine=ME&&ME.id===c.uid;
      h+='<div class="cmt"><span class="n">'+esc(c.name)+'</span><span class="t num">'+esc((c.time||'').slice(5,16))+'</span><p>'+esc(c.content)+'</p>'
        +'<div style="margin-top:4px"><button class="btn txt" style="font-size:12px;padding:4px 0" onclick="likeComment('+c.id+','+pid+')">赞 '+c.likes+'</button>'
        +(mine?'':'<button class="btn txt" style="font-size:12px;padding:4px 0;margin-left:14px" onclick="report(\\'comment\\','+c.id+')">举报</button>')
        +'</div></div>';
    });
    var box=$('cmts');if(box)box.innerHTML=h||'<div class="empty">还没有评论，抢个沙发</div>';
  });
}
function pubComment(pid){
  var el=$('cin'),v=el.value.trim();if(!v)return;
  req('/comment',{pid:pid,content:v}).then(function(r){
    if(r.err){toast(r.err);return}
    el.value='';toast('已发布 +1 分');loadComments(pid);
  });
}
function likePost(id){
  req('/like',{ttype:'post',tid:id}).then(function(r){
    if(r.err){toast(r.err);return}
    var el=$('pl'+id);if(el)el.textContent=+el.textContent+1;toast('已赞');
  });
}
function likeComment(cid,pid){
  req('/like',{ttype:'comment',tid:cid}).then(function(r){
    if(r.err){toast(r.err);return}
    loadComments(pid);toast('已赞');
  });
}
function pubPost(){
  var t=$('cTitle').value.trim(),c=$('cBody').value.trim(),g=$('cTag').value.trim()||'闲聊';
  if(!t||!c){toast('标题和正文都要填');return}
  req('/post',{title:t,content:c,tag:g}).then(function(r){
    if(r.err){toast(r.err);return}
    $('cTitle').value='';$('cBody').value='';$('cTag').value='';
    toast('发布成功 +1 分');go('v-posts');loadPosts();loadMe();
  });
}
function recallPost(id){
  if(!confirm('撤回这篇帖子？'))return;
  req('/recall',{t:'post',id:id}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已撤回');go('v-posts');loadPosts();
  });
}
function report(ttype,tid){
  var reason=prompt('举报原因：');if(!reason||!reason.trim())return;
  req('/report',{ttype:ttype,tid:tid,reason:reason.trim()}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已提交，AI 会先复核');
  });
}

/* ===== 导航 ===== */
var SITE_CAT='全部';
function setCat(c){SITE_CAT=c;loadSites()}
function loadSites(){
  return req('/sites').then(function(d){
    var list=(d&&d.list)||[];
    var cats=['全部'];
    list.forEach(function(s){var t=s.tag||'其他';if(cats.indexOf(t)<0)cats.push(t)});
    var fh='';
    cats.forEach(function(c){
      fh+='<span onclick="setCat(\\''+esc(c).replace(/'/g,'')+'\\')" style="cursor:pointer;padding-bottom:2px;'+(SITE_CAT===c?'font-weight:800;color:var(--red);border-bottom:2px solid var(--red)':'color:var(--gray)')+'">'+esc(c)+'</span>';
    });
    $('siteCats').innerHTML=fh;
    var h='';
    list.forEach(function(s){
      if(s.status===0&&!(ME&&ME.role>=1))return;
      if(SITE_CAT!=='全部'&&(s.tag||'其他')!==SITE_CAT)return;
      var host=esc(String(s.url||'').replace(/^https?:\\/\\//,'').split('/')[0]);
      h+='<div class="site" style="cursor:pointer" onclick="window.open(\\''+esc(String(s.url||'').replace(/'/g,''))+'\\',\\'_blank\\')"><span class="nm">'+esc(s.name)+'</span><span class="u num">'+host+'</span>'
        +(s.status===0?'<span class="u acc">待审</span>':'')
        +'<div class="d">'+esc(s.desc||'')+'</div></div>';
    });
    $('siteList').innerHTML=h||'<div class="empty">这个分类还没有网站</div>';
  }).catch(function(){$('siteList').innerHTML='<div class="empty">加载失败</div>'});
}
function pubSite(){
  var n=$('stName').value.trim(),u=$('stUrl').value.trim();
  if(!n||!u){toast('名称和网址必填');return}
  req('/site',{name:n,url:u,desc:$('stDesc').value.trim(),tag:$('stTag').value.trim()}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已提交，等管理员审核');
    $('stName').value=$('stUrl').value=$('stDesc').value=$('stTag').value='';
    tg('siteForm');
  });
}

/* ===== 我的 ===== */
function avHtml(name,avatar){
  return (avatar&&/^data:image/.test(avatar))?'<img src="'+esc(avatar)+'" alt="">':esc((name||'?').charAt(0));
}
function renderMe(){
  var h='';
  if(ME){
    h+='<div class="prof" onclick="openProfile('+ME.id+')"><div class="big">'+avHtml(ME.name,ME.avatar)+'</div><div>'
      +'<div class="nm">'+esc(ME.name)+' <span class="acc" style="font-size:12px;font-weight:700">'+roleName(ME.role)+'</span></div>'
      +'<div class="sig">'+esc(ME.bio||'还没写签名，点我主页去写')+'</div></div></div>';
  }
  h+='<div class="mi" onclick="openProfile('+((ME&&ME.id)||0)+')">我的主页<span class="s">资料 · 帖子 · 统计</span></div>';
  h+='<div class="mi" onclick="pickAvatar()">换头像<span class="s">支持者及以上可用</span></div>';
  h+='<div class="mi" onclick="go(\\'v-pass\\')">改密码<span class="s">定期更换更安全</span></div>';
  h+='<div class="mi" onclick="showGuide()">使用指南<span class="s">第一次来？看这个</span></div>';
  h+='<div class="mi" onclick="go(\\'v-sponsor\\')">赞助支持<span class="s">升级等级与权限</span></div>';
  h+='<div class="mi" onclick="doRename()">改名<span class="s">30 天一次</span></div>';
  h+='<div class="mi" onclick="doDelete()">注销账号<span class="s">不可恢复</span></div>';
  if(ME&&ME.role>=1)h+='<div class="mi" onclick="go(\\'v-admin\\')">管理面板<span class="s">用户 · 举报 · 赞助</span></div>';
  h+='<div class="mi" onclick="logout()">退出登录<span class="s">'+esc((ME&&ME.name)||'')+'</span></div>';
  h+='<div style="text-align:center;font-size:12px;color:var(--faint);padding:22px 0 8px;line-height:1.7">觉得这里不错？把链接发给朋友，人多才热闹。</div>';
  $('meBox').innerHTML=h;
}

/* ===== 赞助 ===== */
var SP_IMG='';
var PAY_WECHAT='${PAY_WECHAT}',PAY_ALIPAY='${PAY_ALIPAY}';
function renderPay(){
  var box=$('payBox');if(!box)return;
  var h='';
  if(PAY_WECHAT&&PAY_WECHAT.indexOf('%%')<0)h+='<div style="text-align:center;margin-bottom:16px"><img src="'+PAY_WECHAT+'" alt="微信收款码" style="width:220px;max-width:70%;display:block;margin:0 auto"><div style="font-size:12px;color:var(--faint);margin-top:6px">微信支付 · 扫码赞助</div></div>';
  if(PAY_ALIPAY&&PAY_ALIPAY.indexOf('%%')<0)h+='<div style="text-align:center"><img src="'+PAY_ALIPAY+'" alt="支付宝收款码" style="width:220px;max-width:70%;display:block;margin:0 auto"><div style="font-size:12px;color:var(--faint);margin-top:6px">支付宝 · 扫码赞助</div></div>';
  box.innerHTML=h||'<div class="empty">收款码待站长添加</div>';
}
var FUND_PENDING=0;
function loadFund(){
  req('/fund').then(function(d){
    if(!d||d.err)return;
    var total=d.total||0,goal=d.goal||0;
    var bar=$('fundBar');if(!bar)return;
    $('fundNums').textContent=total+' / '+(goal>0?goal:'—')+' 元';
    $('fundCap').textContent=goal>0?(total>=goal?'目标已达成，感谢大家！':'距离目标还差 '+(goal-total)+' 元'):'感谢每一位支持的鸡友';
    var oldT=0;try{oldT=+(localStorage.getItem('cz_fund_total')||0)}catch(e){}
    bar.style.transition='none';
    bar.style.width=(goal>0?Math.min(100,oldT/goal*100):0)+'%';
    void bar.offsetWidth;
    bar.style.transition='width .9s cubic-bezier(.34,1.56,.64,1)';
    setTimeout(function(){bar.style.width=(goal>0?Math.min(100,total/goal*100):(total>0?100:0))+'%'},60);
    if(oldT>0&&total>oldT)toast('收到新的赞助，感谢支持！');
    try{localStorage.setItem('cz_fund_total',total)}catch(e){}
    var h='';
    (d.list||[]).forEach(function(x){
      h+='<div style="display:flex;justify-content:space-between;font-size:13px;padding:6px 0;border-bottom:1px solid var(--line)"><span>'+esc(x.name)+'</span><span class="num" style="color:var(--gray)">+'+x.amount+' 元 · '+esc((x.time||'').slice(5,10))+'</span></div>';
    });
    $('fundList').innerHTML=h||'<div style="font-size:12px;color:var(--faint)">还没有公开的赞助记录</div>';
    if(ME&&ME.role===2)$('goalBtn').classList.remove('hide');
    if(d.myPending&&d.myPending.length){FUND_PENDING=d.myPending[0];$('m-honor').classList.remove('hide')}
  }).catch(function(){});
}
function setDisplay(mode){
  req('/fund/display',{id:FUND_PENDING,mode:mode}).then(function(r){
    if(r.err){toast(r.err);return}
    $('m-honor').classList.add('hide');
    toast(mode===0?'好的，不上墙':mode===1?'已实名上榜，感谢！':'已匿名上榜，感谢！');
    loadFund();
  });
}
function setGoal(){
  var g=prompt('新的赞助目标金额（元，0 = 不显示目标）：');
  if(g===null)return;
  var n=parseInt(g,10);
  if(!(n>=0)){toast('请输入数字');return}
  req('/fund/goal',{goal:n}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('目标已更新');loadFund();
  });
}
function loadSponsor(){
  renderPay();loadFund();
  req('/sponsor/me').then(function(d){
    $('spTotal').textContent=d.total||0;
    var h='';
    (d.levels||[]).forEach(function(x){
      h+='<div class="row"><div class="r1">'+(x.badge?'<span class="acc">'+x.badge+'</span> ':'')+x.name+' <span style="float:right;color:var(--faint);font-size:13px;font-weight:400">≥'+x.min+' 元</span></div>'
        +'<div class="r2">每日 '+(x.postLimit>=999?'不限':x.postLimit)+' 帖'+(x.avatarMax?' · 可传 '+x.avatarMax+'KB 头像':'')+'</div></div>';
    });
    $('lvList').innerHTML=h;
    var hh='';
    (d.history||[]).forEach(function(s){
      var st=s.status===0?'<span class="acc">待审</span>':s.status===1?'已通过':'已驳回';
      hh+='<div class="row"><div class="r1 num">'+(s.amount?s.amount+' 元':'—')+' <span style="float:right;font-weight:400;font-size:12px;color:var(--faint)">'+st+' · '+esc((s.time||'').slice(5,16))+'</span></div></div>';
    });
    $('spHist').innerHTML=hh||'<div class="empty">还没有赞助记录</div>';
  }).catch(function(){});
}
function pickSp(){$('spFile').click()}
function onSpFile(e){
  var f=e.target.files&&e.target.files[0];if(!f)return;
  var r=new FileReader();
  r.onload=function(ev){
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'),x=c.getContext('2d');
      var s=Math.min(1,900/Math.max(img.width,img.height));
      c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
      x.drawImage(img,0,0,c.width,c.height);
      var q=0.7,d;
      do{d=c.toDataURL('image/jpeg',q);q-=0.15}while(d.length>250000&&q>0.05);
      SP_IMG=d;$('spZone').textContent='已选择截图，点下面按钮提交';
    };img.src=ev.target.result;
  };r.readAsDataURL(f);e.target.value='';
}
function submitSponsor(){
  if(!SP_IMG){toast('先上传转账截图');return}
  var b=$('spBtn');b.disabled=true;b.textContent='AI 审核中…';
  req('/sponsor/submit',{image:SP_IMG}).then(function(r){
    b.disabled=false;b.textContent='提交审核';
    if(r.err){toast(r.err);return}
    if(r.auto){toast('审核通过，+'+r.amount+' 元，升级至「'+r.levelName+'」');loadMe()}
    else{toast('已提交，等待人工审核')}
    SP_IMG='';$('spZone').textContent='点击上传转账截图';loadSponsor();
  }).catch(function(){b.disabled=false;b.textContent='提交审核'});
}

/* ===== 个人主页 ===== */
var CUR_PROFILE=0;
function openProfile(uid){
  if(!uid){toast('请先登录');return}
  CUR_PROFILE=uid;go('v-profile');
  var box=$('v-profile');box.innerHTML='<div class="empty">加载中…</div>';
  req('/user/profile?id='+uid).then(function(d){
    if(d.err){box.innerHTML='<button class="btn txt" onclick="go(\\'v-me\\')">← 返回</button><div class="empty">'+esc(d.err)+'</div>';return}
    var u=d.user,st=d.stats,isMe=ME&&ME.id===u.id;
    var h='<button class="btn txt" onclick="go(\\'v-me\\')">← 返回</button>'
      +'<div class="prof"><div class="big">'+avHtml(u.name,u.avatar)+'</div><div>'
      +'<div class="nm">'+esc(u.name)+' <span class="acc" style="font-size:12px;font-weight:700">'+roleName(u.role)+'</span>'
      +(u.sponsor_level>0?' <span class="acc" style="font-size:12px">'+(u.levelInfo&&u.levelInfo.badge||'')+(u.levelInfo&&u.levelInfo.name||'')+'</span>':'')+'</div>'
      +'<div class="sig">'+esc(u.bio||'这个人很安静')+'</div></div></div>'
      +'<div class="stats num"><div><b>'+st.posts+'</b><span>帖子</span></div><div><b>'+st.likes+'</b><span>获赞</span></div><div><b>'+st.messages+'</b><span>消息</span></div></div>';
    if(isMe)h+='<button class="btn ghost" style="width:100%;justify-content:center;margin-bottom:10px" onclick="editBio()">改签名</button>';
    if(isMe)h+='<button class="btn ghost" style="width:100%;justify-content:center;margin-bottom:10px" onclick="pickAvatar()">换头像</button>';
    else h+='<button class="btn ghost" style="width:100%;justify-content:center;margin-bottom:10px" onclick="openChat('+u.id+',\\''+esc(u.name).replace(/'/g,'')+'\\')">发私信</button>';
    h+='<h3 style="font-size:13px;color:var(--gray);margin:14px 0 6px">最近的帖子</h3>';
    var rp=d.recentPosts||[];
    if(!rp.length)h+='<div class="empty">还没有帖子</div>';
    rp.forEach(function(p){
      if(!POSTS.some(function(x){return x.id===p.id}))POSTS.push({id:p.id,uid:u.id,name:u.name,title:p.title,content:p.content,tag:p.tag,time:p.time,likes:p.likes,cmts:p.cmts,pinned:p.pinned});
      h+='<div class="post" onclick="openPost('+p.id+')">'
        +'<div class="ttl">'+esc(p.title)+'</div><div class="meta num"><span>'+esc(p.time)+'</span><span>'+p.likes+' 赞</span><span>'+p.cmts+' 评论</span></div></div>';
    });
    h+='<h3 style="font-size:13px;color:var(--gray);margin:14px 0 6px">最近的评论</h3>';
    var rc=d.recentComments||[];
    if(!rc.length)h+='<div class="empty">还没有评论</div>';
    rc.forEach(function(c){
      h+='<div class="cmt"><p>'+esc(c.content)+'</p><div class="t">'+esc((c.time||'').slice(5,16))+' · 在「'+esc(c.title||'已删除')+'」</div></div>';
    });
    box.innerHTML=h;
  }).catch(function(){box.innerHTML='<div class="empty">加载失败</div>'});
}
function editBio(){
  var nb=prompt('新的个性签名（100 字内）：',(ME&&ME.bio)||'');
  if(nb===null)return;
  req('/user/bio',{bio:nb.slice(0,100)}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已更新');loadMe().then(renderMe);
  });
}

/* ===== 管理面板 ===== */
function loadAdmin(){
  if(!ME||ME.role<1)return;
  req('/admin/stats').then(function(s){
    $('adStats').innerHTML='<div class="stats num" style="box-shadow:none;margin:0">'
      +'<div><b>'+s.users+'</b><span>用户</span></div><div><b>'+s.posts+'</b><span>帖子</span></div>'
      +'<div><b>'+s.messages+'</b><span>消息</span></div><div><b>'+s.reports+'</b><span>待处理举报</span></div></div>'
      +'<div style="font-size:12px;color:var(--faint);margin-top:10px" class="num">今日 AI 复核 '+s.aiToday+' 次 · 待审网址 '+s.pending+'</div>';
  });
  req('/admin/users').then(function(list){
    var h='<table><tr><th>ID</th><th>昵称</th><th>角色</th><th>操作</th></tr>';
    (list||[]).forEach(function(u){
      var ops='';
      if(u.id!==ME.id&&u.role<ME.role)ops+='<span class="op" onclick="adminUser('+u.id+',\\'ban\\','+(u.banned?0:1)+')">'+(u.banned?'解禁':'禁言')+'</span>';
      if(ME.role===2&&u.role<2&&u.id!==ME.id)ops+='<span class="op" onclick="adminUser('+u.id+',\\'promote\\','+(u.role===1?0:1)+')">'+(u.role===1?'撤管':'提拔')+'</span>';
      if(ME.role===2&&u.role<2&&u.id!==ME.id)ops+='<span class="op warn" onclick="delUser('+u.id+')">删除</span>';
      if(!ops)ops='<span style="color:var(--faint)">—</span>';
      h+='<tr><td class="num">'+u.id+'</td><td>'+esc(u.name)+'</td><td>'+roleName(u.role)+'</td><td>'+ops+'</td></tr>';
    });
    $('adUsers').innerHTML=h+'</table>';
  });
  req('/admin/reports').then(function(list){
    var h='<table><tr><th>对象</th><th>原因</th><th>状态</th><th>操作</th></tr>';
    (list||[]).forEach(function(r){
      var st=r.status===0?'待处理':r.status===1?'已成立':'已驳回';
      var ops=r.status===0?'<span class="op warn" onclick="handleReport('+r.id+',\\'del\\')">确认违规</span><span class="op" onclick="handleReport('+r.id+',\\'ok\\')">驳回</span>':'—';
      h+='<tr><td>'+esc(r.ttype)+' #'+r.tid+'</td><td>'+esc(r.reason)+'</td><td>'+st+'</td><td>'+ops+'</td></tr>';
    });
    $('adReports').innerHTML=h+'</table>';
  });
  if(ME.role===2){
    req('/admin/sponsors').then(function(list){
      var h='<table><tr><th>用户</th><th>AI 识别金额</th><th>操作</th></tr>';
      (list||[]).forEach(function(s){
        h+='<tr><td>'+esc(s.uname||('用户'+s.uid))+'</td><td class="num">¥ '+(s.amount||0)+'</td>'
          +'<td><span class="op" onclick="handleSponsor('+s.id+',1)">通过</span><span class="op warn" onclick="handleSponsor('+s.id+',0)">驳回</span></td></tr>';
      });
      $('adSponsors').innerHTML=h+'</table>';
    });
  }else{
    $('adSponsors').innerHTML='<div class="empty">赞助审核仅站长可见</div>';
  }
}
function adminUser(id,a,v){
  req('/admin/user',{id:id,action:a,val:v}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已处理');loadAdmin();
  });
}
function delUser(id){
  if(!confirm('删除该用户？所有数据不可恢复！'))return;
  req('/admin/user',{id:id,action:'delete'}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已删除');loadAdmin();
  });
}
function handleReport(id,a){
  req('/admin/report',{id:id,action:a}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已处理');loadAdmin();loadPosts();
  });
}
function handleSponsor(id,ok){
  req('/admin/sponsor',{id:id,ok:ok}).then(function(r){
    if(r.err){toast(r.err);return}
    toast(ok?'已通过':'已驳回');loadAdmin();
  });
}
function atab(t,b){
  ['stats','users','reports','sponsors','search','images','posts','ai','sites','msgs'].forEach(function(x){$('a-'+x).classList.toggle('hide',x!==t)});
  document.querySelectorAll('.tabs button').forEach(function(x){x.classList.remove('on')});
  b.classList.add('on');
  if(t==='images')loadImages();
  if(t==='posts')loadPostMgr();
  if(t==='ai')loadApiKey();
  if(t==='sites')loadSiteMgr();
  if(t==='msgs')loadMsgMgr();
}
function loadMsgMgr(){
  $('adMsgs').innerHTML='<div class="empty">加载中…</div>';
  req('/messages?since=0').then(function(list){
    if(!list||list.err||!list.length){$('adMsgs').innerHTML='<div class="empty">还没有消息</div>';return}
    var h='<table><tr><th>ID</th><th>用户</th><th>内容</th><th>操作</th></tr>';
    list.forEach(function(m){
      var c=m.type==='image'?'<img src="'+esc(m.content)+'" style="width:56px;height:56px;object-fit:cover;display:block">':esc(String(m.content||'').slice(0,28));
      h+='<tr><td class="num">'+m.id+'</td><td>'+esc(m.name)+'</td><td>'+c+'</td><td><span class="op warn" onclick="delMsg('+m.id+')">删除</span></td></tr>';
    });
    $('adMsgs').innerHTML=h+'</table>';
  });
}
function delMsg(id){
  if(!confirm('删除这条消息？'))return;
  req('/admin/msg',{id:id}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('已删除');loadMsgMgr();
  });
}
function loadSiteMgr(){
  $('adSites').innerHTML='<div class="empty">加载中…</div>';
  req('/sites').then(function(d){
    var list=(d&&d.list)||[];
    if(!list.length){$('adSites').innerHTML='<div class="empty">还没有收录网站</div>';return}
    var h='<table><tr><th>ID</th><th>名称</th><th>状态</th><th>操作</th></tr>';
    list.forEach(function(s){
      var st=s.status===0?'<span style="color:var(--red);font-weight:700">待审</span>':s.status===1?'已上架':'已拒绝';
      var ops='';
      if(s.status===0)ops+='<span class="op" onclick="auditSite('+s.id+',1)">通过</span><span class="op" onclick="auditSite('+s.id+',0)">拒绝</span>';
      ops+='<span class="op warn" onclick="delSite('+s.id+')">删除</span>';
      h+='<tr><td class="num">'+s.id+'</td><td>'+esc(s.name)+'</td><td>'+st+'</td><td>'+ops+'</td></tr>';
    });
    $('adSites').innerHTML=h+'</table>';
  });
}
function auditSite(id,ok){req('/audit',{id:id,ok:ok}).then(function(r){if(r.err){toast(r.err);return}toast(ok?'已通过':'已拒绝');loadSiteMgr();loadSites()})}
function delSite(id){if(!confirm('删除这个网址？'))return;req('/del',{t:'site',id:id}).then(function(r){if(r.err){toast(r.err);return}toast('已删除');loadSiteMgr();loadSites()})}
function loadPostMgr(){
  $('adPosts').innerHTML='<div class="empty">加载中…</div>';
  req('/posts').then(function(list){
    if(!list||!list.length){$('adPosts').innerHTML='<div class="empty">还没有帖子</div>';return}
    var h='<table><tr><th>ID</th><th>标题</th><th>作者</th><th>操作</th></tr>';
    list.forEach(function(p){
      h+='<tr><td class="num">'+p.id+'</td><td>'+esc(p.title)+'</td><td>'+esc(p.name)+'</td><td><span class="op" onclick="adminPin('+p.id+','+(p.pinned?0:1)+')">'+(p.pinned?'取消置顶':'置顶')+'</span><span class="op warn" onclick="adminDelPost('+p.id+')">删除</span></td></tr>';
    });
    $('adPosts').innerHTML=h+'</table>';
  });
}
function adminPin(id,val){req('/admin/post',{id:id,action:'pin',val:val}).then(function(r){if(r.err){toast(r.err);return}toast('已处理');loadPostMgr();loadPosts()})}
function adminDelPost(id){if(!confirm('删除这篇帖子？'))return;req('/admin/post',{id:id,action:'del'}).then(function(r){if(r.err){toast(r.err);return}toast('已删除');loadPostMgr();loadPosts()})}
function doAI(action){
  var topic='';
  if(action==='post')topic=($('aiT1').value||'').trim();
  if(action==='message')topic=($('aiT2').value||'').trim();
  if(action==='batch')topic=($('aiT3').value||'').trim();
  if(!topic&&action!=='message'){toast('先填主题');return}
  if(!confirm('确定执行？'))return;
  req('/admin/ai',{action:action,topic:topic,tag:'分享'}).then(function(r){
    if(r.err){toast(r.err);return}
    if(action==='post')toast('AI 已发帖');
    else if(action==='message')toast('AI 已发言');
    else toast('已发布 '+(r.count||0)+' 帖');
    setTimeout(syncNow,1500);loadPosts();
  });
}
function loadApiKey(){
  req('/admin/apikey').then(function(d){if(d&&!d.err)$('apiKeyBox').value=(d.key||'')});
  req('/bot/status').then(function(s){if(s&&s.name&&$('botNameIn'))$('botNameIn').value=s.name}).catch(function(){});
}
function saveBotName(){
  var n=($('botNameIn').value||'').trim();
  if(!n){toast('名字不能为空');return}
  req('/admin/botname',{name:n}).then(function(r){
    if(r.err){toast(r.err);return}
    toast('机器人已改名为「'+r.name+'」');
  });
}
function pickBotImg(){$('botFile').click()}
function onBotImg(e){
  var f=e.target.files&&e.target.files[0];if(!f)return;
  toast('图片处理中…');
  var r=new FileReader();
  r.onload=function(ev){
    var img=new Image();
    img.onload=function(){
      var c=document.createElement('canvas'),x=c.getContext('2d');
      var s=Math.min(1,800/Math.max(img.width,img.height));
      c.width=Math.round(img.width*s);c.height=Math.round(img.height*s);
      x.drawImage(img,0,0,c.width,c.height);
      var q=0.7,d2;
      do{d2=c.toDataURL('image/jpeg',q);q-=0.15}while(d2.length>100000&&q>0.05);
      req('/admin/ai',{action:'image',content:d2}).then(function(res){
        if(res.err){toast(res.err);return}
        toast('已发送');setTimeout(syncNow,800);
      });
    };img.src=ev.target.result;
  };r.readAsDataURL(f);e.target.value='';
}
function genApiKey(){
  if(!confirm('生成新 Key？旧的会立即失效'))return;
  req('/admin/apikey',{}).then(function(d){
    if(d.err){toast(d.err);return}
    $('apiKeyBox').value=d.key;toast('已生成，发给 AI 工具用吧');
  });
}
function loadImages(){
  $('imMsgs').innerHTML='<div class="empty">加载中…</div>';
  req('/admin/images').then(function(d){
    var h='';
    (d.msgs||[]).forEach(function(m){
      h+='<img src="'+esc(m.content)+'" style="width:90px;height:90px;object-fit:cover" title="'+esc(m.name)+' '+esc(m.time)+'">';
    });
    $('imMsgs').innerHTML=h||'<div class="empty">还没有图片消息</div>';
    var hv='';
    (d.avatars||[]).forEach(function(u){
      hv+='<div style="text-align:center"><img src="'+esc(u.avatar)+'" style="width:56px;height:56px;object-fit:cover;display:block"><div style="font-size:11px;color:var(--faint);margin-top:2px">'+esc(u.name)+'</div></div>';
    });
    $('imAvs').innerHTML=hv||'<div class="empty">还没有用户上传头像</div>';
  });
}
function doSearch(){
  var q=$('seInput').value.trim(),t=$('seType').value;
  if(!q){toast('输入关键词或 ID');return}
  $('seResults').innerHTML='<div class="empty">搜索中…</div>';
  req('/admin/search?q='+encodeURIComponent(q)+'&type='+t).then(function(d){
    var list=(d&&d.results)||[],h='';
    if(!list.length){$('seResults').innerHTML='<div class="empty">没有结果</div>';return}
    list.forEach(function(x){
      if(t==='user')h+='<div class="row" onclick="openProfile('+x.id+')"><div class="r1">#'+x.id+' '+esc(x.name)+' <span class="acc">'+roleName(x.role)+'</span>'+(x.banned?' <span style="color:var(--red)">禁言</span>':'')+'</div><div class="r2">'+esc(x.account||'')+' · '+x.points+' 分</div></div>';
      else if(t==='post')h+='<div class="row"><div class="r1">#'+x.id+' '+esc(x.title)+'</div><div class="r2">'+esc(x.name)+' · '+esc(x.time||'')+(x.deleted?' · 已删除':'')+'</div></div>';
      else{
        var isImg=/^data:image/.test(x.content||'');
        h+='<div class="row"><div class="r1">#'+x.id+' '+esc(x.name)+(x.deleted?' · 已删除':'')+'</div>'+(isImg?'<img src="'+esc(x.content)+'" style="max-width:140px;margin-top:6px;display:block">':'<div class="r2" style="color:var(--gray)">'+esc(String(x.content||'').slice(0,80))+'</div>')+'<div class="r2">'+esc(x.time||'')+'</div></div>';
      }
    });
    $('seResults').innerHTML=h;
  });
}

/* ===== 视图切换 ===== */
var VIEWS=['v-hall','v-posts','v-post','v-compose','v-sites','v-me','v-sponsor','v-profile','v-admin','v-pass','v-pm','v-pmchat'];
function go(v,btn){
  VIEWS.forEach(function(x){$(x).classList.toggle('hide',x!==v)});
  var map={'v-hall':'v-hall','v-posts':'v-posts','v-post':'v-posts','v-compose':'v-posts','v-sites':'v-sites','v-me':'v-me','v-sponsor':'v-me','v-profile':'v-me','v-admin':'v-me','v-pass':'v-me','v-pm':'v-pm','v-pmchat':'v-pm'};
  document.querySelectorAll('nav button').forEach(function(b){b.classList.toggle('on',b.dataset.v===map[v])});
  $('main').classList.toggle('has-c',v==='v-hall');
  document.querySelector('.composer').classList.toggle('hide',v!=='v-hall');
  window.scrollTo(0,0);
  if(v==='v-posts')loadPosts();
  if(v==='v-sites')loadSites();
  if(v==='v-me'){loadMe().then(renderMe)}
  if(v==='v-sponsor')loadSponsor();
  if(v==='v-admin')loadAdmin();
  if(v==='v-pm')loadPM();
}
</script>
</body>
</html>
`;

/* ============================================================
 *  Tier 1 兼容版
 * ============================================================ */
const HTML_LEGACY = `<!DOCTYPE html>
<html><head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${SITE_NAME}</title>
<style type="text/css">
*{margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font:14px/1.6 Arial,"Microsoft YaHei",sans-serif}
a{color:#58a6ff;text-decoration:none}
.hide{display:none!important}
input,textarea,select,button{font:14px Arial,"Microsoft YaHei",sans-serif;border:1px solid #30363d;background:#0d1117;color:#c9d1d9;padding:6px 8px}
button{background:#21262d;cursor:pointer;padding:6px 12px}
button.primary{background:#2f81f7;border-color:#2f81f7;color:#fff}
button.green{background:#238636;border-color:#238636;color:#fff}
button.danger{background:#da3633;border-color:#da3633;color:#fff}
button.gold{background:#9e6a03;border-color:#9e6a03;color:#fff}
button.lg{width:100%;height:36px;font-weight:600}
#iebar{background:#1a1707;border-bottom:1px solid #3d2f0a;padding:8px 16px;font-size:12px;color:#d29922;text-align:center}
#auth{width:340px;margin:40px auto;padding:20px;border:1px solid #30363d;background:#161b22}
#auth h1{font-size:20px;margin-bottom:4px}
#auth p.sub{color:#8b949e;font-size:12px;margin-bottom:16px}
#auth input{width:100%;height:34px;margin-bottom:8px;box-sizing:border-box}
#auth button.main{width:100%;height:36px;font-weight:600;background:#2f81f7;border-color:#2f81f7;color:#fff;margin-top:4px}
#auth .sw{display:block;text-align:center;color:#58a6ff;font-size:12px;margin-top:10px}
#auth .captcha b{color:#d29922;font-family:monospace;font-size:15px}
#wrap{width:920px;margin:0 auto;border-left:1px solid #30363d;border-right:1px solid #30363d}
#top{height:52px;background:#161b22;border-bottom:1px solid #30363d;padding:0 20px}
#top .brand{float:left;font-size:15px;font-weight:600;line-height:52px}
#top .who{float:right;font-size:12px;color:#8b949e;line-height:52px}
#top .pts{color:#d29922;font-weight:600}
.clear{clear:both}
#tabs{background:#161b22;border-bottom:1px solid #30363d;height:44px}
#tabs a{display:block;float:left;height:44px;line-height:44px;padding:0 20px;color:#8b949e;font-size:13px;text-decoration:none;border-bottom:2px solid transparent}
#tabs a.on{color:#2f81f7;border-bottom-color:#2f81f7}
#view{padding:16px 20px 60px}
.panel{border:1px solid #30363d;background:#161b22;padding:14px;margin-bottom:10px}
.panel .pt{font-size:15px;font-weight:600;margin-bottom:8px}
.panel .pc{font-size:13px;line-height:1.7;white-space:pre-wrap;word-break:break-all}
.panel .pm{font-size:12px;color:#8b949e;margin-top:10px}
.tag{font-size:11px;padding:1px 6px;background:#21262d;color:#8b949e;border:1px solid #30363d;margin-left:6px}
#chatlist{border:1px solid #30363d;background:#161b22;padding:12px;height:420px;overflow-y:auto;margin-bottom:10px}
.msg{margin-bottom:12px;overflow:hidden}
.msg .nm{font-size:12px;color:#8b949e;margin-bottom:3px}
.msg .nm b{color:#58a6ff}
.msg.me .nm b{color:#3fb950}
.msg.bot .nm b{color:#d29922}
.msg .bub{display:inline-block;padding:7px 11px;background:#0d1117;border:1px solid #30363d;max-width:70%;word-break:break-all;white-space:pre-wrap;font-size:13px}
.msg.me{text-align:right}
.msg.me .bub{background:#1f6feb;border-color:#1f6feb;color:#fff}
.msg.bot .bub{background:#1a1707;border-left:3px solid #d29922}
.msg .tm{font-size:10px;color:#6e7681}
#chatbar{padding:10px 0}
#chatbar input{width:70%;height:34px;vertical-align:middle}
#chatbar button{height:36px;vertical-align:middle;padding:6px 16px}
.tip{font-size:12px;color:#8b949e;line-height:1.9;padding:6px 0}
.form{padding:14px;border:1px solid #30363d;background:#161b22;margin-bottom:10px}
.form input,.form textarea,.form select{width:100%;margin-bottom:8px;box-sizing:border-box}
.form textarea{height:100px;resize:none}
.stat{width:100%;border-collapse:separate;border-spacing:8px 0;margin-bottom:14px}
.stat td{width:33%;border:1px solid #30363d;background:#161b22;padding:12px;text-align:center}
.stat td b{display:block;font-size:20px;color:#e6edf3;font-weight:600;margin-bottom:2px}
.stat td span{font-size:11px;color:#8b949e}
.empty{text-align:center;color:#8b949e;padding:40px;font-size:13px}
#toast{position:fixed;left:50%;top:40px;margin-left:-100px;width:200px;background:#161b22;border:1px solid #30363d;color:#e6edf3;padding:10px;font-size:13px;text-align:center;display:none;z-index:1000}
#toast.on{display:block}
#terms{position:fixed;left:0;top:0;right:0;bottom:0;background:rgba(0,0,0,0.85);display:none;z-index:998}
#terms.on{display:block}
#terms .tp{width:560px;margin:30px auto;background:#161b22;border:1px solid #30363d}
#terms .th{padding:16px;border-bottom:1px solid #30363d;font-size:15px;font-weight:600}
#terms .tb{padding:16px;max-height:400px;overflow-y:auto;font-size:13px;line-height:1.8}
#terms .tf{padding:12px 16px;border-top:1px solid #30363d}
#terms .tf button{width:100%;height:36px;font-weight:600;background:#21262d;color:#8b949e;cursor:not-allowed}
#terms .tf button.ready{background:#2f81f7;border-color:#2f81f7;color:#fff;cursor:pointer}
</style>
</head><body>

<div id="iebar">检测到您的浏览器版本较旧，部分功能可能受限。建议使用 Chrome、Edge 或 Firefox。</div>

<div id="terms"><div class="tp">
<div class="th">使用条款与社区守则</div>
<div class="tb" id="termsBox">
<p>${SITE_NAME} 是一个轻量、干净、无广告的小型兴趣社区。</p>
<p>普通用户连续 11 天未登录，账号及全部数据将被自动删除，无法恢复。</p>
<p>请遵守社区守则，不发布违规内容。违规累计 3 次自动禁言。</p>
<p>赞助可提升等级与特权。详情请访问现代版浏览器查看。</p>
</div>
<div class="tf"><div id="termsTip" class="tip" style="text-align:center">请向下滚动阅读完全部内容</div><button id="termsBtn" disabled onclick="agreeTerms()">请先阅读完</button></div>
</div></div>

<div id="auth">
<h1>${SITE_NAME}</h1>
<p class="sub">${SITE_DESC}</p>
<input id="acc" type="text" placeholder="手机号或邮箱">
<input id="pwd" type="password" placeholder="密码（至少 6 位）">
<input id="nick" type="text" placeholder="昵称（仅注册）" maxlength="20" class="hide">
<input id="akey" type="password" placeholder="站长密钥（仅站长注册）" class="hide">
<div class="captcha" style="margin-bottom:8px"><label>人机验证：<b id="captchaQ">加载中...</b></label><input id="captchaAns" type="text" placeholder="请输入答案" style="width:100%;height:30px;margin-top:4px"></div>
<button class="main" id="authBtn" onclick="doAuth()">登录</button>
<a class="sw" id="switchMode" href="javascript:toggleMode()">没有账号？去注册</a>
</div>

<div id="wrap" class="hide">
<div id="top"><span class="brand" id="ttl">聊天大厅</span><span class="who"><span id="meName">-</span> · <span class="pts" id="mePts">0</span> 分</span><div class="clear"></div></div>
<div id="tabs">
<a id="tab-chat" class="on" href="javascript:switchTab('chat')">大厅</a>
<a id="tab-posts" href="javascript:switchTab('posts')">帖子</a>
<a id="tab-sites" href="javascript:switchTab('sites')">导航</a>
<a id="tab-me" href="javascript:switchTab('me')">我的</a>
<a id="tab-admin" href="javascript:switchTab('admin')" class="hide">管理</a>
<div class="clear"></div>
</div>
<div id="view">
<div id="page-chat">
<div id="chatlist"></div>
<div id="chatbar"><input id="msgIn" type="text" placeholder="说点什么..." maxlength="500"><button class="primary" onclick="sendMsg()">发送</button></div>
</div>
<div id="page-posts" class="hide">
<button class="primary lg" onclick="toggleForm('postForm')" style="margin-bottom:10px;">发布新帖</button>
<div class="form hide" id="postForm">
<label>标题</label><input id="ptTitle" type="text" maxlength="60">
<label>正文</label><textarea id="ptBody" maxlength="3000"></textarea>
<label>分类</label><select id="ptTag"><option>交友</option><option>闲聊</option><option>求助</option><option>分享</option></select>
<button class="green lg" onclick="pubPost()">发布</button>
</div>
<div id="postList"></div>
</div>
<div id="page-sites" class="hide">
<button class="primary lg" onclick="toggleForm('siteForm')" style="margin-bottom:10px;">推荐好站</button>
<div class="form hide" id="siteForm">
<label>网站名称</label><input id="stName" type="text" maxlength="30">
<label>网址</label><input id="stUrl" type="text" maxlength="200">
<label>简介</label><input id="stDesc" type="text" maxlength="100">
<label>分类</label><input id="stTag" type="text" maxlength="10">
<button class="green lg" onclick="pubSite()">提交审核</button>
</div>
<div id="siteList"></div>
</div>
<div id="page-me" class="hide">
<table class="stat"><tr>
<td><b id="stPoints">0</b><span>积分</span></td>
<td><b id="stStreak">0</b><span>连续签到</span></td>
<td><b id="stRole">用户</b><span>身份</span></td>
</tr></table>
<table class="stat"><tr><td><b id="stWarn">0</b><span>违规累计</span></td></tr></table>
<button class="gold lg" onclick="doSign()" style="margin-bottom:8px;">每日签到</button>
<button class="primary lg" onclick="doLottery()" style="margin-bottom:14px;">抽奖（消耗 50 积分）</button>
<div class="panel"><div class="pt">赞助等级</div><div id="sponsorInfo" class="tip">加载中...</div></div>
<div class="panel"><div class="pt">积分流水</div><div id="plogList" class="tip">加载中...</div></div>
<button class="danger lg" onclick="logout()">退出登录</button>
</div>
<div id="page-admin" class="hide">
<table class="stat"><tr>
<td><b id="adUsers">0</b><span>用户</span></td>
<td><b id="adPosts">0</b><span>帖子</span></td>
<td><b id="adPending">0</b><span>待审资源</span></td>
</tr></table>
<div class="panel"><div class="pt">搜索</div>
<div style="margin-bottom:8px"><select id="searchType" style="width:80px"><option value="user">用户</option><option value="post">帖子</option><option value="message">消息</option></select> <input id="searchInput" type="text" style="width:300px" placeholder="ID 或关键词"><button class="primary" onclick="doSearch()">搜索</button></div>
<div id="searchResults" class="tip"></div>
</div>
<div class="panel"><div class="pt">用户管理</div><div id="userList"></div></div>
<div class="panel"><div class="pt">举报处理</div><div id="reportList"></div></div>
<div id="applyBox"></div><div id="logBox"></div>
<button class="lg" onclick="switchTab('me')">返回我的</button>
</div>
</div>
</div>

<div id="toast"></div>

<script type="text/javascript">
(function(w){var doc=w.document;w.$=function(id){return doc.getElementById(id)};w.addEvent=function(el,type,fn){if(!el)return;if(el.addEventListener){el.addEventListener(type,fn,false)}else if(el.attachEvent){el.attachEvent("on"+type,function(){fn.call(el,w.event)})}else{el["on"+type]=fn}};if(!w.JSON){w.JSON={parse:function(s){if(s===null||s==="")return null;if(typeof s!=="string")s=String(s);return eval("("+s+")")},stringify:function(o){if(o===null)return"null";var t=typeof o;if(t==="string")return'"'+o.replace(/\\\\/g,"\\\\\\\\").replace(/"/g,'\\\\"').replace(/\\n/g,"\\\\n")+'"';if(t==="number")return isFinite(o)?String(o):"null";if(t==="boolean")return o?"true":"false";if(Object.prototype.toString.call(o)==="[object Array]"){var a=[],i;for(i=0;i<o.length;i++)a.push(w.JSON.stringify(o[i]));return"["+a.join(",")+"]"}if(t==="object"){var p=[],k;for(k in o){if(o.hasOwnProperty(k))p.push('"'+k+'":'+w.JSON.stringify(o[k]))}return"{"+p.join(",")+"}"}return"null"}}})(window);

var API=location.origin,TOKEN="",ME=null,TAB="chat",MODE="login";
var BOT_UID=0,CAPTCHA_TOKEN="",MSGS=[],POSTS=[],LAST_MSG_ID=0,LAST_POST_ID=0,LAST_SYNC_TIME=0,SYNCING=false,TIMER=null;

function esc(s){if(s===null||s===undefined)s="";return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;")}
function toast(t){var el=$("toast");el.innerHTML=esc(t);el.className="on";clearTimeout(el._t);el._t=setTimeout(function(){el.className=""},1800)}
function ajax(method,path,data,cb){var xhr=null;try{xhr=new XMLHttpRequest()}catch(e){try{xhr=new ActiveXObject("Microsoft.XMLHTTP")}catch(e2){toast("浏览器不支持 AJAX");return}}xhr.open(method,API+path,true);if(TOKEN)xhr.setRequestHeader("X-Token",TOKEN);xhr.onreadystatechange=function(){if(xhr.readyState!==4)return;var d={};try{d=JSON.parse(xhr.responseText)}catch(e){d={err:"解析失败"}}cb(d,xhr.status)};if(data!==undefined&&data!==null){try{xhr.setRequestHeader("Content-Type","application/json")}catch(e){}xhr.send(JSON.stringify(data||{}))}else{xhr.send(null)}}
function getReq(p,cb){ajax("GET",p,null,cb)}
function postReq(p,b,cb){ajax("POST",p,b||{},cb)}
function trim(s){return(s||"").replace(/^\\s+|\\s+$/g,"")}
function hide(id){var e=$(id);if(e)e.className+=" hide"}
function show(id){var e=$(id);if(e)e.className=e.className.replace(/\\s*hide/g,"")}
function toggleForm(id){var e=$(id);if(!e)return;if(/hide/.test(e.className))show(id);else hide(id)}
function switchTab(t){TAB=t;var names=["chat","posts","sites","me","admin"],i;for(i=0;i<names.length;i++){if(names[i]===t){show("page-"+names[i]);var tab=$("tab-"+names[i]);if(tab)tab.className="on"}else{hide("page-"+names[i]);var tab2=$("tab-"+names[i]);if(tab2)tab2.className=""}}$("ttl").innerHTML={chat:"聊天大厅",posts:"帖子广场",sites:"网址导航",me:"我的",admin:"管理后台"}[t];if(t==="chat"){renderMsgs();syncNow()}if(t==="posts"){renderPosts();syncNow()}if(t==="sites")loadSites();if(t==="me"){loadMe();loadSponsorInfo()}if(t==="admin")loadAdmin()}
function roleName(r){return r>=2?"站长":r===1?"管理员":"用户"}

function showTerms(){var box=$("termsBox"),btn=$("termsBtn");btn.disabled=true;btn.className="";btn.innerHTML="请先阅读完";$("terms").className="on";box.scrollTop=0;setTimeout(checkTermsScroll,100);if(box.attachEvent)box.attachEvent("onscroll",checkTermsScroll);else if(box.addEventListener)box.addEventListener("scroll",checkTermsScroll,false)}
function checkTermsScroll(){var box=$("termsBox"),btn=$("termsBtn");if(!box||!btn)return;var atEnd=box.scrollTop+box.clientHeight>=box.scrollHeight-20;var short=box.scrollHeight-box.clientHeight<=20;if((short||atEnd)&&btn.disabled){btn.disabled=false;btn.className="ready";btn.innerHTML="我已阅读并同意"}}
function agreeTerms(){if($("termsBtn").disabled){toast("请先读完全部内容");return}try{localStorage.setItem("cz_terms_v1","1")}catch(e){}$("terms").className=""}
(function(){var done=false;try{done=localStorage.getItem("cz_terms_v1")==="1"}catch(e){}if(!done){$("terms").className="on";var box=$("termsBox");if(box.attachEvent)box.attachEvent("onscroll",checkTermsScroll);else if(box.addEventListener)box.addEventListener("scroll",checkTermsScroll,false);setTimeout(checkTermsScroll,100)}})();

function loadCaptcha(){getReq("/captcha",function(r){if(r.err){$("captchaQ").innerHTML="加载失败";return}$("captchaQ").innerHTML=esc(r.q);CAPTCHA_TOKEN=r.token||""})}
function toggleMode(){MODE=MODE==="login"?"reg":"login";$("authBtn").innerHTML=MODE==="login"?"登录":"注册";$("switchMode").innerHTML=MODE==="login"?"没有账号？去注册":"已有账号？去登录";if(MODE==="login"){hide("nick");hide("akey")}else{show("nick");show("akey")}}
function doAuth(){var acc=trim($("acc").value),pwd=$("pwd").value;if(!acc||!pwd){toast("请填写账号和密码");return}var ans=$("captchaAns").value;var payload={account:acc,pass:pwd,authMethod:"captcha",captchaToken:CAPTCHA_TOKEN,captchaAns:ans};if(MODE==="login"){postReq("/login",payload,function(r){if(r.err){toast(r.err);loadCaptcha();return}TOKEN=r.token;try{localStorage.setItem("cz_t",TOKEN)}catch(e){}boot()})}else{var nk=trim($("nick").value);if(!nk){toast("请填写昵称");return}payload.name=nk;payload.adminKey=$("akey").value;postReq("/reg",payload,function(r){if(r.err){toast(r.err);loadCaptcha();return}TOKEN=r.token;try{localStorage.setItem("cz_t",TOKEN)}catch(e){}boot()})}}
function logout(){if(!confirm("确定退出登录？"))return;TOKEN="";try{localStorage.removeItem("cz_t")}catch(e){}location.reload()}

function boot(){hide("auth");show("wrap");MSGS=[];POSTS=[];LAST_MSG_ID=0;LAST_POST_ID=0;LAST_SYNC_TIME=0;loadMe();switchTab("chat");syncNow();if(TIMER)clearInterval(TIMER);TIMER=setInterval(syncNow,10000)}
function syncNow(){if(SYNCING)return;SYNCING=true;getReq("/sync?msgSince="+LAST_MSG_ID+"&postSince="+LAST_POST_ID+"&sinceTime="+LAST_SYNC_TIME,function(d){SYNCING=false;if(!d||d.err)return;var nm=d.messages||[],np=d.posts||[],dm=d.deletedMessages||[],dp=d.deletedPosts||[];var i,j;for(i=0;i<nm.length;i++){var m=nm[i];if(m.id>LAST_MSG_ID){MSGS.push(m);LAST_MSG_ID=m.id}}for(i=0;i<np.length;i++){var p=np[i];if(p.id>LAST_POST_ID){POSTS.push(p);LAST_POST_ID=p.id}}if(dm.length){var dset={};for(j=0;j<dm.length;j++)dset[dm[j]]=1;var n1=[];for(i=0;i<MSGS.length;i++)if(!dset[MSGS[i].id])n1.push(MSGS[i]);MSGS=n1}if(dp.length){var dset2={};for(j=0;j<dp.length;j++)dset2[dp[j]]=1;var n2=[];for(i=0;i<POSTS.length;i++)if(!dset2[POSTS[i].id])n2.push(POSTS[i]);POSTS=n2}LAST_SYNC_TIME=d.serverTime||Date.now();if(TAB==="chat")renderMsgs();if(TAB==="posts")renderPosts()})}
function loadMe(){getReq("/me",function(u){ME=u||{};$("meName").innerHTML=esc(ME.name||"-");$("mePts").innerHTML=ME.points||0;$("stPoints").innerHTML=ME.points||0;$("stStreak").innerHTML=ME.streak||0;$("stRole").innerHTML=roleName(ME.role||0);$("stWarn").innerHTML=ME.warn_count||0;if(ME.role>=1){$("tab-admin").className=""}else{hide("tab-admin")}loadPlog()})}
function loadSponsorInfo(){getReq("/sponsor/me",function(d){var info=d.levelInfo||{};var h='当前等级：<b style="color:'+(info.color||"#8b949e")+'">'+(info.badge||"")+" "+(info.name||"普通用户")+'</b><br>累计赞助：<b>'+((d.total)||0)+'</b> 元';$("sponsorInfo").innerHTML=h})}
function loadPlog(){getReq("/plog",function(list){if(!list||!list.length){$("plogList").innerHTML="暂无记录";return}var h="",i;for(i=0;i<list.length;i++){var p=list[i];h+='<div style="padding:3px 0">'+esc(p.reason)+' <span style="float:right;color:'+(p.delta>=0?"#3fb950":"#f85149")+'">'+(p.delta>0?"+":"")+p.delta+'</span></div>'}$("plogList").innerHTML=h})}

function renderMsgs(){var box=$("chatlist");if(!box)return;var h="",i;for(i=0;i<MSGS.length;i++)h+=msgHtml(MSGS[i]);box.innerHTML=h||'<div class="empty">还没有消息</div>';box.scrollTop=box.scrollHeight}
function msgHtml(m){var self=ME&&m.uid===ME.id,isBot=m.uid===BOT_UID;var body=m.type==="image"?'[图片]':esc(m.content);var botMark=isBot?'<span class="tag">AI</span>':'';var acts="";if(self||(ME&&ME.role>=1))acts+=' <a href="javascript:recallMsg('+m.id+')" style="font-size:11px;color:#f85149">撤回</a>';return '<div class="msg'+(self?" me":"")+(isBot?" bot":"")+'"><div class="nm"><b>'+esc(m.name)+'</b>'+botMark+' <span>#'+m.id+'</span></div><div class="bub">'+body+'</div><div class="tm">'+esc(m.time)+acts+'</div></div>'}
function recallMsg(id){if(!confirm("确定撤回这条消息？"))return;postReq("/recall",{t:"message",id:id},function(r){if(r.err){toast(r.err);return}var n=[];for(var i=0;i<MSGS.length;i++)if(MSGS[i].id!==id)n.push(MSGS[i]);MSGS=n;renderMsgs();toast("已撤回")})}
function sendMsg(){var el=$("msgIn"),v=trim(el.value);if(!v)return;el.value="";postReq("/send",{content:v,type:"text"},function(r){if(r.err){toast(r.err);return}setTimeout(syncNow,1200)})}

function renderPosts(){var h="",i;for(i=0;i<POSTS.length;i++)h+=postHtml(POSTS[i]);$("postList").innerHTML=h||'<div class="empty">还没有帖子</div>'}
function postHtml(p){var canRecall=(ME&&(ME.id===p.uid||ME.role>=1));var recallBtn=canRecall?' <a href="javascript:recallPost('+p.id+')" style="color:#f85149">撤回</a>':'';var adminBtn=(ME&&ME.role>=1)?' <a href="javascript:adminPin('+p.id+','+(p.pinned?0:1)+')">'+(p.pinned?"取消置顶":"置顶")+'</a>':'';return '<div class="panel"><div class="pt">'+esc(p.title)+'<span class="tag">'+esc(p.tag)+'</span>'+(p.pinned?'<span class="tag">置顶</span>':'')+'</div><div class="pm">'+esc(p.name)+' · '+esc(p.time)+' <a href="javascript:likePost('+p.id+')">赞 <span id="lk'+p.id+'">'+p.likes+'</span></a>'+adminBtn+recallBtn+'</div><div class="pc">'+esc(p.content)+'</div></div>'}
function pubPost(){var t=trim($("ptTitle").value),c=trim($("ptBody").value),g=$("ptTag").value;if(!t||!c){toast("标题和内容都要填");return}postReq("/post",{title:t,content:c,tag:g},function(r){if(r.err){toast(r.err);return}$("ptTitle").value="";$("ptBody").value="";hide("postForm");setTimeout(syncNow,500);toast("发布成功")})}
function recallPost(id){if(!confirm("确定撤回？"))return;postReq("/recall",{t:"post",id:id},function(r){if(r.err){toast(r.err);return}var n=[];for(var i=0;i<POSTS.length;i++)if(POSTS[i].id!==id)n.push(POSTS[i]);POSTS=n;renderPosts();toast("已撤回")})}
function likePost(id){postReq("/like",{ttype:"post",tid:id},function(r){if(r.err){toast(r.err);return}var el=$("lk"+id);if(el)el.innerHTML=(+el.innerHTML)+1;toast("已点赞")})}
function adminPin(id,val){postReq("/admin/post",{id:id,action:"pin",val:val},function(r){if(r.err){toast(r.err);return}syncNow()})}

function loadSites(){getReq("/sites",function(r){var list=(r&&r.list)||[],h="",i;for(i=0;i<list.length;i++){var s=list[i];h+='<div class="panel"><div class="pt"><a href="'+esc(s.url)+'" target="_blank">'+esc(s.name)+'</a></div><div class="pc">'+esc(s.desc)+'</div><div class="pm">推荐人：'+esc(s.user)+'</div></div>'}$("siteList").innerHTML=h||'<div class="empty">还没有网站</div>'})}
function pubSite(){var n=trim($("stName").value),u=trim($("stUrl").value);if(!n||!u){toast("名称和网址必填");return}postReq("/site",{name:n,url:u,desc:trim($("stDesc").value),tag:trim($("stTag").value)},function(r){if(r.err){toast(r.err);return}toast("提交成功");$("stName").value=$("stUrl").value=$("stDesc").value=$("stTag").value="";hide("siteForm")})}

function doSign(){postReq("/sign",{},function(r){if(r.err){toast(r.err);return}toast("签到成功 +"+r.points+" 分");loadMe()})}
function doLottery(){if(!confirm("消耗 50 积分抽奖？"))return;postReq("/lottery",{},function(r){if(r.err){toast(r.err);return}toast("获得 "+r.gain+" 积分");loadMe()})}

function doSearch(){var q=trim($("searchInput").value);var type=$("searchType").value;if(!q){toast("请输入关键词");return}$("searchResults").innerHTML="搜索中...";getReq("/admin/search?q="+encodeURIComponent(q)+"&type="+type,function(d){var list=d.results||[];if(!list.length){$("searchResults").innerHTML="没有找到";return}var h="",i;for(i=0;i<list.length;i++){var it=list[i];if(type==="user")h+='<div style="padding:6px 0;border-bottom:1px solid #30363d">#'+it.id+' '+esc(it.name)+' ('+roleName(it.role)+')</div>';else if(type==="post")h+='<div style="padding:6px 0;border-bottom:1px solid #30363d">#'+it.id+' '+esc(it.title)+'</div>';else h+='<div style="padding:6px 0;border-bottom:1px solid #30363d">#'+it.id+' '+esc(it.content).slice(0,50)+'</div>'}$("searchResults").innerHTML=h})}
function loadAdmin(){if(!ME||ME.role<1)return;getReq("/admin/stats",function(s){$("adUsers").innerHTML=s.users;$("adPosts").innerHTML=s.posts;$("adPending").innerHTML=s.pending});getReq("/admin/users",function(list){var h="",i;for(i=0;i<list.length;i++){var u=list[i];h+='<div style="padding:6px 0;border-bottom:1px solid #30363d;font-size:13px">#'+u.id+' '+esc(u.name)+' ('+roleName(u.role)+')</div>'}$("userList").innerHTML=h||"暂无用户"});getReq("/admin/reports",function(list){var h="",i;if(!list||!list.length)h='<div class="tip">暂无举报</div>';else{for(i=0;i<list.length;i++){var r=list[i];h+='<div style="padding:6px 0;border-bottom:1px solid #30363d;font-size:13px">'+esc(r.rname)+' 举报 '+esc(r.ttype)+'#'+r.tid+'</div>'}}$("reportList").innerHTML=h})}

addEvent($("msgIn"),"keydown",function(e){e=e||window.event;if(e.keyCode===13){sendMsg();if(e.preventDefault)e.preventDefault();else e.returnValue=false}});
addEvent($("captchaAns"),"keydown",function(e){e=e||window.event;if(e.keyCode===13){doAuth();if(e.preventDefault)e.preventDefault();else e.returnValue=false}});
(function(){var t="";try{t=localStorage.getItem("cz_t")||""}catch(e){}if(!t){loadCaptcha();return}TOKEN=t;getReq("/me",function(u){if(!u||!u.id){try{localStorage.removeItem("cz_t")}catch(e){}loadCaptcha();return}boot()})})();
<\/script>
</body></html>`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const cors = corsHeaders(request);
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    let res;
    if (url.pathname === "/" || url.pathname === "/index.html") {
      const ua = request.headers.get("User-Agent") || "";
      const tier = detectTier(ua);
      let html;
      if (tier === 0) html = HTML_TIER0;
      else if (tier === 1) html = HTML_LEGACY;
      else html = HTML_MODERN;
      res = H(html);
    } else if (!env.DB) {
      res = J({ err: "服务器未绑定 D1 数据库（变量名必须为 DB）" }, 500);
    } else if (!env.SECRET) {
      res = J({ err: "服务器未设置 SECRET" }, 500);
    } else {
      try {
        await init(env.DB);
        res = await api(request, env, url, ctx);
      } catch (e) {
        res = J({ err: String((e && e.message) || e) }, 500);
      }
    }
    const h = new Headers(res.headers);
    for (const k in cors) h.set(k, cors[k]);
    return new Response(res.body, { status: res.status, headers: h });
  },

  async scheduled(event, env, ctx) {
    if (!env.DB) return;
    ctx.waitUntil((async () => {
      try {
        await init(env.DB);
        lastClean = 0;
        await maybeClean(env.DB);
        if (!env.AI_KEY) return;
        const r = await env.DB.prepare("SELECT id,uid,name,title,content FROM posts WHERE status=0 AND deleted=0 ORDER BY id DESC LIMIT 20").all();
        for (const po of (r.results || [])) {
          if (!(await aiQuotaOK(env.DB, env))) break;
          const c = await aiCheck(env, (po.title || "") + "\n" + po.content, "帖子抽检", "");
          if (c.level >= 2) {
            await env.DB.prepare("UPDATE posts SET deleted=1, deleted_at=? WHERE id=?").bind(Date.now(), po.id).run();
            await bumpWarn(env.DB, po.uid, po.name, c.level, "抽检:" + c.reason, "post", po.id);
          }
        }
      } catch (e) {}
    })());
  }
};