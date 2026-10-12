'use strict';

// 凭据健康度：Cookie 剩余寿命推算 + V2EX API 2.0 Personal Access Token 心跳。
//
// 设计约束（重要）：
//   - PAT 只能访问 /api/v2/，不能认证 HTML 页面，因此签到、阅读、余额三项
//     仍然必须依赖 Cookie。本模块只做「诊断与预警」，不替代 Cookie 主流程。
//   - PAT 未配置时，所有调用方行为必须与改动前完全一致（纯增量、可回退）。
//   - 网络传输可通过 options.requestJson 注入，便于单元测试不触网。

const fs = require('fs');
const https = require('https');
const config = require('./config');

const V2EX_ORIGIN = 'https://www.v2ex.com';
const API_PREFIX = '/api/v2/';
const DAY_MS = 24 * 60 * 60 * 1000;

// V2EX 会话 Cookie 的实测寿命约 29-30 天，这里取 30 天作为推算基准。
const DEFAULT_SESSION_TTL_DAYS = 30;
const DEFAULT_COOKIE_WARN_DAYS = 5;
const DEFAULT_PAT_WARN_DAYS = 14;
const MAX_API_BYTES = 256 * 1024;
const DEFAULT_TIMEOUT_MS = 15000;

const PAT_PATTERN = /^[0-9A-Za-z._-]{16,64}$/;
const SESSION_COOKIE = 'PB3_SESSION';

function getCookieValue(cookie, name) {
  for (const part of String(cookie || '').split(';')) {
    const index = part.indexOf('=');
    if (index <= 0) continue;
    if (part.slice(0, index).trim() !== name) continue;
    return part.slice(index + 1).trim().replace(/^"|"$/g, '');
  }
  return '';
}

// PB3_SESSION 形如：2|1:0|10:1789264398|11:PB3_SESSION|36:...|<sig>
// 其中 "10:<seconds>" 是 Tornado secure cookie 的签发时间戳。
function parseCookieIssuedAt(cookie) {
  const raw = getCookieValue(cookie, SESSION_COOKIE);
  if (!raw) return null;
  for (const part of raw.split('|')) {
    const match = /^10:(\d+)$/.exec(part.trim());
    if (!match) continue;
    const seconds = Number(match[1]);
    return Number.isSafeInteger(seconds) && seconds > 0 ? seconds : null;
  }
  return null;
}

function cookieAgeDays(cookie, nowMs = Date.now()) {
  const issuedAt = parseCookieIssuedAt(cookie);
  if (!issuedAt) return null;
  return (nowMs - issuedAt * 1000) / DAY_MS;
}

function cookieRemainingDays(cookie, nowMs = Date.now(), ttlDays = DEFAULT_SESSION_TTL_DAYS) {
  const issuedAt = parseCookieIssuedAt(cookie);
  if (!issuedAt) return null;
  return (issuedAt * 1000 + ttlDays * DAY_MS - nowMs) / DAY_MS;
}

function normalizePat(value) {
  const text = String(value || '').trim();
  if (!text || /[\s\r\n\0]/.test(text)) return '';
  return PAT_PATTERN.test(text) ? text : '';
}

function readPat(cfg, options = {}) {
  const fromEnv = normalizePat(process.env.V2EX_PAT);
  if (fromEnv) return { value: fromEnv, source: 'env' };
  const file = options.patFile || (cfg && cfg.patFile) || '';
  if (!file) return { value: '', source: 'missing' };
  try {
    if (!fs.existsSync(file)) return { value: '', source: 'missing' };
    return { value: normalizePat(fs.readFileSync(file, 'utf8').trim()), source: 'file' };
  } catch (_) {
    return { value: '', source: 'missing' };
  }
}

function defaultRequestJson(target, headers, timeoutMs) {
  return new Promise((resolve, reject) => {
    let parsed;
    try {
      parsed = new URL(target);
    } catch (e) {
      reject(e);
      return;
    }
    if (parsed.origin !== V2EX_ORIGIN || parsed.protocol !== 'https:') {
      reject(new Error('凭据检查拒绝跨 V2EX HTTPS 源请求'));
      return;
    }
    let settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true;
      if (error) reject(error);
      else resolve(value);
    };
    const req = https.request({
      protocol: 'https:',
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: `${parsed.pathname}${parsed.search}`,
      method: 'GET',
      headers: Object.assign({ Accept: 'application/json' }, headers),
    }, (res) => {
      let body = '';
      let received = 0;
      res.setEncoding('utf8');
      res.on('data', (chunk) => {
        received += Buffer.byteLength(chunk);
        if (received > MAX_API_BYTES) {
          req.destroy(new Error('凭据检查响应过大'));
          return;
        }
        body += chunk;
      });
      res.on('aborted', () => finish(new Error('凭据检查响应被中断')));
      res.on('error', finish);
      res.on('end', () => finish(null, { statusCode: res.statusCode || 0, body }));
    });
    req.on('error', finish);
    req.setTimeout(timeoutMs || DEFAULT_TIMEOUT_MS, () => req.destroy(new Error('凭据检查请求超时')));
    req.end();
  });
}

async function callApi(endpoint, pat, options = {}) {
  const requestJson = options.requestJson || defaultRequestJson;
  const response = await requestJson(
    `${V2EX_ORIGIN}${API_PREFIX}${endpoint}`,
    { Authorization: `Bearer ${pat}` },
    options.timeoutMs || DEFAULT_TIMEOUT_MS
  );
  const statusCode = response.statusCode || 0;
  if (statusCode < 200 || statusCode >= 300) {
    return { ok: false, code: 'pat_http_status', statusCode };
  }
  let payload = null;
  try {
    payload = JSON.parse(response.body);
  } catch (_) {
    return { ok: false, code: 'pat_invalid_json', statusCode };
  }
  if (!payload || payload.success !== true) {
    return {
      ok: false,
      code: 'pat_rejected',
      statusCode,
      message: (payload && payload.message) || '',
    };
  }
  return { ok: true, result: payload.result || {}, statusCode };
}

async function readPatStatus(pat, options = {}) {
  const token = normalizePat(pat);
  if (!token) return { configured: false, ok: false, code: 'pat_missing', warnings: [] };

  let tokenCall;
  try {
    tokenCall = await callApi('token', token, options);
  } catch (e) {
    return { configured: true, ok: false, code: 'pat_network', message: e.message, warnings: [] };
  }
  if (!tokenCall.ok) {
    return { configured: true, ok: false, code: tokenCall.code, statusCode: tokenCall.statusCode, warnings: [] };
  }

  const result = tokenCall.result || {};
  const goodForDays = Number.isFinite(Number(result.good_for_days)) ? Number(result.good_for_days) : null;
  const status = {
    configured: true,
    ok: true,
    code: 'ok',
    scope: typeof result.scope === 'string' ? result.scope : '',
    expiration: Number.isFinite(Number(result.expiration)) ? Number(result.expiration) : null,
    goodForDays,
    username: '',
    warnings: [],
  };

  let memberCall = null;
  try {
    memberCall = await callApi('member', token, options);
  } catch (_) { /* 心跳以 token 接口为准，member 失败不影响结论 */ }
  if (memberCall && memberCall.ok && memberCall.result) {
    status.username = String(memberCall.result.username || '');
  }

  const warnDays = options.patWarnDays || DEFAULT_PAT_WARN_DAYS;
  if (goodForDays !== null && goodForDays <= warnDays) {
    status.warnings.push(goodForDays > 0
      ? `PAT 将在约 ${goodForDays} 天后过期，请及时更新`
      : 'PAT 已过期，请更新');
  }
  if (status.scope && status.scope !== 'everything') {
    status.warnings.push(`PAT scope 为 ${status.scope}，无法用于续期操作`);
  }
  return status;
}

function assessCookie(cookie, options = {}) {
  const nowMs = options.nowMs || Date.now();
  const ttlDays = options.sessionTtlDays || DEFAULT_SESSION_TTL_DAYS;
  const warnDays = options.cookieWarnDays || DEFAULT_COOKIE_WARN_DAYS;
  const remaining = cookieRemainingDays(cookie, nowMs, ttlDays);
  if (remaining === null) {
    return { known: false, code: 'cookie_age_unknown', warnings: [] };
  }
  const warnings = [];
  let code = 'ok';
  if (remaining <= 0) {
    code = 'cookie_expired';
    warnings.push(`Cookie 会话已签发超过 ${ttlDays} 天，大概率已失效，请更新 Cookie`);
  } else if (remaining <= warnDays) {
    code = 'cookie_expiring';
    warnings.push(`Cookie 会话预计还剩约 ${Math.max(1, Math.ceil(remaining))} 天到期，请提前更新`);
  }
  return {
    known: true,
    code,
    ageDays: cookieAgeDays(cookie, nowMs),
    remainingDays: remaining,
    warnings,
  };
}

async function assess(options = {}) {
  const cookie = options.cookie || '';
  const pat = options.pat === undefined
    ? readPat(options.cfg, options).value
    : normalizePat(options.pat);
  const cookieReport = assessCookie(cookie, options);
  const patStatus = pat
    ? await readPatStatus(pat, options)
    : { configured: false, ok: false, code: 'pat_missing', warnings: [] };
  const warnings = cookieReport.warnings.concat(patStatus.warnings || []);
  if (patStatus.configured && !patStatus.ok) {
    warnings.push(`PAT 心跳失败 (${patStatus.code})，无法确认账号状态`);
  }
  return { cookie: cookieReport, pat: patStatus, warnings };
}

// Cookie 探针失败时的交叉验证：用 PAT 判断「账号本身是否还活着」。
function explainCookieFailure(_failureCode, patStatus) {
  if (!patStatus || !patStatus.configured) {
    return { code: 'unknown', advice: '' };
  }
  if (patStatus.ok) {
    return {
      code: 'cookie_expired_account_ok',
      advice: `PAT 心跳正常（账号 ${patStatus.username || '未知'} 有效），确认只是 Cookie 过期，更新 Cookie 即可恢复`,
    };
  }
  return {
    code: 'account_unreachable',
    advice: `PAT 心跳同样失败 (${patStatus.code})，可能是账号异常或网络/代理问题`,
  };
}

module.exports = {
  DEFAULT_COOKIE_WARN_DAYS,
  DEFAULT_PAT_WARN_DAYS,
  DEFAULT_SESSION_TTL_DAYS,
  assess,
  assessCookie,
  callApi,
  cookieAgeDays,
  cookieRemainingDays,
  explainCookieFailure,
  getCookieValue,
  normalizePat,
  parseCookieIssuedAt,
  readPat,
  readPatStatus,
};
