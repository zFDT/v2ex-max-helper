'use strict';

const test = require('node:test');
const assert = require('node:assert');
const credentialHealth = require('../lib/credential-health');

const ISSUED_AT = 1791517988; // 2026-10-09 前后
const DAY_MS = 24 * 60 * 60 * 1000;

function makeCookie(issuedAt = ISSUED_AT, { quoted = true } = {}) {
  const value = `2|1:0|10:${issuedAt}|11:PB3_SESSION|36:djJleDo|73616d706c65`;
  const pb3 = quoted ? `PB3_SESSION="${value}"` : `PB3_SESSION=${value}`;
  return `A2="2|1:0|10:${issuedAt + 100}|2:A2|48:YWJj"; ${pb3}; V2EX_LANG=zhcn`;
}

function jsonRespond(payload, statusCode = 200) {
  return async () => ({ statusCode, body: JSON.stringify(payload) });
}

test('parseCookieIssuedAt 从带引号与不带引号的 PB3_SESSION 中解析签发时间', () => {
  assert.equal(credentialHealth.parseCookieIssuedAt(makeCookie()), ISSUED_AT);
  assert.equal(credentialHealth.parseCookieIssuedAt(makeCookie(ISSUED_AT, { quoted: false })), ISSUED_AT);
});

test('parseCookieIssuedAt 对缺失或异常 Cookie 返回 null', () => {
  assert.equal(credentialHealth.parseCookieIssuedAt(''), null);
  assert.equal(credentialHealth.parseCookieIssuedAt('A2=x; V2EX_LANG=zhcn'), null);
  assert.equal(credentialHealth.parseCookieIssuedAt('PB3_SESSION="garbage"'), null);
});

test('cookieAgeDays 与 cookieRemainingDays 按 30 天寿命推算', () => {
  const issuedMs = ISSUED_AT * 1000;
  assert.equal(credentialHealth.cookieAgeDays(makeCookie(), issuedMs), 0);
  assert.equal(credentialHealth.cookieAgeDays(makeCookie(), issuedMs + 10 * DAY_MS), 10);
  assert.equal(credentialHealth.cookieRemainingDays(makeCookie(), issuedMs, 30), 30);
  assert.equal(credentialHealth.cookieRemainingDays(makeCookie(), issuedMs + 25 * DAY_MS, 30), 5);
  assert.equal(credentialHealth.cookieRemainingDays('bad', issuedMs, 30), null);
});

test('assessCookie 在寿命充足时不告警', () => {
  const report = credentialHealth.assessCookie(makeCookie(), {
    nowMs: ISSUED_AT * 1000 + 3 * DAY_MS,
  });
  assert.equal(report.known, true);
  assert.equal(report.code, 'ok');
  assert.deepEqual(report.warnings, []);
});

test('assessCookie 在剩余不足 5 天时提前预警', () => {
  const report = credentialHealth.assessCookie(makeCookie(), {
    nowMs: ISSUED_AT * 1000 + 27 * DAY_MS,
  });
  assert.equal(report.code, 'cookie_expiring');
  assert.equal(report.warnings.length, 1);
  assert.match(report.warnings[0], /还剩约 3 天到期/);
});

test('assessCookie 在超过寿命时判定为已失效', () => {
  const report = credentialHealth.assessCookie(makeCookie(), {
    nowMs: ISSUED_AT * 1000 + 31 * DAY_MS,
  });
  assert.equal(report.code, 'cookie_expired');
  assert.match(report.warnings[0], /大概率已失效/);
});

test('assessCookie 在无法解析签发时间时不臆断', () => {
  const report = credentialHealth.assessCookie('V2EX_LANG=zhcn', { nowMs: Date.now() });
  assert.equal(report.known, false);
  assert.equal(report.code, 'cookie_age_unknown');
  assert.deepEqual(report.warnings, []);
});

test('normalizePat 拒绝含空白或格式不符的令牌', () => {
  assert.equal(credentialHealth.normalizePat('31622c80-dced-4ab1-8e10-71ea313e1ce2'), '31622c80-dced-4ab1-8e10-71ea313e1ce2');
  assert.equal(credentialHealth.normalizePat('  spaced  '), '');
  assert.equal(credentialHealth.normalizePat('bad\r\nBearer: x'), '');
  assert.equal(credentialHealth.normalizePat('short'), '');
});

test('readPatStatus 解析令牌信息并带上 Bearer 头', async () => {
  const calls = [];
  const requestJson = async (target, headers) => {
    calls.push({ target, headers });
    if (target.endsWith('/api/v2/token')) {
      return { statusCode: 200, body: JSON.stringify({
        success: true,
        result: { token: 'x', scope: 'everything', expiration: 15552000, good_for_days: 178 },
      }) };
    }
    return { statusCode: 200, body: JSON.stringify({ success: true, result: { username: 'a451697920' } }) };
  };

  const status = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', { requestJson });
  assert.equal(status.ok, true);
  assert.equal(status.scope, 'everything');
  assert.equal(status.goodForDays, 178);
  assert.equal(status.username, 'a451697920');
  assert.deepEqual(status.warnings, []);
  assert.ok(calls.length >= 1);
  assert.equal(calls[0].headers.Authorization, 'Bearer 31622c80-dced-4ab1-8e10-71ea313e1ce2');
});

test('readPatStatus 在剩余天数不足阈值时预警', async () => {
  const status = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', {
    requestJson: jsonRespond({ success: true, result: { scope: 'everything', good_for_days: 9 } }),
  });
  assert.equal(status.ok, true);
  assert.equal(status.warnings.length, 1);
  assert.match(status.warnings[0], /约 9 天后过期/);
});

test('readPatStatus 标记非 everything scope', async () => {
  const status = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', {
    requestJson: jsonRespond({ success: true, result: { scope: 'regular', good_for_days: 100 } }),
  });
  assert.equal(status.warnings.length, 1);
  assert.match(status.warnings[0], /无法用于续期操作/);
});

test('readPatStatus 区分 HTTP 拒绝、非法 JSON 与网络异常', async () => {
  const httpFail = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', {
    requestJson: async () => ({ statusCode: 401, body: '{"success":false}' }),
  });
  assert.equal(httpFail.ok, false);
  assert.equal(httpFail.code, 'pat_http_status');

  const badJson = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', {
    requestJson: async () => ({ statusCode: 200, body: 'not json' }),
  });
  assert.equal(badJson.code, 'pat_invalid_json');

  const network = await credentialHealth.readPatStatus('31622c80-dced-4ab1-8e10-71ea313e1ce2', {
    requestJson: async () => { throw new Error('timeout'); },
  });
  assert.equal(network.code, 'pat_network');

  const unconfigured = await credentialHealth.readPatStatus('');
  assert.equal(unconfigured.configured, false);
  assert.equal(unconfigured.code, 'pat_missing');
});

test('explainCookieFailure 用 PAT 结果区分 Cookie 过期与账号异常', () => {
  const okPat = { configured: true, ok: true, code: 'ok', username: 'a451697920' };
  const dead = { configured: true, ok: false, code: 'pat_http_status' };
  const none = { configured: false, ok: false, code: 'pat_missing' };

  assert.equal(credentialHealth.explainCookieFailure('logged_out', okPat).code, 'cookie_expired_account_ok');
  assert.match(credentialHealth.explainCookieFailure('logged_out', okPat).advice, /只是 Cookie 过期/);
  assert.equal(credentialHealth.explainCookieFailure('logged_out', dead).code, 'account_unreachable');
  assert.equal(credentialHealth.explainCookieFailure('logged_out', none).code, 'unknown');
  assert.equal(credentialHealth.explainCookieFailure('logged_out', none).advice, '');
});

test('assess 汇总 Cookie 与 PAT 两方面的告警', async () => {
  const report = await credentialHealth.assess({
    cookie: makeCookie(),
    pat: '31622c80-dced-4ab1-8e10-71ea313e1ce2',
    nowMs: ISSUED_AT * 1000 + 27 * DAY_MS,
    requestJson: jsonRespond({ success: true, result: { scope: 'everything', good_for_days: 9 } }),
  });
  assert.equal(report.cookie.code, 'cookie_expiring');
  assert.equal(report.pat.ok, true);
  assert.equal(report.warnings.length, 2);
});

test('assess 在未配置 PAT 时不产生 PAT 相关告警', async () => {
  const report = await credentialHealth.assess({
    cookie: makeCookie(),
    pat: '',
    nowMs: ISSUED_AT * 1000 + 3 * DAY_MS,
  });
  assert.equal(report.pat.configured, false);
  assert.deepEqual(report.warnings, []);
});
