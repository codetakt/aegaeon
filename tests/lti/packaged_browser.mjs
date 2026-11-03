// Actual TLS sockets, release handlers, Redis sessions and an independent Tool.
// CDP controls the browser only; no Fetch interception or supplied auth cookie.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, createPublicKey, generateKeyPairSync, randomUUID, sign, verify } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import http from 'node:http';
import https from 'node:https';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const [directory, backendPort, output] = process.argv.slice(2);
const info = JSON.parse(await readFile(join(directory, 'fixture.json')));
const cert = await readFile(join(directory, 'tls.crt'));
const key = await readFile(join(directory, 'tls.key'));
const spki = createHash('sha256').update(await readFile(join(directory, 'tls-public.der'))).digest('base64');
const issuer = new URL(info.issuer);
const toolOrigin = new URL(info.tool);
const transactions = new Map();
const transport = [];
const successes = [];
const errors = [];
const continuations = [];
const responses = [];
let mode = 'GET';
let dpopNonce;
let fatal;
let chrome;
let socket;
let session;
let sequence = 0;
const pending = new Map();
const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const jwk = publicKey.export({ format: 'jwk' });
const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');

function proof(path, token) {
  const claims = { htm: 'POST', htu: `${info.issuer}${path}`, iat: Math.floor(Date.now() / 1000), jti: randomUUID() };
  if (dpopNonce) claims.nonce = dpopNonce;
  if (token) claims.ath = createHash('sha256').update(token).digest('base64url');
  const input = `${encode({ typ: 'dpop+jwt', alg: 'EdDSA', jwk })}.${encode(claims)}`;
  return `${input}.${sign(null, Buffer.from(input), privateKey).toString('base64url')}`;
}
function request(url, options = {}, body = '') {
  return new Promise((resolve, reject) => {
    const call = https.request(url, { ca: cert, family: 4, timeout: 10000, ...options }, response => {
      const chunks = [];
      response.on('data', chunk => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks).toString() }));
    });
    call.on('error', reject);
    call.on('timeout', () => call.destroy(new Error('HTTPS request deadline')));
    call.end(body);
  });
}
function escape(value) { return String(value).replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;'); }
function form(action, pairs) {
  return `<form method="post" action="${escape(action)}">${[...pairs].map(([name, value]) => `<input type="hidden" name="${escape(name)}" value="${escape(value)}">`).join('')}</form><script>document.forms[0].submit()</script>`;
}
async function bodyOf(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    assert(size <= 65536, 'bounded Tool response');
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString();
}
function handler(action) {
  return (req, res) => { action(req, res).catch(error => { fatal ??= error; res.writeHead(500); res.end('fixture failed'); }); };
}
const proxy = https.createServer({ cert, key, minVersion: 'TLSv1.2' }, handler(async (req, res) => {
  transport.push({ path: new URL(req.url, issuer).pathname, method: req.method, tls: req.socket.getProtocol() });
  const headers = { ...req.headers };
  for (const name of Object.keys(headers)) if (name === 'forwarded' || name.startsWith('x-forwarded-') || name === 'connection') delete headers[name];
  headers.host = issuer.host;
  headers.forwarded = `for=127.0.0.1;proto=https;host="${issuer.host}"`;
  const upstream = http.request({ host: '127.0.0.1', port: backendPort, method: req.method, path: req.url, headers }, response => {
    responses.push({ path: new URL(req.url, issuer).pathname, status: response.statusCode });
    if (req.url === '/lti/authorize' && req.method === 'POST') continuations.push({ status: response.statusCode, hadSession: (req.headers.cookie ?? '').includes('aegaeon_auth_session=') });
    res.writeHead(response.statusCode, response.headers);
    response.pipe(res);
  });
  upstream.on('error', error => { fatal ??= error; res.writeHead(502); res.end(); });
  req.pipe(upstream);
}));
const tool = https.createServer({ cert, key, minVersion: 'TLSv1.2' }, handler(async (req, res) => {
  const url = new URL(req.url, toolOrigin);
  assert(['TLSv1.2', 'TLSv1.3'].includes(req.socket.getProtocol()));
  if (url.pathname === '/favicon.ico') { res.writeHead(404); res.end(); return; }
  if (url.pathname === '/login') {
    assert.equal(req.method, 'GET');
    assert.equal(url.searchParams.get('iss'), info.issuer);
    assert.equal(url.searchParams.get('client_id'), 'tool');
    assert.equal(url.searchParams.get('lti_deployment_id'), 'deployment-1');
    assert.equal(url.searchParams.get('target_link_uri'), `${info.tool}/resource`);
    const state = ` state+&=/${randomUUID()} `;
    const nonce = ` nonce+日本&/${randomUUID()} `;
    const cookie = randomUUID();
    const parameters = new URLSearchParams({ scope: 'openid', response_type: 'id_token', client_id: 'tool', redirect_uri: `${info.tool}/launch`, login_hint: url.searchParams.get('login_hint'), lti_message_hint: url.searchParams.get('lti_message_hint'), response_mode: 'form_post', prompt: 'none', nonce, state });
    transactions.set(state, { nonce, cookie, parameters, used: false });
    res.setHeader('Set-Cookie', `tool_session=${cookie}; Path=/; Secure; HttpOnly; SameSite=None`);
    if (mode === 'HOLD') { res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>Authentication held</p>'); }
    else if (mode === 'GET') { res.writeHead(303, { Location: `${info.issuer}/lti/authorize?${parameters}` }); res.end(); }
    else { res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(form(`${info.issuer}/lti/authorize`, parameters)); }
    return;
  }
  assert.equal(url.pathname, '/launch');
  assert.equal(req.method, 'POST');
  assert.match(req.headers['content-type'], /^application\/x-www-form-urlencoded/);
  const response = new URLSearchParams(await bodyOf(req));
  const state = response.get('state');
  const transaction = transactions.get(state);
  assert(transaction, 'state matches independent Tool transaction');
  assert((req.headers.cookie ?? '').split('; ').includes(`tool_session=${transaction.cookie}`));
  if (response.has('error')) {
    assert(!response.has('id_token'));
    errors.push(response.get('error'));
    res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>Launch refused</p>'); return;
  }
  assert(!transaction.used, 'Tool replay protection');
  const token = response.get('id_token');
  assert(token && response.getAll('id_token').length === 1);
  const parts = token.split('.');
  assert.equal(parts.length, 3);
  const header = JSON.parse(Buffer.from(parts[0], 'base64url'));
  const claims = JSON.parse(Buffer.from(parts[1], 'base64url'));
  assert.equal(header.alg, 'RS256');
  assert(header.kid);
  const keysResponse = await request(`${info.issuer}/jwks`);
  assert.equal(keysResponse.status, 200);
  const signingKey = JSON.parse(keysResponse.body).keys.find(candidate => candidate.kid === header.kid);
  assert(signingKey && signingKey.kty === 'RSA' && signingKey.n && signingKey.e);
  const publicKey = createPublicKey({ key: signingKey, format: 'jwk' });
  const signed = Buffer.from(parts.slice(0, 2).join('.'));
  const signature = Buffer.from(parts[2], 'base64url');
  assert(verify('RSA-SHA256', signed, publicKey, signature));
  assert(!verify('RSA-SHA256', Buffer.concat([signed, Buffer.from('tampered')]), publicKey, signature), 'independent signature negative control');
  assert.equal(claims.iss, info.issuer);
  assert.deepEqual(claims.aud, 'tool');
  assert.equal(claims.sub, info.subject);
  assert.equal(claims.nonce, transaction.nonce);
  const now = Math.floor(Date.now() / 1000);
  assert(claims.iat <= now && now < claims.exp && claims.exp - claims.iat <= 60);
  assert(claims.auth_time <= now);
  const prefix = 'https://purl.imsglobal.org/spec/lti/claim/';
  assert.equal(claims[`${prefix}message_type`], 'LtiResourceLinkRequest');
  assert.equal(claims[`${prefix}version`], '1.3.0');
  assert.equal(claims[`${prefix}deployment_id`], 'deployment-1');
  assert.equal(claims[`${prefix}target_link_uri`], `${info.tool}/resource`);
  assert.equal(claims[`${prefix}resource_link`].id, 'resource-1');
  assert.equal(claims[`${prefix}context`].id, 'context-1');
  assert.deepEqual(claims[`${prefix}roles`], ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner']);
  assert.equal(claims.nickname, 'Mapped local nickname');
  assert(!('email' in claims));
  transaction.used = true;
  successes.push(transaction);
  res.writeHead(200, { 'Content-Type': 'text/html' }); res.end('<p>Resource launch verified</p>');
}));

async function until(condition, message, milliseconds = 10000) {
  const deadline = Date.now() + milliseconds;
  while (!await condition()) {
    if (fatal) throw fatal;
    assert(Date.now() < deadline, `deadline: ${message}`);
    await delay(25);
  }
  if (fatal) throw fatal;
}
function send(method, params = {}, targeted = true) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    socket.send(JSON.stringify({ id, method, params, ...(targeted && session ? { sessionId: session } : {}) }));
  });
}
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true });
  assert(!result.exceptionDetails, 'browser evaluation');
  return result.result.value;
}
async function navigate(url, text) {
  const response = await send('Page.navigate', { url });
  assert(!response.errorText, response.errorText);
  await until(() => evaluate(`document.readyState === 'complete' && document.body?.textContent.includes(${JSON.stringify(text)})`), text);
}
function stopChrome(signal) {
  if (chrome) try { process.kill(-chrome.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
function sessionReadPermission(allowed) {
  const result = execFileSync('redis-cli', ['--raw', '-u', process.env.AEGAEON_AUTH_SESSION_REDIS_URL, 'ACL', 'SETUSER', 'default', allowed ? '+get' : '-get'], { timeout: 3000, encoding: 'utf8' });
  assert.equal(result.trim(), 'OK');
}
process.once('SIGTERM', () => { stopChrome('SIGKILL'); process.exit(143); });
process.once('SIGINT', () => { stopChrome('SIGKILL'); process.exit(130); });
try {
  await new Promise(resolve => proxy.listen(Number(issuer.port), '127.0.0.1', resolve));
  await new Promise(resolve => tool.listen(Number(toolOrigin.port), '127.0.0.1', resolve));
  await assert.rejects(request(`${info.issuer}/jwks`, { ca: undefined }), 'untrusted TLS certificate rejected');
  const jwksResponse = await request(`${info.issuer}/jwks`);
  assert.equal(jwksResponse.status, 200, jwksResponse.body);
  async function issueToken() {
    return request(`${info.issuer}/token`, { method: 'POST', headers: { authorization: `Basic ${Buffer.from(`${info.producer}:${info.producer_secret}`).toString('base64')}`, dpop: proof('/token'), 'content-type': 'application/x-www-form-urlencoded' } }, 'grant_type=client_credentials&scope=lti%3Alaunch');
  }
  let tokenResponse = await issueToken();
  assert.equal(JSON.parse(tokenResponse.body).error, 'use_dpop_nonce', 'secure-default nonce challenge');
  dpopNonce = tokenResponse.headers['dpop-nonce'];
  assert(dpopNonce);
  tokenResponse = await issueToken();
  assert.equal(tokenResponse.status, 200, tokenResponse.body);
  const token = JSON.parse(tokenResponse.body);
  assert.equal(token.token_type, 'DPoP');
  const launchBody = JSON.stringify({ clientId: 'tool', deploymentId: 'deployment-1', resourceLinkId: 'resource-1', userId: info.user, roles: ['http://purl.imsglobal.org/vocab/lis/v2/membership#Learner'] });
  async function createLaunch(proofValue = proof('/lti/launches', token.access_token)) {
    return request(`${info.issuer}/lti/launches`, { method: 'POST', headers: { authorization: `DPoP ${token.access_token}`, dpop: proofValue, 'content-type': 'application/json' } }, launchBody);
  }
  const resourceChallenge = await createLaunch();
  assert.equal(resourceChallenge.status, 401);
  assert.equal(JSON.parse(resourceChallenge.body).error, 'use_dpop_nonce', 'resource nonce is separate from authorization server nonce');
  dpopNonce = resourceChallenge.headers['dpop-nonce'];
  assert(dpopNonce);
  const replayProof = proof('/lti/launches', token.access_token);
  const admitted = await createLaunch(replayProof);
  assert.equal(admitted.status, 201, admitted.body);
  assert.equal((await createLaunch(replayProof)).status, 401, 'real DPoP proof replay refused');
  assert.equal((await createLaunch(proof('/lti/launches', 'wrong-token'))).status, 401, 'real ath binding');
  chrome = spawn(process.env.AEGAEON_CHROMIUM, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--no-proxy-server', `--ignore-certificate-errors-spki-list=${spki}`, '--remote-debugging-port=0', `--user-data-dir=${join(directory, 'chrome')}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe'], detached: true });
  let diagnostics = '';
  chrome.stderr.on('data', value => { diagnostics += value; });
  chrome.on('error', error => { fatal = error; });
  await until(() => /DevTools listening on (ws:\/\/[^\s]+)/.test(diagnostics), 'Chromium startup');
  socket = new WebSocket(diagnostics.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = ({ data }) => {
    const value = JSON.parse(data);
    if (value.id) { const waiter = pending.get(value.id); pending.delete(value.id); if (value.error) waiter.reject(new Error(value.error.message)); else waiter.resolve(value.result); }
  };
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' }, false);
  ({ sessionId: session } = await send('Target.attachToTarget', { targetId, flatten: true }, false));
  await send('Page.enable');
  await navigate(`${info.issuer}/auth/login`, 'Sign in');
  await evaluate(`document.querySelector('[name=identifier]').value=${JSON.stringify(info.subject)};document.querySelector('[name=password]').value=${JSON.stringify(info.password)};document.querySelector('form').requestSubmit()`);
  await until(() => evaluate('document.body?.textContent.includes("Your local sign-in succeeded")'), 'actual local password login');
  for (const verb of ['GET', 'POST']) {
    mode = verb;
    const response = await createLaunch();
    assert.equal(response.status, 201, response.body);
    await navigate(JSON.parse(response.body).launchUrl, 'Example Tool');
    await until(() => evaluate('document.querySelector("button[value=approve]") !== null'), 'default consent');
    const previous = successes.length;
    await evaluate('document.querySelector("button[value=approve]").click()');
    await until(() => successes.length === previous + 1, `${verb} signed launch`);
    await until(() => evaluate('document.body?.textContent.includes("Resource launch verified")'), 'Tool rendered');
    await navigate(`${info.issuer}/lti/authorize?${successes.at(-1).parameters}`, 'Launch refused');
    assert.equal(errors.at(-1), 'invalid_request', 'consumed launch replay');
  }
  mode = 'HOLD';
  const recoverable = await createLaunch();
  assert.equal(recoverable.status, 201, recoverable.body);
  await navigate(JSON.parse(recoverable.body).launchUrl, 'Example Tool');
  await evaluate('document.querySelector("button[value=approve]").click()');
  await until(() => evaluate('document.body?.textContent.includes("Authentication held")'), 'held Tool authentication');
  const pendingRequest = [...transactions.values()].at(-1).parameters;
  const pendingUrl = `${info.issuer}/lti/authorize?${pendingRequest}`;
  const beforeFault = successes.length;
  sessionReadPermission(false);
  try {
    await navigate(pendingUrl, 'temporarily_unavailable');
    assert.equal(responses.filter(value => value.path === '/lti/authorize').at(-1).status, 503);
    assert.equal(successes.length, beforeFault, 'store refusal publishes no token');
  } finally {
    sessionReadPermission(true);
  }
  await navigate(pendingUrl, 'Resource launch verified');
  assert.equal(successes.length, beforeFault + 1, 'same unconsumed intent succeeds after supplier repair');
  const revocable = await createLaunch();
  assert.equal(revocable.status, 201, revocable.body);
  await navigate(JSON.parse(revocable.body).launchUrl, 'Example Tool');
  await evaluate('document.querySelector("button[value=approve]").click()');
  await until(() => evaluate('document.body?.textContent.includes("Authentication held")'), 'revocable Tool authentication');
  const revokedRequest = [...transactions.values()].at(-1).parameters;
  await navigate(`${info.issuer}/auth/login`, 'Sign in');
  await evaluate('const form=document.createElement("form");form.method="POST";form.action="/auth/logout";document.body.append(form);form.submit()');
  await until(() => responses.some(value => value.path === '/auth/logout' && value.status === 303), 'actual session logout');
  await until(() => evaluate('document.readyState === "complete" && document.querySelector("[name=password]") !== null'), 'logout login page');
  const beforeRevocation = successes.length;
  await navigate(`${info.issuer}/lti/authorize?${revokedRequest}`, 'Launch refused');
  assert.equal(errors.at(-1), 'login_required');
  assert.equal(successes.length, beforeRevocation, 'revoked session cannot complete pending launch');
  assert(continuations.some(value => !value.hadSession && value.status === 303), 'actual cross-site POST requires SameSite continuation');
  assert(transport.some(value => value.path.startsWith('/lti/continue/')));
  assert(transport.every(value => ['TLSv1.2', 'TLSv1.3'].includes(value.tls)));
  assert(!fatal);
  const result = { passed: true, browser_login: 1, signed_get_launch: 1, signed_post_launch: 1, launch_replay_refused: errors.filter(value => value === 'invalid_request').length, dpop_replay_refused: 1, ath_mismatch_refused: 1, untrusted_certificate_refused: 1, signature_tamper_refused: successes.length, session_store_refusal: 1, session_store_recovery: 1, session_revocation_refused: 1, post_continuation: true, transport: 'real TLS sockets; Node CA and hostname validation; Chromium trusts only fixture SPKI; no CDP transport interception', tls_versions: [...new Set(transport.map(value => value.tls))] };
  await writeFile(join(output, 'journey.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result));
} finally {
  socket?.close();
  stopChrome('SIGTERM');
  await delay(200);
  stopChrome('SIGKILL');
  proxy.closeAllConnections(); tool.closeAllConnections();
  await Promise.all([new Promise(resolve => proxy.close(resolve)), new Promise(resolve => tool.close(resolve))]);
}
