// Real Chromium form/CSP behavior over a loopback bridge to the Rust handlers.
// CDP supplies transport only; no external Tool or TLS qualification is implied.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

const bridge = process.argv[2];
assert.match(bridge, /^http:\/\/127\.0\.0\.1:\d+$/);
const info = await (await fetch(`${bridge}/__fixture_info`)).json();
const issuer = new URL(info.issuer).origin;
const directory = await mkdtemp(join(tmpdir(), 'aegaeon-lti-browser-'));
const chrome = spawn(process.env.AEGAEON_CHROMIUM, [
  '--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
  '--disable-component-update', '--no-first-run', '--no-default-browser-check',
  '--remote-debugging-port=0', `--user-data-dir=${directory}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe'], detached: true });
function stopChrome(signal) {
  try { process.kill(-chrome.pid, signal); } catch (error) { if (error.code !== 'ESRCH') throw error; }
}
process.once('SIGTERM', () => { stopChrome('SIGKILL'); process.exit(143); });
process.once('SIGINT', () => { stopChrome('SIGKILL'); process.exit(130); });
let socket;
let diagnostics = '';
let sequence = 0;
let session;
let fatal;
let legacy = false;
const pending = new Map();
const toolRequests = [];
const foreignRequests = [];
const violations = [];
const responses = [];
const idleLoaders = new Set();
let mainFrame;
let interceptions = 0;
let delayedFavicons = 0;
const slowFavicon = process.env.AEGAEON_LTI_BROWSER_SLOW_FAVICON === '1';
async function until(condition, description) {
  const end = Date.now() + 5000;
  while (true) {
    if (fatal) throw fatal;
    if (await condition()) {
      if (fatal) throw fatal;
      return;
    }
    assert(Date.now() < end, `deadline: ${description}`);
    await delay(20);
  }
}
function send(method, params = {}, targeted = true) {
  const id = ++sequence;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject, method });
    socket.send(JSON.stringify({ id, method, params, ...(targeted && session ? { sessionId: session } : {}) }));
  });
}
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true });
  assert(!result.exceptionDetails, 'browser evaluation failed');
  return result.result.value;
}
async function settledPage(previousLoader, expectedLoader) {
  // A response acknowledgement is not a completed navigation. Wait for the
  // actual document and its subresources before replacing the page again.
  await until(() => mainFrame && mainFrame.loaderId !== previousLoader
    && (!expectedLoader || mainFrame.loaderId === expectedLoader)
    && idleLoaders.has(mainFrame.loaderId) && interceptions === 0, 'document network idle');
  assert.equal(await evaluate('document.readyState'), 'complete');
}
async function navigate(url) {
  const previousLoader = mainFrame?.loaderId;
  const { loaderId, errorText } = await send('Page.navigate', { url });
  assert(!errorText, `navigation failed: ${errorText}`);
  assert(loaderId, 'expected a new document navigation');
  await settledPage(previousLoader, loaderId);
}
async function submit(button) {
  const previousLoader = mainFrame.loaderId;
  await evaluate(`document.querySelector("button[value=${button}]").click()`);
  await settledPage(previousLoader);
}
async function intercept({ requestId, request }) {
  const url = new URL(request.url);
  let status = 200;
  let headers = [{ name: 'Content-Type', value: 'text/html' }];
  let body = Buffer.from('<link rel="icon" href="data:,"><p>Tool reached</p>');
  let responseRecord;
  if (url.origin === issuer) {
    if (slowFavicon && url.pathname === '/favicon.ico') {
      delayedFavicons++;
      await delay(750);
    }
    const forwarded = { ...request.headers, cookie: `aegaeon_auth_session=${info.session}` };
    for (const name of Object.keys(forwarded)) {
      if (['host', 'content-length', 'accept-encoding', 'connection'].includes(name.toLowerCase())) delete forwarded[name];
    }
    const response = await fetch(`${bridge}${url.pathname}${url.search}`, {
      method: request.method, headers: forwarded, redirect: 'manual',
      ...(request.postData ? { body: request.postData } : {}),
    });
    status = response.status;
    responseRecord = { path: url.pathname, method: request.method, status };
    headers = [...response.headers].filter(([name]) => !['content-length', 'content-encoding', 'transfer-encoding'].includes(name)).map(([name, value]) => ({ name, value }));
    if (legacy) {
      for (const header of headers) {
        if (header.name === 'content-security-policy') header.value = header.value.replace(/form-action [^;]+/, "form-action 'self'");
      }
    }
    body = Buffer.from(await response.arrayBuffer());
  } else if (url.origin === 'https://tool.example') {
    assert.equal(request.method, 'GET');
    if (url.pathname === '/favicon.ico') {
      await send('Fetch.fulfillRequest', { requestId, responseCode: 404, body: '' });
      return;
    }
    assert.equal(url.pathname, '/login');
    for (const field of ['iss', 'client_id', 'login_hint', 'lti_message_hint', 'lti_deployment_id', 'target_link_uri']) assert(url.searchParams.has(field));
    toolRequests.push(url.pathname);
  } else {
    foreignRequests.push(url.origin);
    await send('Fetch.failRequest', { requestId, errorReason: 'BlockedByClient' });
    return;
  }
  await send('Fetch.fulfillRequest', { requestId, responseCode: status, responseHeaders: headers, body: body.toString('base64') });
  if (responseRecord) responses.push(responseRecord);
}
try {
  chrome.stderr.on('data', data => { diagnostics += data; });
  chrome.on('error', error => { fatal = error; });
  await until(() => /DevTools listening on (ws:\/\/[^\s]+)/.test(diagnostics), 'Chromium startup');
  const endpoint = diagnostics.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1];
  socket = new WebSocket(endpoint);
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject; });
  socket.onmessage = ({ data }) => {
    const value = JSON.parse(data);
    if (value.id) {
      const waiter = pending.get(value.id);
      pending.delete(value.id);
      if (value.error) waiter.reject(new Error(`${waiter.method}: ${value.error.message}`)); else waiter.resolve(value.result);
    } else if (value.method === 'Fetch.requestPaused') {
      interceptions++;
      intercept(value.params).catch(error => { fatal ??= error; }).finally(() => { interceptions--; });
    } else if (value.method === 'Page.frameNavigated' && !value.params.frame.parentId) {
      mainFrame = value.params.frame;
    } else if (value.method === 'Page.lifecycleEvent' && value.params.name === 'networkIdle'
      && value.params.frameId === mainFrame?.id) {
      idleLoaders.add(value.params.loaderId);
    } else if (value.method === 'Log.entryAdded' && value.params.entry.text.includes('form-action')) {
      violations.push(value.params.entry.text);
    }
  };
  const { targetId } = await send('Target.createTarget', { url: 'about:blank' }, false);
  ({ sessionId: session } = await send('Target.attachToTarget', { targetId, flatten: true }, false));
  await send('Page.enable');
  await send('Page.setLifecycleEventsEnabled', { enabled: true });
  await send('Log.enable');
  await send('Fetch.enable', { patterns: [{ urlPattern: '*' }] });
  async function consent(index) {
    await navigate(`${issuer}${info.paths[index]}`);
    await until(() => evaluate(`location.pathname === ${JSON.stringify(info.paths[index])} && document.readyState === 'complete' && document.querySelector("button[value=approve]") !== null`), 'consent form');
  }
  await consent(0);
  await submit('approve');
  assert(await evaluate('document.body.textContent.includes("Tool reached")'), 'registered Tool redirect');
  assert.equal(toolRequests.length, 1);
  assert.equal(violations.length, 0);
  await navigate(`${issuer}${info.paths[0]}`);
  await until(() => responses.some(r => r.path === info.paths[0] && r.method === 'GET' && r.status === 403), 'replay refusal');
  await consent(1);
  await submit('deny');
  assert(await evaluate('document.body.textContent.includes("Launch cancelled.")'), 'consent cancellation');
  await consent(2);
  await evaluate('document.querySelector("form").action="https://unregistered.example/post";document.querySelector("button[value=approve]").click()');
  await until(() => violations.length >= 1, 'unregistered destination refusal');
  assert.equal(foreignRequests.length, 0);
  const beforeLegacy = violations.length;
  legacy = true;
  await consent(3);
  await evaluate('document.querySelector("button[value=approve]").click()');
  await until(() => violations.length > beforeLegacy, 'original self-only CSP negative control');
  await until(() => interceptions === 0, 'interception completion');
  assert(responses.some(r => r.path === info.paths[3] && r.method === 'POST' && r.status === 303));
  assert.equal(toolRequests.length, 1);
  assert.equal(foreignRequests.length, 0);
  if (slowFavicon) assert(delayedFavicons > 0, 'delayed favicon regression was exercised');
  assert(!fatal);
  console.log(JSON.stringify({ passed: true, approved: 1, cancelled: 1, replay_refused: 1, foreign_destination_blocked: 1, original_csp_failure_detected: 1, delayed_favicons: delayedFavicons, transport: 'CDP bridge to real handlers; not TLS qualification' }));
} catch (error) {
  if (!diagnostics.includes('DevTools listening on')) console.error(diagnostics.slice(0, 8192));
  console.error(error);
  throw error;
} finally {
  if (socket) socket.close();
  stopChrome('SIGTERM');
  await Promise.race([new Promise(resolve => chrome.once('exit', resolve)), delay(2000)]);
  stopChrome('SIGKILL');
  await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
}
