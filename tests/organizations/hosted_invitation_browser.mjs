// Checks the actual Rust-rendered landing in Chromium over HTTPS. A scripted
// actions endpoint isolates the browser contract from issuer and DB tests.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import https from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowserProtocol } from '../lti/browser_protocol.mjs';

const chunks = [];
for await (const chunk of process.stdin) chunks.push(chunk);
const { headers, html } = JSON.parse(Buffer.concat(chunks).toString());
const directory = await mkdtemp(join(tmpdir(), 'hosted-invitation-browser-'));
const issuer = 'https://issuer.example.test';
const mailbox = 'https://mail.example.org';
const landing = '/organization-invitations/hosted';
const flow = 'opaque-flow-1234567890';
const browserCsrf = 'synthetic-landing-csrf';
const flowCsrf = 'synthetic-flow-csrf';
const account = { identifier: 'Registrar <test@example.test>', subject: 'subject-1' };
const details = {
  issuer, organizationId: '00000000-0000-0000-0000-000000000008',
  organizationName: '<untrusted display text>', roles: [{ key: 'admin', label: 'Admin & owner' }],
};
const encode = value => Buffer.from(typeof value === 'string' ? value : JSON.stringify(value)).toString('base64url');
const invitation = {
  issuer, environmentId: '00000000-0000-0000-0000-000000000001', domainId: '00000000-0000-0000-0000-000000000002',
  invitationId: '00000000-0000-0000-0000-000000000003', objectId: '00000000-0000-0000-0000-000000000003',
  template: 'organization_invitation', capability: Buffer.alloc(32, 7).toString('base64url'), deliveryRevision: 1, expiresAt: 1800000299,
};
const proof = template => ({ ...invitation, template, objectId: '00000000-0000-0000-0000-000000000004' });
let mail = encode(invitation);
let pending;
let fatal;
let chromium;
let protocol;
let session;
let server;
const observed = [];

async function until(test, description, timeout = 10000) {
  const deadline = performance.now() + timeout;
  while (!await test()) {
    if (fatal) throw fatal;
    assert(performance.now() < deadline, 'deadline: ' + description);
    await delay(10);
  }
}
function stopBrowser() {
  if (chromium?.pid) {
    try { process.kill(-chromium.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
  }
}
async function route(req, res) {
  assert(!req.url.includes(invitation.capability) && !req.url.includes('#'));
  const path = new URL(req.url, issuer).pathname;
  observed.push([req.method, path]);
  if (req.headers.host === 'mail.example.org' && req.method === 'GET' && path === '/') {
    res.writeHead(200, { 'content-type': 'text/html' });
    res.end('<a id="mail" href="' + issuer + landing + '#aegaeon=' + mail + '">Open message</a>'); return;
  }
  if (path === '/favicon.ico') { res.writeHead(404); res.end(); return; }
  assert.equal(req.headers.host, 'issuer.example.test');
  if (path === landing && req.method === 'GET') {
    res.writeHead(200, headers); res.end(html); return;
  }
  assert.equal(path, landing + '/actions');
  assert.equal(req.method, 'POST');
  assert.equal(req.headers.origin, issuer);
  assert.equal(req.headers.referer, undefined);
  assert.equal(req.headers['content-type'], 'application/json');
  const raw = [];
  for await (const chunk of req) raw.push(chunk);
  assert(!pending);
  pending = { body: JSON.parse(Buffer.concat(raw).toString()), csrf: req.headers['x-csrf-token'], res };
}
async function evaluate(expression) {
  const result = await protocol.send('Runtime.evaluate', { expression, returnByValue: true }, session);
  if (result.exceptionDetails) throw new Error('Browser evaluation failed');
  return result.result.value;
}
async function textIncludes(value) {
  await until(() => evaluate('document.getElementById("view")?.innerText.includes(' + JSON.stringify(value) + ')'), value);
}
async function click(label) {
  assert(await evaluate("Array.from(document.querySelectorAll('button')).some(b => { if(b.textContent !== " + JSON.stringify(label) + " || b.disabled) return false; b.click(); return true; })"), 'button: ' + label);
}
async function openMail(encoded) {
  mail = encoded;
  await protocol.send('Page.navigate', { url: mailbox + '/' }, session);
  await until(() => evaluate('location.origin === ' + JSON.stringify(mailbox) + ' && Boolean(document.querySelector("#mail"))'), 'test mailbox');
  await evaluate('document.querySelector("#mail").click()');
}
async function exchange(expected, response, token = flowCsrf) {
  await until(() => pending != null, expected.action);
  const packet = pending;
  // Observe the already-clean browser URL while the first request is still
  // outstanding. No script injection, request interception or manual proof entry.
  assert.equal(await evaluate('location.hash'), '');
  assert.deepEqual(packet.body, expected);
  assert.equal(packet.csrf, token);
  pending = undefined;
  packet.res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  packet.res.end(JSON.stringify({ flow, csrfToken: flowCsrf, ...response }));
}
async function readMail(template, step, extra = {}) {
  const encoded = encode(template);
  await openMail(encoded);
  await exchange({ action: 'import', fragment: encoded }, { step, ...extra }, browserCsrf);
}
try {
  const keyPath = join(directory, 'tls.key');
  const certPath = join(directory, 'tls.crt');
  execFileSync('openssl', ['req', '-newkey', 'rsa:2048', '-x509', '-noenc', '-days', '1',
    '-subj', '/CN=issuer.example.test', '-addext', 'subjectAltName=DNS:issuer.example.test,DNS:mail.example.org',
    '-keyout', keyPath, '-out', certPath], { stdio: 'ignore', timeout: 10000 });
  const cert = await readFile(certPath);
  const hash = createHash('sha256').update(new X509Certificate(cert).publicKey.export({ type: 'spki', format: 'der' })).digest('base64');
  server = https.createServer({ cert, key: await readFile(keyPath) }, (req, res) => {
    route(req, res).catch(error => { fatal = error; res.destroy(); });
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  chromium = spawn(process.env.AEGAEON_CHROMIUM, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking',
    '--no-first-run', '--disable-component-update', '--no-default-browser-check', '--no-proxy-server',
    '--host-resolver-rules=MAP issuer.example.test:443 127.0.0.1:' + port + ',MAP mail.example.org:443 127.0.0.1:' + port,
    '--ignore-certificate-errors-spki-list=' + hash, '--remote-debugging-port=0', '--user-data-dir=' + join(directory, 'profile'), 'about:blank'],
  { detached: true, stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, CHROME_CONFIG_HOME: join(directory, 'config') } });
  let startup = '';
  let devtools;
  chromium.stderr.on('data', data => {
    if (devtools) return;
    startup = (startup + data).slice(-32768);
    devtools = startup.match(/DevTools listening on (ws:\/\/[^\s]+)\s/)?.[1];
  });
  chromium.on('error', error => { fatal = error; });
  process.once('exit', stopBrowser);
  await until(() => {
    assert.equal(chromium.exitCode, null, 'Chromium exited before reporting its debug socket');
    assert.equal(chromium.signalCode, null, 'Chromium was signalled during startup');
    return Boolean(devtools);
  }, 'Chromium startup', 45000);
  protocol = new BrowserProtocol(new WebSocket(devtools));
  await protocol.ready();
  const { targetId } = await protocol.send('Target.createTarget', { url: 'about:blank' });
  ({ sessionId: session } = await protocol.send('Target.attachToTarget', { targetId, flatten: true }));
  await protocol.send('Page.enable', {}, session);
  await readMail(invitation, 'invitation', { canRegister: true, canRecover: true });
  await textIncludes('separate browser profile');
  for (const width of [320, 375]) {
    await protocol.send('Emulation.setDeviceMetricsOverride', { width, height: 740, deviceScaleFactor: 1, mobile: true }, session);
    const layout = await evaluate(`(() => {
      const name = document.querySelector('.brand-name');
      const rect = name.getBoundingClientRect();
      return { name: name.textContent, left: rect.left, right: rect.right, height: rect.height,
        lineHeight: parseFloat(getComputedStyle(name).lineHeight), pageWidth: document.documentElement.scrollWidth };
    })()`);
    assert.equal(layout.name, 'W'.repeat(64));
    assert.ok(layout.left >= 0 && layout.right <= width && layout.pageWidth <= width);
    assert.ok(layout.height > layout.lineHeight);
  }
  await protocol.send('Emulation.clearDeviceMetricsOverride', {}, session);
  assert.deepEqual(observed.filter(([method]) => method === 'POST').length, 1);
  await click('Send registration email');
  await exchange({ action: 'identityRequest', purpose: 'registration', flow }, { step: 'identityWaiting' });
  await textIncludes('Check your email');
  for (const template of ['organization_identity_registration', 'organization_identity_recovery']) {
    await readMail(proof(template), 'identityReady');
    await textIncludes('Set your password');
    await evaluate("document.querySelector('[name=password]').value='synthetic-password'; document.querySelector('[name=passwordConfirmation]').value='synthetic-password'");
    await click('Save credentials');
    await exchange({ action: 'identityComplete', password: 'synthetic-password', passwordConfirmation: 'synthetic-password', flow }, { step: 'invitation' });
    await textIncludes('Continue your invitation');
  }
  await readMail(invitation, 'signedIn', { account });
  await textIncludes('Verify the invited address');
  await click('Check available challenge requests');
  await exchange({ action: 'status', flow }, { step: 'sendReady', remainingChallenges: 1, expiresAt: invitation.expiresAt, account, confirmation: 'send-1' });
  await textIncludes('1 of 5');
  await click('Send verification email');
  await exchange({ action: 'send', flow, confirmation: 'send-1' }, { step: 'challengeWaiting', remainingChallenges: 0, expiresAt: invitation.expiresAt });
  await textIncludes('profile where you requested it');
  await readMail(proof('organization_recipient_challenge'), 'proofReady', { account });
  await textIncludes('Review the invitation');
  await click('Show invitation details');
  await exchange({ action: 'preview', flow }, { step: 'confirm', account, preview: details, confirmation: 'preview-1' });
  for (const value of [details.organizationName, details.organizationId, details.roles[0].label, account.identifier, account.subject]) await textIncludes(value);
  assert.equal(await evaluate("Boolean(document.querySelector('untrusted'))"), false);
  await click('Accept and join organization');
  await exchange({ action: 'confirm', flow, confirmation: 'preview-1' }, { step: 'complete' });
  await textIncludes('Invitation accepted');
  assert.equal(await evaluate('document.querySelectorAll("button").length'), 0);
  const count = observed.filter(([method]) => method === 'POST').length;
  for (const bad of ['_', encode({ ...invitation, expiresAt: 1800000000 }), encode({ ...invitation, template: 'organization_identity_recovery' }),
    encode('{"domain\\u0049d": "bad",' + JSON.stringify(invitation).slice(1)), encode({ ...invitation, extra: 1 }),
    encode(JSON.stringify(invitation).replace('"deliveryRevision":1', '"deliveryRevision":1e0')),
    encode({ ...invitation, issuer: 'https://other.example.test' }), 'A'.repeat(10924)]) {
    await openMail(bad);
    await textIncludes('Unable to open this invitation');
    assert.equal(await evaluate('location.hash'), '');
  }
  assert.equal(observed.filter(([method]) => method === 'POST').length, count);
  assert.equal(await evaluate('localStorage.length + sessionStorage.length'), 0);
  if (fatal) throw fatal;
  console.log('Chromium verified four HTTPS mail landings, form actions, explicit send/accept, escaped details and eight invalid fragments.');
} finally {
  protocol?.close();
  if (chromium?.pid && chromium.exitCode === null && chromium.signalCode === null) {
    const exited = new Promise(resolve => chromium.once('exit', resolve)); stopBrowser(); await exited;
  }
  process.removeListener('exit', stopBrowser);
  server?.closeAllConnections();
  if (server?.listening) await new Promise(resolve => server.close(resolve));
  await rm(directory, { recursive: true, force: true, maxRetries: 3 });
}
