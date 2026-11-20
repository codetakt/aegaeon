// Human-facing sequence over the actual first-party pages and adapter mail.
// CDP drives a normal browser; no OAuth or invitation proof is transcribed.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowserProtocol } from '../lti/browser_protocol.mjs';
const input = [];
for await (const chunk of process.stdin) input.push(chunk);
const { directory, issuer, organization, password, delegated, returnUrl, previousPassword, parentLifetimeSeconds } = JSON.parse(Buffer.concat(input).toString());
const pins = [];
for (const name of ['browser.crt', 'mailbox.example.org.crt']) {
  const cert = new X509Certificate(await readFile(join(directory, name)));
  pins.push(createHash('sha256').update(cert.publicKey.export({ type: 'spki', format: 'der' })).digest('base64'));
}
// Stay in the test owner's process group for cancellation and cleanup.
const child = spawn(process.env.AEGAEON_CHROMIUM, ['--headless', '--no-sandbox', '--disable-gpu',
  '--no-first-run', '--disable-background-networking', '--disable-component-update',
  '--no-default-browser-check', '--no-proxy-server', '--ignore-certificate-errors-spki-list=' + pins.join(','),
  '--remote-debugging-port=0', '--user-data-dir=' + join(directory, 'chromium'), 'about:blank'],
{ stdio: ['ignore', 'ignore', 'pipe'] });
let startup = '';
let fatal;
let protocol;
let session;
const exit = new Promise(resolve => child.once('exit', resolve));
child.on('error', error => { fatal = error; });
child.stderr.on('data', data => { startup = (startup + data).slice(-32768); });
async function until(check, message, limit = 12000) {
  const end = performance.now() + limit;
  while (!await check()) {
    if (fatal) throw fatal;
    if (performance.now() >= end) {
      // Only the trusted UI heading and path (no query, email link or fields).
      const page = protocol && session ? await evaluate("({path:location.pathname, heading:document.querySelector('h1')?.textContent, step:document.querySelector('h2')?.textContent})") : {};
      throw new Error(message + ': ' + JSON.stringify(page));
    }
    await delay(35);
  }
}
async function evaluate(expression) {
  const r = await protocol.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, session);
  if (r.exceptionDetails) throw new Error('page evaluation failed');
  return r.result.value;
}
async function waitText(text) {
  await until(() => evaluate('document.body?.innerText.includes(' + JSON.stringify(text) + ')'), 'wait for ' + text);
}
async function click(text) {
  await until(() => evaluate("Array.from(document.querySelectorAll('button')).some(b => { if (b.textContent !== " +
    JSON.stringify(text) + " || b.disabled) return false; b.click(); return true; })"), text);
}
async function inputValue(name, value) {
  const selector = JSON.stringify('[name=' + name + ']');
  await until(() => evaluate('!!document.querySelector(' + selector + ')'), 'field ' + name);
  await evaluate('document.querySelector(' + selector + ').value=' + JSON.stringify(value));
}
async function checkNoReturn() {
  await until(() => evaluate("document.querySelector('h2')?.textContent === 'Invitation accepted' && !Array.from(document.querySelectorAll('button')).some(b => b.textContent==='Return to application')"), 'local completion without a return link');
  assert.equal(await evaluate('location.origin + location.pathname'), issuer + '/organization-invitations/hosted');
  // Use the actual browser session and CSRF-protected endpoint to send one
  // extra JSON field a caller might try. No credential leaves this origin.
  const result = await evaluate(`(async () => {
    const flow = new URL(location.href).searchParams.get('flow');
    const path = location.pathname + '/actions';
    const post = (csrf, body) => fetch(path, {method: 'POST', headers: {'content-type': 'application/json', 'x-csrf-token': csrf}, body: JSON.stringify({flow,...body})});
    const landing = await fetch(location.href, {cache:'no-store', redirect:'error'});
    const page = new DOMParser().parseFromString(await landing.text(), 'text/html');
    const resumed = await post(page.querySelector('script[data-csrf]').dataset.csrf, {action:'resume'});
    if (!resumed.ok) return {status:resumed.status};
    const view = await resumed.json();
    const forged = await post(view.csrfToken, {action:'return', returnUrl:'https://client.example.test/unregistered'});
    const ordinary = await post(view.csrfToken, {action:'return'});
    const completion = await ordinary.json();
    return {status:forged.status, ordinary:ordinary.status, step:completion.step, allowed:completion.canReturn, redirect: 'navigateTo' in completion};
  })()`);
  assert.deepEqual(result, {status:400, ordinary:200, step:'complete', allowed:false, redirect:false});
}
async function openMail(subject, count = 1) {
  const end = performance.now() + 18000;
  for (;;) {
    await protocol.send('Page.navigate', { url: 'https://mailbox.example.org/' + (delegated ? 'member' : '') }, session);
    await until(() => evaluate("document.title==='Test mailbox'"), 'mailbox navigation');
    const opened = await evaluate("(() => {const links = Array.from(document.querySelectorAll('a')).filter(a => a.textContent===" +
      JSON.stringify(subject) + "); if(links.length!==" + count + ")return false; links.at(-1).click(); return true;})()");
    if (opened) break;
    assert(performance.now() < end, 'mail delivery: ' + subject);
    await delay(300);
  }
  await until(() => evaluate('location.origin===' + JSON.stringify(issuer) + ' && !location.hash'), 'sanitized mail landing');
}
async function applicationCheck(path, text) {
  const invitation = session;
  session = await tab();
  await protocol.send('Page.navigate', { url: 'https://client.example.test/sso/' + path }, session);
  await waitText(text);
  session = invitation;
}
async function loginAs(identifier, value) {
  await inputValue('identifier', identifier);
  await inputValue('password', value);
  await evaluate("document.querySelector('[name=identifier]').form.requestSubmit()");
  await waitText('Invitation access');
  await waitText(identifier);
}
async function savePassword(value) {
  await inputValue('password', value);
  await inputValue('passwordConfirmation', value);
  await click('Save credentials');
  await waitText('Continue your invitation');
}
async function tab(browserContextId) {
  const { targetId } = await protocol.send('Target.createTarget', {url: 'about:blank', browserContextId});
  const connected = await protocol.send('Target.attachToTarget', { targetId, flatten: true });
  await protocol.send('Page.enable', {}, connected.sessionId);
  return connected.sessionId;
}
try {
  await until(() => /DevTools listening on (ws:\/\/[^\s]+)/.test(startup), 'Chromium startup');
  protocol = new BrowserProtocol(new WebSocket(startup.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]));
  await protocol.ready();
  session = await tab();
  await openMail('Organization invitation');
  await waitText('Continue your invitation');
  const identifier = delegated ? 'person@example.test' : 'invitee@example.test';
  if (!delegated) {
    await click('Send registration email');
    await waitText('Check your email');
    await openMail('Complete account registration');
    await savePassword(password);
    await inputValue('loginIdentifier', 'invitee@example.test');
    await click('Send recovery email');
    await waitText('Check your email');
    await openMail('Recover your account');
    await savePassword(password + '2');
    await delay(1100); // the issuer's revision cutoff is an exclusive whole second
  }
  await click('Sign in');
  await loginAs(identifier, delegated ? password : password + '2');
  for (const text of [identifier, issuer + '/userinfo', 'openid', 'read', 'offline_access', 'organization.invitation.accept']) await waitText(text);
  assert.equal(await evaluate("document.body.innerText.includes('Example school')"), false);
  if (delegated) {
    // Denial returns without a recipient exchange or mail allocation.
    await click('Deny access');
    await waitText('Continue your invitation');
    await click('Sign in');
    // Start as the previous browser account, then explicitly switch before
    // requesting a challenge. An old BFF handle cannot resume that session.
    await loginAs('invitee@example.test', previousPassword);
    await click('Allow access');
    await waitText('Verify the invited address');
    await waitText('Other applications can see the new account');
    await applicationCheck('start', 'Application observed administrator');
    const oldHandle = await evaluate('location.href');
    await click('Switch account');
    await loginAs(identifier, password);
    const newTab = session;
    session = await tab();
    await protocol.send('Page.navigate', {url: oldHandle}, session);
    await waitText('Unable to confirm this step');
    session = newTab;
  }
  await click('Allow access');
  await waitText('Verify the invited address');
  if (delegated) {
    await applicationCheck('session', 'Original application session');
    await applicationCheck('start', 'Application observed member');
    await click('Cancel invitation flow');
    await waitText('Invitation flow closed');
    await openMail('Organization invitation');
    await waitText('Restart this invitation');
    await click('Restart invitation');
    await click('Sign in');
    await loginAs(identifier, password);
    await click('Allow access');
    await waitText('Verify the invited address');
  }
  await click('Check available challenge requests');
  await waitText('5 of 5');
  await click('Send verification email');
  if (!delegated) {
    await waitText('Check the pending send');
    await openMail('Organization invitation');
    await waitText('Check the pending send');
    await click('Retry the same send');
  }
  await waitText('4 of 5');
  if (!delegated) {
    // Let the actual configured parent and first challenge expire. Asking
    // to review a replacement must not send it during reauthorization.
    await delay((parentLifetimeSeconds + 1) * 1000);
    await click('Review a replacement request');
    if (await evaluate("document.body.innerText.includes('The challenge has expired')")) {
      await click('Check remaining requests');
    }
    await waitText('Continue your invitation');
    await click('Sign in');
    await loginAs(identifier, password + '2');
    await click('Deny access');
    await waitText('Continue your invitation');
    await click('Sign in');
    await loginAs(identifier, password + '2');
    await click('Allow access');
    await waitText('Verify the invited address');
    await click('Check available challenge requests');
    // Denying re-consent and signing in again sent no email or allocation.
    await waitText('4 of 5');
    await click('Send verification email');
    await waitText('3 of 5');
  }
  const original = session;
  session = await tab();
  await openMail('Organization invitation');
  await waitText(delegated ? '4 of 5' : '3 of 5');
  // A separate profile can read its own mailbox but cannot bind an existing
  // challenge to another flow. Return to the original profile to finish.
  const signedInTab = session;
  const { browserContextId } = await protocol.send('Target.createBrowserContext');
  session = await tab(browserContextId);
  await openMail('Confirm your invitation', delegated ? 1 : 2);
  await waitText('Unable to open this invitation');
  await protocol.send('Target.disposeBrowserContext', {browserContextId});
  session = signedInTab;
  await openMail('Confirm your invitation', delegated ? 1 : 2);
  await waitText('Review the invitation');
  await click('Show invitation details');
  for (const text of ['Confirm organization membership', 'Example school', delegated ? 'Member' : 'Administrator', identifier, organization]) {
    await waitText(text);
  }
  await click('Accept and join organization');
  if (!delegated) {
    await waitText('Check acceptance');
    await click('Retry the same acceptance');
  }
  await waitText('Invitation accepted');
  session = original;
  await openMail('Organization invitation');
  await waitText('Invitation accepted');
  if (!delegated) {
    await click('Return to application');
    await waitText('Organization application');
    assert.equal(await evaluate('location.href'), returnUrl);
    // The operator changed the domain configuration after this first use.
    // The prior completion may still display its snapshotted return button.
    await openMail('Organization invitation');
    await waitText('Invitation accepted');
    await click('Return to application');
  }
  await checkNoReturn();
} finally {
  protocol?.close();
  if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
  await exit;
}
