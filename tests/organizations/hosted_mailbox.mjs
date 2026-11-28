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
{ stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, CHROME_CONFIG_HOME: join(directory, 'chromium-config') } });
let startup = '';
let devtools;
let fatal;
let protocol;
let session;
const exit = new Promise(resolve => child.once('exit', resolve));
child.on('error', error => { fatal = error; });
child.stderr.on('data', data => {
  if (devtools) return;
  startup = (startup + data).slice(-32768);
  devtools = startup.match(/DevTools listening on (ws:\/\/[^\s]+)\s/)?.[1];
});
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
async function evaluate(expression, target = session) {
  const r = await protocol.send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true }, target);
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
async function waitForMail(subject, count) {
  const end = performance.now() + 18000;
  for (;;) {
    await protocol.send('Page.navigate', { url: 'https://mailbox.example.org/' + (delegated ? 'member' : '') }, session);
    await until(() => evaluate("document.title==='Test mailbox'"), 'mailbox navigation');
    const delivered = await evaluate("Array.from(document.querySelectorAll('a')).filter(a => a.textContent===" +
      JSON.stringify(subject) + ").length");
    if (delivered === count) return;
    assert(performance.now() < end, 'mail delivery: ' + subject);
    await delay(300);
  }
}
async function openMail(subject, count = 1) {
  await waitForMail(subject, count);
  await evaluate("Array.from(document.querySelectorAll('a')).filter(a => a.textContent===" + JSON.stringify(subject) + ").at(-1).click()");
  await until(() => evaluate('location.origin===' + JSON.stringify(issuer) + ' && !location.hash'), 'sanitized mail landing');
}
async function concurrentResume(expected) {
  const tabs = await Promise.all([tab(), tab()]);
  const mailbox = 'https://mailbox.example.org/' + (delegated ? 'member' : '');
  const invitation = "Array.from(document.querySelectorAll('a')).find(a => a.textContent==='Organization invitation')";
  await Promise.all(tabs.map(async target => {
    await protocol.send('Page.navigate', {url: mailbox}, target);
    await until(() => evaluate('!!' + invitation, target), 'original invitation in second tab');
  }));
  await Promise.all(tabs.map(target => evaluate(invitation + '.click()', target)));
  const views = await Promise.all(tabs.map(async target => {
    await until(() => evaluate("location.origin===" + JSON.stringify(issuer) + " && !location.hash && document.querySelector('#view')?.innerText.includes(" + JSON.stringify(expected) + ")", target), 'concurrent resume of ' + expected);
    return evaluate("({handle:new URL(location.href).searchParams.get('flow'),text:document.getElementById('view').innerText})", target);
  }));
  assert(views[0].handle && views[0].handle === views[1].handle && views[0].text === views[1].text,
    'both mail opens resumed one hosted flow with identical pending details');
  await Promise.all(tabs.map(async target => {
    const { targetInfo } = await protocol.send('Target.getTargetInfo', {}, target);
    await protocol.send('Target.closeTarget', {targetId: targetInfo.targetId});
  }));
}
async function applicationCheck(path, text) {
  const invitation = session;
  session = await tab();
  await protocol.send('Page.navigate', { url: 'https://client.example.test/sso/' + path }, session);
  await waitText(text);
  session = invitation;
}
async function loginAs(identifier, value) {
  const limited = 'Too many sign-in attempts. Please wait and try again.';
  for (let attempt = 0; attempt < 2; attempt++) {
    await inputValue('identifier', identifier);
    await inputValue('password', value);
    await evaluate("document.querySelector('[name=identifier]').form.dataset.submitted='1'; document.querySelector('[name=identifier]').form.requestSubmit()");
    await until(() => evaluate("!document.querySelector('form[data-submitted]') && (document.body?.innerText.includes('Invitation access') || document.body?.innerText.includes(" + JSON.stringify(limited) + "))"), 'issuer sign-in response');
    if (await evaluate("document.body.innerText.includes('Invitation access')")) break;
    assert.equal(attempt, 0, 'issuer still rate-limited after its full window');
    await delay(61000);
  }
  await waitText(identifier);
}
async function startSignInWithPendingIdentityChecks(identifier) {
  const original = session;
  const stale = [];
  for (const label of ['Send registration email', 'Send recovery email']) {
    session = await tab();
    await openMail('Organization invitation');
    await waitText(label);
    if (label === 'Send recovery email') await inputValue('loginIdentifier', identifier);
    stale.push({target: session, label});
  }
  session = original;
  await click('Sign in');
  await until(() => evaluate("Boolean(document.querySelector('[name=identifier]'))"), 'issuer login started');
  // These are the original, valid forms in two already-open tabs. Neither
  // action may allocate mail once the issuer authorization has begun.
  for (const {target, label} of stale) {
    session = target;
    let status;
    const observe = ({data}) => {
      const event = JSON.parse(data);
      if (event.sessionId === target && event.method === 'Network.responseReceived' &&
          event.params.response.url === issuer + '/organization-invitations/hosted/actions') status = event.params.response.status;
    };
    await protocol.send('Network.enable', {}, target);
    protocol.socket.addEventListener('message', observe);
    try {
      await click(label);
      await waitText('Unable to confirm this step');
      await until(() => status !== undefined, 'stale identity action response');
      assert.equal(status, 403, label);
    } finally {
      protocol.socket.removeEventListener('message', observe);
    }
  }
  const verifyPending = async () => {
    await waitText('Continue sign-in');
    assert.deepEqual(await evaluate("Array.from(document.querySelectorAll('button'), b => b.textContent)"), ['Continue sign-in', 'Cancel invitation flow']);
  };
  await openMail('Organization invitation');
  await verifyPending();
  session = original;
  await evaluate('history.back()');
  await verifyPending();
  await click('Continue sign-in');
  for (const {target} of stale) {
    const {targetInfo} = await protocol.send('Target.getTargetInfo', {}, target);
    await protocol.send('Target.closeTarget', {targetId: targetInfo.targetId});
  }
}
async function restartFromInvitation(identifier, secret) {
  await openMail('Organization invitation');
  await waitText('Continue your invitation');
  await click('Sign in');
  await loginAs(identifier, secret);
  await click('Allow access');
  await waitText('Verify the invited address');
  await click('Check available challenge requests');
}
async function reviewDetails(count, identifier, role) {
  await openMail('Confirm your invitation', count);
  await waitText('Review the invitation');
  await click('Show invitation details');
  for (const text of ['Confirm organization membership', 'Example school', role, identifier, organization]) await waitText(text);
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
  await until(() => {
    assert.equal(child.exitCode, null, 'Chromium exited before reporting its debug socket');
    assert.equal(child.signalCode, null, 'Chromium was signalled during startup');
    return Boolean(devtools);
  }, 'Chromium startup', 45000);
  protocol = new BrowserProtocol(new WebSocket(devtools));
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
  const anonymousHandle = await evaluate('location.href');
  if (delegated) await click('Sign in');
  else await startSignInWithPendingIdentityChecks(identifier);
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
  if (!delegated) {
    const authenticated = session;
    session = await tab();
    await protocol.send('Page.navigate', {url: anonymousHandle}, session);
    await waitText('Unable to confirm this step');
    session = authenticated;
  }
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
    await concurrentResume('Check the pending send');
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
  let original = session;
  await concurrentResume(delegated ? '4 of 5' : '3 of 5');
  session = await tab();
  await openMail('Organization invitation');
  await waitText(delegated ? '4 of 5' : '3 of 5');
  // Following a child link from an independent browser cannot attach that
  // challenge. The only way forward there is to start from the original mail.
  const signedInTab = session;
  const { browserContextId } = await protocol.send('Target.createBrowserContext');
  session = await tab(browserContextId);
  let challengeEmails = delegated ? 1 : 2;
  await openMail('Confirm your invitation', challengeEmails);
  await waitText('Unable to open this invitation');
  if (delegated) {
    await protocol.send('Target.disposeBrowserContext', {browserContextId});
    session = signedInTab;
  } else {
    await restartFromInvitation(identifier, password + '2');
    await waitText('3 of 5');
    const requester = session;
    const mailboxTab = await tab(browserContextId);
    session = requester;
    // Each delivery on this device requires its own current status and Send.
    for (let remaining = 3; remaining > 0; remaining--) {
      if (remaining < 3) await click('Review a replacement request');
      await waitText('Send a verification email');
      await waitText(remaining + ' of 5');
      await click('Send verification email');
      await waitText((remaining - 1) + ' of 5');
      challengeEmails++;
      // The outbox can deliver equally ready messages in a different order.
      // Observe each arrival before superseding it with another request.
      session = mailboxTab;
      await waitForMail('Confirm your invitation', challengeEmails);
      session = requester;
    }
    original = session;
    const third = await protocol.send('Target.createBrowserContext');
    session = await tab(third.browserContextId);
    await restartFromInvitation(identifier, password + '2');
    await waitText('No more challenges available');
    await waitText('contact the inviter for a new invitation');
    assert.equal(await evaluate("Array.from(document.querySelectorAll('button')).some(b => b.textContent==='Send verification email')"), false);
    await protocol.send('Target.disposeBrowserContext', {browserContextId: third.browserContextId});
    // The issuing device can still use its fifth live challenge from another tab.
    session = await tab(browserContextId);
    await openMail('Organization invitation');
    await waitText('0 of 5');
  }
  await reviewDetails(challengeEmails, identifier, delegated ? 'Member' : 'Administrator');
  if (delegated) {
    const priorConfirmation = session;
    session = await tab();
    await openMail('Organization invitation');
    await waitText('Confirm organization membership');
    await click('Switch account');
    await loginAs('invitee@example.test', previousPassword);
    await click('Allow access');
    await waitText('Verify the invited address');
    const switched = session;
    session = priorConfirmation;
    await click('Accept and join organization');
    await waitText('Unable to confirm this step');
    session = switched;
    await click('Switch account');
    await loginAs(identifier, password);
    await click('Allow access');
    await waitText('Verify the invited address');
    await click('Check available challenge requests');
    await waitText('4 of 5');
    await click('Send verification email');
    await waitText('3 of 5');
    await reviewDetails(challengeEmails + 1, identifier, 'Member');
    await applicationCheck('before-accept', 'Existing application grant checked');
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
