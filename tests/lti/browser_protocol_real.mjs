import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { setTimeout as delay } from 'node:timers/promises';
import { BrowserProtocol } from './browser_protocol.mjs';

const root = process.argv[2];
assert(root, 'protocol evidence directory required');
await mkdir(root, { recursive: true });
const executable = process.env.AEGAEON_CHROMIUM;
assert(executable, 'actual Chromium is required');
const results = [];
const groups = new Set();
function signal(group, sig) { try { process.kill(-group, sig); } catch (error) { if (error.code !== 'ESRCH') throw error; } }
for (const sig of ['SIGINT', 'SIGTERM']) process.once(sig, () => { for (const group of groups) signal(group, 'SIGKILL'); process.exit(1); });
async function members(group) {
  const found = [];
  for (const pid of await readdir('/proc')) {
    if (!/^\d+$/.test(pid)) continue;
    let stat;
    try { stat = await readFile(`/proc/${pid}/stat`, 'utf8'); } catch (error) { if (['ENOENT', 'ESRCH'].includes(error.code)) continue; throw error; }
    const fields = stat.slice(stat.lastIndexOf(') ') + 2).split(' ');
    if (Number(fields[2]) === group && !['Z', 'X'].includes(fields[0])) found.push(Number(pid));
  }
  return found;
}
async function until(check, milliseconds) {
  const deadline = performance.now() + milliseconds;
  while (!await check()) { assert(performance.now() < deadline, 'actual browser lifecycle deadline'); await delay(10); }
}
async function run(name, action) {
  const directory = await mkdtemp(join(tmpdir(), 'aegaeon-lti-protocol-'));
  const started = performance.now();
  const chrome = spawn(executable, ['--headless', '--no-sandbox', '--disable-gpu', '--disable-background-networking', '--disable-component-update', '--no-first-run', '--no-default-browser-check', '--remote-debugging-port=0', `--user-data-dir=${directory}`, 'about:blank'], { detached: true, stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, CHROME_CONFIG_HOME: join(directory, 'config') } });
  const childStarted = Number.isInteger(chrome.pid) && chrome.pid > 0;
  if (childStarted) groups.add(chrome.pid);
  let diagnostics = ''; let spawnError; let protocol;
  chrome.stderr.on('data', value => { diagnostics = (diagnostics + value).slice(-65536); });
  chrome.on('error', error => { spawnError = error; });
  const record = { name, pid: chrome.pid ?? null, executable };
  try {
    await until(() => { if (spawnError) throw spawnError; assert.equal(chrome.exitCode, null, 'Chromium exited during startup'); assert.equal(chrome.signalCode, null, 'Chromium signalled during startup'); return /DevTools listening on (ws:\/\/[^\s]+)/.test(diagnostics); }, 10000);
    protocol = new BrowserProtocol(new WebSocket(diagnostics.match(/DevTools listening on (ws:\/\/[^\s]+)/)[1]), 1000);
    await protocol.ready();
    record.version = await protocol.send('Browser.getVersion');
    await action(protocol, chrome.pid, record);
    record.passed = true;
  } catch (error) {
    record.passed = false; record.error = error.stack;
    // Preserve the primary stack even if a later cleanup wait also rejects.
    console.error(JSON.stringify({ name, passed: false, error: record.error, browser_diagnostics: diagnostics }));
    throw error;
  } finally {
    protocol?.close();
    if (childStarted) {
      signal(chrome.pid, 'SIGKILL');
      await until(async () => chrome.exitCode !== null || chrome.signalCode !== null, 3000);
      await until(async () => (await members(chrome.pid)).length === 0, 3000);
    }
    record.live_members_after = childStarted ? await members(chrome.pid) : [];
    record.cleanup_confirmed = record.live_members_after.length === 0;
    if (childStarted) groups.delete(chrome.pid);
    await rm(directory, { recursive: true, force: true });
    record.elapsed_ms = performance.now() - started;
    results.push(record);
    await writeFile(join(root, `real-${name}.stderr`), diagnostics, { flag: 'wx' });
    await writeFile(join(root, `real-${name}.json`), JSON.stringify(record, null, 2) + '\n', { flag: 'wx' });
    console.log(JSON.stringify({ name, passed: record.passed, cleanup_confirmed: record.cleanup_confirmed }));
  }
}
await run('normal-and-protocol-error', async protocol => {
  const { targetId } = await protocol.send('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await protocol.send('Target.attachToTarget', { targetId, flatten: true });
  const value = await protocol.send('Runtime.evaluate', { expression: '21 * 2', returnByValue: true }, sessionId);
  assert.equal(value.result.value, 42);
  await assert.rejects(protocol.send('NotARealMethod.invalid'), /protocol error/);
  assert.equal(protocol.pending.size, 0);
});
await run('stopped-browser-deadline', async (protocol, pid, record) => {
  signal(pid, 'SIGSTOP');
  const started = performance.now();
  await assert.rejects(protocol.send('Browser.getVersion'), /response deadline/);
  record.deadline_elapsed_ms = performance.now() - started;
  assert.equal(protocol.pending.size, 0);
});
await run('lost-browser-disconnect', async (protocol, pid) => {
  signal(pid, 'SIGSTOP');
  const command = protocol.send('Browser.getVersion');
  const result = assert.rejects(command, /CDP socket (closed|error)/);
  signal(pid, 'SIGKILL');
  await result;
  assert.equal(protocol.pending.size, 0);
  await assert.rejects(protocol.send('Browser.getVersion'), /CDP socket/);
});
assert.equal(groups.size, 0);
await writeFile(join(root, 'REAL-BROWSER-RESULT.json'), JSON.stringify({ passed: true, results, unconfirmed_groups: [...groups], limits: 'Actual pinned Chromium CDP normal/deadline/disconnection only; not the complete packaged LTI journey.' }, null, 2) + '\n', { flag: 'wx' });
