import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BrowserProtocol } from './browser_protocol.mjs';

class Socket extends EventTarget {
  readyState = 1;
  sent = [];
  send(text) { this.sent.push(JSON.parse(text)); }
  close() { this.readyState = 3; this.dispatchEvent(new Event('close')); }
  receive(value) { this.dispatchEvent(new MessageEvent('message', { data: JSON.stringify(value) })); }
}

test('commands preserve parameters/session and correlate out-of-order replies', async () => {
  const socket = new Socket();
  const protocol = new BrowserProtocol(socket, 1000);
  await protocol.ready();
  const first = protocol.send('Page.enable', { value: 'private' }, 'session');
  const second = protocol.send('Browser.getVersion');
  assert.deepEqual(socket.sent[0], { id: 1, method: 'Page.enable', params: { value: 'private' }, sessionId: 'session' });
  socket.receive({ id: 2, result: { version: 1 } });
  socket.receive({ id: 1, result: {} });
  assert.deepEqual(await second, { version: 1 });
  assert.deepEqual(await first, {});
  assert.deepEqual(protocol.snapshot(), { lastCompleted: 'Page.enable', pending: [], failure: undefined });
  assert(!JSON.stringify(protocol.snapshot()).includes('private'));
  protocol.close();
});

test('missing command response expires and a late reply cannot settle another command', async () => {
  const socket = new Socket();
  const protocol = new BrowserProtocol(socket, 20);
  await assert.rejects(protocol.send('Runtime.evaluate'), /Runtime.evaluate: response deadline/);
  assert.equal(protocol.pending.size, 0);
  const second = protocol.send('Page.enable');
  socket.receive({ id: 1, result: 'late' });
  assert.equal(protocol.pending.size, 1);
  socket.receive({ id: 2, result: 'current' });
  assert.equal(await second, 'current');
  protocol.close();
});

test('connection deadline closes transport and clears its pending registration', async () => {
  const socket = new Socket();
  socket.readyState = 0;
  const protocol = new BrowserProtocol(socket, 20);
  await assert.rejects(protocol.ready(), /connection deadline/);
  assert.equal(socket.readyState, 3);
  assert.equal(protocol.pending.size, 0);
  await assert.rejects(protocol.send('Page.enable'), /connection deadline/);
});

for (const event of ['close', 'error']) {
  test(`${event} rejects every pending command and future commands`, async () => {
    const socket = new Socket();
    const protocol = new BrowserProtocol(socket, 1000);
    const commands = [protocol.send('Page.enable'), protocol.send('Browser.getVersion')];
    const rejected = commands.map(command => assert.rejects(command, /CDP socket/));
    socket.dispatchEvent(new Event(event));
    await Promise.all(rejected);
    assert.equal(protocol.pending.size, 0);
    await assert.rejects(protocol.send('Page.enable'), /CDP socket/);
    protocol.close();
  });
}

test('protocol errors identify command without echoing remote details', async () => {
  const socket = new Socket();
  const protocol = new BrowserProtocol(socket, 1000);
  const command = protocol.send('Invalid.command');
  socket.receive({ id: 1, error: { message: 'private response' } });
  await assert.rejects(command, error => error.message === 'CDP Invalid.command: protocol error');
  protocol.close();
});

test('malformed response refuses pending and future commands', async () => {
  const socket = new Socket();
  const protocol = new BrowserProtocol(socket, 1000);
  const command = protocol.send('Page.enable');
  socket.dispatchEvent(new MessageEvent('message', { data: '{' }));
  await assert.rejects(command, /malformed CDP response/);
  await assert.rejects(protocol.send('Page.enable'), /malformed CDP response/);
  protocol.close();
});

test('synchronous send failure clears pending registration and deadline', async () => {
  const socket = new Socket();
  socket.send = () => { throw new Error('send failed'); };
  const protocol = new BrowserProtocol(socket, 1000);
  await assert.rejects(protocol.send('Page.enable'), /send failed/);
  assert.equal(protocol.pending.size, 0);
  protocol.close();
});

for (const code of ['ENOENT', 'EACCES']) {
  test(`actual ${code} spawn failure preserves evidence and removes its directory`, async () => {
    const directory = await mkdtemp(join(tmpdir(), 'aegaeon-browser-spawn-test-'));
    try {
      const temporary = join(directory, 'temporary');
      const evidence = join(directory, 'evidence');
      const executable = join(directory, 'chromium');
      await mkdir(temporary);
      if (code === 'EACCES') await writeFile(executable, 'not executable\n', { mode: 0o600 });
      const child = spawnSync(process.execPath, [fileURLToPath(new URL('./browser_protocol_real.mjs', import.meta.url)), evidence], {
        env: { ...process.env, TMPDIR: temporary, AEGAEON_CHROMIUM: executable },
        encoding: 'utf8', timeout: 15000, killSignal: 'SIGKILL', maxBuffer: 1024 * 1024,
      });
      assert.equal(child.error, undefined);
      assert.equal(child.signal, null);
      assert.equal(child.status, 1);
      assert.match(child.stderr, new RegExp(code));
      assert.doesNotMatch(child.stderr, /ERR_INVALID_ARG_TYPE/);
      assert.deepEqual(await readdir(temporary), []);
      const record = JSON.parse(await readFile(join(evidence, 'real-normal-and-protocol-error.json'), 'utf8'));
      assert.equal(record.passed, false);
      assert.equal(record.pid, null);
      assert.match(record.error, new RegExp(code));
      assert.equal(record.cleanup_confirmed, true);
      assert.deepEqual(record.live_members_after, []);
      assert.deepEqual((await readdir(evidence)).sort(), ['real-normal-and-protocol-error.json', 'real-normal-and-protocol-error.stderr']);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
