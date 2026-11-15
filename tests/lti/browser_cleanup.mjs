import { rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const describe = error => error instanceof Error ? error.stack : String(error);

// Cleanup uncertainty must not discard either the original failure or its evidence.
export async function finishBrowserCheck({ root, directory, record, primaryError, steps, inspect, groups, diagnostics, started }) {
  const failures = primaryError === undefined ? [] : [primaryError];
  if (primaryError !== undefined) record.error = describe(primaryError);
  record.cleanup_errors = [];
  record.evidence_errors = [];
  record.cleanup_confirmed = false;
  record.live_members_after = null;
  record.directory_removed = false;
  const cleanup = async (phase, action) => {
    try { await action(); } catch (error) {
      failures.push(error);
      record.cleanup_errors.push({ phase, error: describe(error) });
    }
  };
  for (const { phase, action } of steps) await cleanup(phase, action);
  await cleanup('inspect', async () => {
    const state = await inspect();
    record.live_members_after = state.members;
    record.cleanup_confirmed = state.exited && state.members.length === 0;
  });
  if (record.cleanup_confirmed) {
    groups.delete(record.pid);
    await cleanup('remove-directory', async () => {
      await rm(directory, { recursive: true, force: true });
      record.directory_removed = true;
    });
  } else if (record.cleanup_errors.length === 0) {
    const error = new Error('browser process cleanup is unconfirmed');
    failures.push(error);
    record.cleanup_errors.push({ phase: 'inspect', error: describe(error) });
  }
  if (!record.directory_removed) record.retained_directory = directory;
  record.unconfirmed_groups = [...groups];
  record.elapsed_ms = performance.now() - started;
  record.passed = record.passed === true && failures.length === 0;
  const captured = diagnostics().slice(-65536);
  const reportFailure = () => console.error(JSON.stringify({ ...record, browser_diagnostics: captured }));
  if (!record.passed) reportFailure();
  const publish = async (phase, path, contents) => {
    try { await writeFile(path, contents(), { flag: 'wx' }); } catch (error) {
      failures.push(error);
      record.passed = false;
      record.evidence_errors.push({ phase, error: describe(error) });
      reportFailure();
    }
  };
  await publish('stderr', join(root, `real-${record.name}.stderr`), () => captured);
  // Attempt the structured record even when publishing stderr failed.
  await publish('json', join(root, `real-${record.name}.json`), () => JSON.stringify(record, null, 2) + '\n');
  console.log(JSON.stringify({ name: record.name, passed: record.passed, cleanup_confirmed: record.cleanup_confirmed }));
  if (failures.length === 1) throw failures[0];
  if (failures.length > 1) throw new AggregateError(failures, 'browser check, cleanup or evidence publication failed', { cause: failures[0] });
}
