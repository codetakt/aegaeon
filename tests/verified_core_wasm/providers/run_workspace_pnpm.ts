#!/usr/bin/env node
import { execFile as execFileCallback } from 'node:child_process';
import path from 'node:path';
import { promisify } from 'node:util';

const execFile = promisify(execFileCallback);

export async function commandExists(command, cwd = process.cwd()) {
  try {
    await execFile('bash', ['-lc', `command -v ${command}`], { cwd });
    return true;
  } catch {
    return false;
  }
}

export async function runWorkspacePnpm({ workspaceRoot, args, env = process.env }) {
  const repositoryRoot = path.resolve(workspaceRoot, '..');

  if (process.env.IN_NIX_SHELL && await commandExists('pnpm', workspaceRoot)) {
    return execFile('pnpm', args, {
      cwd: workspaceRoot,
      env,
    });
  }

  if (await commandExists('nix', repositoryRoot)) {
    return execFile('nix', ['develop', '.', '--command', 'pnpm', '--dir', 'sdk', ...args], {
      cwd: repositoryRoot,
      env,
    });
  }

  if (await commandExists('pnpm', workspaceRoot)) {
    return execFile('pnpm', args, {
      cwd: workspaceRoot,
      env,
    });
  }

  throw new Error('pnpm is required; enter `nix develop .` from the repository root');
}
