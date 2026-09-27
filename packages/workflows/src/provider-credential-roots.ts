import { chmod, lstat, mkdir, mkdtemp, readdir, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

import type { StrictSubscriptionProvider } from './deps';

const MANAGED_ROOT_PREFIX = 'archon-provider-credentials-v1-';
const ENTRY = /^(\d+)-[A-Za-z0-9._-]+$/;
const JANITOR_INTERVAL_MS = 10 * 60 * 1000;
let janitor: ReturnType<typeof setInterval> | undefined;

function currentUid(): number | undefined {
  return typeof process.getuid === 'function' ? process.getuid() : undefined;
}

export function managedProviderCredentialRoot(): string {
  return join(tmpdir(), `${MANAGED_ROOT_PREFIX}${currentUid() ?? 'nouid'}`);
}

async function requirePrivateOwnedDirectory(path: string): Promise<void> {
  const info = await lstat(path);
  const uid = currentUid();
  if (!info.isDirectory() || info.isSymbolicLink() || (uid !== undefined && info.uid !== uid)) {
    throw new Error('managed provider credential root is not a private owned directory');
  }
  await chmod(path, 0o700);
}

function processIsAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

export async function sweepStaleProviderCredentialRoots(
  root = managedProviderCredentialRoot(),
  isAlive: (pid: number) => boolean = processIsAlive
): Promise<void> {
  try {
    await requirePrivateOwnedDirectory(root);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
    throw error;
  }
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const match = ENTRY.exec(entry.name);
    if (!entry.isDirectory() || !match) continue;
    const pid = Number(match[1]);
    if (!Number.isSafeInteger(pid) || pid <= 0 || isAlive(pid)) continue;
    await rm(join(root, entry.name), { recursive: true, force: true });
  }
}

function startJanitor(root: string): void {
  if (janitor !== undefined) return;
  janitor = setInterval(() => {
    void sweepStaleProviderCredentialRoots(root).catch(() => undefined);
  }, JANITOR_INTERVAL_MS);
  janitor.unref();
}

export async function createStrictProviderCredentialRoots(
  providers: ReadonlySet<StrictSubscriptionProvider>
): Promise<{
  runRoot: string;
  providers: Partial<Record<StrictSubscriptionProvider, string>>;
}> {
  const root = managedProviderCredentialRoot();
  try {
    await mkdir(root, { mode: 0o700 });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
  }
  await requirePrivateOwnedDirectory(root);
  await sweepStaleProviderCredentialRoots(root);
  startJanitor(root);

  const runRoot = await mkdtemp(join(root, `${process.pid}-`));
  await chmod(runRoot, 0o700);
  const result: Partial<Record<StrictSubscriptionProvider, string>> = {};
  try {
    for (const provider of providers) {
      const path = join(runRoot, provider);
      await mkdir(path, { mode: 0o700 });
      result[provider] = path;
    }
  } catch (error) {
    await rm(runRoot, { recursive: true, force: true });
    throw error;
  }
  return { runRoot, providers: result };
}
