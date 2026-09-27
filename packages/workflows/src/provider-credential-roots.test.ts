import { mkdir, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, test } from 'bun:test';
import { trackTempRoots } from '@archon/paths/test-utils';

import { sweepStaleProviderCredentialRoots } from './provider-credential-roots';

const trackTempRoot = trackTempRoots();

describe('provider credential root janitor', () => {
  test('removes dead-process credential roots and preserves live or unknown entries', async () => {
    const root = trackTempRoot(await mkdtemp(join(tmpdir(), 'archon-provider-root-test-')));
    const dead = join(root, '41001-dead');
    const live = join(root, '41002-live');
    const unknown = join(root, 'README');
    await mkdir(dead);
    await mkdir(live);
    await writeFile(join(dead, 'auth.json'), 'secret');
    await writeFile(join(live, 'auth.json'), 'live-secret');
    await writeFile(unknown, 'leave me');
    await sweepStaleProviderCredentialRoots(root, pid => pid === 41002);
    await expect(stat(dead)).rejects.toThrow();
    await expect(readFile(join(live, 'auth.json'), 'utf8')).resolves.toBe('live-secret');
    await expect(readFile(unknown, 'utf8')).resolves.toBe('leave me');
  });
});
