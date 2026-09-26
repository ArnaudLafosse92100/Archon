import { afterEach, describe, expect, it } from 'bun:test';
import { chmod, mkdtemp, mkdir, realpath, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { removeTempTree } from '@archon/paths/test-utils';
import {
  managedCodegraphTestHelpers,
  inspectCodegraphManagedRegistry,
  prepareManagedCodegraph,
  type CodegraphProcessRunner,
} from './managed-codegraph';

const roots: string[] = [];
afterEach(async () => {
  await Promise.all(roots.splice(0).map(removeTempTree));
});

async function fixture() {
  const root = await realpath(await mkdtemp(join(tmpdir(), 'archon-codegraph-')));
  roots.push(root);
  const owner = join(root, 'owner');
  const project = join(root, 'project');
  await mkdir(owner);
  await mkdir(project);
  await mkdir(join(project, '.codegraph'));
  Bun.spawnSync(['git', 'init', '-q'], { cwd: project });
  await writeFile(join(project, 'tracked.txt'), 'tracked\n');
  Bun.spawnSync(['git', 'add', 'tracked.txt'], { cwd: project });
  Bun.spawnSync(
    [
      'git',
      '-c',
      'user.name=Archon Test',
      '-c',
      'user.email=test@archon.local',
      'commit',
      '-qm',
      'fixture',
    ],
    { cwd: project }
  );
  const head = Bun.spawnSync(['git', 'rev-parse', 'HEAD'], { cwd: project })
    .stdout.toString()
    .trim();
  const adapter = join(owner, 'adapter');
  const runtime = join(owner, 'codegraph');
  const manifest = join(owner, 'versions.json');
  await writeFile(adapter, '#!/bin/sh\nexit 0\n');
  await writeFile(runtime, '#!/bin/sh\nexit 0\n');
  await chmod(adapter, 0o755);
  await chmod(runtime, 0o755);
  await writeFile(manifest, JSON.stringify({ codegraph: { pin: '1.5.0' } }));
  const adapterHelper = join(owner, 'adapter-helper.mjs');
  const runtimeHelper = join(owner, 'runtime-helper.js');
  await writeFile(adapterHelper, 'export const helper = true;\n');
  await writeFile(runtimeHelper, 'module.exports = true;\n');
  const adapterSha = createHash('sha256')
    .update(Buffer.from(await Bun.file(adapter).arrayBuffer()))
    .digest('hex');
  const runtimeSha = createHash('sha256')
    .update(Buffer.from(await Bun.file(runtime).arrayBuffer()))
    .digest('hex');
  const bundle = async (includes: string[]) => ({
    algorithm: 'sha256-tree-v1' as const,
    root: owner,
    includes,
    sha256: managedCodegraphTestHelpers.sha256Canonical(
      await managedCodegraphTestHelpers.bundleFileEntries({
        algorithm: 'sha256-tree-v1',
        root: owner,
        includes,
        sha256: '0'.repeat(64),
      })
    ),
  });
  const contract = {
    schemaVersion: 1 as const,
    owner,
    protocol: 'codegraph_worktree_adapter_v1' as const,
    adapter: {
      command: adapter,
      sha256: adapterSha,
      bundle: await bundle(['adapter', 'adapter-helper.mjs']),
    },
    pin: { manifest, field: 'codegraph.pin' as const },
    runtime: {
      command: runtime,
      sha256: runtimeSha,
      bundle: await bundle(['codegraph', 'runtime-helper.js']),
      args: ['serve', '--mcp'] as const,
    },
    environment: {
      CODEGRAPH_TELEMETRY: '0' as const,
      CODEGRAPH_NO_UPDATE_CHECK: '1' as const,
      CODEGRAPH_MCP_TOOLS: 'explore' as const,
      DO_NOT_TRACK: '1' as const,
    },
  };
  const registry = {
    ...contract,
    contractSha256: managedCodegraphTestHelpers.sha256Canonical(contract),
  };
  const attestationPayload = {
    schemaVersion: 1,
    kind: 'codegraph_worktree_attestation_v1',
    action: 'prepare',
    result: 'ready',
    project: { root: project, head },
    engine: { version: '1.5.0', pin: '1.5.0', indexRoot: join(project, '.codegraph') },
    // Keep this fixture byte-for-byte compatible with the AI-Setup adapter's
    // strict-audit evidence contract. A first snapshot may race once, hence
    // the bounded 1|2 attempts value is part of the signed attestation.
    freshness: { strict: true, attempts: 1, sourceCount: 1, sourceSha256: 'a'.repeat(64) },
    contractSha256: registry.contractSha256,
    attestedAt: '2026-09-26T00:00:00.000Z',
  };
  const attestation = {
    ...attestationPayload,
    attestationSha256: managedCodegraphTestHelpers.sha256Canonical(attestationPayload),
  };
  const runner: CodegraphProcessRunner = async (command, args) => {
    expect(command).toBe(adapter);
    expect(args).toEqual(['prepare', '--directory', project, '--json']);
    return { exitCode: 0, stdout: JSON.stringify(attestation), stderr: '' };
  };
  return {
    root,
    owner,
    project,
    adapter,
    adapterHelper,
    runtimeHelper,
    registry,
    attestation,
    runner,
  };
}

describe('prepareManagedCodegraph', () => {
  it('attests the exact worktree and constructs only the fixed managed MCP command', async () => {
    const f = await fixture();
    const result = await prepareManagedCodegraph(f.project, 'required', f.registry, f.runner);
    expect(result.prepared).toEqual({
      mode: 'required',
      root: f.project,
      command: f.registry.runtime.command,
      args: ['serve', '--mcp', '-p', f.project],
      env: f.registry.environment,
      version: '1.5.0',
    });
  });

  it('fails required mode before adapter execution on digest drift', async () => {
    const f = await fixture();
    await writeFile(f.adapter, '#!/bin/sh\nexit 7\n');
    let called = false;
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, async () => {
        called = true;
        return f.runner('', [], { cwd: '', env: {} });
      })
    ).rejects.toThrow('adapter command sha256');
    expect(called).toBeFalse();
  });

  it('fails required mode before adapter execution on runtime digest drift', async () => {
    const f = await fixture();
    await writeFile(f.registry.runtime.command, '#!/bin/sh\nexit 9\n');
    let called = false;
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, async () => {
        called = true;
        return f.runner('', [], { cwd: '', env: {} });
      })
    ).rejects.toThrow('runtime command sha256');
    expect(called).toBeFalse();
  });

  it('fails before adapter execution when an adapter dependency drifts', async () => {
    const f = await fixture();
    await writeFile(f.adapterHelper, 'export const helper = false;\n');
    let called = false;
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, async () => {
        called = true;
        return f.runner('', [], { cwd: '', env: {} });
      })
    ).rejects.toThrow('adapter bundle sha256');
    expect(called).toBeFalse();
  });

  it('rejects runtime dependency drift before exposing the MCP command', async () => {
    const f = await fixture();
    const runner: CodegraphProcessRunner = async () => {
      await writeFile(f.runtimeHelper, 'module.exports = false;\n');
      return { exitCode: 0, stdout: JSON.stringify(f.attestation), stderr: '' };
    };
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, runner)
    ).rejects.toThrow('runtime bundle sha256');
  });

  it('rejects a symlinked adapter', async () => {
    const f = await fixture();
    const link = join(f.root, 'adapter-link');
    await symlink(f.adapter, link);
    const contract = { ...f.registry, adapter: { ...f.registry.adapter, command: link } };
    const registry = {
      ...contract,
      contractSha256: managedCodegraphTestHelpers.sha256Canonical(
        Object.fromEntries(Object.entries(contract).filter(([key]) => key !== 'contractSha256'))
      ),
    };
    await expect(
      prepareManagedCodegraph(f.project, 'required', registry, f.runner)
    ).rejects.toThrow('symbolic link');
  });

  it('rejects a final runtime command symlink even when its ancestor policy allows links', async () => {
    const f = await fixture();
    const link = join(f.root, 'runtime-link');
    await symlink(f.registry.runtime.command, link);
    const contract = { ...f.registry, runtime: { ...f.registry.runtime, command: link } };
    const registry = {
      ...contract,
      contractSha256: managedCodegraphTestHelpers.sha256Canonical(
        Object.fromEntries(Object.entries(contract).filter(([key]) => key !== 'contractSha256'))
      ),
    };
    await expect(inspectCodegraphManagedRegistry(registry)).rejects.toThrow('symbolic link');
  });

  it('rejects a symlink inside a governed dependency bundle', async () => {
    const f = await fixture();
    await rm(f.adapterHelper);
    await symlink(f.adapter, f.adapterHelper);
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, f.runner)
    ).rejects.toThrow('bundle entry must not be a symbolic link');
  });

  it('accepts a governed command reached through a symlinked ancestor', async () => {
    const f = await fixture();
    const linkedOwner = join(f.root, 'linked-owner');
    await symlink(f.owner, linkedOwner);
    const contract = {
      ...f.registry,
      runtime: { ...f.registry.runtime, command: join(linkedOwner, 'codegraph') },
    };
    const registry = {
      ...contract,
      contractSha256: managedCodegraphTestHelpers.sha256Canonical(
        Object.fromEntries(Object.entries(contract).filter(([key]) => key !== 'contractSha256'))
      ),
    };
    await expect(inspectCodegraphManagedRegistry(registry)).resolves.toMatchObject({ ready: true });
  });

  it('accepts the exact worktree index path when .codegraph is a directory symlink', async () => {
    const f = await fixture();
    const indexTarget = join(f.root, 'managed-index');
    await mkdir(indexTarget);
    await rm(join(f.project, '.codegraph'), { recursive: true });
    await symlink(indexTarget, join(f.project, '.codegraph'));
    const result = await prepareManagedCodegraph(f.project, 'required', f.registry, f.runner);
    expect(result.prepared?.root).toBe(f.project);
  });

  it('rejects a non-executable adapter during the non-mutating readiness probe', async () => {
    const f = await fixture();
    await chmod(f.adapter, 0o644);
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, f.runner)
    ).rejects.toThrow('adapter command must be executable');
  });

  it('reports an observable optional fallback for malformed registry data', async () => {
    const f = await fixture();
    const result = await prepareManagedCodegraph(f.project, 'optional', { nope: true }, f.runner);
    expect(result.prepared).toBeUndefined();
    expect(result.fallbackReason).toContain('invalid codegraph_managed_v1 registry');
  });

  it('does not leak ambient secrets to the adapter process', async () => {
    const f = await fixture();
    const original = process.env.SECRET_CANARY;
    process.env.SECRET_CANARY = 'must-not-leak';
    try {
      const result = await import('./managed-codegraph').then(({ runCodegraphAdapter }) =>
        runCodegraphAdapter('/usr/bin/env', [], { cwd: f.project, env: f.registry.environment })
      );
      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toContain('SECRET_CANARY');
      expect(result.stdout).toContain('CODEGRAPH_TELEMETRY=0');
    } finally {
      if (original === undefined) delete process.env.SECRET_CANARY;
      else process.env.SECRET_CANARY = original;
    }
  });

  it('rejects a validly signed attestation for a different worktree', async () => {
    const f = await fixture();
    const wrongPayload = {
      ...f.attestation,
      project: { root: join(f.root, 'other'), head: 'deadbeef' },
    };
    const { attestationSha256: _old, ...unsigned } = wrongPayload;
    const wrong = {
      ...unsigned,
      attestationSha256: managedCodegraphTestHelpers.sha256Canonical(unsigned),
    };
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, async () => ({
        exitCode: 0,
        stdout: JSON.stringify(wrong),
        stderr: '',
      }))
    ).rejects.toThrow('root does not match');
  });

  it('rejects a validly signed attestation for a stale worktree HEAD', async () => {
    const f = await fixture();
    const stalePayload = {
      ...f.attestation,
      project: { root: f.project, head: 'deadbeef' },
    };
    const { attestationSha256: _old, ...unsigned } = stalePayload;
    const stale = {
      ...unsigned,
      attestationSha256: managedCodegraphTestHelpers.sha256Canonical(unsigned),
    };
    await expect(
      prepareManagedCodegraph(f.project, 'required', f.registry, async () => ({
        exitCode: 0,
        stdout: JSON.stringify(stale),
        stderr: '',
      }))
    ).rejects.toThrow('HEAD does not match');
  });
});
