import { createHash } from 'node:crypto';
import { constants } from 'node:fs';
import { access, lstat, readFile, readdir, realpath, stat } from 'node:fs/promises';
import { dirname, isAbsolute, join, posix, relative, sep } from 'node:path';
import { z } from '@hono/zod-openapi';
import {
  codegraphManagedResourceSchema,
  type CodegraphManagedMode,
  type CodegraphManagedResourceV1,
} from './schemas/managed-resources';
import type { WorkflowConfig } from './deps';

const attestationSchema = z
  .object({
    schemaVersion: z.literal(1),
    kind: z.literal('codegraph_worktree_attestation_v1'),
    action: z.literal('prepare'),
    result: z.literal('ready'),
    project: z.object({ root: z.string(), head: z.string().min(1) }).strict(),
    engine: z
      .object({
        version: z.string().min(1),
        pin: z.string().min(1),
        indexRoot: z.string().min(1),
        files: z.number().int().nonnegative().optional(),
        nodes: z.number().int().nonnegative().optional(),
      })
      .strict(),
    freshness: z
      .object({
        strict: z.literal(true),
        attempts: z.union([z.literal(1), z.literal(2)]),
        sourceCount: z.number().int().nonnegative(),
        sourceSha256: z.string().regex(/^[a-f0-9]{64}$/),
      })
      .strict(),
    contractSha256: z.string().regex(/^[a-f0-9]{64}$/),
    attestedAt: z.string().min(1),
    attestationSha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export type CodegraphWorktreeAttestationV1 = z.infer<typeof attestationSchema>;

export interface CodegraphProcessResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type CodegraphProcessRunner = (
  command: string,
  args: readonly string[],
  options: { cwd: string; env: Record<string, string> }
) => Promise<CodegraphProcessResult>;

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (typeof value !== 'object' || value === null) return value;
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>)
      // The producer's sha256-tree-v1 contract uses locale-independent,
      // code-unit ordering. localeCompare would make a signed digest depend on
      // the host locale and already diverges for real runtime filenames.
      .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      .map(([key, entry]) => [key, canonicalize(entry)])
  );
}

function sha256Canonical(value: unknown): string {
  return createHash('sha256')
    .update(JSON.stringify(canonicalize(value)))
    .digest('hex');
}

async function assertRegularNonSymlink(path: string, label: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path.`);
  const stat = await lstat(path);
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link.`);
  if (!stat.isFile()) throw new Error(`${label} must be a regular file.`);
}

async function assertExecutable(path: string, label: string): Promise<void> {
  try {
    await access(path, constants.X_OK);
  } catch {
    throw new Error(`${label} must be executable.`);
  }
}

async function sha256File(path: string): Promise<string> {
  return createHash('sha256')
    .update(await readFile(path))
    .digest('hex');
}

type CodegraphBundle = CodegraphManagedResourceV1['adapter']['bundle'];

async function bundleFileEntries(bundle: CodegraphBundle): Promise<[string, string][]> {
  const canonicalRoot = await realpath(bundle.root);
  if (canonicalRoot !== bundle.root) {
    throw new Error('CodeGraph bundle root must be its canonical real path.');
  }
  const files = new Map<string, string>();
  const visit = async (absolute: string, relativePath: string): Promise<void> => {
    const entry = await lstat(absolute);
    if (entry.isSymbolicLink()) {
      throw new Error(`CodeGraph bundle entry must not be a symbolic link: ${relativePath}`);
    }
    if (entry.isDirectory()) {
      for (const child of (await readdir(absolute)).sort()) {
        await visit(join(absolute, child), posix.join(relativePath, child));
      }
      return;
    }
    if (!entry.isFile()) {
      throw new Error(`CodeGraph bundle entry must be a regular file: ${relativePath}`);
    }
    const lexicalRelative = relative(bundle.root, absolute).split(sep).join('/');
    if (lexicalRelative !== relativePath || lexicalRelative.startsWith('../')) {
      throw new Error(`CodeGraph bundle entry escapes its root: ${relativePath}`);
    }
    files.set(relativePath, await sha256File(absolute));
  };
  for (const include of bundle.includes) {
    await visit(join(bundle.root, ...include.split('/')), include);
  }
  return [...files].sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
}

async function verifyBundle(bundle: CodegraphBundle, label: string): Promise<void> {
  if (sha256Canonical(await bundleFileEntries(bundle)) !== bundle.sha256) {
    throw new Error(`${label} sha256 does not match its governed files.`);
  }
}

async function verifyGovernedCommand(
  entry: { command: string; sha256: string; bundle: CodegraphBundle },
  label: string
): Promise<string> {
  await assertRegularNonSymlink(entry.command, label);
  await assertExecutable(entry.command, label);
  const canonical = await realpath(entry.command);
  if ((await sha256File(canonical)) !== entry.sha256) {
    throw new Error(`${label} sha256 does not match the executable bytes.`);
  }
  await verifyBundle(entry.bundle, label.replace(/ command$/, ' bundle'));
  return canonical;
}

async function assertDirectoryNonSymlink(path: string, label: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path.`);
  const stat = await lstat(path);
  if (stat.isSymbolicLink()) throw new Error(`${label} must not be a symbolic link.`);
  if (!stat.isDirectory()) throw new Error(`${label} must be a directory.`);
}

async function assertDirectoryExists(path: string, label: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error(`${label} must be an absolute path.`);
  if (!(await stat(path)).isDirectory()) throw new Error(`${label} must resolve to a directory.`);
}

function readDottedField(value: unknown, field: string): unknown {
  let current = value;
  for (const segment of field.split('.')) {
    if (typeof current !== 'object' || current === null || Array.isArray(current)) return undefined;
    current = (current as Record<string, unknown>)[segment];
  }
  return current;
}

export async function runCodegraphAdapter(
  command: string,
  args: readonly string[],
  options: { cwd: string; env: Record<string, string> }
): Promise<CodegraphProcessResult> {
  const inherited = Object.fromEntries(
    ['HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR', 'ARCHON_HOME']
      .map(key => [key, process.env[key]] as const)
      .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
  );
  const child = Bun.spawn([command, ...args], {
    cwd: options.cwd,
    env: { ...inherited, ...options.env },
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const timeout = setTimeout(() => {
    child.kill();
  }, 120_000);
  try {
    const [exitCode, stdout, stderr] = await Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]);
    return { exitCode, stdout, stderr };
  } finally {
    clearTimeout(timeout);
  }
}

async function readGitHead(cwd: string): Promise<string> {
  const child = Bun.spawn(['git', 'rev-parse', 'HEAD'], {
    cwd,
    env: Object.fromEntries(
      ['HOME', 'PATH', 'LANG', 'LC_ALL', 'TMPDIR']
        .map(key => [key, process.env[key]] as const)
        .filter((entry): entry is [string, string] => typeof entry[1] === 'string')
    ),
    stdin: 'ignore',
    stdout: 'pipe',
    stderr: 'pipe',
  });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  if (exitCode !== 0 || stdout.trim().length === 0) {
    throw new Error('Unable to resolve the workflow worktree HEAD for CodeGraph attestation.');
  }
  return stdout.trim();
}

export interface PrepareCodegraphResult {
  prepared?: NonNullable<WorkflowConfig['preparedCodegraph']>;
  fallbackReason?: string;
}

export interface CodegraphRegistryInspection {
  configured: true;
  ready: true;
  schemaVersion: 1;
  protocol: 'codegraph_worktree_adapter_v1';
  expectedVersion: string;
  contractSha256: string;
}

/** Non-mutating registry probe used by doctor; it never invokes the adapter. */
export async function inspectCodegraphManagedRegistry(
  rawRegistry: unknown
): Promise<CodegraphRegistryInspection | { configured: false; ready: false }> {
  if (rawRegistry === undefined) return { configured: false, ready: false };
  const parsed = codegraphManagedResourceSchema.safeParse(rawRegistry);
  if (!parsed.success) {
    throw new Error(
      `invalid codegraph_managed_v1 registry: ${parsed.error.issues
        .map(issue => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
        .join('; ')}`
    );
  }
  const registry = parsed.data;
  await assertDirectoryNonSymlink(registry.owner, 'CodeGraph owner');
  await verifyGovernedCommand(registry.adapter, 'CodeGraph adapter command');
  await assertRegularNonSymlink(registry.pin.manifest, 'CodeGraph version manifest');
  await verifyGovernedCommand(registry.runtime, 'CodeGraph runtime command');
  const { contractSha256, ...contract } = registry;
  if (sha256Canonical(contract) !== contractSha256) {
    throw new Error('codegraph_managed_v1 contractSha256 does not match the registry payload.');
  }
  const manifest = JSON.parse(await readFile(registry.pin.manifest, 'utf8')) as unknown;
  const expectedVersion = readDottedField(manifest, registry.pin.field);
  if (typeof expectedVersion !== 'string' || expectedVersion.trim().length === 0) {
    throw new Error(`CodeGraph pin '${registry.pin.field}' is missing from its manifest.`);
  }
  return {
    configured: true,
    ready: true,
    schemaVersion: 1,
    protocol: registry.protocol,
    expectedVersion,
    contractSha256,
  };
}

/**
 * Validate the operator registry and obtain point-in-time, exact-worktree freshness evidence.
 * This is the only function allowed to execute the managed adapter.
 */
export async function prepareManagedCodegraph(
  cwd: string,
  mode: CodegraphManagedMode,
  rawRegistry: unknown,
  runner: CodegraphProcessRunner = runCodegraphAdapter
): Promise<PrepareCodegraphResult> {
  if (mode === 'off') return {};

  try {
    const inspection = await inspectCodegraphManagedRegistry(rawRegistry);
    if (!inspection.configured) throw new Error('codegraph_managed_v1 registry is not configured.');
    const registry: CodegraphManagedResourceV1 = codegraphManagedResourceSchema.parse(rawRegistry);
    const canonicalRoot = await realpath(cwd);
    const expectedVersion = inspection.expectedVersion;

    // Recheck the complete adapter closure immediately before handing it control.
    const canonicalAdapter = await verifyGovernedCommand(
      registry.adapter,
      'CodeGraph adapter command'
    );

    const result = await runner(
      canonicalAdapter,
      ['prepare', '--directory', canonicalRoot, '--json'],
      { cwd: canonicalRoot, env: registry.environment }
    );
    if (result.exitCode !== 0) {
      throw new Error(`CodeGraph adapter failed with exit ${result.exitCode}.`);
    }
    let rawAttestation: unknown;
    try {
      rawAttestation = JSON.parse(result.stdout.trim());
    } catch {
      throw new Error('CodeGraph adapter returned malformed JSON.');
    }
    const attestationResult = attestationSchema.safeParse(rawAttestation);
    if (!attestationResult.success) {
      throw new Error(
        `CodeGraph adapter returned an invalid attestation: ${attestationResult.error.issues
          .map(issue => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
          .join('; ')}`
      );
    }
    const attestation = attestationResult.data;
    const { attestationSha256, ...attestationPayload } = attestation;
    if (sha256Canonical(attestationPayload) !== attestationSha256) {
      throw new Error('CodeGraph attestationSha256 does not match its payload.');
    }
    if (attestation.contractSha256 !== registry.contractSha256) {
      throw new Error('CodeGraph attestation was produced for a different registry contract.');
    }
    if (attestation.project.root !== canonicalRoot) {
      throw new Error('CodeGraph attestation root does not match the workflow worktree.');
    }
    if (attestation.project.head !== (await readGitHead(canonicalRoot))) {
      throw new Error('CodeGraph attestation HEAD does not match the workflow worktree HEAD.');
    }
    if (
      attestation.engine.version !== expectedVersion ||
      attestation.engine.pin !== expectedVersion
    ) {
      throw new Error('CodeGraph attestation version does not match the OpenConfig pin.');
    }
    const expectedIndexRoot = join(canonicalRoot, '.codegraph');
    if (attestation.engine.indexRoot !== expectedIndexRoot) {
      throw new Error(
        'CodeGraph attestation indexRoot is not local to the exact workflow worktree.'
      );
    }
    if (dirname(attestation.engine.indexRoot) !== canonicalRoot) {
      throw new Error('CodeGraph attestation indexRoot escapes the workflow worktree.');
    }
    // CodeGraph may intentionally place a worktree's derived index behind a
    // project-local `.codegraph` symlink on the home volume. The attested path
    // must remain the exact lexical worktree path, while its target must exist.
    await assertDirectoryExists(attestation.engine.indexRoot, 'CodeGraph index root');

    // The runtime closure may have changed while the adapter prepared the index.
    // Bind the MCP exposure to the bytes present at this exact point in time.
    const canonicalRuntime = await verifyGovernedCommand(
      registry.runtime,
      'CodeGraph runtime command'
    );

    return {
      prepared: {
        mode,
        root: canonicalRoot,
        command: canonicalRuntime,
        args: [...registry.runtime.args, '-p', canonicalRoot],
        env: { ...registry.environment },
        version: expectedVersion,
      },
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    if (mode === 'required') throw new Error(`CodeGraph required preflight failed: ${message}`);
    return { fallbackReason: message };
  }
}

export const managedCodegraphTestHelpers = {
  canonicalize,
  sha256Canonical,
  readGitHead,
  bundleFileEntries,
};
