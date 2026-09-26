import { z } from '@hono/zod-openapi';

export const codegraphManagedModeSchema = z.enum(['off', 'optional', 'required']);
export type CodegraphManagedMode = z.infer<typeof codegraphManagedModeSchema>;

const absolutePathSchema = z
  .string()
  .trim()
  .min(1)
  .refine(value => value.startsWith('/'), {
    message: 'must be an absolute path',
  });

const bundleIncludeSchema = z
  .string()
  .min(1)
  .refine(value => !value.startsWith('/') && !value.includes('\\') && !value.includes('\0'), {
    message: 'must be a POSIX-relative path',
  })
  .refine(
    value =>
      value === value.split('/').filter(Boolean).join('/') &&
      value !== '.' &&
      value !== '..' &&
      !value.startsWith('../') &&
      !value.split('/').includes('..'),
    { message: 'must not escape its bundle root' }
  );

const codegraphBundleSchema = z
  .object({
    algorithm: z.literal('sha256-tree-v1'),
    root: absolutePathSchema,
    includes: z
      .array(bundleIncludeSchema)
      .min(1)
      .refine(
        values =>
          new Set(values).size === values.length &&
          values.every((value, index) => index === 0 || values[index - 1] < value),
        { message: 'must be unique and sorted' }
      ),
    sha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export const codegraphPrivacyEnvironmentSchema = z
  .object({
    CODEGRAPH_TELEMETRY: z.literal('0'),
    CODEGRAPH_NO_UPDATE_CHECK: z.literal('1'),
    CODEGRAPH_MCP_TOOLS: z.literal('explore'),
    DO_NOT_TRACK: z.literal('1'),
  })
  .strict();

/** Operator-owned global registry entry. Run/workflow input can select only its mode. */
export const codegraphManagedResourceSchema = z
  .object({
    schemaVersion: z.literal(1),
    owner: absolutePathSchema,
    protocol: z.literal('codegraph_worktree_adapter_v1'),
    adapter: z
      .object({
        command: absolutePathSchema,
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
        bundle: codegraphBundleSchema,
      })
      .strict(),
    pin: z
      .object({
        manifest: absolutePathSchema,
        field: z.literal('codegraph.pin'),
      })
      .strict(),
    runtime: z
      .object({
        command: absolutePathSchema,
        sha256: z.string().regex(/^[a-f0-9]{64}$/),
        bundle: codegraphBundleSchema,
        args: z.tuple([z.literal('serve'), z.literal('--mcp')]),
      })
      .strict(),
    environment: codegraphPrivacyEnvironmentSchema,
    contractSha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export type CodegraphManagedResourceV1 = z.infer<typeof codegraphManagedResourceSchema>;

export const managedResourcesGlobalSchema = z
  .object({ codegraph_managed_v1: codegraphManagedResourceSchema.optional() })
  .passthrough();

export type ManagedResourcesGlobal = z.infer<typeof managedResourcesGlobalSchema>;

export const managedResourcesRunSchema = z
  .object({
    codegraph: z.object({ mode: codegraphManagedModeSchema }).strict().optional(),
  })
  .strict();

export type ManagedResourcesRun = z.infer<typeof managedResourcesRunSchema>;
