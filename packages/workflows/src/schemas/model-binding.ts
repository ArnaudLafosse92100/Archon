import { z } from '@hono/zod-openapi';
import { effortLevelSchema, rejectRetiredThinking } from './effort';

export const TIER_NAMES = ['small', 'medium', 'large'] as const;
export const tierNameSchema = z.enum(TIER_NAMES);
export type TierName = z.infer<typeof tierNameSchema>;

/**
 * Portable capability names that bundled/global workflows may depend on.
 *
 * These are virtual defaults, not materialized aliases: resolving through the
 * tier at use time keeps sparse per-run tier overrides effective. An explicit
 * configured alias with the same name still wins.
 */
export const PORTABLE_SYSTEM_ALIAS_TIERS = {
  '@implementer': 'medium',
  '@architect': 'large',
  '@reviewer': 'medium',
  '@adjudicator': 'medium',
} as const satisfies Readonly<Record<string, TierName>>;

/** Stable observability vocabulary advertised by `archon version --json`. */
export const ROUTING_TELEMETRY_FIELDS = ['model_ref', 'provider_source'] as const;
export const ROUTING_LIFECYCLE_EVENT_TYPES = [
  'node_started',
  'node_completed',
  'node_failed',
] as const;

export type PortableSystemAlias = keyof typeof PORTABLE_SYSTEM_ALIAS_TIERS;

export function isPortableSystemAlias(value: string): value is PortableSystemAlias {
  return Object.hasOwn(PORTABLE_SYSTEM_ALIAS_TIERS, value);
}

export function portableSystemAliasTier(value: string): TierName | undefined {
  return isPortableSystemAlias(value) ? PORTABLE_SYSTEM_ALIAS_TIERS[value] : undefined;
}

const modelAliasPresetObjectSchema = z.object({
  provider: z.string().min(1),
  model: z.string().min(1),
  effort: effortLevelSchema.optional(),
});
export const modelAliasPresetSchema = z.preprocess(
  rejectRetiredThinking,
  modelAliasPresetObjectSchema
);
const runModelAliasPresetSchema = z.preprocess(
  rejectRetiredThinking,
  modelAliasPresetObjectSchema.extend({ model: z.string().trim().min(1) }).strict()
);

export type ModelAliasPreset = z.infer<typeof modelAliasPresetSchema>;
export type RawAliasEntry = z.infer<typeof modelAliasPresetSchema>;

export const rawAliasesConfigSchema = z.record(z.string(), modelAliasPresetSchema);
export const runAliasesConfigSchema = z.record(
  z.string().refine(name => name.startsWith('@'), 'run alias names must start with @'),
  runModelAliasPresetSchema
);
export const rawTiersConfigSchema = z.partialRecord(tierNameSchema, modelAliasPresetSchema);
export const runTiersConfigSchema = z.partialRecord(tierNameSchema, runModelAliasPresetSchema);

export type RawAliasesConfig = z.infer<typeof rawAliasesConfigSchema>;
export type RawTiersConfig = z.infer<typeof rawTiersConfigSchema>;

export const resolvedRunModelOverridesSchema = z.object({
  tiers: runTiersConfigSchema.optional(),
  aliases: runAliasesConfigSchema.optional(),
});

export type ResolvedRunModelOverrides = z.infer<typeof resolvedRunModelOverridesSchema>;

export const resolvedAiProfileSchema = z.object({
  defaultProvider: z.string(),
  aliases: rawAliasesConfigSchema,
});

export type ResolvedAiProfile = z.infer<typeof resolvedAiProfileSchema>;

export const runModelBindingsMetadataSchema = z.object({
  overrides: resolvedRunModelOverridesSchema,
  effective: resolvedAiProfileSchema,
});

export type RunModelBindingsMetadata = z.infer<typeof runModelBindingsMetadataSchema>;
