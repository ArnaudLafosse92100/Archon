import { createHash, randomUUID } from 'node:crypto';
import type { ProviderLaunchAttestationV1 } from '@archon/providers/types';

export type NodeBillingClass = 'subscription' | 'metered' | 'unknown';

export interface NodeLifecycleIdentityV1 {
  nodeId: string;
  authoredNodeId: string;
  aiNode: boolean;
}

export interface NodeAuthContextV1 {
  schema_version: 1;
  issuer: 'archon';
  run_id: string;
  node_id: string;
  authored_node_id: string;
  step_name: string;
  context_id: string;
  context_sha256: string;
  route: {
    provider: string;
    model: string | null;
    tier?: string;
    effort?: string;
  };
  billing: {
    class: NodeBillingClass;
    claim: 'unverified';
    basis: 'strict_subscription_policy' | 'api_route' | 'unknown';
  };
  credential:
    | {
        mode: 'strict_subscription';
        launch_attestation: ProviderLaunchAttestationV1;
        values_recorded: false;
      }
    | {
        mode: 'provider_native';
        route_vendor?: string;
        kind: 'api_key' | 'ambient' | 'unknown';
        delivery: 'environment' | 'managed_file' | 'provider_native' | 'unknown';
        values_recorded: false;
      };
  executable_identity: { status: 'deferred_to_provider' };
}

export type NodeAuthContextWithoutDigest = Omit<NodeAuthContextV1, 'context_sha256'>;

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null';
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, item]) => item !== undefined)
    // Every contract key is ASCII. Relational comparison is code-unit ordered
    // and therefore reproduces Python's ordinary string sort for these keys;
    // localeCompare would make the digest depend on host ICU/locale data.
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0));
  return `{${entries
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(',')}}`;
}

export function createNodeLifecycleIdentity(
  authoredNodeId: string,
  aiNode: boolean
): NodeLifecycleIdentityV1 {
  return { nodeId: randomUUID(), authoredNodeId, aiNode };
}

export function lifecycleEventData(identity: NodeLifecycleIdentityV1): Record<string, unknown> {
  return {
    ai_node: identity.aiNode,
    node_id: identity.nodeId,
    authored_node_id: identity.authoredNodeId,
  };
}

function validateStrictAttestation(
  attestation: ProviderLaunchAttestationV1,
  authoredNodeId: string,
  provider: string,
  model: string | undefined
): void {
  if (
    attestation.version !== 1 ||
    attestation.provider !== provider ||
    attestation.nodeId !== authoredNodeId ||
    attestation.model !== model ||
    attestation.credential.kind !== 'subscription' ||
    attestation.billingClaim !== 'unverified' ||
    attestation.executableIdentity.status !== 'deferred_to_provider'
  ) {
    throw new Error('node_auth_context_attestation_mismatch');
  }
}

export function buildNodeAuthContextV1(params: {
  runId: string;
  stepName: string;
  identity: NodeLifecycleIdentityV1;
  provider: string;
  model?: string;
  tier?: string;
  effort?: string;
  launchAttestation?: ProviderLaunchAttestationV1;
}): NodeAuthContextV1 {
  if (!params.identity.aiNode) throw new Error('node_auth_context_non_ai_node');

  const contextId = randomUUID();
  const route = {
    provider: params.provider,
    model: params.model ?? null,
    ...(params.tier !== undefined ? { tier: params.tier } : {}),
    ...(params.effort !== undefined ? { effort: params.effort } : {}),
  };

  let billing: NodeAuthContextWithoutDigest['billing'];
  let credential: NodeAuthContextWithoutDigest['credential'];
  if (params.launchAttestation !== undefined) {
    validateStrictAttestation(
      params.launchAttestation,
      params.identity.authoredNodeId,
      params.provider,
      params.model
    );
    billing = {
      class: 'subscription',
      claim: 'unverified',
      basis: 'strict_subscription_policy',
    };
    credential = {
      mode: 'strict_subscription',
      launch_attestation: params.launchAttestation,
      values_recorded: false,
    };
  } else if (params.provider === 'pi' && params.model?.startsWith('openrouter/')) {
    billing = { class: 'metered', claim: 'unverified', basis: 'api_route' };
    credential = {
      mode: 'provider_native',
      route_vendor: 'openrouter',
      kind: 'unknown',
      delivery: 'provider_native',
      values_recorded: false,
    };
  } else {
    billing = { class: 'unknown', claim: 'unverified', basis: 'unknown' };
    credential = {
      mode: 'provider_native',
      kind: 'unknown',
      delivery: 'unknown',
      values_recorded: false,
    };
  }

  const withoutDigest: NodeAuthContextWithoutDigest = {
    schema_version: 1,
    issuer: 'archon',
    run_id: params.runId,
    node_id: params.identity.nodeId,
    authored_node_id: params.identity.authoredNodeId,
    step_name: params.stepName,
    context_id: contextId,
    route,
    billing,
    credential,
    executable_identity: { status: 'deferred_to_provider' },
  };
  return {
    ...withoutDigest,
    context_sha256: computeNodeAuthContextDigest(withoutDigest),
  };
}

export function verifyNodeAuthContextDigest(context: NodeAuthContextV1): boolean {
  const withoutDigest = { ...context };
  delete (withoutDigest as Partial<NodeAuthContextV1>).context_sha256;
  return computeNodeAuthContextDigest(withoutDigest) === context.context_sha256;
}

/**
 * Portable digest input: UTF-8 JSON, no insignificant whitespace, object keys sorted by
 * Unicode/code-point order (all schema keys are ASCII), array order preserved, and the
 * `context_sha256` field excluded. Python equivalent:
 * `sha256(json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()`.
 */
export function computeNodeAuthContextDigest(context: NodeAuthContextWithoutDigest): string {
  return createHash('sha256').update(canonicalJson(context), 'utf8').digest('hex');
}
