import { describe, expect, it } from 'bun:test';
import type { ProviderLaunchAttestationV1 } from '@archon/providers/types';
import {
  buildNodeAuthContextV1,
  computeNodeAuthContextDigest,
  verifyNodeAuthContextDigest,
  type NodeAuthContextWithoutDigest,
} from './node-auth-context';

const identity = {
  nodeId: '11111111-1111-4111-8111-111111111111',
  authoredNodeId: 'planner',
  aiNode: true,
};

const strictClaudeAttestation: ProviderLaunchAttestationV1 = {
  version: 1,
  provider: 'claude',
  nodeId: 'planner',
  model: 'claude-opus-5-5',
  credential: { vendor: 'anthropic', kind: 'subscription', delivery: 'environment' },
  neutralizedAliases: ['ANTHROPIC_API_KEY'],
  deliveredAliases: ['CLAUDE_CODE_OAUTH_TOKEN'],
  managedPathIdentity: 'claude-config',
  envPolicy: 'targeted_empty_overrides',
  filesystemSettingsPolicy: 'disabled',
  executableIdentity: { status: 'deferred_to_provider' },
  billingClaim: 'unverified',
};

describe('node_auth_context_v1', () => {
  it('matches the portable Python canonical-JSON digest vector', () => {
    const vector: NodeAuthContextWithoutDigest = {
      schema_version: 1,
      issuer: 'archon',
      run_id: 'run-é',
      node_id: identity.nodeId,
      authored_node_id: identity.authoredNodeId,
      step_name: 'group.planner',
      context_id: '22222222-2222-4222-8222-222222222222',
      route: { provider: 'pi', model: 'openrouter/z-ai/glm-5.3' },
      billing: { class: 'metered', claim: 'unverified', basis: 'api_route' },
      credential: {
        mode: 'provider_native',
        route_vendor: 'openrouter',
        kind: 'unknown',
        delivery: 'provider_native',
        values_recorded: false,
      },
      executable_identity: { status: 'deferred_to_provider' },
    };
    expect(computeNodeAuthContextDigest(vector)).toBe(
      '67d95756d02d48cb1a364d2f14c6bd1b29ba8cd482428808e404c4dd194e99c5'
    );
  });

  it('records strict subscription provenance without secret values', () => {
    const context = buildNodeAuthContextV1({
      runId: 'run-strict',
      stepName: 'planner',
      identity,
      provider: 'claude',
      model: 'claude-opus-5-5',
      launchAttestation: strictClaudeAttestation,
    });
    expect(context.billing).toEqual({
      class: 'subscription',
      claim: 'unverified',
      basis: 'strict_subscription_policy',
    });
    expect(context.credential).toEqual({
      mode: 'strict_subscription',
      launch_attestation: strictClaudeAttestation,
      values_recorded: false,
    });
    expect(verifyNodeAuthContextDigest(context)).toBe(true);
    expect(JSON.stringify(context)).not.toContain('secret-token');
  });

  it('rejects an attestation whose provider, model, or authored node does not match', () => {
    for (const mismatch of [
      { provider: 'codex' },
      { model: 'different-model' },
      { nodeId: 'different-node' },
    ]) {
      expect(() =>
        buildNodeAuthContextV1({
          runId: 'run-mismatch',
          stepName: 'planner',
          identity,
          provider: 'claude',
          model: 'claude-opus-5-5',
          launchAttestation: {
            ...strictClaudeAttestation,
            ...mismatch,
          } as ProviderLaunchAttestationV1,
        })
      ).toThrow('node_auth_context_attestation_mismatch');
    }
  });

  it('classifies OpenRouter through Pi as metered and leaves other unproven routes unknown', () => {
    const metered = buildNodeAuthContextV1({
      runId: 'run-pi',
      stepName: 'planner',
      identity,
      provider: 'pi',
      model: 'openrouter/z-ai/glm-5.3',
    });
    expect(metered.billing).toEqual({
      class: 'metered',
      claim: 'unverified',
      basis: 'api_route',
    });
    expect(metered.credential).toMatchObject({
      mode: 'provider_native',
      route_vendor: 'openrouter',
      values_recorded: false,
    });

    const unknown = buildNodeAuthContextV1({
      runId: 'run-unknown',
      stepName: 'planner',
      identity,
      provider: 'future-provider',
      model: 'future-model',
    });
    expect(unknown.billing.class).toBe('unknown');
    expect(unknown.credential).toMatchObject({
      mode: 'provider_native',
      kind: 'unknown',
      delivery: 'unknown',
    });
  });

  it('detects any context mutation after the digest was recorded', () => {
    const context = buildNodeAuthContextV1({
      runId: 'run-tamper',
      stepName: 'planner',
      identity,
      provider: 'pi',
      model: 'openrouter/z-ai/glm-5.3',
    });
    context.route.model = 'openrouter/changed';
    expect(verifyNodeAuthContextDigest(context)).toBe(false);
  });
});
