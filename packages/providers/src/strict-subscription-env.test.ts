import { afterEach, describe, expect, test } from 'bun:test';

import type { ProviderLaunchAttestationV1 } from './types';
import { buildStrictSubscriptionEnv } from './strict-subscription-env';

const savedBaseUrl = process.env.OPENAI_BASE_URL;
afterEach(() => {
  if (savedBaseUrl === undefined) delete process.env.OPENAI_BASE_URL;
  else process.env.OPENAI_BASE_URL = savedBaseUrl;
});

function codexAttestation(): ProviderLaunchAttestationV1 {
  return {
    version: 1,
    provider: 'codex',
    nodeId: 'implement',
    model: 'gpt-5.6-sol',
    credential: { vendor: 'openai', kind: 'subscription', delivery: 'managed_file' },
    neutralizedAliases: ['OPENAI_API_KEY', 'CODEX_API_KEY', 'OPENAI_BASE_URL'],
    deliveredAliases: ['CODEX_HOME'],
    managedPathIdentity: 'codex-home/auth.json',
    envPolicy: 'strict_child_allowlist_v1',
    executableIdentity: { status: 'deferred_to_provider' },
    billingClaim: 'unverified',
  };
}

describe('strict subscription subprocess environment', () => {
  test('does not inherit an ambient provider endpoint and uses the private home', () => {
    process.env.OPENAI_BASE_URL = 'https://ambient.invalid';
    const env = buildStrictSubscriptionEnv(codexAttestation(), {
      CODEX_HOME: '/private/codex',
      OPENAI_BASE_URL: '',
      PROJECT_FLAG: 'kept',
    });
    expect(env.OPENAI_BASE_URL).toBeUndefined();
    expect(env.HOME).toBe('/private/codex');
    expect(env.PROJECT_FLAG).toBe('kept');
  });

  test('rejects an unclassified nonempty credential-bearing project variable', () => {
    expect(() =>
      buildStrictSubscriptionEnv(codexAttestation(), {
        CODEX_HOME: '/private/codex',
        SURPRISE_ACCESS_TOKEN: 'must-not-cross',
      })
    ).toThrow('strict_subscription_env_rejected:SURPRISE_ACCESS_TOKEN');
  });

  test('rejects provider-prefixed routing variables even without a generic sensitive suffix', () => {
    expect(() =>
      buildStrictSubscriptionEnv(codexAttestation(), {
        CODEX_HOME: '/private/codex',
        CODEX_URL: 'https://reroute.invalid',
      })
    ).toThrow('strict_subscription_env_rejected:CODEX_URL');
  });
});
