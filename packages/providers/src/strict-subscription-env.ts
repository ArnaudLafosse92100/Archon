import type { ProviderLaunchAttestationV1 } from './types';

const SAFE_PARENT_ENV_KEYS = [
  'PATH',
  'TMPDIR',
  'LANG',
  'LC_ALL',
  'TERM',
  'TZ',
  'SHELL',
  'USER',
  'LOGNAME',
  'SystemRoot',
  'WINDIR',
  'PATHEXT',
] as const;

const SENSITIVE_NAME =
  /^(?:ANTHROPIC|CLAUDE|OPENAI|CODEX|AWS|GOOGLE|CLOUDSDK|AZURE)_|(?:KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|IDENTITY|FEDERATION|_BASE_URL|_ENDPOINT|_PROXY(?:_|$)|_FILE(?:_|$)|CERTIFICATE|_CA(?:_|$))/i;

function definedParentEnv(): Record<string, string> {
  const result: Record<string, string> = {};
  for (const key of SAFE_PARENT_ENV_KEYS) {
    const value = process.env[key];
    if (value !== undefined) result[key] = value;
  }
  return result;
}

/** Build a strict provider child env from scratch; never extend process.env. */
export function buildStrictSubscriptionEnv(
  attestation: ProviderLaunchAttestationV1,
  requestEnv: Record<string, string> | undefined
): Record<string, string> {
  const env = { ...definedParentEnv() };
  for (const [key, value] of Object.entries(requestEnv ?? {})) {
    // Neutralized aliases are represented by absence in the child process.
    // Keeping an empty key would still affect CLIs that test key presence.
    if (value !== '') env[key] = value;
  }
  const delivered = new Set(attestation.deliveredAliases);
  for (const [key, value] of Object.entries(env)) {
    if (value && SENSITIVE_NAME.test(key) && !delivered.has(key)) {
      throw new Error(`strict_subscription_env_rejected:${key}`);
    }
  }
  const privateHome = attestation.provider === 'codex' ? env.CODEX_HOME : env.CLAUDE_CONFIG_DIR;
  if (!privateHome) throw new Error('strict_subscription_env_missing_private_home');
  env.HOME = privateHome;
  return env;
}
