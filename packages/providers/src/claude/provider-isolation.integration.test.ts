import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { removeTempTree } from '@archon/paths/test-utils';
import { ClaudeProvider } from './provider';
import { STRICT_CLAUDE_ROUTING_AUTH_ENV_KEYS } from '../types';

const originalClaudeBinPath = process.env.CLAUDE_BIN_PATH;
const originalSandbox = process.env.IS_SANDBOX;

afterEach(() => {
  if (originalClaudeBinPath === undefined) delete process.env.CLAUDE_BIN_PATH;
  else process.env.CLAUDE_BIN_PATH = originalClaudeBinPath;
  if (originalSandbox === undefined) delete process.env.IS_SANDBOX;
  else process.env.IS_SANDBOX = originalSandbox;
});

describe('strict Claude provider launch isolation', () => {
  test('actual SDK subprocess invocation disables project settings before auth selection', async () => {
    const root = mkdtempSync(join(tmpdir(), 'archon-claude-strict-'));
    const projectDir = join(root, 'project');
    const settingsDir = join(projectDir, '.claude');
    const capturePath = join(root, 'capture.jsonl');
    const fixturePath = join(root, 'claude-fixture');
    const managedClaudeConfig = join(root, 'managed-claude-config');
    const oauthToken = 'offline-oauth-sentinel';
    const projectApiKey = 'project-api-key-must-not-win';
    const ambientRoutes: Record<string, string> = {
      ANTHROPIC_AUTH_TOKEN: 'ambient-auth-token-must-not-win',
      CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR: '77',
      ANTHROPIC_BASE_URL: 'http://127.0.0.1:9/exfiltration-sentinel',
      CLAUDE_CODE_USE_BEDROCK: '1',
      CLAUDE_CODE_USE_VERTEX: '1',
      CLAUDE_CODE_USE_FOUNDRY: '1',
      OPENAI_API_KEY: 'ambient-openai-must-not-cross',
      CODEX_API_KEY: 'ambient-codex-must-not-cross',
      CODEX_HOME: '/ambient/codex-home-must-not-cross',
      OPENROUTER_API_KEY: 'ambient-openrouter-must-not-cross',
    };
    const originalAmbientRoutes = Object.fromEntries(
      Object.keys(ambientRoutes).map(key => [key, process.env[key]])
    );
    mkdirSync(settingsDir, { recursive: true });
    mkdirSync(managedClaudeConfig, { recursive: true });
    writeFileSync(
      join(settingsDir, 'settings.json'),
      JSON.stringify({ env: { ANTHROPIC_API_KEY: projectApiKey } }),
      'utf8'
    );
    writeFileSync(
      fixturePath,
      `#!/usr/bin/env node
const fs = require('node:fs');
const path = require('node:path');
const sourceArg = process.argv.slice(2).find(arg => arg.startsWith('--setting-sources='));
const sources = sourceArg === undefined
  ? ['project', 'user', 'local']
  : sourceArg.slice('--setting-sources='.length).split(',').filter(Boolean);
const effectiveEnv = { ...process.env };
if (sources.includes('project')) {
  const settings = JSON.parse(fs.readFileSync(path.join(process.cwd(), '.claude', 'settings.json'), 'utf8'));
  Object.assign(effectiveEnv, settings.env ?? {});
}
fs.appendFileSync(${JSON.stringify(capturePath)}, JSON.stringify({
  args: process.argv.slice(2),
  apiKeySource: effectiveEnv.ANTHROPIC_API_KEY
    ? 'ANTHROPIC_API_KEY'
    : effectiveEnv.ANTHROPIC_AUTH_TOKEN
      ? 'ANTHROPIC_AUTH_TOKEN'
    : effectiveEnv.CLAUDE_CODE_OAUTH_TOKEN
      ? 'CLAUDE_CODE_OAUTH_TOKEN'
      : null,
  anthropicApiKey: effectiveEnv.ANTHROPIC_API_KEY ?? null,
  anthropicAuthToken: effectiveEnv.ANTHROPIC_AUTH_TOKEN ?? null,
  gatewayTokenFileDescriptor: effectiveEnv.CLAUDE_CODE_GATEWAY_TOKEN_FILE_DESCRIPTOR ?? null,
  anthropicBaseUrl: effectiveEnv.ANTHROPIC_BASE_URL ?? null,
  bedrock: effectiveEnv.CLAUDE_CODE_USE_BEDROCK ?? null,
  vertex: effectiveEnv.CLAUDE_CODE_USE_VERTEX ?? null,
  foundry: effectiveEnv.CLAUDE_CODE_USE_FOUNDRY ?? null,
  openaiApiKey: effectiveEnv.OPENAI_API_KEY ?? null,
  codexApiKey: effectiveEnv.CODEX_API_KEY ?? null,
  codexHome: effectiveEnv.CODEX_HOME ?? null,
  openrouterApiKey: effectiveEnv.OPENROUTER_API_KEY ?? null,
  oauthToken: effectiveEnv.CLAUDE_CODE_OAUTH_TOKEN ?? null,
}) + '\\n');
process.exit(1);
`,
      'utf8'
    );
    chmodSync(fixturePath, 0o755);
    process.env.CLAUDE_BIN_PATH = fixturePath;
    process.env.IS_SANDBOX = '1';
    Object.assign(process.env, ambientRoutes);

    try {
      const provider = new ClaudeProvider({ retryBaseDelayMs: 1 });
      const consume = async (): Promise<void> => {
        for await (const _ of provider.sendQuery('offline fixture', projectDir, undefined, {
          nodeConfig: { settingSources: ['project'] },
          assistantConfig: { settingSources: ['project', 'user'] },
          env: {
            ...Object.fromEntries(STRICT_CLAUDE_ROUTING_AUTH_ENV_KEYS.map(key => [key, ''])),
            OPENAI_API_KEY: '',
            CODEX_API_KEY: '',
            CODEX_HOME: '',
            OPENROUTER_API_KEY: '',
            CLAUDE_CODE_OAUTH_TOKEN: oauthToken,
            ANTHROPIC_OAUTH_TOKEN: oauthToken,
            CLAUDE_CONFIG_DIR: managedClaudeConfig,
          },
          providerLaunchAttestation: {
            version: 1,
            provider: 'claude',
            nodeId: 'strict-offline-fixture',
            credential: {
              vendor: 'anthropic',
              kind: 'subscription',
              delivery: 'environment',
            },
            neutralizedAliases: STRICT_CLAUDE_ROUTING_AUTH_ENV_KEYS,
            deliveredAliases: [
              'CLAUDE_CODE_OAUTH_TOKEN',
              'ANTHROPIC_OAUTH_TOKEN',
              'CLAUDE_CONFIG_DIR',
            ],
            managedPathIdentity: 'claude-config',
            envPolicy: 'strict_child_allowlist_v1',
            filesystemSettingsPolicy: 'disabled',
            executableIdentity: { status: 'deferred_to_provider' },
            billingClaim: 'unverified',
          },
        })) {
          // The fixture exits before yielding a provider response.
        }
      };
      await expect(consume()).rejects.toThrow();

      const captures = readFileSync(capturePath, 'utf8')
        .trim()
        .split('\n')
        .map(line => JSON.parse(line) as Record<string, unknown>);
      expect(captures.length).toBeGreaterThan(0);
      for (const capture of captures) {
        expect(capture.args).toContain('--setting-sources=');
        expect(capture.apiKeySource).toBe('CLAUDE_CODE_OAUTH_TOKEN');
        // Strict launches remove neutralized aliases entirely. Empty values
        // are not retained because some CLIs branch on key presence.
        expect(capture.anthropicApiKey).toBeNull();
        expect(capture.gatewayTokenFileDescriptor).toBeNull();
        expect(capture.anthropicAuthToken).toBeNull();
        expect(capture.anthropicBaseUrl).toBeNull();
        expect(capture.bedrock).toBeNull();
        expect(capture.vertex).toBeNull();
        expect(capture.foundry).toBeNull();
        expect(capture.openaiApiKey).toBeNull();
        expect(capture.codexApiKey).toBeNull();
        expect(capture.codexHome).toBeNull();
        expect(capture.openrouterApiKey).toBeNull();
        expect(capture.oauthToken).toBe(oauthToken);
        expect(JSON.stringify(capture)).not.toContain(projectApiKey);
      }
    } finally {
      for (const [key, value] of Object.entries(originalAmbientRoutes)) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
      await removeTempTree(root);
    }
  }, 10_000);
});
