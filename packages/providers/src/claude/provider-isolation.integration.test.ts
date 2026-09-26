import { afterEach, describe, expect, test } from 'bun:test';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ClaudeProvider } from './provider';

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
    const oauthToken = 'offline-oauth-sentinel';
    const projectApiKey = 'project-api-key-must-not-win';
    mkdirSync(settingsDir, { recursive: true });
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
fs.appendFileSync(process.env.ARCHON_CAPTURE_PATH, JSON.stringify({
  args: process.argv.slice(2),
  apiKeySource: effectiveEnv.ANTHROPIC_API_KEY
    ? 'ANTHROPIC_API_KEY'
    : effectiveEnv.CLAUDE_CODE_OAUTH_TOKEN
      ? 'CLAUDE_CODE_OAUTH_TOKEN'
      : null,
  anthropicApiKey: effectiveEnv.ANTHROPIC_API_KEY ?? null,
  oauthToken: effectiveEnv.CLAUDE_CODE_OAUTH_TOKEN ?? null,
}) + '\\n');
process.exit(1);
`,
      'utf8'
    );
    chmodSync(fixturePath, 0o755);
    process.env.CLAUDE_BIN_PATH = fixturePath;
    process.env.IS_SANDBOX = '1';

    try {
      const provider = new ClaudeProvider({ retryBaseDelayMs: 1 });
      const consume = async (): Promise<void> => {
        for await (const _ of provider.sendQuery('offline fixture', projectDir, undefined, {
          nodeConfig: { settingSources: ['project'] },
          assistantConfig: { settingSources: ['project', 'user'] },
          env: {
            ARCHON_CAPTURE_PATH: capturePath,
            ANTHROPIC_API_KEY: '',
            CLAUDE_API_KEY: '',
            CLAUDE_CODE_OAUTH_TOKEN: oauthToken,
            ANTHROPIC_OAUTH_TOKEN: oauthToken,
            CLAUDE_CONFIG_DIR: join(root, 'managed-claude-config'),
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
            neutralizedAliases: ['ANTHROPIC_API_KEY', 'CLAUDE_API_KEY'],
            deliveredAliases: [
              'CLAUDE_CODE_OAUTH_TOKEN',
              'ANTHROPIC_OAUTH_TOKEN',
              'CLAUDE_CONFIG_DIR',
            ],
            managedPathIdentity: 'claude-config',
            envPolicy: 'targeted_empty_overrides',
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
        // Strict launches use targeted empty overrides rather than deleting the
        // inherited keys from the subprocess environment.
        expect(capture.anthropicApiKey).toBe('');
        expect(capture.oauthToken).toBe(oauthToken);
        expect(JSON.stringify(capture)).not.toContain(projectApiKey);
      }
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  }, 10_000);
});
