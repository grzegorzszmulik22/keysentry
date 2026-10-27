import { describe, expect, test } from 'vitest';
import { AgentRefusalError, assertHumanForMutation, detectAgentEnvironment } from '../../src/safety/index.js';

describe('agent environment detection', () => {
  test.each([
    ['CLAUDE_CODE_CHILD_SESSION', '1', 'Claude Code'],
    ['AI_AGENT', 'claude-code_2.1.3_agent', 'claude-code'],
    ['CODEX_SANDBOX', 'seatbelt', 'Codex'],
    ['CODEX_SANDBOX_NETWORK_DISABLED', '1', 'Codex'],
    ['CODEX_THREAD_ID', 'thread-private-value', 'Codex'],
    ['CODEX_CI', '1', 'Codex'],
    ['GEMINI_CLI', '1', 'Gemini CLI'],
    ['QWEN_CODE', '1', 'Qwen Code'],
    ['CURSOR_AGENT', 'active-session-private-value', 'Cursor'],
    ['COPILOT_AGENT', '1', 'GitHub Copilot'],
    ['COPILOT_CLI', '1', 'GitHub Copilot CLI'],
    ['COPILOT_AGENT_SESSION_ID', 'copilot-private-value', 'GitHub Copilot CLI'],
    ['CLINE_ACTIVE', 'true', 'Cline'],
    ['OPENCODE', '1', 'opencode'],
    ['GOOSE_TERMINAL', '1', 'Goose'],
    ['AGENT_SESSION_ID', 'goose-private-value', 'Goose'],
    ['AGENT', '1', 'opencode'],
    ['AGENT', 'goose', 'goose'],
    ['AGENT', 'amp', 'amp'],
    ['OR_APP_NAME', 'Aider', 'Aider'],
  ])('detects %s=%s using only the marker name', (marker, value, agent) => {
    expect(detectAgentEnvironment({ [marker]: value })).toEqual({ agent, marker });
  });

  test('nothing in a clean environment is detected', () => {
    expect(detectAgentEnvironment({})).toBeNull();
  });

  test.each([
    { CLAUDECODE: '1' }, { CLAUDE_CODE_SESSION_ID: 'session' }, { TERM_PROGRAM: 'kiro' },
    { CURSOR_TRACE_ID: 'trace' }, { REPL_ID: 'repl' }, { CODEX_SESSION_ID: 'session' },
    { CODEX_VERSION: '1.0' }, { AI_AGENT: '' }, { AGENT: 'human' },
    { CLAUDE_CODE_CHILD_SESSION: '0' }, { CODEX_SANDBOX_NETWORK_DISABLED: '0' },
    { CODEX_CI: 'true' }, { GEMINI_CLI: 'true' }, { QWEN_CODE: 'true' },
    { COPILOT_AGENT: 'true' }, { COPILOT_CLI: 'true' }, { CLINE_ACTIVE: '1' },
    { OPENCODE: 'true' }, { GOOSE_TERMINAL: 'true' }, { OR_APP_NAME: 'Another app' },
  ])('does not confuse human IDE or inactive markers with agents: %j', env => {
    expect(detectAgentEnvironment(env)).toBeNull();
  });

  test('uses a fixed documented first-match order', () => {
    expect(detectAgentEnvironment({ CLAUDE_CODE_CHILD_SESSION: '1', AI_AGENT: 'other', CODEX_CI: '1' }))
      .toEqual({ agent: 'Claude Code', marker: 'CLAUDE_CODE_CHILD_SESSION' });
    expect(detectAgentEnvironment({ CODEX_CI: '1', AI_AGENT: 'opencode', CURSOR_AGENT: '1' }))
      .toEqual({ agent: 'opencode', marker: 'AI_AGENT' });
    expect(detectAgentEnvironment({ AGENT: 'goose', OR_APP_NAME: 'Aider', CODEX_THREAD_ID: 'thread' }))
      .toEqual({ agent: 'Codex', marker: 'CODEX_THREAD_ID' });
  });
});

describe('human mutation gate', () => {
  const human = { env: {}, stdinIsTTY: true, stdoutIsTTY: true, action: 'rotate keys' };

  test('allows an interactive human', () => {
    expect(() => assertHumanForMutation(human)).not.toThrow();
  });

  test('refuses agents even on a TTY with the required message and code', () => {
    try {
      assertHumanForMutation({ ...human, env: { CODEX_THREAD_ID: 'private-thread' } });
      expect.fail('Agent mutation was allowed');
    } catch (error) {
      expect(error).toBeInstanceOf(AgentRefusalError);
      expect(error).toMatchObject({ code: 'AGENT_REFUSED', message: "keysentry won't rotate keys when an AI coding agent runs it (detected: Codex). Your agent can show you the command; run it yourself in a normal terminal." });
      expect(String(error)).not.toContain('private-thread');
    }
  });

  test.each([[false, true], [true, false], [false, false]])('refuses non-TTY stdin=%s stdout=%s', (stdinIsTTY, stdoutIsTTY) => {
    expect(() => assertHumanForMutation({ ...human, stdinIsTTY, stdoutIsTTY }))
      .toThrow('rotate keys needs you at an interactive terminal.');
  });

  test('environment overrides cannot bypass the agent refusal', () => {
    expect(() => assertHumanForMutation({ ...human, env: { CODEX_CI: '1', KEYSENTRY_ALLOW_AGENT: '1', KEYSENTRY_NO_SANDBOX: '1', KEYSENTRY_YES: '1' } }))
      .toThrow(AgentRefusalError);
  });

  test('allows piped stdin only with the explicit stdin option and an interactive stdout', () => {
    expect(() => assertHumanForMutation({ ...human, stdinIsTTY: false, allowPipedStdin: true })).not.toThrow();
    expect(() => assertHumanForMutation({ ...human, stdinIsTTY: false })).toThrow(AgentRefusalError);
    expect(() => assertHumanForMutation({ ...human, stdinIsTTY: false, stdoutIsTTY: false, allowPipedStdin: true }))
      .toThrow(AgentRefusalError);
  });

  test('checks agent markers before allowing an explicitly piped value', () => {
    expect(() => assertHumanForMutation({ ...human, env: { CODEX_CI: '1' }, stdinIsTTY: false, allowPipedStdin: true }))
      .toThrow(/detected: Codex/);
  });
});
