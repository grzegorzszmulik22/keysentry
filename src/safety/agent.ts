export interface AgentEnvironment {
  agent: string;
  marker: string;
}

/**
 * First match wins in this order: Claude child, AI_AGENT convention, Codex,
 * Gemini, Qwen, Cursor, Copilot, Cline, opencode, Goose, AGENT convention, Aider.
 * IDE-wide markers are deliberately excluded: they also identify human terminals.
 */
export function detectAgentEnvironment(env: NodeJS.ProcessEnv): AgentEnvironment | null {
  // https://code.claude.com/docs/en/env-vars
  if (env.CLAUDE_CODE_CHILD_SESSION === '1') return { agent: 'Claude Code', marker: 'CLAUDE_CODE_CHILD_SESSION' };
  // https://github.com/cli/cli/blob/561d9f9/internal/agents/detect.go
  if (env.AI_AGENT) return { agent: env.AI_AGENT.split('_')[0]!, marker: 'AI_AGENT' };
  // https://github.com/openai/codex/blob/ff2346f/codex-rs/core/src/spawn.rs
  if (env.CODEX_SANDBOX) return { agent: 'Codex', marker: 'CODEX_SANDBOX' };
  // https://github.com/openai/codex/blob/ff2346f/codex-rs/core/src/exec.rs
  if (env.CODEX_SANDBOX_NETWORK_DISABLED === '1') return { agent: 'Codex', marker: 'CODEX_SANDBOX_NETWORK_DISABLED' };
  // https://github.com/openai/codex/blob/ff2346f/codex-rs/core/src/exec_env.rs
  if (env.CODEX_THREAD_ID) return { agent: 'Codex', marker: 'CODEX_THREAD_ID' };
  // https://github.com/openai/codex/blob/ff2346f/codex-rs/core/src/unified_exec/process_manager.rs
  if (env.CODEX_CI === '1') return { agent: 'Codex', marker: 'CODEX_CI' };
  // https://github.com/google-gemini/gemini-cli/blob/main/docs/tools/shell.md
  if (env.GEMINI_CLI === '1') return { agent: 'Gemini CLI', marker: 'GEMINI_CLI' };
  // https://github.com/QwenLM/qwen-code/blob/779a4d5/packages/core/src/services/shellExecutionService.ts
  if (env.QWEN_CODE === '1') return { agent: 'Qwen Code', marker: 'QWEN_CODE' };
  // https://cursor.com/docs/agent/tools/terminal
  if (env.CURSOR_AGENT) return { agent: 'Cursor', marker: 'CURSOR_AGENT' };
  // https://github.com/microsoft/vscode/blob/35eba2c/src/vs/workbench/contrib/terminalContrib/chatAgentTools/browser/toolTerminalCreator.ts
  if (env.COPILOT_AGENT === '1') return { agent: 'GitHub Copilot', marker: 'COPILOT_AGENT' };
  // https://github.com/github/copilot-cli/blob/main/changelog.md
  if (env.COPILOT_CLI === '1') return { agent: 'GitHub Copilot CLI', marker: 'COPILOT_CLI' };
  // https://github.com/github/copilot-cli/blob/main/changelog.md
  if (env.COPILOT_AGENT_SESSION_ID) return { agent: 'GitHub Copilot CLI', marker: 'COPILOT_AGENT_SESSION_ID' };
  // https://github.com/cline/cline/blob/8b4d197/apps/vscode/src/hosts/vscode/terminal/VscodeTerminalRegistry.ts
  if (env.CLINE_ACTIVE === 'true') return { agent: 'Cline', marker: 'CLINE_ACTIVE' };
  // https://github.com/anomalyco/opencode/blob/dad29a8/packages/core/src/tool/plugin/shell.ts
  if (env.OPENCODE === '1') return { agent: 'opencode', marker: 'OPENCODE' };
  // https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/environment-variables.md
  if (env.GOOSE_TERMINAL === '1') return { agent: 'Goose', marker: 'GOOSE_TERMINAL' };
  // https://github.com/aaif-goose/goose/blob/3b094d7/crates/goose/src/agents/platform_extensions/developer/shell.rs
  if (env.AGENT_SESSION_ID) return { agent: 'Goose', marker: 'AGENT_SESSION_ID' };
  // https://github.com/anomalyco/opencode/blob/dad29a8/packages/core/src/tool/plugin/shell.ts
  if (env.AGENT === '1') return { agent: 'opencode', marker: 'AGENT' };
  // https://github.com/aaif-goose/goose/blob/main/documentation/docs/guides/environment-variables.md
  if (env.AGENT === 'goose') return { agent: env.AGENT, marker: 'AGENT' };
  // https://github.com/cli/cli/blob/561d9f9/internal/agents/detect.go (accepted by the phase 1 clarification)
  if (env.AGENT === 'amp') return { agent: env.AGENT, marker: 'AGENT' };
  // https://github.com/Aider-AI/aider/blob/7fe7dd7/aider/llm.py
  if (env.OR_APP_NAME === 'Aider') return { agent: 'Aider', marker: 'OR_APP_NAME' };
  return null;
}

export class AgentRefusalError extends Error {
  readonly code = 'AGENT_REFUSED';

  constructor(message: string) {
    super(message);
    this.name = 'AgentRefusalError';
  }
}

export function assertHumanForMutation(opts: {
  env: NodeJS.ProcessEnv;
  stdinIsTTY: boolean;
  stdoutIsTTY: boolean;
  action: string;
}): void {
  const detected = detectAgentEnvironment(opts.env);
  if (detected) {
    throw new AgentRefusalError(`keysentry won't ${opts.action} when an AI coding agent runs it (detected: ${detected.agent}). Your agent can show you the command; run it yourself in a normal terminal.`);
  }
  if (!opts.stdinIsTTY || !opts.stdoutIsTTY) {
    throw new AgentRefusalError(`${opts.action} needs you at an interactive terminal.`);
  }
}
