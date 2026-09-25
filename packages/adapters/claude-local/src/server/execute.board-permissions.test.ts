import { BOARD_ASK_RULES } from "./permissions.js";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import type { RunProcessResult } from "@paperclipai/adapter-utils/server-utils";

const { runChildProcess, ensureCommandResolvable, resolveCommandForLogs } = vi.hoisted(() => ({
  runChildProcess: vi.fn(async (_runId: string, _command: string, args: string[]): Promise<RunProcessResult> => ({
    exitCode: 0,
    signal: null,
    timedOut: false,
    stdout: args.includes("--version")
      ? "2.1.282 (Claude Code)\n"
      : [
          JSON.stringify({ type: "system", subtype: "init", session_id: "s-1", model: "claude-opus-5-5" }),
          JSON.stringify({ type: "result", session_id: "s-1", result: "ok", usage: { input_tokens: 1, cache_read_input_tokens: 0, output_tokens: 1 } }),
        ].join("\n"),
    stderr: "",
    pid: 123,
    startedAt: new Date().toISOString(),
  })),
  ensureCommandResolvable: vi.fn(async () => undefined),
  resolveCommandForLogs: vi.fn(async () => "claude"),
}));

vi.mock("@paperclipai/adapter-utils/server-utils", async () => {
  const actual = await vi.importActual<typeof import("@paperclipai/adapter-utils/server-utils")>(
    "@paperclipai/adapter-utils/server-utils",
  );
  return { ...actual, ensureCommandResolvable, resolveCommandForLogs, runChildProcess };
});

import { execute } from "./execute.js";
import { resetClaudeCliCapabilitiesCacheForTests } from "./cli-capabilities.js";

const BRIDGE = {
  name: "paperclip_permissions",
  url: "http://127.0.0.1:3100/api/mcp/claude-permissions",
  token: "run-token",
  connectionId: "paperclip-permission-prompts",
};
const PROJECTS = {
  name: "Paperclip projects",
  url: "http://127.0.0.1:3100/api/mcp/project-tools",
  token: "run-token",
  connectionId: "paperclip-project-tools",
};
const CONNECTIONS = {
  name: "Paperclip connections",
  url: "http://127.0.0.1:3100/api/mcp/gateway",
  token: "run-token",
  connectionId: "paperclip-runtime-tools",
};

type Call = [string, string, string[], { env: Record<string, string> }];

describe("claude_local board permission prompts", () => {
  const cleanupDirs: string[] = [];

  afterEach(async () => {
    vi.clearAllMocks();
    vi.unstubAllEnvs();
    resetClaudeCliCapabilitiesCacheForTests();
    while (cleanupDirs.length > 0) {
      await rm(cleanupDirs.pop()!, { recursive: true, force: true }).catch(() => undefined);
    }
  });

  async function run(config: Record<string, unknown>, servers: Array<typeof BRIDGE>) {
    const root = await mkdtemp(path.join(os.tmpdir(), "paperclip-claude-board-"));
    cleanupDirs.push(root);
    const workspace = path.join(root, "workspace");
    await mkdir(workspace, { recursive: true });
    vi.stubEnv("PAPERCLIP_HOME", path.join(root, "home"));
    const logs: string[] = [];
    await execute({
      runId: "run-board-1",
      agent: { id: "agent-1", companyId: "company-1", name: "Claude", adapterType: "claude_local", adapterConfig: {} },
      runtime: { sessionId: null, sessionParams: null, sessionDisplayId: null, taskKey: null },
      config: { engine: "cli", command: "claude", ...config },
      context: { paperclipWorkspace: { cwd: workspace, source: "project_primary" } },
      runtimeMcp: { getServers: () => servers },
      onLog: async (_stream: string, chunk: string) => { logs.push(chunk); },
    } as never);
    const call = runChildProcess.mock.calls.find(
      (c) => !(c[2] as string[]).includes("--version"),
    ) as unknown as Call;
    return { args: call[2], env: call[3].env, logs: logs.join(""), root };
  }

  const valueAfter = (args: string[], flag: string) => args[args.indexOf(flag) + 1];

  it("asks the board instead of bypassing, even when skip-permissions is configured", async () => {
    const { args, env } = await run(
      { permissionPrompts: "board", dangerouslySkipPermissions: true, approvalTimeoutSec: 900 },
      [PROJECTS, CONNECTIONS, BRIDGE],
    );
    expect(args).not.toContain("--dangerously-skip-permissions");
    expect(valueAfter(args, "--permission-mode")).toBe("default");
    expect(valueAfter(args, "--permission-prompts")).toBe("host");
    expect(valueAfter(args, "--permission-prompt-tool")).toBe("mcp__paperclip_permissions__approve");
    expect(valueAfter(args, "--setting-sources")).toBe("user,project");
    const settings = JSON.parse(valueAfter(args, "--settings")!);
    expect(settings.permissions.ask).toEqual([...BOARD_ASK_RULES]);
    // No blanket Bash rule (ls/find/grep run freely), but network, remote-access and
    // env-printing commands always ask, as do writes and reads outside the workspace.
    expect(settings.permissions.ask).not.toContain("Bash");
    expect(settings.permissions.ask).toEqual(expect.arrayContaining([
      "Bash(curl:*)", "Bash(ssh:*)", "Bash(unicorn:*)", "Bash(env:*)", "Bash(printenv:*)",
      "Write", "Edit", "Read(//**)",
    ]));
    // Nothing is pre-allowed: task/project creation is delegation and needs the board too.
    expect(settings.permissions.allow).toEqual([]);
    expect(env.MCP_TOOL_TIMEOUT).toBe(String((900 + 120) * 1000));
  });

  it("adds the agent's instructions folder as a working directory in board mode only", async () => {
    const dir = await mkdtemp(path.join(os.tmpdir(), "paperclip-claude-instructions-"));
    cleanupDirs.push(dir);
    const instructionsFilePath = path.join(dir, "AGENTS.md");
    await writeFile(instructionsFilePath, "# Agent\n");
    const addDirs = (args: string[]) => args.flatMap((arg, i) => (arg === "--add-dir" ? [args[i + 1]] : []));

    const board = await run({ permissionPrompts: "board", instructionsFilePath }, [BRIDGE]);
    expect(addDirs(board.args)).toContain(dir);

    runChildProcess.mockClear();
    const off = await run({ instructionsFilePath }, [BRIDGE]);
    expect(addDirs(off.args)).not.toContain(dir);
  });

  it("writes rule-safe MCP server names so the rules name real tools", async () => {
    const { root } = await run({ permissionPrompts: "board" }, [PROJECTS, CONNECTIONS, BRIDGE]);
    const configPath = path.join(
      root, "home", "instances", "default", "companies", "company-1", "agents", "agent-1",
      "claude-runtime", "runs", "run-board-1", "mcp", "mcp-config.json",
    );
    const written = JSON.parse(await readFile(configPath, "utf8"));
    expect(Object.keys(written.mcpServers)).toEqual([
      "Paperclip_projects", "Paperclip_connections", "paperclip_permissions",
    ]);
  });

  it("strips user extra args that would widen permissions", async () => {
    const { args } = await run(
      {
        permissionPrompts: "board",
        extraArgs: [
          "--dangerously-skip-permissions", "--permission-mode", "bypassPermissions",
          "--allowedTools", "Bash", "Write", "--settings={}", "--verbose",
        ],
      },
      [BRIDGE],
    );
    expect(args).not.toContain("--dangerously-skip-permissions");
    expect(args).not.toContain("bypassPermissions");
    expect(args).not.toContain("--allowedTools");
    expect(args).not.toContain("--settings={}");
    expect(args.filter((a) => a === "--permission-mode")).toHaveLength(1);
  });

  it("fails closed when the run has no permission bridge", async () => {
    const { args, logs } = await run({ permissionPrompts: "board" }, [PROJECTS]);
    expect(args).not.toContain("--dangerously-skip-permissions");
    expect(args).not.toContain("--permission-prompt-tool");
    expect(valueAfter(args, "--permission-prompts")).toBe("none");
    expect(logs).toContain("no Paperclip permission bridge");
  });

  it("keeps today's behaviour when prompts are off", async () => {
    const { args, env } = await run({}, [PROJECTS]);
    expect(args).toContain("--dangerously-skip-permissions");
    expect(args).not.toContain("--permission-prompt-tool");
    expect(env.MCP_TOOL_TIMEOUT).toBeUndefined();
  });
});
