interface ClaudePermissionInput {
  dangerouslySkipPermissions: boolean;
  targetIsRemote: boolean;
  localProcessUid?: number | null;
}

// Permission defaults are identical for local, remote, and connected tools.
// A tool allowlist is not equivalent to full bypass: it misses MCP tools and
// tools added by later provider releases. Let Claude enforce its own launch
// requirements rather than silently downgrading the requested permission mode.
export function buildClaudeExecutionPermissionArgs(input: ClaudePermissionInput): string[] {
  return input.dangerouslySkipPermissions ? ["--dangerously-skip-permissions"] : [];
}

export const buildClaudeProbePermissionArgs = buildClaudeExecutionPermissionArgs;

/** Claude permits full bypass as root only inside an identified sandbox. */
export function claudeSandboxPermissionEnv(input: {
  dangerouslySkipPermissions: boolean;
  targetIsSandbox: boolean;
}): Record<string, string> {
  return input.dangerouslySkipPermissions && input.targetIsSandbox ? { IS_SANDBOX: "1" } : {};
}

// ---------------------------------------------------------------------------
// Board permission prompts. Instead of bypassing permissions, Claude asks a
// Paperclip-served MCP tool about every tool use its rules do not already
// allow; the server turns each call into an approve/deny card for the board and
// holds the call open until someone decides.

export type ClaudePermissionPrompts = "off" | "board";

/** MCP server name and connection id the server uses for the permission bridge. */
export const PAPERCLIP_PERMISSION_MCP_SERVER = "paperclip_permissions";
export const PAPERCLIP_PERMISSION_CONNECTION_ID = "paperclip-permission-prompts";
export const PAPERCLIP_PERMISSION_TOOL = "approve";

export const DEFAULT_APPROVAL_TIMEOUT_SEC = 1800;
const MIN_APPROVAL_TIMEOUT_SEC = 60;
const MAX_APPROVAL_TIMEOUT_SEC = 10_800;

export function parseClaudePermissionPrompts(value: unknown): ClaudePermissionPrompts {
  return value === "board" ? "board" : "off";
}

export function parseClaudeApprovalTimeoutSec(value: unknown): number {
  const n = typeof value === "number" ? value : typeof value === "string" ? Number(value) : NaN;
  if (!Number.isFinite(n)) return DEFAULT_APPROVAL_TIMEOUT_SEC;
  return Math.min(MAX_APPROVAL_TIMEOUT_SEC, Math.max(MIN_APPROVAL_TIMEOUT_SEC, Math.round(n)));
}

/** Claude waits this long for any MCP tool call; the approval tool must outlive the board's deadline. */
export function claudeApprovalMcpToolTimeoutMs(approvalTimeoutSec: number): number {
  return (approvalTimeoutSec + 120) * 1000;
}

/**
 * Board mode asks about anything that can change state or reach the network; Claude's own
 * read-only command handling lets ls/find/grep/cat-in-workspace run freely, and anything it
 * does not consider read-only (writes, installs, restarts, arbitrary scripts) asks by default.
 *
 * Explicit rules cover what Claude would otherwise treat as read-only: plain network fetches
 * and commands that print the environment (where the agent's keys live). Claude applies Bash
 * rules to each part of a compound command, so `cd x && curl ...` still asks.
 * File tools always consult the prompt tool; the server allows reads inside the run's own
 * workspace and asks the board about everything else.
 */
export const BOARD_ASK_RULES = [
  "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "WebSearch", "KillShell",
  "Bash(curl:*)", "Bash(wget:*)", "Bash(ssh:*)", "Bash(scp:*)", "Bash(sftp:*)", "Bash(rsync:*)",
  "Bash(nc:*)", "Bash(ncat:*)", "Bash(socat:*)", "Bash(telnet:*)", "Bash(unicorn:*)",
  "Bash(env:*)", "Bash(printenv:*)",
  "Read(//**)", "Grep(//**)", "Glob(//**)",
] as const;

export interface SkillScriptSource {
  /** Directory name the skill is materialized under (e.g. "zammad-ticket--7c0fbb3f36"). */
  runtimeName: string;
  /** Real directory the materialized skill links to. */
  source: string;
}

/**
 * Allow rules for skill scripts the operator marked safe, e.g. "zammad-ticket/scripts/fetch_ticket.py".
 * The skill prefix matches a materialized skill's runtime name (exactly, or before its "--hash").
 * Rules name the script by absolute path, both through the prompt bundle and at its real source,
 * so a script elsewhere with the same file name still asks.
 */
export function buildSkillScriptAllowRules(input: {
  scripts: readonly string[];
  skills: readonly SkillScriptSource[];
  skillsHome: string;
}): string[] {
  const rules = new Set<string>();
  for (const raw of input.scripts) {
    const entry = raw.trim().replace(/^\/+/, "");
    const slash = entry.indexOf("/");
    if (slash <= 0) continue;
    const skillName = entry.slice(0, slash);
    const relative = entry.slice(slash + 1);
    if (!relative || relative.split("/").some((part) => part === ".." || part === "")) continue;
    for (const skill of input.skills) {
      if (skill.runtimeName !== skillName && !skill.runtimeName.startsWith(`${skillName}--`)) continue;
      for (const base of [`${input.skillsHome}/${skill.runtimeName}`, skill.source]) {
        const script = `${base.replace(/\/+$/, "")}/${relative}`;
        for (const prefix of ["python3 ", "python ", ""]) rules.add(`Bash(${prefix}${script}:*)`);
      }
    }
  }
  return [...rules];
}

export function buildClaudeBoardPermissionArgs(input: {
  /** Tool name of the permission bridge, or null when the run has no bridge. */
  promptTool: string | null;
  /** Rules for tools that never need a prompt (Paperclip's own task tools). */
  allowRules: readonly string[];
  /** --setting-sources user is already on the command line. */
  settingSourcesPresent?: boolean;
}): string[] {
  const settings = {
    permissions: { ask: [...BOARD_ASK_RULES], allow: [...input.allowRules] },
  };
  const args = ["--permission-mode", "default"];
  // A workspace .claude/settings*.json is writable by the agent; never let it pre-allow tools.
  // "project" must stay on: Paperclip delivers skills through --add-dir, and Claude only loads
  // add-dir skills from the project source ("user" alone reports every skill as unknown).
  // It does not weaken the gate: flag-level ask rules outrank project allow rules, and Claude
  // ignores allow rules in an untrusted workspace's .claude/settings.json.
  if (!input.settingSourcesPresent) args.push("--setting-sources", "user,project");
  args.push("--settings", JSON.stringify(settings));
  if (input.promptTool) {
    args.push("--permission-prompts", "host", "--permission-prompt-tool", input.promptTool);
  } else {
    // No bridge: fail closed. Anything that would prompt is denied.
    args.push("--permission-prompts", "none");
  }
  return args;
}

const BOARD_MANAGED_FLAGS_WITH_VALUE = new Set([
  "--permission-mode",
  "--permission-prompts",
  "--permission-prompt-tool",
  "--settings",
  "--setting-sources",
]);
const BOARD_MANAGED_FLAGS_VARIADIC = new Set(["--allowedTools", "--allowed-tools"]);
const BOARD_MANAGED_FLAGS_BARE = new Set([
  "--dangerously-skip-permissions",
  "--allow-dangerously-skip-permissions",
]);

/** Remove user extra args that would widen or replace the board permission contract. */
export function stripBoardManagedClaudeArgs(extraArgs: readonly string[]): string[] {
  const out: string[] = [];
  for (let i = 0; i < extraArgs.length; i++) {
    const arg = extraArgs[i]!;
    const flag = arg.includes("=") ? arg.slice(0, arg.indexOf("=")) : arg;
    const inline = flag !== arg;
    if (BOARD_MANAGED_FLAGS_BARE.has(flag)) continue;
    if (BOARD_MANAGED_FLAGS_WITH_VALUE.has(flag)) {
      if (!inline) i++;
      continue;
    }
    if (BOARD_MANAGED_FLAGS_VARIADIC.has(flag)) {
      if (!inline) while (i + 1 < extraArgs.length && !extraArgs[i + 1]!.startsWith("-")) i++;
      continue;
    }
    out.push(arg);
  }
  return out;
}
