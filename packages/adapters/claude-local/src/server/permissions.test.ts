import { BOARD_ASK_RULES, buildSkillScriptAllowRules } from "./permissions.js";
import { describe, expect, it } from "vitest";
import {
  buildClaudeBoardPermissionArgs,
  buildClaudeExecutionPermissionArgs,
  buildClaudeProbePermissionArgs,
  claudeApprovalMcpToolTimeoutMs,
  claudeSandboxPermissionEnv,
  parseClaudeApprovalTimeoutSec,
  parseClaudePermissionPrompts,
  stripBoardManagedClaudeArgs,
} from "./permissions.js";

describe("Claude full-auto permission args", () => {
  for (const [name, build] of [["execution", buildClaudeExecutionPermissionArgs], ["probe", buildClaudeProbePermissionArgs]] as const) {
    it.each([
      { targetIsRemote: false, localProcessUid: 1000 },
      { targetIsRemote: true, localProcessUid: 1000 },
      { targetIsRemote: false, localProcessUid: 0 },
      { targetIsRemote: true, localProcessUid: 0 },
    ])(`${name} requests full bypass for %j`, (target) => {
      expect(build({ ...target, dangerouslySkipPermissions: true }))
        .toEqual(["--dangerously-skip-permissions"]);
      expect(build({ ...target, dangerouslySkipPermissions: false })).toEqual([]);
    });
  }

  it("identifies managed sandboxes for Claude's root launch check only when full auto is enabled", () => {
    expect(claudeSandboxPermissionEnv({ dangerouslySkipPermissions: true, targetIsSandbox: true })).toEqual({ IS_SANDBOX: "1" });
    expect(claudeSandboxPermissionEnv({ dangerouslySkipPermissions: false, targetIsSandbox: true })).toEqual({});
    expect(claudeSandboxPermissionEnv({ dangerouslySkipPermissions: true, targetIsSandbox: false })).toEqual({});
  });
});

describe("Claude board permission prompts", () => {
  it("routes prompts to the bridge tool and never bypasses", () => {
    const args = buildClaudeBoardPermissionArgs({
      promptTool: "mcp__paperclip_permissions__approve",
      allowRules: ["mcp__Paperclip_projects"],
    });
    expect(args).not.toContain("--dangerously-skip-permissions");
    expect(args).toEqual(expect.arrayContaining([
      "--permission-mode", "default",
      "--setting-sources", "user,project",
      "--permission-prompts", "host",
      "--permission-prompt-tool", "mcp__paperclip_permissions__approve",
    ]));
    const settings = JSON.parse(args[args.indexOf("--settings") + 1]!);
    expect(settings).toEqual({
      permissions: { ask: [...BOARD_ASK_RULES], allow: ["Skill", "mcp__Paperclip_projects"] },
    });
  });

  it("denies everything that would prompt when there is no bridge", () => {
    const args = buildClaudeBoardPermissionArgs({ promptTool: null, allowRules: [] });
    expect(args).not.toContain("--permission-prompt-tool");
    expect(args[args.indexOf("--permission-prompts") + 1]).toBe("none");
  });

  it("does not repeat --setting-sources when it is already present", () => {
    const args = buildClaudeBoardPermissionArgs({ promptTool: "t", allowRules: [], settingSourcesPresent: true });
    expect(args).not.toContain("--setting-sources");
  });

  it("strips flags that widen or replace the permission contract", () => {
    expect(stripBoardManagedClaudeArgs([
      "--verbose",
      "--dangerously-skip-permissions",
      "--allow-dangerously-skip-permissions",
      "--permission-mode", "bypassPermissions",
      "--permission-mode=acceptEdits",
      "--permission-prompts", "none",
      "--permission-prompt-tool", "mcp__evil__yes",
      "--settings", "{\"permissions\":{\"allow\":[\"Bash\"]}}",
      "--setting-sources", "project",
      "--allowedTools", "Bash", "Write",
      "--allowed-tools=Bash",
      "--max-turns", "5",
    ])).toEqual(["--verbose", "--max-turns", "5"]);
  });

  it("parses the mode and clamps the approval timeout", () => {
    expect(parseClaudePermissionPrompts("board")).toBe("board");
    expect(parseClaudePermissionPrompts("yes")).toBe("off");
    expect(parseClaudePermissionPrompts(undefined)).toBe("off");
    expect(parseClaudeApprovalTimeoutSec(undefined)).toBe(1800);
    expect(parseClaudeApprovalTimeoutSec(5)).toBe(60);
    expect(parseClaudeApprovalTimeoutSec(999_999)).toBe(10_800);
    expect(parseClaudeApprovalTimeoutSec("600")).toBe(600);
    expect(claudeApprovalMcpToolTimeoutMs(600)).toBe(720_000);
  });
});

describe("buildSkillScriptAllowRules", () => {
  const skills = [
    { runtimeName: "zammad-ticket--7c0fbb3f36", source: "/home/op/.claude/skills/zammad-ticket" },
    { runtimeName: "trmm-shell--e3f1482459", source: "/home/op/.claude/skills/trmm-shell" },
  ];
  const skillsHome = "/cache/bundle/.claude/skills";

  it("allows a listed script by absolute path, via the bundle and at its source", () => {
    const rules = buildSkillScriptAllowRules({ scripts: ["zammad-ticket/scripts/fetch_ticket.py"], skills, skillsHome });
    expect(rules).toEqual(expect.arrayContaining([
      "Bash(python3 /cache/bundle/.claude/skills/zammad-ticket--7c0fbb3f36/scripts/fetch_ticket.py:*)",
      "Bash(python3 /home/op/.claude/skills/zammad-ticket/scripts/fetch_ticket.py:*)",
      "Bash(/home/op/.claude/skills/zammad-ticket/scripts/fetch_ticket.py:*)",
    ]));
    // Only the listed skill: nothing for trmm-shell.
    expect(rules.some((rule) => rule.includes("trmm-shell"))).toBe(false);
  });

  it("ignores unknown skills, traversal, and entries without a script path", () => {
    expect(buildSkillScriptAllowRules({
      scripts: ["nope/scripts/x.py", "zammad-ticket/../trmm-shell/scripts/trmm_shell.py", "zammad-ticket", "zammad-ticket/"],
      skills,
      skillsHome,
    })).toEqual([]);
  });

  it("does not match a skill whose name merely starts with the prefix", () => {
    expect(buildSkillScriptAllowRules({
      scripts: ["zammad/scripts/fetch_ticket.py"],
      skills,
      skillsHome,
    })).toEqual([]);
  });
});

