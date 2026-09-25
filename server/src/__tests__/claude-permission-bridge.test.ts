import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import express from "express";
import request from "supertest";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { and, eq } from "drizzle-orm";
import { agents, companies, createDb, heartbeatRunEvents, heartbeatRuns, type Db } from "@paperclipai/db";
import {
  isAutoAllowedRead,
  requestBoardPermission,
  resolveApprovalTimeoutSec,
  resolveClaudePermissionRequest,
} from "../services/claude-permission-bridge.js";
import { readPendingNativeRuntimeRequest } from "../services/native-runtime/runtime-request-resolution-authority.js";
import { claudePermissionBridgeRoutes } from "../routes/claude-permission-bridge.js";
import { errorHandler } from "../middleware/error-handler.js";
import { startEmbeddedPostgresTestDatabase } from "./helpers/embedded-postgres.js";

const companyId = "30000000-0000-4000-8000-000000000001";
const agentId = "30000000-0000-4000-8000-000000000002";
const otherAgentId = "30000000-0000-4000-8000-000000000003";
let runSeq = 100;
const nextRunId = () => `30000000-0000-4000-8000-${String(runSeq++).padStart(12, "0")}`;

let temporary: Awaited<ReturnType<typeof startEmbeddedPostgresTestDatabase>>;
let db: Db;
let workspace: string;

async function createRun(overrides: Partial<typeof heartbeatRuns.$inferInsert> = {}) {
  const id = nextRunId();
  await db.insert(heartbeatRuns).values({
    id,
    companyId,
    agentId,
    status: "running",
    contextSnapshot: { paperclipWorkspace: { cwd: workspace, source: "project" } },
    ...overrides,
  });
  return { id, companyId, agentId: overrides.agentId ?? agentId };
}

async function requestEvents(runId: string) {
  return db.select().from(heartbeatRunEvents)
    .where(eq(heartbeatRunEvents.runId, runId)).orderBy(heartbeatRunEvents.seq);
}

async function waitForCreated(runId: string): Promise<string> {
  for (let i = 0; i < 200; i++) {
    const [created] = await db.select().from(heartbeatRunEvents).where(and(
      eq(heartbeatRunEvents.runId, runId),
      eq(heartbeatRunEvents.eventType, "runtime_request.created"),
    ));
    const id = (created?.payload as any)?.prpEvent?.payload?.request?.requestId;
    if (id) return id;
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
  throw new Error("no runtime_request.created event");
}

beforeAll(async () => {
  temporary = await startEmbeddedPostgresTestDatabase("paperclip-claude-permissions-");
  db = createDb(temporary.connectionString);
  workspace = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "perm-ws-")));
  await db.insert(companies).values({ id: companyId, name: "Permission fixture", issuePrefix: "PRM" });
  await db.insert(agents).values([
    { id: agentId, companyId, name: "Claude agent", adapterType: "claude_local", adapterConfig: { permissionPrompts: "board", approvalTimeoutSec: 60 } },
    { id: otherAgentId, companyId, name: "Other agent", adapterType: "claude_local", adapterConfig: {} },
  ]);
}, 120_000);

afterAll(async () => {
  await temporary?.cleanup();
  if (workspace) await fs.rm(workspace, { recursive: true, force: true });
});

describe("claude permission bridge: board decisions", () => {
  it("returns the stored input on Allow once, not a later mutation", async () => {
    const run = await createRun();
    const toolInput = { command: "echo hi" };
    const pending = requestBoardPermission(db, { run, toolName: "Bash", toolInput, timeoutSec: 60, pollMs: 20 });
    const requestId = await waitForCreated(run.id);
    toolInput.command = "rm -rf /";
    expect(await resolveClaudePermissionRequest(db, { run, requestId, action: "accept", resolvedByUserId: "u1" })).toBe(true);

    await expect(pending).resolves.toEqual({ behavior: "allow", updatedInput: { command: "echo hi" } });
    const events = await requestEvents(run.id);
    expect(events.map((event) => event.eventType)).toEqual(["runtime_request.created", "runtime_request.resolved"]);
    const created = (events[0]!.payload as any).prpEvent;
    expect(created).toMatchObject({
      schema: "paperclip.prp.event.v1",
      schemaVersion: 1,
      sourceKind: "paperclip_permission_bridge",
      runId: run.id,
      turnId: `claude-${run.id}`,
    });
    expect(created.payload.request).toMatchObject({
      requestKind: "permission_approval",
      status: "pending",
      choices: [{ key: "accept", label: "Allow once" }, { key: "decline", label: "Deny" }],
    });
    expect(created.payload.request.prompt).toContain("Claude wants to use Bash");
  });

  it("is readable by the shared resolution authority while pending", async () => {
    const run = await createRun();
    const pending = requestBoardPermission(db, { run, toolName: "Write", toolInput: { file_path: "/x" }, timeoutSec: 60, pollMs: 20 });
    const requestId = await waitForCreated(run.id);
    await expect(readPendingNativeRuntimeRequest(db, { companyId, runId: run.id, requestId })).resolves.toMatchObject({
      requestKind: "permission_approval",
      resolverPolicy: "instance_admin",
    });
    await resolveClaudePermissionRequest(db, { run, requestId, action: "decline", resolvedByUserId: "u1" });
    await expect(pending).resolves.toMatchObject({ behavior: "deny" });
    await expect(readPendingNativeRuntimeRequest(db, { companyId, runId: run.id, requestId })).resolves.toBeNull();
  });

  it("lets the first decision win", async () => {
    const run = await createRun();
    const pending = requestBoardPermission(db, { run, toolName: "Bash", toolInput: { command: "ls" }, timeoutSec: 60, pollMs: 20 });
    const requestId = await waitForCreated(run.id);
    const results = await Promise.all([
      resolveClaudePermissionRequest(db, { run, requestId, action: "accept", resolvedByUserId: "a" }),
      resolveClaudePermissionRequest(db, { run, requestId, action: "decline", resolvedByUserId: "b" }),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    await pending;
    expect((await requestEvents(run.id)).filter((event) => event.eventType === "runtime_request.resolved")).toHaveLength(1);
  });

  it("expires and denies at the deadline", async () => {
    const run = await createRun();
    let clock = 0;
    const decision = await requestBoardPermission(db, {
      run, toolName: "Bash", toolInput: { command: "ls" }, timeoutSec: 60, pollMs: 5,
      now: () => (clock += 20_000),
    });
    expect(decision).toMatchObject({ behavior: "deny" });
    expect((decision as { message: string }).message).toContain("No board decision within 1 min");
    expect((await requestEvents(run.id)).at(-1)?.eventType).toBe("runtime_request.expired");
    const requestId = await waitForCreated(run.id);
    expect(await resolveClaudePermissionRequest(db, { run, requestId, action: "accept", resolvedByUserId: "late" })).toBe(false);
  });

  it("expires when the run stops running", async () => {
    const run = await createRun();
    const pending = requestBoardPermission(db, { run, toolName: "Bash", toolInput: { command: "ls" }, timeoutSec: 60, pollMs: 20 });
    await waitForCreated(run.id);
    await db.update(heartbeatRuns).set({ status: "cancelled" }).where(eq(heartbeatRuns.id, run.id));
    await expect(pending).resolves.toMatchObject({ behavior: "deny" });
    expect((await requestEvents(run.id)).at(-1)?.eventType).toBe("runtime_request.expired");
  });

  it("clamps the configured approval timeout", () => {
    expect(resolveApprovalTimeoutSec({})).toBe(1800);
    expect(resolveApprovalTimeoutSec({ approvalTimeoutSec: 5 })).toBe(60);
    expect(resolveApprovalTimeoutSec({ approvalTimeoutSec: 99_999 })).toBe(10_800);
  });
});

describe("claude permission bridge: workspace read policy", () => {
  it("auto-allows reads inside the workspace and nothing else", async () => {
    await fs.writeFile(path.join(workspace, "notes.md"), "x");
    const outside = await fs.realpath(await fs.mkdtemp(path.join(os.tmpdir(), "perm-outside-")));
    await fs.writeFile(path.join(outside, "secret"), "s");
    await fs.symlink(outside, path.join(workspace, "escape"));
    const allowed = (toolName: string, toolInput: Record<string, unknown>, cwd: string | null = workspace) =>
      isAutoAllowedRead({ toolName, toolInput, cwd, roots: [workspace] });
    try {
      expect(await allowed("Read", { file_path: path.join(workspace, "notes.md") })).toBe(true);
      expect(await allowed("Read", { file_path: "notes.md" })).toBe(true);
      expect(await allowed("Grep", { pattern: "x" })).toBe(true);
      expect(await allowed("Glob", { pattern: "**/*.md" })).toBe(true);

      expect(await allowed("Read", { file_path: path.join(outside, "secret") })).toBe(false);
      expect(await allowed("Read", { file_path: "../../etc/passwd" })).toBe(false);
      expect(await allowed("Read", { file_path: "escape/secret" })).toBe(false);
      expect(await allowed("Read", { file_path: "~/.ssh/id_rsa" })).toBe(false);
      expect(await allowed("Glob", { pattern: "../**" })).toBe(false);
      expect(await allowed("Glob", { pattern: "/home/*/.ssh/*" })).toBe(false);
      expect(await allowed("Grep", { pattern: "x", glob: "../../**" })).toBe(false);
      expect(await allowed("Grep", { pattern: "x", path: outside })).toBe(false);
      expect(await allowed("Bash", { command: "cat notes.md" })).toBe(false);
      expect(await allowed("Read", { file_path: "notes.md" }, null)).toBe(false);
    } finally {
      await fs.rm(outside, { recursive: true, force: true });
    }
  });
});

describe("claude permission bridge: MCP route", () => {
  function appFor(actor: Record<string, unknown>) {
    const app = express();
    app.use(express.json({ limit: "10mb" }));
    app.use((req, _res, next) => { (req as any).actor = actor; next(); });
    app.use("/api", claudePermissionBridgeRoutes(db));
    app.use(errorHandler);
    return app;
  }
  const actorFor = (run: { id: string; agentId: string }) => ({
    type: "agent", source: "agent_jwt", runId: run.id, agentId: run.agentId, companyId,
  });
  const call = (name: string, args: Record<string, unknown>) => ({
    jsonrpc: "2.0", id: 7, method: "tools/call", params: { name, arguments: args },
  });

  it("refuses a token whose run belongs to another agent", async () => {
    const run = await createRun();
    const res = await request(appFor({ ...actorFor(run), agentId: otherAgentId }))
      .post("/api/mcp/claude-permissions")
      .send(call("approve", { tool_name: "Bash", input: { command: "ls" } }));
    expect(res.status).toBe(403);
    expect(await requestEvents(run.id)).toHaveLength(0);
  });

  it("answers workspace reads immediately without a card", async () => {
    const run = await createRun();
    await fs.writeFile(path.join(workspace, "readme.txt"), "r");
    const res = await request(appFor(actorFor(run)))
      .post("/api/mcp/claude-permissions")
      .send(call("approve", { tool_name: "Read", input: { file_path: "readme.txt" } }));
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body.result.content[0].text)).toEqual({
      behavior: "allow", updatedInput: { file_path: "readme.txt" },
    });
    expect(await requestEvents(run.id)).toHaveLength(0);
  });

  it("holds a command open as an event stream until the board decides", async () => {
    const run = await createRun();
    const response = request(appFor(actorFor(run)))
      .post("/api/mcp/claude-permissions")
      .set("Accept", "application/json, text/event-stream")
      .send(call("approve", { tool_name: "Bash", input: { command: "hostname" }, tool_use_id: "toolu_1" }))
      .buffer(true)
      .parse((res, done) => {
        let data = "";
        res.on("data", (chunk: Buffer) => { data += chunk.toString(); });
        res.on("end", () => done(null, data));
      });
    const settled = response.then((res) => res);
    const requestId = await waitForCreated(run.id);
    await resolveClaudePermissionRequest(db, { run, requestId, action: "accept", resolvedByUserId: "u1" });
    const res = await settled;
    expect(res.headers["content-type"]).toContain("text/event-stream");
    const dataLine = String(res.body).split("\n").find((line) => line.startsWith("data: "))!;
    const message = JSON.parse(dataLine.slice(6));
    expect(message.id).toBe(7);
    expect(JSON.parse(message.result.content[0].text)).toEqual({
      behavior: "allow", updatedInput: { command: "hostname" },
    });
  }, 30_000);

  it("denies oversized inputs without a card", async () => {
    const run = await createRun();
    const res = await request(appFor(actorFor(run)))
      .post("/api/mcp/claude-permissions")
      .send(call("approve", { tool_name: "Write", input: { file_path: "a", content: "x".repeat(300 * 1024) } }));
    expect(JSON.parse(res.body.result.content[0].text).behavior).toBe("deny");
    expect(await requestEvents(run.id)).toHaveLength(0);
  });
});
