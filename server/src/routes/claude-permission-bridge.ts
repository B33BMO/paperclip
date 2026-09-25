import { Router, type Request, type Response } from "express";
import { and, eq } from "drizzle-orm";
import { agents, heartbeatRuns, type Db } from "@paperclipai/db";
import { assertCompanyAccess } from "./authz.js";
import { forbidden } from "../errors.js";
import {
  CLAUDE_PERMISSION_SERVER_NAME,
  CLAUDE_PERMISSION_TOOL_NAME,
  MAX_PERMISSION_INPUT_BYTES,
  isAutoAllowedRead,
  requestBoardPermission,
  resolveApprovalTimeoutSec,
  resolveReadRoots,
  resolveRunCwd,
  type PermissionDecision,
} from "../services/claude-permission-bridge.js";

const KEEPALIVE_MS = 25_000;

const APPROVE_TOOL = {
  name: CLAUDE_PERMISSION_TOOL_NAME,
  description: "Paperclip board approval for Claude tool use. Called by Claude Code's permission prompt; not for direct use.",
  inputSchema: {
    type: "object",
    properties: {
      tool_name: { type: "string" },
      input: { type: "object" },
      tool_use_id: { type: "string" },
    },
    required: ["tool_name", "input"],
  },
};

/** Only the authenticated run's own token may ask; never caller-supplied run IDs. */
async function permissionRunContext(db: Db, actor: Request["actor"]) {
  if (actor.type !== "agent" || actor.source !== "agent_jwt" || !actor.runId || !actor.agentId || !actor.companyId) {
    throw forbidden("Permission prompts require an authenticated agent run");
  }
  const [run] = await db.select().from(heartbeatRuns).where(and(
    eq(heartbeatRuns.id, actor.runId),
    eq(heartbeatRuns.companyId, actor.companyId),
    eq(heartbeatRuns.agentId, actor.agentId),
  )).limit(1);
  if (!run) throw forbidden("Run is unavailable");
  const [agent] = await db.select().from(agents).where(and(
    eq(agents.id, actor.agentId),
    eq(agents.companyId, actor.companyId),
  )).limit(1);
  if (!agent || agent.adapterType !== "claude_local") throw forbidden("Permission prompts are only available to Claude runs");
  return { run, agent };
}

function toolResult(decision: PermissionDecision) {
  return { content: [{ type: "text", text: JSON.stringify(decision) }] };
}

/** Mounted after actor middleware, beside the project tools MCP endpoint. */
export function claudePermissionBridgeRoutes(db: Db) {
  const router = Router();
  router.post("/mcp/claude-permissions", async (req: Request, res: Response) => {
    const { run, agent } = await permissionRunContext(db, req.actor);
    assertCompanyAccess(req, run.companyId);
    const { id = null, method, params } = req.body ?? {};
    const send = (result: unknown) => res.json({ jsonrpc: "2.0", id, result });
    if (method === "initialize") {
      return send({
        protocolVersion: "2025-03-26",
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: CLAUDE_PERMISSION_SERVER_NAME, version: "1" },
      });
    }
    if (method === "notifications/initialized") return res.status(202).end();
    if (method === "tools/list") return send({ tools: [APPROVE_TOOL] });
    if (method !== "tools/call" || params?.name !== CLAUDE_PERMISSION_TOOL_NAME) {
      return res.json({ jsonrpc: "2.0", id, error: { code: -32601, message: "Method not found" } });
    }

    const args = params?.arguments ?? {};
    const toolName = typeof args.tool_name === "string" ? args.tool_name : "";
    const toolInput = typeof args.input === "object" && args.input !== null && !Array.isArray(args.input)
      ? args.input as Record<string, unknown>
      : null;
    if (!toolName || !toolInput) {
      return send(toolResult({ behavior: "deny", message: "Malformed permission request." }));
    }
    if (Buffer.byteLength(JSON.stringify(toolInput), "utf8") > MAX_PERMISSION_INPUT_BYTES) {
      return send(toolResult({ behavior: "deny", message: "Tool input is too large to review; split the change into smaller steps." }));
    }
    if (run.status !== "running" || run.runtimeMode === "native") {
      return send(toolResult({ behavior: "deny", message: "This run is not accepting permission requests." }));
    }

    const adapterConfig = agent.adapterConfig;
    const cwd = resolveRunCwd(run, adapterConfig);
    if (await isAutoAllowedRead({ toolName, toolInput, cwd, roots: resolveReadRoots({ run, adapterConfig }) })) {
      return send(toolResult({ behavior: "allow", updatedInput: toolInput }));
    }

    // Stream the answer: keepalive comments hold the connection open while a
    // human decides, then one JSON-RPC message ends the stream.
    const streaming = String(req.headers.accept ?? "").includes("text/event-stream");
    const abort = new AbortController();
    res.on("close", () => { if (!res.writableEnded) abort.abort(); });
    let keepalive: NodeJS.Timeout | null = null;
    if (streaming) {
      res.status(200).set({
        "Content-Type": "text/event-stream",
        "Cache-Control": "no-cache, no-transform",
        Connection: "keep-alive",
      });
      res.flushHeaders();
      keepalive = setInterval(() => res.write(": keepalive\n\n"), KEEPALIVE_MS);
    }
    try {
      const decision = await requestBoardPermission(db, {
        run,
        toolName,
        toolInput,
        toolUseId: typeof args.tool_use_id === "string" ? args.tool_use_id : null,
        timeoutSec: resolveApprovalTimeoutSec(adapterConfig),
        signal: abort.signal,
      });
      const message = { jsonrpc: "2.0", id, result: toolResult(decision) };
      if (!streaming) return res.json(message);
      res.write(`event: message\ndata: ${JSON.stringify(message)}\n\n`);
      return res.end();
    } finally {
      if (keepalive) clearInterval(keepalive);
    }
  });
  return router;
}
