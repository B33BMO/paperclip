import { createHash, randomUUID } from "node:crypto";
import { EventEmitter } from "node:events";
import fs from "node:fs/promises";
import path from "node:path";
import { and, desc, eq, inArray, sql } from "drizzle-orm";
import type { Db } from "@paperclipai/db";
import { heartbeatRunEvents, heartbeatRuns } from "@paperclipai/db";
import { resolvePaperclipInstanceRoot } from "../home-paths.js";
import { allocateHeartbeatRunEventSeq } from "./heartbeat-run-events.js";

/**
 * Board approval for claude_local tool use. Claude Code's headless
 * `--permission-prompt-tool` calls the `approve` tool on this bridge for every
 * tool use its permission rules do not already allow. The bridge auto-allows
 * read-only tools confined to the run's own workspace; everything else becomes
 * a `permission_approval` runtime request card that only a board user can
 * resolve. The open tool call is the wait: Claude blocks until it answers.
 */

export const CLAUDE_PERMISSION_SOURCE_KIND = "paperclip_permission_bridge";
export const CLAUDE_PERMISSION_SERVER_NAME = "paperclip_permissions";
export const CLAUDE_PERMISSION_CONNECTION_ID = "paperclip-permission-prompts";
export const CLAUDE_PERMISSION_TOOL_NAME = "approve";

export const DEFAULT_APPROVAL_TIMEOUT_SEC = 1800;
const MIN_APPROVAL_TIMEOUT_SEC = 60;
const MAX_APPROVAL_TIMEOUT_SEC = 10_800;
export const MAX_PERMISSION_INPUT_BYTES = 256 * 1024;
const DISPLAY_LIMIT_BYTES = 8 * 1024;
const DECISION_POLL_MS = 2_000;
const LIVENESS_REFRESH_MS = 60_000;

const READ_ONLY_TOOLS = new Set(["Read", "Grep", "Glob", "LS", "NotebookRead"]);
const PATH_KEYS = ["file_path", "path", "notebook_path"] as const;
const RUNTIME_REQUEST_EVENTS = [
  "runtime_request.created",
  "runtime_request.resolved",
  "runtime_request.cancelled",
  "runtime_request.expired",
] as const;

export type PermissionDecision =
  | { behavior: "allow"; updatedInput: Record<string, unknown> }
  | { behavior: "deny"; message: string };

export type ClaudePermissionAction = "accept" | "decline";

type RunRow = typeof heartbeatRuns.$inferSelect;

function record(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function nonEmpty(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

export function resolveApprovalTimeoutSec(adapterConfig: unknown): number {
  const raw = Number(record(adapterConfig)?.approvalTimeoutSec);
  if (!Number.isFinite(raw)) return DEFAULT_APPROVAL_TIMEOUT_SEC;
  return Math.min(MAX_APPROVAL_TIMEOUT_SEC, Math.max(MIN_APPROVAL_TIMEOUT_SEC, Math.floor(raw)));
}

export function claudePermissionTurnId(runId: string): string {
  return `claude-${runId}`;
}

// ---------------------------------------------------------------- workspace policy

/**
 * Mirrors the claude_local adapter's cwd choice: an agent-home workspace
 * yields to an explicitly configured cwd; otherwise the realized workspace wins.
 */
export function resolveRunCwd(run: Pick<RunRow, "contextSnapshot">, adapterConfig: unknown): string | null {
  const workspace = record(record(run.contextSnapshot)?.paperclipWorkspace);
  const workspaceCwd = nonEmpty(workspace?.cwd);
  const configuredCwd = nonEmpty(record(adapterConfig)?.cwd);
  if (workspace?.source === "agent_home" && configuredCwd) return configuredCwd;
  return workspaceCwd ?? configuredCwd;
}

export function resolveReadRoots(input: {
  run: Pick<RunRow, "contextSnapshot" | "companyId">;
  adapterConfig: unknown;
  instanceRoot?: string;
}): string[] {
  const workspace = record(record(input.run.contextSnapshot)?.paperclipWorkspace);
  const config = record(input.adapterConfig);
  const roots = [
    resolveRunCwd(input.run, input.adapterConfig),
    nonEmpty(workspace?.cwd),
    nonEmpty(workspace?.worktreePath),
    nonEmpty(workspace?.agentHome),
    nonEmpty(config?.instructionsRootPath),
    path.resolve(
      input.instanceRoot ?? resolvePaperclipInstanceRoot(),
      "companies",
      input.run.companyId,
      "claude-prompt-cache",
    ),
  ];
  return [...new Set(roots.filter((root): root is string => Boolean(root) && path.isAbsolute(root!)))];
}

/** realpath of the path, or of its nearest existing ancestor plus the remainder. */
async function realpathLenient(candidate: string): Promise<string> {
  const resolved = path.resolve(candidate);
  const tail: string[] = [];
  let current = resolved;
  for (;;) {
    try {
      const real = await fs.realpath(current);
      return tail.length ? path.join(real, ...tail.reverse()) : real;
    } catch {
      const parent = path.dirname(current);
      if (parent === current) return resolved;
      tail.push(path.basename(current));
      current = parent;
    }
  }
}

function within(root: string, candidate: string): boolean {
  const rel = path.relative(root, candidate);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function hasTraversal(pattern: string): boolean {
  return path.isAbsolute(pattern) || pattern.startsWith("~") || pattern.split(/[\\/]/).includes("..");
}

export async function isAutoAllowedRead(input: {
  toolName: string;
  toolInput: Record<string, unknown>;
  cwd: string | null;
  roots: readonly string[];
}): Promise<boolean> {
  if (!READ_ONLY_TOOLS.has(input.toolName) || !input.cwd || !path.isAbsolute(input.cwd)) return false;
  // A glob can reach outside its base directory on its own.
  for (const key of ["pattern", "glob"] as const) {
    const pattern = input.toolInput[key];
    if (input.toolName !== "Grep" && key === "pattern" && typeof pattern === "string" && hasTraversal(pattern)) {
      return false;
    }
    if (key === "glob" && typeof pattern === "string" && hasTraversal(pattern)) return false;
  }
  const paths = PATH_KEYS
    .map((key) => input.toolInput[key])
    .filter((value): value is string => typeof value === "string" && value.length > 0);
  if (paths.length === 0) {
    if (input.toolName === "Read" || input.toolName === "NotebookRead") return false;
    paths.push(input.cwd);
  }
  const realRoots = await Promise.all(input.roots.map((root) => realpathLenient(root)));
  for (const candidate of paths) {
    if (candidate.startsWith("~")) return false;
    const real = await realpathLenient(path.resolve(input.cwd, candidate));
    if (!realRoots.some((root) => within(root, real))) return false;
  }
  return true;
}

// ---------------------------------------------------------------- events

function inputHash(input: Record<string, unknown>): string {
  return createHash("sha256").update(JSON.stringify(input)).digest("hex");
}

export function buildPermissionPrompt(toolName: string, input: Record<string, unknown>): string {
  const pretty = JSON.stringify(input, null, 2);
  const bytes = Buffer.byteLength(pretty, "utf8");
  const shown = bytes > DISPLAY_LIMIT_BYTES
    ? `${Buffer.from(pretty, "utf8").subarray(0, DISPLAY_LIMIT_BYTES).toString("utf8")}\n… (truncated: showing ${DISPLAY_LIMIT_BYTES} of ${bytes} bytes)`
    : pretty;
  return `Claude wants to use ${toolName}\n\n${shown}`;
}

function envelope(input: {
  runId: string;
  eventType: (typeof RUNTIME_REQUEST_EVENTS)[number];
  request: Record<string, unknown>;
}): Record<string, unknown> {
  return {
    prpEvent: {
      schema: "paperclip.prp.event.v1",
      schemaVersion: 1,
      eventType: input.eventType,
      sourceKind: CLAUDE_PERMISSION_SOURCE_KIND,
      sourceEventId: randomUUID(),
      runId: input.runId,
      turnId: claudePermissionTurnId(input.runId),
      emittedAt: new Date().toISOString(),
      payload: { request: input.request },
    },
  };
}

type Executor = Pick<Db, "select" | "update" | "insert">;

async function latestRequestEvent(executor: Executor, runId: string, requestId: string) {
  const [latest] = await executor
    .select({ eventType: heartbeatRunEvents.eventType, payload: heartbeatRunEvents.payload })
    .from(heartbeatRunEvents)
    .where(and(
      eq(heartbeatRunEvents.runId, runId),
      inArray(heartbeatRunEvents.eventType, [...RUNTIME_REQUEST_EVENTS]),
      sql`${heartbeatRunEvents.payload} #>> '{prpEvent,payload,request,requestId}' = ${requestId}`,
    ))
    .orderBy(desc(heartbeatRunEvents.seq))
    .limit(1);
  return latest ?? null;
}

/**
 * Append a terminal event only while the request is still pending, under the
 * run-row lock. The first terminal event wins; later callers get `false`.
 */
async function appendTerminalIfPending(db: Db, input: {
  run: Pick<RunRow, "id" | "companyId" | "agentId">;
  requestId: string;
  eventType: "runtime_request.resolved" | "runtime_request.expired";
  request: Record<string, unknown>;
}): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [locked] = await tx.select({ id: heartbeatRuns.id }).from(heartbeatRuns)
      .where(eq(heartbeatRuns.id, input.run.id)).for("update").limit(1);
    if (!locked) return false;
    const latest = await latestRequestEvent(tx as unknown as Executor, input.run.id, input.requestId);
    if (latest?.eventType !== "runtime_request.created") return false;
    const seq = await allocateHeartbeatRunEventSeq(tx as unknown as Db, input.run.id);
    await tx.insert(heartbeatRunEvents).values({
      companyId: input.run.companyId,
      runId: input.run.id,
      agentId: input.run.agentId,
      seq,
      eventType: input.eventType,
      stream: "system",
      level: "info",
      message: input.eventType === "runtime_request.resolved"
        ? `Permission request ${input.requestId} ${String(input.request.action)}`
        : `Permission request ${input.requestId} expired`,
      payload: envelope({ runId: input.run.id, eventType: input.eventType, request: input.request }),
    });
    return true;
  });
}

// ---------------------------------------------------------------- decisions

const decisions = new EventEmitter();
decisions.setMaxListeners(0);
const decisionKey = (runId: string, requestId: string) => `${runId}:${requestId}`;

/** Board resolution. Returns false when the request is no longer pending. */
export async function resolveClaudePermissionRequest(db: Db, input: {
  run: Pick<RunRow, "id" | "companyId" | "agentId">;
  requestId: string;
  action: ClaudePermissionAction;
  resolvedByUserId: string;
}): Promise<boolean> {
  const applied = await appendTerminalIfPending(db, {
    run: input.run,
    requestId: input.requestId,
    eventType: "runtime_request.resolved",
    request: {
      schema: "paperclip.runtime_request.v2",
      requestId: input.requestId,
      requestKind: "permission_approval",
      turnId: claudePermissionTurnId(input.run.id),
      status: "resolved",
      action: input.action,
      resolvedByUserId: input.resolvedByUserId,
    },
  });
  if (applied) decisions.emit(decisionKey(input.run.id, input.requestId));
  return applied;
}

export interface RequestPermissionInput {
  run: Pick<RunRow, "id" | "companyId" | "agentId">;
  toolName: string;
  toolInput: Record<string, unknown>;
  toolUseId?: string | null;
  timeoutSec: number;
  /** Aborted when the MCP client disconnects. */
  signal?: AbortSignal;
  /** Called periodically while waiting (keepalives). */
  onTick?: () => void;
  now?: () => number;
  pollMs?: number;
  livenessMs?: number;
}

function timeoutMessage(timeoutSec: number): string {
  const minutes = Math.max(1, Math.round(timeoutSec / 60));
  return `No board decision within ${minutes} min; do not retry this tool — report the task as blocked.`;
}

/** Create a card and hold until the board decides, the deadline passes, or the run ends. */
export async function requestBoardPermission(db: Db, input: RequestPermissionInput): Promise<PermissionDecision> {
  // The stored copy is what an approval releases — never anything sent later.
  const stored = structuredClone(input.toolInput);
  const requestId = `perm-${randomUUID()}`;
  const turnId = claudePermissionTurnId(input.run.id);
  const now = input.now ?? Date.now;
  const pollMs = input.pollMs ?? DECISION_POLL_MS;
  const livenessMs = input.livenessMs ?? LIVENESS_REFRESH_MS;

  await db.transaction(async (tx) => {
    const seq = await allocateHeartbeatRunEventSeq(tx as unknown as Db, input.run.id);
    await tx.insert(heartbeatRunEvents).values({
      companyId: input.run.companyId,
      runId: input.run.id,
      agentId: input.run.agentId,
      seq,
      eventType: "runtime_request.created",
      stream: "system",
      level: "warn",
      message: `Claude requests permission to use ${input.toolName}`,
      payload: envelope({
        runId: input.run.id,
        eventType: "runtime_request.created",
        request: {
          schema: "paperclip.runtime_request.v2",
          requestId,
          requestKind: "permission_approval",
          turnId,
          status: "pending",
          type: "permission",
          prompt: buildPermissionPrompt(input.toolName, stored),
          choices: [
            { key: "accept", label: "Allow once" },
            { key: "decline", label: "Deny" },
          ],
          details: {
            toolName: input.toolName,
            toolUseId: input.toolUseId ?? null,
            inputSha256: inputHash(stored),
          },
        },
      }),
    });
  });

  const deadline = now() + input.timeoutSec * 1000;
  const key = decisionKey(input.run.id, requestId);
  let lastLiveness = now();
  let wake: (() => void) | null = null;
  const onDecision = () => wake?.();
  decisions.on(key, onDecision);
  const onAbort = () => wake?.();
  input.signal?.addEventListener("abort", onAbort);

  const expire = async (reason: string): Promise<PermissionDecision> => {
    const applied = await appendTerminalIfPending(db, {
      run: input.run,
      requestId,
      eventType: "runtime_request.expired",
      request: {
        schema: "paperclip.runtime_request.v2",
        requestId,
        requestKind: "permission_approval",
        turnId,
        status: "expired",
        reason,
      },
    });
    // A decision may have landed in the same instant; honour it.
    return applied ? { behavior: "deny", message: timeoutMessage(input.timeoutSec) } : readDecision();
  };

  const readDecision = async (): Promise<PermissionDecision> => {
    const latest = await latestRequestEvent(db, input.run.id, requestId);
    const request = record(record(record(latest?.payload)?.prpEvent)?.payload)?.request;
    const action = record(request)?.action;
    if (latest?.eventType === "runtime_request.resolved" && action === "accept") {
      return { behavior: "allow", updatedInput: stored };
    }
    if (latest?.eventType === "runtime_request.resolved") {
      return { behavior: "deny", message: "The board denied this request. Do not retry it; explain what you needed and report the task as blocked." };
    }
    return { behavior: "deny", message: timeoutMessage(input.timeoutSec) };
  };

  try {
    for (;;) {
      const latest = await latestRequestEvent(db, input.run.id, requestId);
      if (latest && latest.eventType !== "runtime_request.created") return await readDecision();
      if (input.signal?.aborted) return await expire("client_disconnected");
      if (now() >= deadline) return await expire("timeout");
      const [run] = await db.select({ status: heartbeatRuns.status }).from(heartbeatRuns)
        .where(eq(heartbeatRuns.id, input.run.id)).limit(1);
      if (!run || run.status !== "running") return await expire("run_not_running");
      if (now() - lastLiveness >= livenessMs) {
        lastLiveness = now();
        // Keep active-run watchdogs from treating a waiting run as silent.
        await db.update(heartbeatRuns).set({ lastOutputAt: new Date() }).where(eq(heartbeatRuns.id, input.run.id));
      }
      input.onTick?.();
      await new Promise<void>((resolve) => {
        const timer = setTimeout(resolve, Math.max(0, Math.min(pollMs, deadline - now())));
        wake = () => { clearTimeout(timer); resolve(); };
      });
      wake = null;
    }
  } finally {
    decisions.off(key, onDecision);
    input.signal?.removeEventListener("abort", onAbort);
  }
}
