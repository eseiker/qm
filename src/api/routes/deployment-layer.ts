import { errMessage } from "../../util/errors.ts";
import {
  DeploymentLayerConflictError,
  DeploymentLayerPersistedError,
  DeploymentLayerValidationError,
  type DeploymentLayerBundle,
  type DeploymentLayerPrecondition,
} from "../../deployment/deployment-layer-store.ts";
import { sendJson } from "../http.ts";
import { isObj } from "./shared.ts";
import type { ApiCtx, Route } from "./route.ts";

const OPERATION_ID = /^[a-f0-9]{32}$/;

function bundleFrom(body: unknown): DeploymentLayerBundle | null {
  if (!isObj(body) || body.contract !== 1 || !Array.isArray(body.tools) || !Array.isArray(body.skills)) return null;
  return body as unknown as DeploymentLayerBundle;
}

function preconditionFrom(ctx: ApiCtx): DeploymentLayerPrecondition | null {
  const generations = ctx.url.searchParams.getAll("generation");
  const sources = ctx.url.searchParams.getAll("source");
  const hashes = ctx.url.searchParams.getAll("contentHash");
  const operationIds = ctx.url.searchParams.getAll("currentOperationId");
  if (generations.length !== 1 || sources.length !== 1 || hashes.length > 1 || operationIds.length > 1) return null;
  const generation = Number(generations[0]);
  const source = sources[0];
  const contentHash = hashes[0] ?? null;
  const operationId = operationIds[0] ?? null;
  if (!/^\d+$/.test(generations[0]!) || !Number.isSafeInteger(generation)) return null;
  if (operationId !== null && !OPERATION_ID.test(operationId)) return null;
  if (source !== "durable" && source !== "filesystem" && source !== "none") return null;
  if (source === "durable") {
    if (generation < 1 || contentHash === null || !/^[a-f0-9]{64}$/.test(contentHash)) return null;
  } else if (contentHash !== null) {
    return null;
  }
  return { generation, source, contentHash, operationId };
}

function operationIdFrom(ctx: ApiCtx): string | null {
  const operationIds = ctx.url.searchParams.getAll("operationId");
  return operationIds.length === 1 && OPERATION_ID.test(operationIds[0]!) ? operationIds[0]! : null;
}

async function getDeploymentLayer(ctx: ApiCtx): Promise<void> {
  const store = ctx.deps.deploymentLayer;
  if (!store) return sendJson(ctx.res, 404, { error: "not_found" });
  const { record, generation, operationId } = await store.read();
  if (!record) {
    const live = store.live();
    return sendJson(ctx.res, 200, {
      contract: 1,
      version: 0,
      generation,
      contentHash: null,
      source: live.source,
      operationId,
    });
  }
  const live = store.live();
  return sendJson(ctx.res, 200, {
    contract: 1,
    version: record.version,
    generation: record.version,
    contentHash: record.contentHash,
    operationId: record.operationId ?? null,
    updatedAt: record.updatedAt,
    updatedBy: record.updatedBy,
    status: (await store.isApplied(record.contentHash)) ? "applied" : "degraded",
    runtimeContentHash: live.contentHash,
    source: live.source,
    bundle: record.bundle,
  });
}

async function putDeploymentLayer(ctx: ApiCtx): Promise<void> {
  const store = ctx.deps.deploymentLayer;
  if (!store) return sendJson(ctx.res, 404, { error: "not_found" });
  const bundle = bundleFrom(ctx.body);
  if (!bundle) {
    return sendJson(ctx.res, 400, { error: "bad_request", message: "contract: 1, tools[], and skills[] required" });
  }
  const precondition = preconditionFrom(ctx);
  const operationId = operationIdFrom(ctx);
  if (!precondition || !operationId)
    return sendJson(ctx.res, 400, {
      error: "bad_request",
      message: "an exact deployment-layer generation and operation ID are required",
    });
  const updatedBy = "source-authenticated deployment CLI";
  try {
    const record = await store.put(bundle, updatedBy, { precondition, operationId });
    return sendJson(ctx.res, 200, {
      ok: true,
      version: record.version,
      contentHash: record.contentHash,
      operationId: record.operationId ?? null,
      changed: record.operationId === operationId && record.version === precondition.generation + 1,
      durable: store.durable,
    });
  } catch (error) {
    if (error instanceof DeploymentLayerPersistedError) {
      const record = error.record;
      return sendJson(ctx.res, 202, {
        ok: true,
        status: "degraded",
        message: errMessage(error),
        version: record.version,
        contentHash: record.contentHash,
        operationId: record.operationId ?? null,
        changed: record.operationId === operationId && record.version === precondition.generation + 1,
        durable: store.durable,
      });
    }
    if (error instanceof DeploymentLayerValidationError) {
      return sendJson(ctx.res, 400, { error: "invalid_deployment_layer", message: errMessage(error) });
    }
    if (error instanceof DeploymentLayerConflictError) {
      return sendJson(ctx.res, 409, { error: "deployment_layer_conflict", message: errMessage(error) });
    }
    throw error;
  }
}

async function clearDeploymentLayer(ctx: ApiCtx): Promise<void> {
  const store = ctx.deps.deploymentLayer;
  if (!store) return sendJson(ctx.res, 404, { error: "not_found" });
  const precondition = preconditionFrom(ctx);
  const operationId = operationIdFrom(ctx);
  if (!precondition || precondition.source !== "durable" || precondition.contentHash === null || !operationId) {
    return sendJson(ctx.res, 400, {
      error: "bad_request",
      message: "an exact durable generation and operation ID are required",
    });
  }
  const updatedBy = "source-authenticated deployment CLI";
  try {
    const record = await store.clear(precondition, updatedBy, { operationId });
    return sendJson(ctx.res, 200, {
      ok: true,
      status: "applied",
      version: record.version,
      contentHash: precondition.contentHash,
      operationId: record.operationId ?? null,
      changed: record.operationId === operationId && record.version === precondition.generation + 1,
      durable: store.durable,
    });
  } catch (error) {
    if (error instanceof DeploymentLayerPersistedError) {
      return sendJson(ctx.res, 202, {
        ok: true,
        status: "degraded",
        message: errMessage(error),
        version: error.record.version,
        contentHash: precondition.contentHash,
        operationId: error.record.operationId ?? null,
        changed: error.record.operationId === operationId && error.record.version === precondition.generation + 1,
        durable: store.durable,
      });
    }
    if (error instanceof DeploymentLayerConflictError) {
      return sendJson(ctx.res, 409, { error: "deployment_layer_conflict", message: errMessage(error) });
    }
    if (error instanceof DeploymentLayerValidationError) {
      return sendJson(ctx.res, 400, { error: "invalid_deployment_layer", message: errMessage(error) });
    }
    throw error;
  }
}

export const deploymentLayerRoutes: ReadonlyArray<Route<ApiCtx>> = [
  { method: "GET", path: "/v1/deployment-layer", auth: "source", handle: getDeploymentLayer },
  { method: "PUT", path: "/v1/deployment-layer", auth: "source", handle: putDeploymentLayer },
  { method: "DELETE", path: "/v1/deployment-layer", auth: "source", handle: clearDeploymentLayer },
];
