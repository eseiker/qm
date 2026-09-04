import { signedRequestHeaders } from "./source-auth-sign.ts";

export type HttpMethod = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface SignedCoreFetchInit extends Omit<RequestInit, "body" | "headers" | "method" | "redirect"> {
  body?: RequestInit["body"] | NodeJS.ReadableStream;
  duplex?: "half";
  headers?: RequestInit["headers"];
  jsonContentType?: boolean;
  signatureTail?: string;
}

export const CAPABILITY_HEADER = "x-agent-capability";

export function signedHeaders(
  secret: string | undefined,
  method: string,
  pathWithQuery: string,
  rawBody = "",
  signatureTail = rawBody,
): Record<string, string> {
  return signedRequestHeaders(secret, method, pathWithQuery, signatureTail, { "content-type": "application/json" });
}

export function withSourceAuthNonce(pathWithQuery: string, secret: string | undefined): string {
  if (!secret) return pathWithQuery;
  const url = new URL(pathWithQuery, "http://core.local");
  url.searchParams.set("_sourceAuthNonce", `${Date.now()}-${Math.random().toString(16).slice(2)}`);
  return `${url.pathname}${url.search}`;
}

export function signedCoreFetch(
  coreApiUrl: string,
  secret: string | undefined,
  method: string,
  pathWithQuery: string,
  init: SignedCoreFetchInit = {},
): Promise<Response> {
  const {
    body,
    duplex,
    headers: inputHeaders,
    jsonContentType = true,
    signatureTail = typeof body === "string" ? body : "",
    ...requestInit
  } = init;
  const baseHeaders = Object.fromEntries(new Headers(inputHeaders).entries());
  const headers = signedRequestHeaders(secret, method, pathWithQuery, signatureTail, {
    ...(jsonContentType ? { "content-type": "application/json" } : {}),
    ...baseHeaders,
  });
  return fetch(`${coreApiUrl}${pathWithQuery}`, {
    ...requestInit,
    method,
    headers,
    ...(body !== undefined && body !== null ? { body: body as RequestInit["body"] } : {}),
    ...(duplex ? { duplex } : {}),
    redirect: "error",
  } as RequestInit & { duplex?: "half" });
}
