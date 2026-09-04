type FetchLike = (input: string | URL | Request, init?: RequestInit) => Promise<Response>;

export function sourceAuthFetch(
  input: string | URL | Request,
  init: RequestInit,
  fetchImpl: FetchLike = fetch,
): Promise<Response> {
  return fetchImpl(input, { ...init, redirect: "error" });
}
