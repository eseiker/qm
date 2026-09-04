import assert from "node:assert/strict";
import { createServer, type IncomingHttpHeaders, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { sourceAuthFetch } from "../src/auth/source-auth-fetch.ts";

interface ReceivedRequest {
  body: string;
  headers: IncomingHttpHeaders;
  method: string | undefined;
  url: string | undefined;
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

async function receive(req: IncomingMessage): Promise<ReceivedRequest> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return {
    body: Buffer.concat(chunks).toString("utf8"),
    headers: req.headers,
    method: req.method,
    url: req.url,
  };
}

test("source-auth fetch rejects every redirect without leaking headers or bodies to another origin", async () => {
  const targetRequests: ReceivedRequest[] = [];
  const target = createServer((req, res) => {
    void receive(req).then((received) => {
      targetRequests.push(received);
      res.writeHead(200).end("unexpected");
    });
  });
  const targetOrigin = await listen(target);
  const sourceRequests: ReceivedRequest[] = [];
  const source = createServer((req, res) => {
    void receive(req).then((received) => {
      sourceRequests.push(received);
      const status = Number(new URL(received.url ?? "/", "http://source.invalid").pathname.slice(1));
      res.writeHead(status, { location: `${targetOrigin}/redirect-target` }).end();
    });
  });
  const sourceOrigin = await listen(source);
  try {
    for (const status of [301, 302, 303, 307, 308]) {
      const body = `signed-body-${status}`;
      await assert.rejects(
        sourceAuthFetch(`${sourceOrigin}/${status}`, {
          method: "POST",
          headers: {
            authorization: "Bearer private-token",
            "content-type": "text/plain",
            "x-signature": `signature-${status}`,
            "x-timestamp": "1234567890",
          },
          body,
        }),
      );
      const received = sourceRequests.at(-1);
      assert.equal(received?.method, "POST");
      assert.equal(received?.headers.authorization, "Bearer private-token");
      assert.equal(received?.headers["x-signature"], `signature-${status}`);
      assert.equal(received?.body, body);
      assert.equal(sourceRequests.length, [301, 302, 303, 307, 308].indexOf(status) + 1);
      assert.deepEqual(targetRequests, []);
    }
  } finally {
    await close(source);
    await close(target);
  }
});

test("source-auth fetch preserves ordinary response streams and transport errors", async () => {
  const response = new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("first"));
        controller.enqueue(new TextEncoder().encode("-second"));
        controller.close();
      },
    }),
    { status: 207 },
  );
  let redirect: RequestInit["redirect"];
  const returned = await sourceAuthFetch(
    "https://core.example.test/signed",
    { redirect: "follow" },
    async (_input, init) => {
      redirect = init?.redirect;
      return response;
    },
  );
  assert.strictEqual(returned, response);
  assert.equal(redirect, "error");
  assert.equal(returned.status, 207);
  assert.equal(await returned.text(), "first-second");

  const transportError = new Error("transport failed");
  await assert.rejects(
    sourceAuthFetch("https://core.example.test/signed", {}, async () => {
      throw transportError;
    }),
    (error) => error === transportError,
  );
});
