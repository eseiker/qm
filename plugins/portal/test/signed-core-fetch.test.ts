import test from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { Readable } from "node:stream";
import { signedCoreFetch } from "../../chassis/src/core-client.ts";
import { proxyToDeployment } from "../src/proxy.ts";

interface ReceivedRequest {
  body: Buffer;
  headers: IncomingMessage["headers"];
  url: string;
}

function listen(server: Server): Promise<string> {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address() as AddressInfo;
      resolve(`http://127.0.0.1:${port}`);
    });
  });
}

function close(server: Server): Promise<void> {
  return new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())));
}

async function readRequest(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks);
}

test("signed core fetch rejects redirects without forwarding signed headers or streamed bodies", async (t) => {
  const destinationRequests: ReceivedRequest[] = [];
  const destination = createServer(async (req, res) => {
    destinationRequests.push({ body: await readRequest(req), headers: req.headers, url: req.url ?? "" });
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("destination");
  });
  const destinationUrl = await listen(destination);
  let redirectStatus = 301;
  const sourceRequests: ReceivedRequest[] = [];
  const source = createServer(async (req, res) => {
    sourceRequests.push({ body: await readRequest(req), headers: req.headers, url: req.url ?? "" });
    res.writeHead(redirectStatus, { location: `${destinationUrl}/redirect-destination` });
    res.end(`redirect-${redirectStatus}`);
  });
  const sourceUrl = await listen(source);
  t.after(async () => {
    await Promise.all([close(source), close(destination)]);
  });

  for (const status of [301, 302, 303, 307, 308]) {
    redirectStatus = status;
    const body = Buffer.from(`streamed-${status}`);
    await assert.rejects(
      signedCoreFetch(sourceUrl, "signed-core-fetch-secret", "POST", `/redirect-${status}`, {
        body: Readable.from([body]),
        duplex: "half",
        headers: {
          authorization: "Bearer private-token",
          "content-type": "application/octet-stream",
          "x-private-header": `private-${status}`,
        },
        signatureTail: `tail-${status}`,
      }),
      (error) => {
        assert.ok(error instanceof TypeError);
        return true;
      },
    );
    const received = sourceRequests.at(-1)!;
    assert.equal(received.url, `/redirect-${status}`);
    assert.deepEqual(received.body, body);
    assert.equal(received.headers.authorization, "Bearer private-token");
    assert.equal(received.headers["x-private-header"], `private-${status}`);
    assert.equal(typeof received.headers["x-signature"], "string");
    assert.equal(typeof received.headers["x-timestamp"], "string");
    assert.equal(destinationRequests.length, 0);
    assert.equal(
      destinationRequests.reduce((total, request) => total + request.body.length, 0),
      0,
    );
    assert.deepEqual(
      destinationRequests.flatMap((request) => [
        request.headers.authorization,
        request.headers["x-private-header"],
        request.headers["x-signature"],
        request.headers["x-timestamp"],
      ]),
      [],
    );
  }
});

test("signed core fetch preserves direct response and body semantics", async (t) => {
  const capture: { received?: ReceivedRequest } = {};
  const source = createServer(async (req, res) => {
    capture.received = { body: await readRequest(req), headers: req.headers, url: req.url ?? "" };
    res.writeHead(201, { "content-type": "application/json", "x-core-response": "direct" });
    res.end(JSON.stringify({ ok: true }));
  });
  const sourceUrl = await listen(source);
  t.after(() => close(source));

  const response = await signedCoreFetch(sourceUrl, "signed-core-fetch-secret", "POST", "/direct", {
    body: JSON.stringify({ value: 1 }),
    headers: { "x-direct-caller": "yes" },
  });
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("x-core-response"), "direct");
  assert.deepEqual(await response.json(), { ok: true });
  assert.equal(capture.received?.url, "/direct");
  assert.equal(capture.received?.body.toString(), JSON.stringify({ value: 1 }));
  assert.equal(capture.received?.headers["content-type"], "application/json");
  assert.equal(capture.received?.headers["x-direct-caller"], "yes");
  assert.equal(typeof capture.received?.headers["x-signature"], "string");
  assert.equal(typeof capture.received?.headers["x-timestamp"], "string");
});

test("the deployment proxy preserves signed streaming request and response semantics", async (t) => {
  const capture: { received?: ReceivedRequest } = {};
  const core = createServer(async (req, res) => {
    capture.received = { body: await readRequest(req), headers: req.headers, url: req.url ?? "" };
    res.writeHead(202, { "content-type": "application/octet-stream", "x-core-stream": "yes" });
    res.write("stream-");
    res.end("response");
  });
  const coreUrl = await listen(core);
  const proxy = createServer((req, res) => {
    proxyToDeployment(req, res, {
      coreBase: coreUrl,
      id: "app",
      subPath: "/upload",
      search: "?q=1",
      principal: "alice",
      signingSecret: "deployment-proxy-secret",
    });
  });
  const proxyUrl = await listen(proxy);
  t.after(async () => {
    await Promise.all([close(proxy), close(core)]);
  });

  const body = Buffer.alloc(1024 * 1024, 7);
  const response = await fetch(`${proxyUrl}/upload`, {
    method: "POST",
    headers: { "content-type": "application/octet-stream" },
    body,
  });
  assert.equal(response.status, 202);
  assert.equal(response.headers.get("x-core-stream"), "yes");
  assert.equal(await response.text(), "stream-response");
  assert.equal(capture.received?.url, "/d/app/upload?q=1");
  assert.equal(capture.received?.body.length, body.length);
  assert.deepEqual(capture.received?.body, body);
  assert.equal(capture.received?.headers["x-as-principal"], "alice");
  assert.equal(capture.received?.headers["content-type"], "application/octet-stream");
  assert.equal(typeof capture.received?.headers["x-signature"], "string");
  assert.equal(typeof capture.received?.headers["x-timestamp"], "string");
});
