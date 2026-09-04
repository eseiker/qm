import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type Server, type Socket } from "node:net";
import type { QmConfig } from "../src/config.ts";
import { CliError } from "../src/log.ts";
import { emailTransportPreflight, nodeEngineProblem, smtpVerify, SmtpRejectedError } from "../src/preflight.ts";

const CONFIG: QmConfig = {
  contract: 1,
  orgId: "acme",
  publicUrl: "http://localhost:8080",
  target: "docker",
  services: ["core", "auth"],
  plugins: [],
  skills: [],
  env: {},
  imageOverrides: {},
  sandbox: { backend: "local" },
};

async function quietAsync(fn: () => Promise<void>): Promise<string[]> {
  const lines: string[] = [];
  const log = console.log,
    warnFn = console.warn;
  console.log = (...args: unknown[]): void => void lines.push(args.join(" "));
  console.warn = (...args: unknown[]): void => void lines.push(args.join(" "));
  try {
    await fn();
    return lines;
  } finally {
    console.log = log;
    console.warn = warnFn;
  }
}

test("nodeEngineProblem accepts a satisfying version and rejects an older one", () => {
  assert.equal(nodeEngineProblem(">=24.15.0", "package.json", "v24.15.0"), undefined);
  assert.equal(nodeEngineProblem(">=24.0.0", "package.json", "v24.13.0"), undefined);
  const problem = nodeEngineProblem(">=24.15.0", "the repo package.json", "v24.13.0");
  assert.ok(problem?.includes("v24.13.0"));
  assert.ok(problem?.includes(">=24.15.0"));
  assert.ok(problem?.includes("the repo package.json"));
});

interface FakeSmtp {
  server: Server;
  port: number;
  close: () => Promise<void>;
}

function fakeSmtp(password: string): Promise<FakeSmtp> {
  const server = createServer((socket: Socket) => {
    socket.write("220 fake ESMTP\r\n");
    let buffer = "";
    socket.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let index: number;
      while ((index = buffer.indexOf("\r\n")) !== -1) {
        const line = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        if (line.startsWith("EHLO")) socket.write("250-fake\r\n250 AUTH PLAIN LOGIN\r\n");
        else if (line.startsWith("AUTH PLAIN")) {
          const decoded = Buffer.from(line.slice("AUTH PLAIN ".length), "base64").toString("utf8");
          socket.write(decoded === `\0user\0${password}` ? "235 ok\r\n" : "535 auth failed\r\n");
        } else if (line === "QUIT") {
          socket.write("221 bye\r\n");
          socket.end();
        } else socket.write("502 what\r\n");
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve({
        server,
        port: typeof address === "object" && address ? address.port : 0,
        close: () => new Promise((done) => server.close(() => done())),
      });
    });
  });
}

test("smtpVerify authenticates without sending mail and rejects bad credentials", async () => {
  const smtp = await fakeSmtp("right");
  try {
    await smtpVerify({ host: "127.0.0.1", port: smtp.port, username: "user", password: "right", tls: "none" });
    await assert.rejects(
      () => smtpVerify({ host: "127.0.0.1", port: smtp.port, username: "user", password: "wrong", tls: "none" }),
      SmtpRejectedError,
    );
  } finally {
    await smtp.close();
  }
});

test("email preflight fails check on rejected SMTP credentials and warns on stray transport vars", async () => {
  const smtp = await fakeSmtp("right");
  const config = {
    ...CONFIG,
    env: { auth: { AUTH_EMAIL_TRANSPORT: "smtp", SMTP_PORT: String(smtp.port), SMTP_TLS: "none" } },
  };
  try {
    const okLines = await quietAsync(() =>
      emailTransportPreflight(
        config,
        new Map([
          ["SMTP_HOST", "127.0.0.1"],
          ["SMTP_USERNAME", "user"],
          ["SMTP_PASSWORD", "right"],
          ["RESEND_API_KEY", "re_unused"],
        ]),
      ),
    );
    assert.ok(okLines.some((line) => line.includes("credentials accepted")));
    assert.ok(okLines.some((line) => line.includes("RESEND_API_KEY is set but")));
    await assert.rejects(
      () =>
        emailTransportPreflight(
          config,
          new Map([
            ["SMTP_HOST", "127.0.0.1"],
            ["SMTP_USERNAME", "user"],
            ["SMTP_PASSWORD", "wrong"],
          ]),
        ),
      (e: unknown) => {
        assert.ok(e instanceof CliError);
        assert.ok(e.message.includes("sign-in links cannot be sent"));
        return true;
      },
    );
  } finally {
    await smtp.close();
  }
});

test("email preflight warns when SMTP values are set but the transport is resend", async () => {
  const config = { ...CONFIG, env: { auth: { AUTH_EMAIL_TRANSPORT: "resend" } } };
  const lines = await quietAsync(() =>
    emailTransportPreflight(
      config,
      new Map([
        ["SMTP_HOST", "smtp.example.com"],
        ["SMTP_PASSWORD", "hunter2"],
      ]),
    ),
  );
  assert.ok(lines.some((line) => line.includes('set but env.auth.AUTH_EMAIL_TRANSPORT is "resend"')));
});

test("email preflight does nothing without the auth service", async () => {
  const lines = await quietAsync(() =>
    emailTransportPreflight({ ...CONFIG, services: ["core"] }, new Map([["RESEND_API_KEY", "re_x"]])),
  );
  assert.deepEqual(lines, []);
});
