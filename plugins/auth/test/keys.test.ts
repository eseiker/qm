import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { importJWK, jwtVerify, SignJWT } from "jose";
import { ID_TOKEN_ALG, loadSigningKey } from "../src/keys.ts";

function noncanonicalAlias(value: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  const index = alphabet.indexOf(value.at(-1)!);
  assert.equal(index % 4, 0);
  return `${value.slice(0, -1)}${alphabet[index + 1]}`;
}

test("a signing-only private JWK produces an importable verification JWK", async () => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateJwk = { ...privateKey.export({ format: "jwk" }), key_ops: ["sign"] };
  const signingKey = await loadSigningKey(privateJwk);

  assert.equal(signingKey.publicJwk.kty, privateJwk.kty);
  assert.equal(signingKey.publicJwk.crv, privateJwk.crv);
  assert.equal(signingKey.publicJwk.x, privateJwk.x);
  assert.equal(signingKey.publicJwk.y, privateJwk.y);
  assert.equal(signingKey.publicJwk.d, undefined);
  assert.equal(signingKey.publicJwk.key_ops, undefined);
  assert.equal(signingKey.publicJwk.kid, signingKey.kid);
  assert.equal(signingKey.publicJwk.use, "sig");
  assert.equal(signingKey.publicJwk.alg, ID_TOKEN_ALG);

  const token = await new SignJWT({ verified: true })
    .setProtectedHeader({ alg: ID_TOKEN_ALG, kid: signingKey.kid })
    .sign(signingKey.privateKey);
  const verificationKey = await importJWK(signingKey.publicJwk, ID_TOKEN_ALG);
  const { payload } = await jwtVerify(token, verificationKey, { algorithms: [ID_TOKEN_ALG] });

  assert.equal(payload.verified, true);
});

test("EC public coordinates require canonical unpadded base64url", async (t) => {
  const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const privateJwk = privateKey.export({ format: "jwk" });
  const x = privateJwk.x!;
  const alias = noncanonicalAlias(x);

  assert.equal(Buffer.from(alias, "base64url").toString("base64url"), x);

  for (const [name, malformed] of [
    ["padding", `${x}=`],
    ["junk", `${x}$`],
    ["whitespace", `${x.slice(0, 5)}\n${x.slice(5)}`],
    ["noncanonical trailing bits", alias],
    ["wrong decoded size", x.slice(1)],
  ] as const) {
    await t.test(name, async () => {
      await assert.rejects(
        loadSigningKey({ ...privateJwk, x: malformed }),
        /AUTH_SIGNING_JWK x must be canonical unpadded base64url encoding of 32 bytes/,
      );
    });
  }

  await assert.rejects(
    loadSigningKey({ ...privateJwk, y: `${privateJwk.y!}=` }),
    /AUTH_SIGNING_JWK y must be canonical unpadded base64url encoding of 32 bytes/,
  );
});

test("EC public coordinate sizes follow the declared curve", async () => {
  const p256 = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey.export({ format: "jwk" });
  const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey.export({ format: "jwk" });

  await assert.rejects(
    loadSigningKey({ ...p384, x: p256.x }),
    /AUTH_SIGNING_JWK x must be canonical unpadded base64url encoding of 48 bytes/,
  );
  await assert.rejects(
    loadSigningKey({ ...p256, crv: "P-224" }),
    /AUTH_SIGNING_JWK must use a supported EC or OKP curve/,
  );
});

test("OKP public coordinates require the same canonical encoding", async () => {
  const { privateKey } = generateKeyPairSync("ed25519");
  const privateJwk = privateKey.export({ format: "jwk" });
  const x = privateJwk.x!;

  await assert.rejects(
    loadSigningKey({ ...privateJwk, x: `${x}=` }),
    /AUTH_SIGNING_JWK x must be canonical unpadded base64url encoding of 32 bytes/,
  );
  await assert.rejects(
    loadSigningKey({ ...privateJwk, x: noncanonicalAlias(x) }),
    /AUTH_SIGNING_JWK x must be canonical unpadded base64url encoding of 32 bytes/,
  );
  await assert.rejects(
    loadSigningKey({ ...privateJwk, crv: "Ed256" }),
    /AUTH_SIGNING_JWK must use a supported EC or OKP curve/,
  );
});
