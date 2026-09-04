import { calculateJwkThumbprint, importJWK, type JWK } from "jose";

export const ID_TOKEN_ALG = "ES256";

type PrivateSigningKey = Exclude<Awaited<ReturnType<typeof importJWK>>, Uint8Array>;

export interface SigningKey {
  privateKey: PrivateSigningKey;
  publicJwk: JWK;
  kid: string;
}

const coordinateBytes: Readonly<Record<string, number>> = {
  "EC:P-256": 32,
  "EC:P-384": 48,
  "EC:P-521": 66,
  "OKP:Ed25519": 32,
  "OKP:Ed448": 57,
  "OKP:X25519": 32,
  "OKP:X448": 56,
};

function canonicalCoordinate(value: unknown, bytes: number, name: string): string {
  if (typeof value === "string" && /^[A-Za-z0-9_-]+$/.test(value)) {
    const decoded = Buffer.from(value, "base64url");
    if (decoded.length === bytes && decoded.toString("base64url") === value) return value;
  }
  throw new Error(`AUTH_SIGNING_JWK ${name} must be canonical unpadded base64url encoding of ${bytes} bytes`);
}

function publicMaterialFor(jwk: JWK): JWK {
  const { kty, crv } = jwk;
  const bytes = typeof kty === "string" && typeof crv === "string" ? coordinateBytes[`${kty}:${crv}`] : undefined;
  if (bytes === undefined) throw new Error("AUTH_SIGNING_JWK must use a supported EC or OKP curve");
  const x = canonicalCoordinate(jwk.x, bytes, "x");
  if (kty === "OKP") return { kty, crv, x };
  return { kty, crv, x, y: canonicalCoordinate(jwk.y, bytes, "y") };
}

export async function loadSigningKey(jwk: Record<string, unknown>): Promise<SigningKey> {
  const privateMaterial = jwk as JWK;
  const publicMaterial = publicMaterialFor(privateMaterial);
  const kid = await calculateJwkThumbprint(publicMaterial, "sha256");
  const imported = await importJWK({ ...(jwk as JWK), kid }, ID_TOKEN_ALG);
  if (imported instanceof Uint8Array) throw new Error("AUTH_SIGNING_JWK must be an asymmetric private key");
  return {
    privateKey: imported,
    publicJwk: { ...publicMaterial, kid, use: "sig", alg: ID_TOKEN_ALG },
    kid,
  };
}
