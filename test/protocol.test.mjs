import { generateKeyPairSync, sign } from "node:crypto";
import test from "node:test";
import assert from "node:assert/strict";
import { createEnvelope, encodePayload } from "../scripts/protocol.mjs";
import { verifyPayload } from "../site/app.js";

test("browser verifier accepts a valid signed message", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicKeyBytes = Buffer.from(publicJwk.x, "base64url");
  const envelopeBytes = createEnvelope(
    "Meet me at 3 PM.",
    publicKeyBytes,
    new Date("2026-09-02T22:00:00.000Z"),
  );
  const signatureBytes = sign(null, envelopeBytes, privateKey);
  const payload = encodePayload(envelopeBytes, signatureBytes);

  const result = await verifyPayload(payload, publicJwk.x);

  assert.equal(result.valid, true);
  assert.equal(result.envelope.message, "Meet me at 3 PM.");
  assert.equal(result.envelope.issuedAt, "2026-09-02T22:00:00.000Z");
});

test("browser verifier rejects a modified message", async () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  const publicKeyBytes = Buffer.from(publicJwk.x, "base64url");
  const envelopeBytes = createEnvelope("Original", publicKeyBytes);
  const signatureBytes = sign(null, envelopeBytes, privateKey);
  const payload = encodePayload(envelopeBytes, signatureBytes);
  const [version, encodedEnvelope, encodedSignature] = payload.split(".");
  const modifiedEnvelope = Buffer.from(encodedEnvelope, "base64url")
    .toString("utf8")
    .replace("Original", "Modified");
  const modifiedPayload = `${version}.${Buffer.from(modifiedEnvelope).toString("base64url")}.${encodedSignature}`;

  const result = await verifyPayload(modifiedPayload, publicJwk.x);

  assert.deepEqual(result, { valid: false });
});

test("browser verifier rejects a different public key", async () => {
  const signer = generateKeyPairSync("ed25519");
  const other = generateKeyPairSync("ed25519");
  const signerJwk = signer.publicKey.export({ format: "jwk" });
  const otherJwk = other.publicKey.export({ format: "jwk" });
  const envelopeBytes = createEnvelope("Original", Buffer.from(signerJwk.x, "base64url"));
  const signatureBytes = sign(null, envelopeBytes, signer.privateKey);

  const result = await verifyPayload(encodePayload(envelopeBytes, signatureBytes), otherJwk.x);

  assert.deepEqual(result, { valid: false });
});

