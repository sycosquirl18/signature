import { createHash } from "node:crypto";

export const PROTOCOL_VERSION = 1;
export const ALGORITHM = "Ed25519";

export function toBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

export function fromBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("Invalid base64url value.");
  }
  return Buffer.from(value, "base64url");
}

export function keyId(publicKeyBytes) {
  return createHash("sha256").update(publicKeyBytes).digest().subarray(0, 12).toString("base64url");
}

export function keyFingerprint(publicKeyBytes) {
  return createHash("sha256")
    .update(publicKeyBytes)
    .digest("hex")
    .toUpperCase()
    .match(/.{1,4}/g)
    .join(" ");
}

export function createEnvelope(message, publicKeyBytes, issuedAt = new Date()) {
  if (typeof message !== "string" || message.length === 0) {
    throw new Error("The message must not be empty.");
  }

  return Buffer.from(
    JSON.stringify({
      v: PROTOCOL_VERSION,
      alg: ALGORITHM,
      kid: keyId(publicKeyBytes),
      issuedAt: issuedAt.toISOString(),
      message,
    }),
    "utf8",
  );
}

export function encodePayload(envelopeBytes, signatureBytes) {
  return `v1.${toBase64Url(envelopeBytes)}.${toBase64Url(signatureBytes)}`;
}

export function decodePayload(payload) {
  const parts = payload.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") {
    throw new Error("Unsupported verification payload.");
  }

  return {
    envelopeBytes: fromBase64Url(parts[1]),
    signatureBytes: fromBase64Url(parts[2]),
  };
}

