import { IDENTITY_DISPLAY_NAME, PUBLIC_KEY_BASE64URL } from "./config.js";

const MAX_PAYLOAD_LENGTH = 64 * 1024;

export function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("The link contains invalid encoded data.");
  }

  const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = base64.padEnd(Math.ceil(base64.length / 4) * 4, "=");
  return Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
}

export function parsePayload(payload) {
  if (!payload || payload.length > MAX_PAYLOAD_LENGTH) {
    throw new Error("The verification payload is missing or too large.");
  }

  const parts = payload.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") {
    throw new Error("This verification-link version is not supported.");
  }

  return {
    envelopeBytes: decodeBase64Url(parts[1]),
    signatureBytes: decodeBase64Url(parts[2]),
  };
}

async function expectedKeyId(publicKeyBytes) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKeyBytes));
  return bytesToBase64Url(digest.slice(0, 12));
}

function bytesToBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export async function verifyPayload(payload, publicKeyBase64Url = PUBLIC_KEY_BASE64URL) {
  if (!publicKeyBase64Url) {
    throw new Error("This verifier has not been configured with a public key.");
  }

  const { envelopeBytes, signatureBytes } = parsePayload(payload);
  if (signatureBytes.length !== 64) {
    throw new Error("The signature has an invalid length.");
  }

  const publicKeyBytes = decodeBase64Url(publicKeyBase64Url);
  if (publicKeyBytes.length !== 32) {
    throw new Error("The verifier public key is invalid.");
  }

  const publicKey = await crypto.subtle.importKey(
    "raw",
    publicKeyBytes,
    { name: "Ed25519" },
    false,
    ["verify"],
  );
  const valid = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    signatureBytes,
    envelopeBytes,
  );

  if (!valid) {
    return { valid: false };
  }

  const envelope = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(envelopeBytes));
  if (
    envelope === null ||
    typeof envelope !== "object" ||
    envelope.v !== 1 ||
    envelope.alg !== "Ed25519" ||
    envelope.kid !== (await expectedKeyId(publicKeyBytes)) ||
    typeof envelope.issuedAt !== "string" ||
    !Number.isFinite(Date.parse(envelope.issuedAt)) ||
    typeof envelope.message !== "string" ||
    envelope.message.length === 0
  ) {
    throw new Error("The signed envelope is malformed.");
  }

  return { valid: true, envelope };
}

function setState(state) {
  const result = document.querySelector("#result");
  const badge = document.querySelector("#status-badge");
  const title = document.querySelector("#result-title");
  const detail = document.querySelector("#result-detail");
  const message = document.querySelector("#message");
  const metadata = document.querySelector("#metadata");

  result.dataset.state = state.kind;
  badge.textContent = state.badge;
  title.textContent = state.title;
  detail.textContent = state.detail;
  message.textContent = state.message ?? "";
  message.hidden = state.message === undefined;
  metadata.textContent = state.metadata ?? "";
  metadata.hidden = state.metadata === undefined;
}

async function verifyCurrentLink() {
  if (!location.hash) {
    setState({
      kind: "idle",
      badge: "READY",
      title: "Personal message verifier",
      detail: `Open a complete signed link to verify a message from ${IDENTITY_DISPLAY_NAME}.`,
    });
    return;
  }

  setState({
    kind: "working",
    badge: "CHECKING",
    title: "Verifying signature",
    detail: "The signature is being checked locally in this browser.",
  });

  try {
    const result = await verifyPayload(location.hash.slice(1));
    if (!result.valid) {
      setState({
        kind: "invalid",
        badge: "INVALID",
        title: "Signature does not match",
        detail: "Do not trust this message. Its contents or signature have been changed.",
      });
      return;
    }

    setState({
      kind: "valid",
      badge: "VALID",
      title: `Authentic message from ${IDENTITY_DISPLAY_NAME}`,
      detail: "The signature matches the public key pinned in this verifier.",
      message: result.envelope.message,
      metadata: `Signed ${new Date(result.envelope.issuedAt).toLocaleString()} · Key ${result.envelope.kid}`,
    });
  } catch (error) {
    setState({
      kind: "invalid",
      badge: "ERROR",
      title: "This link could not be verified",
      detail: error instanceof Error ? error.message : "An unexpected verification error occurred.",
    });
  }
}

if (typeof document !== "undefined") {
  document.querySelector("#identity").textContent = IDENTITY_DISPLAY_NAME;
  window.addEventListener("hashchange", verifyCurrentLink);
  verifyCurrentLink();
}

