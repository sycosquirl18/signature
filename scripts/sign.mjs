import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import { createEnvelope, encodePayload } from "./protocol.mjs";
import { readSecret } from "./terminal-secret.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const args = process.argv.slice(2);
let filePath;
const messageParts = [];

for (let index = 0; index < args.length; index += 1) {
  if (args[index] === "--file") {
    filePath = args[index + 1];
    index += 1;
  } else {
    messageParts.push(args[index]);
  }
}

let message;
if (filePath) {
  message = await readFile(path.resolve(filePath), "utf8");
} else if (messageParts.length > 0) {
  message = messageParts.join(" ");
} else if (!process.stdin.isTTY) {
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
  }
  message = Buffer.concat(chunks).toString("utf8");
} else {
  throw new Error('Usage: npm run sign -- "Your message" or npm run sign -- --file message.txt');
}

const passphrase = await readSecret("Private-key passphrase: ");
const privateKeyPem = await readFile(path.join(root, ".keys", "private-key.pem"), "utf8");
const privateKey = createPrivateKey({ key: privateKeyPem, format: "pem", passphrase });
const publicJwk = createPublicKey(privateKey).export({ format: "jwk" });
const publicKeyBytes = Buffer.from(publicJwk.x, "base64url");

const verifierConfig = await import("../site/config.js");
if (verifierConfig.PUBLIC_KEY_BASE64URL !== publicJwk.x) {
  throw new Error("The private key does not match the public key configured in site/config.js.");
}

const envelopeBytes = createEnvelope(message, publicKeyBytes);
const signatureBytes = sign(null, envelopeBytes, privateKey);
const payload = encodePayload(envelopeBytes, signatureBytes);
const { baseUrl } = JSON.parse(await readFile(path.join(root, "signer.config.json"), "utf8"));
const verificationUrl = new URL(baseUrl);
verificationUrl.hash = payload;

console.log("\nSigned verification link:\n");
console.log(verificationUrl.href);

