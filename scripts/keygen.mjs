import { generateKeyPairSync } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { keyFingerprint } from "./protocol.mjs";
import { readSecret } from "./terminal-secret.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const privateKeyPath = path.join(root, ".keys", "private-key.pem");
const verifierConfigPath = path.join(root, "site", "config.js");
const force = process.argv.includes("--force");

try {
  if (!force) {
    await readFile(privateKeyPath);
    throw new Error(`A private key already exists at ${privateKeyPath}. Use --force to replace it.`);
  }
} catch (error) {
  if (error.code !== "ENOENT") {
    throw error;
  }
}

const passphrase = await readSecret("Choose a private-key passphrase: ");
if (passphrase.length < 12) {
  throw new Error("Use a passphrase of at least 12 characters.");
}

const confirmation = await readSecret("Confirm the passphrase: ");
if (passphrase !== confirmation) {
  throw new Error("Passphrases did not match.");
}

const { privateKey, publicKey } = generateKeyPairSync("ed25519");
const privateKeyPem = privateKey.export({
  type: "pkcs8",
  format: "pem",
  cipher: "aes-256-cbc",
  passphrase,
});
const publicJwk = publicKey.export({ format: "jwk" });
const publicKeyBytes = Buffer.from(publicJwk.x, "base64url");

await mkdir(path.dirname(privateKeyPath), { recursive: true });
await writeFile(privateKeyPath, privateKeyPem, { mode: 0o600, flag: force ? "w" : "wx" });

const currentConfig = await readFile(verifierConfigPath, "utf8");
const updatedConfig = currentConfig.replace(
  /export const PUBLIC_KEY_BASE64URL = ".*";/,
  `export const PUBLIC_KEY_BASE64URL = "${publicJwk.x}";`,
);
await writeFile(verifierConfigPath, updatedConfig, "utf8");

console.log("\nKey created.");
console.log(`Private key: ${privateKeyPath}`);
console.log(`Fingerprint: ${keyFingerprint(publicKeyBytes)}`);
console.log("\nCommit and push site/config.js to publish the public key. Never commit the .keys directory.");

