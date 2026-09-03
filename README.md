# Personal Signature

A small personal message-signing system with local Ed25519 signing and static,
client-side verification.

- The encrypted private key stays on the signing computer.
- GitHub Pages serves only static HTML, JavaScript, and the public key.
- Verification uses the browser Web Crypto API.
- Signed messages live in the URL fragment, which this page does not transmit
  to the hosting server.
- The verifier displays the exact message covered by the signature.

## Requirements

- Node.js 20 or newer
- A modern browser with Web Crypto Ed25519 support

There are no npm dependencies.

## First-time setup

Clone the repository and generate an encrypted signing key:

```powershell
git clone https://github.com/sycosquirl18/signature.git C:\dev\signature
Set-Location C:\dev\signature
npm run keygen
```

`keygen` asks for a passphrase, writes the encrypted private key to
`.keys\private-key.pem`, and updates `site\config.js` with the corresponding
public key. The `.keys` directory is ignored by Git.

Back up the private key and its passphrase separately. Losing either makes it
impossible to create additional signatures with this identity. Anyone who
obtains both can impersonate the signer.

Publish the public key:

```powershell
git add site\config.js
git commit -m "Configure signing public key"
git push
```

## Sign a message

Sign text supplied on the command line:

```powershell
npm run sign -- "Meet me at 3 PM."
```

Or preserve the exact contents of a text file:

```powershell
npm run sign -- --file .\message.txt
```

The command asks for the private-key passphrase and prints a verification URL:

```text
https://sycosquirl18.github.io/signature/#v1.<envelope>.<signature>
```

Share both the human-readable message and the link. The text displayed by the
verifier is authoritative; surrounding link text is not cryptographically
protected.

## Run locally

Browsers restrict module loading from `file:` URLs, so serve the static files
through a local HTTP server:

```powershell
npx --yes serve site
```

Then open the localhost URL printed by `serve`.

## Test

```powershell
npm test
```

The tests generate temporary in-memory keys and cover valid signatures,
modified messages, and signatures checked with the wrong public key.

## Publish with GitHub Pages

The included `.github\workflows\pages.yml` workflow tests and deploys the
`site` directory.

1. Open the repository on GitHub.
2. Select **Settings → Pages**.
3. Under **Build and deployment**, choose **GitHub Actions** as the source.
4. Run the **Deploy GitHub Pages** workflow, or push to `main`.

The default project-site URL is:

```text
https://sycosquirl18.github.io/signature/
```

If GitHub Pages is unavailable for a private repository on the account's
current plan, make the repository public or deploy the same `site` directory
to another static host.

## Configuration

`signer.config.json` contains the base URL emitted by the local signer. Update
it if the Pages URL or custom domain changes.

`site/config.js` contains the display name and pinned public key. The verifier
never accepts a public key from a signed link.

## Protocol V1

The URL fragment has three period-separated fields:

```text
v1.<base64url envelope bytes>.<base64url Ed25519 signature>
```

The envelope is UTF-8 JSON created in this property order:

```json
{
  "v": 1,
  "alg": "Ed25519",
  "kid": "first 96 bits of SHA-256(public key), base64url encoded",
  "issuedAt": "ISO 8601 timestamp",
  "message": "exact signed message"
}
```

The signature covers the original envelope bytes. The verifier does not parse
and reserialize the envelope before checking it.

## Security boundaries

- A valid result proves that the message was signed by the private key matching
  the public key pinned in the verifier.
- Identity still depends on trusting the GitHub account or custom domain that
  publishes the verifier.
- Compromise of the Pages repository can make the hosted UI lie, but does not
  expose the locally held signing key.
- Signatures do not encrypt messages. Anyone with a verification link can read
  its message.
- Timestamps are informational in V1. Signatures do not expire automatically.
- Rotating the public key invalidates verification of old links unless the old
  verifier or a future multi-key verifier retains that key.

