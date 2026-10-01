# Tauri Plugin crypto

This project is a Tauri plugin which allows for hardware KeyStore (Secure Enclave (iOS) & StrongBox (Android)) control and management on iOS and Android devices with a consistent API.

It also keeps secrets: `seal` turns a piece of text into one opaque string that only the same device can read back, and `open` reads it. Every answer says what is holding the key it used.

| Platform | Sign & verify | Seal & open | What holds the key                                 |
| -------- | ------------- | ----------- | -------------------------------------------------- |
| Linux    | x             | ✓           | the keyring, else a key file                       |
| Windows  | x             | ✓           | the TPM, else the system's own protection          |
| macOS    | x             | ✓           | the Secure Enclave, else the keychain, else a file |
| Android  | ✓             | ✓           | StrongBox where the phone has it, else the keystore |
| iOS      | ✓             | ✓           | the Secure Enclave                                 |

An `x` means the call is refused on that platform rather than answered. `generate`, `exists`,
`getPublicKey`, `signPayload` and `verifySignature` reject on a desktop, saying signing keys are
kept on phones and tablets. Sealing works everywhere.

`backing`, on every `seal` and `open`, says where the key lives:

- `hardware` — a key that never leaves a secure element, TPM, StrongBox or Secure Enclave.
- `system` — the operating system's own protected store, bound to this user on this device.
- `software` — a key file under the app's data directory.

A sealed string is `<scheme>:<base64url-without-padding>` — one opaque string, safe to store or send anywhere, readable only by `open` on the device that sealed it.

## API

### Available Commands

```ts
import { generate } from "@sosweetham/tauri-plugin-crypto-hw-api";
async function generate() {
  generate("default")
    .then((returnValue) => {
      genRes = returnValue;
    })
    .catch((error) => {
      genRes = error;
    });
}
```

```ts
import { exists } from "@sosweetham/tauri-plugin-crypto-hw-api";
async function exists() {
  exists("default")
    .then((returnValue) => {
      genRes = returnValue;
    })
    .catch((error) => {
      genRes = error;
    });
}
```

```ts
import { getPublicKey } from "@sosweetham/tauri-plugin-crypto-hw-api";
async function getPublicKey() {
  getPublicKey("default")
    .then((returnValue) => {
      genRes = returnValue;
    })
    .catch((error) => {
      genRes = error;
    });
}
```

```ts
import { signPayload } from "@sosweetham/tauri-plugin-crypto-hw-api";
async function signPayload() {
  signPayload("default")
    .then((returnValue) => {
      genRes = returnValue;
    })
    .catch((error) => {
      genRes = error;
    });
}
```

```ts
import { verifySignature } from "@sosweetham/tauri-plugin-crypto-hw-api";
async function verifySignature() {
  verifySignature("default")
    .then((returnValue) => {
      genRes = returnValue;
    })
    .catch((error) => {
      genRes = error;
    });
}
```

```ts
import { seal } from "@sosweetham/tauri-plugin-crypto-hw-api";
// Keeps a piece of text under a name. The promise rejects if this device
// cannot keep a secret.
const { sealed, backing } = await seal("default", "hunter2");
```

```ts
import { open } from "@sosweetham/tauri-plugin-crypto-hw-api";
// Reads a sealed string back. The promise rejects if nothing is kept under
// that name, or if the string was sealed on another device.
const { plaintext, backing } = await open("default", sealed);
```

```ts
import { remove } from "@sosweetham/tauri-plugin-crypto-hw-api";
// Removes the sealing key, so nothing sealed with it opens again. Removing a
// name nothing is kept under resolves to false.
const removed = await remove("default");
```

### Default Permission

This permission set configures which
crypto features are by default exposed.

##### Granted Permissions

It allows access to all crypto commands.

##### This default permission set includes the following:

- `allow-generate`
- `allow-exists`
- `allow-get-public-key`
- `allow-sign-payload`
- `allow-verify-signature`
- `allow-seal`
- `allow-open`
- `allow-delete`

### Permission Table

<table>
<tr>
<th>Identifier</th>
<th>Description</th>
</tr>


<tr>
<td>

`crypto-hw:allow-delete`

</td>
<td>

Enables the delete command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-delete`

</td>
<td>

Denies the delete command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-exists`

</td>
<td>

Enables the exists command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-exists`

</td>
<td>

Denies the exists command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-generate`

</td>
<td>

Enables the generate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-generate`

</td>
<td>

Denies the generate command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-get-public-key`

</td>
<td>

Enables the get_public_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-get-public-key`

</td>
<td>

Denies the get_public_key command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-open`

</td>
<td>

Enables the open command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-open`

</td>
<td>

Denies the open command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-seal`

</td>
<td>

Enables the seal command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-seal`

</td>
<td>

Denies the seal command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-sign-payload`

</td>
<td>

Enables the sign_payload command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-sign-payload`

</td>
<td>

Denies the sign_payload command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:allow-verify-signature`

</td>
<td>

Enables the verify_signature command without any pre-configured scope.

</td>
</tr>

<tr>
<td>

`crypto-hw:deny-verify-signature`

</td>
<td>

Denies the verify_signature command without any pre-configured scope.

</td>
</tr>
</table>
