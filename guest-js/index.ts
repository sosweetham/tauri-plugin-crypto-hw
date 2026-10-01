import { invoke } from "@tauri-apps/api/core";

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The identifier of the keypair to generate
 * @returns A message indicating the result of the operation
 * @description
 * Generates a new keypair with the given identifier. If a keypair with the same identifier already exists, operation will fail, promise will reject but a message string will be returned in all cases.
 * @example
 * ```ts
 * import { generate } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const message = await generate('my-keypair-id');
 * console.log(message);
 * ```
 */
export async function generate(identifier: string): Promise<string> {
	return await invoke<{ message: string }>("plugin:crypto-hw|generate", {
		payload: {
			identifier,
		},
	}).then((r) => r.message);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The identifier of the keypair to check for existence of
 * @returns A boolean indicating whether the keypair exists
 * @description
 * Checks if a keypair with the given identifier exists. If it does, the promise will resolve to true, otherwise it will resolve to false.
 * @example
 * ```ts
 * import { exists } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const keypairExists = await exists('my-keypair-id');
 * console.log(keypairExists); // true or false
 * ```
 */
export async function exists(identifier: string): Promise<boolean> {
	return await invoke<{ exists: boolean }>("plugin:crypto-hw|exists", {
		payload: {
			identifier,
		},
	}).then((r) => r.exists);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The identifier of the public key to retrieve
 * @returns A string representing the public key in multibase hex format
 * @description
 * Retrieves a string based multibase hex representation of the public key associated with the given identifier. If the keypair does not exist, the promise will reject.
 * @example
 * ```ts
 * import { getPublicKey } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const publicKey = await getPublicKey('my-keypair-id');
 * console.log(publicKey); // "0x1234567890abcdef..."
 * ```
 */
export async function getPublicKey(identifier: string): Promise<string> {
	return await invoke<{ publicKey: string }>(
		"plugin:crypto-hw|get_public_key",
		{
			payload: {
				identifier,
			},
		},
	).then((r) => r.publicKey);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The identifier of the private key to retrieve
 * @param payload - The `message` to sign
 * @return A base58btc format string based signature of the payload using the private key associated with the given identifier
 * @description
 * Signs the given payload with the private key associated with the given identifier. The signature is returned as a base58btc format string. If the keypair does not exist, the promise will reject.
 * @example
 * ```ts
 * import { signPayload } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const signature = await signPayload('my-keypair-id', 'Hello, world!');
 * console.log(signature, payload); // "zQ1234567890abcdef..."
 * ```
 */
export async function signPayload(
	identifier: string,
	payload: string,
): Promise<string> {
	return await invoke<{ signature: string }>("plugin:crypto-hw|sign_payload", {
		payload: {
			payload,
			identifier,
		},
	}).then((r) => r.signature);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The identifier of the keypair to verify the signature against
 * @param payload - The `message` to verify
 * @param signature - The base58btc format string signature to verify
 * @returns A boolean indicating whether the signature is valid
 * @description
 * Verifies the given signature against the payload using the public key associated with the given identifier. The signature is expected to be in base58btc format. If the keypair does not exist, the promise will reject.
 * @example
 * ```ts
 * import { verifySignature } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const isValid = await verifySignature('my-keypair-id', 'Hello, world!', 'zQ1234567890abcdef...');
 * console.log(isValid); // true or false
 * ```
 */
export async function verifySignature(
	identifier: string,
	payload: string,
	signature: string,
): Promise<boolean> {
	return await invoke<{ valid: boolean }>("plugin:crypto-hw|verify_signature", {
		payload: {
			identifier,
			payload,
			signature,
		},
	}).then((r) => r.valid);
}

/**
 * What is holding the key a secret was sealed under.
 *
 * - `hardware` — a key that never leaves a secure element, TPM, StrongBox or Secure Enclave.
 * - `system` — the operating system's own protected store, bound to this user on this device.
 * - `software` — a key file under the app's data directory.
 */
export type Backing = "hardware" | "system" | "software";

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The name to keep this secret under
 * @param plaintext - The text to keep
 * @returns The sealed string, and what is holding the key it was sealed under
 * @description
 * Seals a piece of text so that only this device can read it back. The sealing key is created the first time the identifier is used, and is separate from the signing key `generate` makes under the same identifier. The sealed string is `<scheme>:<base64url>` and is safe to store or send anywhere; only `open` on this device can turn it back into text.
 * @example
 * ```ts
 * import { seal } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const { sealed, backing } = await seal('my-secret-id', 'hunter2');
 * console.log(sealed, backing); // "ecies-p256:BFq...", "hardware"
 * ```
 */
export async function seal(
	identifier: string,
	plaintext: string,
): Promise<{ sealed: string; backing: Backing }> {
	return await invoke<{ sealed: string; backing: Backing }>(
		"plugin:crypto-hw|seal",
		{
			payload: {
				identifier,
				plaintext,
			},
		},
	);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The name the secret was sealed under
 * @param sealed - The string `seal` returned
 * @returns The text, and what is holding the key it was sealed under
 * @description
 * Reads a sealed string back as text. The promise rejects if nothing is kept under that identifier, or if the string was sealed on another device or in another way.
 * @example
 * ```ts
 * import { open } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const { plaintext } = await open('my-secret-id', sealed);
 * console.log(plaintext); // "hunter2"
 * ```
 */
export async function open(
	identifier: string,
	sealed: string,
): Promise<{ plaintext: string; backing: Backing }> {
	return await invoke<{ plaintext: string; backing: Backing }>(
		"plugin:crypto-hw|open",
		{
			payload: {
				identifier,
				sealed,
			},
		},
	);
}

/**
 * @author SoSweetHam <sosweetham@gmail.com>
 * @param identifier - The name the secret was sealed under
 * @returns Whether there was a sealing key to remove
 * @description
 * Removes the sealing key kept under this identifier, so anything sealed with it can no longer be opened. Removing a name nothing is kept under succeeds and resolves to false.
 * @example
 * ```ts
 * import { remove } from '@sosweetham/tauri-plugin-crypto-hw-api'
 * const removed = await remove('my-secret-id');
 * console.log(removed); // true or false
 * ```
 */
export async function remove(identifier: string): Promise<boolean> {
	return await invoke<{ deleted: boolean }>("plugin:crypto-hw|delete", {
		payload: {
			identifier,
		},
	}).then((r) => r.deleted);
}
