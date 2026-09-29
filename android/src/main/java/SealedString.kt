package com.plugin.crypto

import android.util.Base64

/** Carries words meant for the person who asked, never for a log. */
internal class Refused(message: String) : Exception(message)

/**
 * The sealed string every platform of this plugin writes: `<scheme>:<base64url-nopad>`.
 * `src/sealed.rs` is the Rust side of the same shape.
 */
internal object SealedString {
    const val SCHEME = "aes-gcm-keystore"
    const val NONCE_LEN = 12

    private const val TAG_LEN = 16
    private const val FLAGS = Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP

    private const val FOREIGN = "This was sealed on a different device or in a different way."
    private const val MALFORMED = "This is not a sealed secret from this app."

    fun of(payload: ByteArray): String = "$SCHEME:" + Base64.encodeToString(payload, FLAGS)

    /** The nonce and ciphertext a sealed string carries. */
    fun payloadOf(sealed: String): ByteArray {
        val bytes = try {
            Base64.decode(payloadTextOf(sealed), FLAGS)
        } catch (notBase64: IllegalArgumentException) {
            throw Refused(MALFORMED)
        }
        if (bytes.size < NONCE_LEN + TAG_LEN) throw Refused(FOREIGN)
        return bytes
    }

    /** Throws [Refused] when the string is not one this backend wrote. */
    fun payloadTextOf(sealed: String): String {
        val colon = sealed.indexOf(':')
        if (colon < 1) throw Refused(MALFORMED)
        if (sealed.substring(0, colon) != SCHEME) throw Refused(FOREIGN)
        return sealed.substring(colon + 1)
    }
}
