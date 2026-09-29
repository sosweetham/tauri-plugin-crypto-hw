package com.plugin.crypto

import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.util.Base64
import androidx.annotation.RequiresApi
import app.tauri.BuildConfig

import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val KEYSTORE = "AndroidKeyStore"
private const val TRANSFORMATION = "AES/GCM/NoPadding"
private const val SEALING_KEY_BITS = 256
private const val TAG_BITS = 128

private const val HARDWARE = "hardware"
private const val SYSTEM = "system"

private const val NO_KEYSTORE = "This device cannot keep a secret for the app."
private const val NOT_KEPT = "That secret could not be kept. Try again."
private const val NO_SECRET = "There is no secret kept under that name on this device."
private const val UNREADABLE = "That secret could not be opened. Seal it again."
private const val NOT_REMOVED = "That secret could not be removed. Try again."


//@InvokeArg
//class PingArgs {
//    var value: String? = null
//}

@InvokeArg class IncludesIdentifier {
    var identifier: String? = null
}

@InvokeArg class SignRequest {
    var identifier: String? = null
    var payload: String? = null
}

@InvokeArg class SealRequest {
    var identifier: String? = null
    var plaintext: String? = null
}

@InvokeArg class OpenRequest {
    var identifier: String? = null
    var sealed: String? = null
}

@InvokeArg class VerifySignatureRequest {
    var identifier: String? = null
    var payload: String? = null
    var signature: String? = null
}

@TauriPlugin
class CryptoPlugin(private val activity: Activity): Plugin(activity) {
    private fun alias(id: String) = "${BuildConfig.LIBRARY_PACKAGE_NAME}.$id"

    /** Generate EC keypair in StrongBox; fail if unavailable or exists */
    private fun generateKeyPair(alias: String) {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
            !activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            throw Exception("StrongBox is not available on this device.")
        }
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) throw Exception("Key already exists")
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setIsStrongBoxBacked(true)
            .build()
        try {
            kpg.initialize(spec)
            kpg.generateKeyPair()
        } catch (e: Exception) {
            throw Exception("StrongBox key generation failed: ${e.message}")
        }
    }

    /** Retrieve KeyPair from AndroidKeyStore */
    private fun getKeyPair(alias: String): KeyPair {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        val priv = ks.getKey(alias, null) ?: throw Exception("Private key missing")
        val pub = ks.getCertificate(alias)?.publicKey ?: throw Exception("Public key missing")
        return KeyPair(pub, priv as java.security.PrivateKey)
    }

    @Command
    fun generate(invoke: Invoke) {
        val id = invoke.parseArgs(IncludesIdentifier::class.java).identifier
            ?: return invoke.reject("Missing identifier")
        try {
            generateKeyPair(alias(id))
            invoke.resolve(JSObject().apply { put("message","Key generated successfully") })
        } catch (e: Exception) {
            if (e.message?.contains("exists") == true) {
                invoke.resolve(JSObject().apply { put("message","Key already exists") })
            } else {
                invoke.reject(e.message ?: "Generation failed")
            }
        }
    }

    @Command
    fun exists(invoke: Invoke) {
        val id = invoke.parseArgs(IncludesIdentifier::class.java).identifier
            ?: return invoke.reject("Missing identifier")
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        invoke.resolve(JSObject().apply { put("exists", ks.containsAlias(alias(id))) })
    }

    @Command
    fun getPublicKey(invoke: Invoke) {
        val id = invoke.parseArgs(IncludesIdentifier::class.java).identifier
            ?: return invoke.reject("Missing identifier")
        try {
            val pub = getKeyPair(alias(id)).public.encoded
            val hex = HexUtils.toMultibaseHex(pub)     // 0x… hex output
            invoke.resolve(JSObject().apply { put("publicKey", hex) })
        } catch (e: Exception) {
            invoke.reject("Couldn't retrieve public key")
        }
    }

    @Command
    fun signPayload(invoke: Invoke) {
        val req = invoke.parseArgs(SignRequest::class.java)
        val id = req.identifier ?: return invoke.reject("Missing identifier")
        val payload = req.payload ?: return invoke.reject("Missing payload")
        try {
            val sig = Signature.getInstance("SHA256withECDSA").apply {
                initSign(getKeyPair(alias(id)).private)
                update(payload.toByteArray())
            }.sign()
            val base58Sig = Base58BTC.encode(sig)
            invoke.resolve(JSObject().apply { put("signature", base58Sig) })
        } catch (e: Exception) {
            invoke.reject("Couldn't create signature")
        }
    }

    @Command
    fun verifySignature(invoke: Invoke) {
        val req = invoke.parseArgs(VerifySignatureRequest::class.java)
        val id = req.identifier ?: return invoke.reject("Missing identifier")
        val payload = req.payload ?: return invoke.reject("Missing payload")
        val sig = req.signature ?: return invoke.reject("Missing signature")
        try {
            val sigBytes = Base58BTC.decode(sig) ?: throw Exception("Invalid signature format")
            val verified = Signature.getInstance("SHA256withECDSA").apply {
                initVerify(getKeyPair(alias(id)).public)
                update(payload.toByteArray())
            }.verify(sigBytes)
            invoke.resolve(JSObject().apply { put("valid", verified) })
        } catch (e: Exception) {
            invoke.reject("Couldn't verify signature")
        }
    }

    /** The name this identifier seals under. An identifier is text a person
     *  chose, so it is encoded rather than pasted: a suffix would let one
     *  identifier name another identifier's entry. */
    private fun sealAlias(id: String) =
        "${BuildConfig.LIBRARY_PACKAGE_NAME}.seal." +
            Base64.encodeToString(
                id.toByteArray(Charsets.UTF_8),
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            )

    private fun keyStore(): KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    /** The key this identifier seals under, made the first time it is asked for. */
    private fun sealingKey(alias: String): SecretKey {
        val ks = keyStore()
        if (ks.containsAlias(alias)) return ks.getKey(alias, null) as SecretKey
        // KeyGenParameterSpec, and with it any Keystore key to seal under, arrives in Android 6.
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) throw Refused(NO_KEYSTORE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)) {
            strongBoxSealingKey(alias)?.let { return it }
        }
        return newSealingKey(alias)
    }

    /** Null where the device offers StrongBox but has none left to give out. */
    @RequiresApi(Build.VERSION_CODES.P)
    private fun strongBoxSealingKey(alias: String): SecretKey? = try {
        generateSealingKey(sealingKeySpec(alias).setIsStrongBoxBacked(true).build())
    } catch (noStrongBox: StrongBoxUnavailableException) {
        null
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun newSealingKey(alias: String): SecretKey =
        generateSealingKey(sealingKeySpec(alias).build())

    @RequiresApi(Build.VERSION_CODES.M)
    private fun sealingKeySpec(alias: String) = KeyGenParameterSpec.Builder(
        alias,
        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
    )
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(SEALING_KEY_BITS)
        .setRandomizedEncryptionRequired(true)

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateSealingKey(spec: KeyGenParameterSpec): SecretKey =
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            .apply { init(spec) }
            .generateKey()

    /**
     * Read back off the key rather than remembered. Before Android 12 the Keystore will
     * not say whether a key sits in StrongBox or in the TEE, so a key it will not tell us
     * that much about is reported at the level this device can show.
     */
    private fun backingOf(key: SecretKey): String {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.S) return SYSTEM
        val info = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        return if (info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX) HARDWARE else SYSTEM
    }

    @Command
    fun seal(invoke: Invoke) {
        val req = invoke.parseArgs(SealRequest::class.java)
        val id = req.identifier ?: return invoke.reject("Missing identifier")
        val text = req.plaintext ?: return invoke.reject("Missing text to seal")

        val key = try {
            sealingKey(sealAlias(id))
        } catch (refused: Refused) {
            return invoke.reject(refused.message)
        } catch (failed: Exception) {
            return invoke.reject(NO_KEYSTORE)
        }

        val plaintext = text.toByteArray(Charsets.UTF_8)
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
            val nonce = cipher.iv
            if (nonce.size != SealedString.NONCE_LEN) return invoke.reject(NOT_KEPT)
            invoke.resolve(JSObject().apply {
                put("sealed", SealedString.of(nonce + cipher.doFinal(plaintext)))
                put("backing", backingOf(key))
            })
        } catch (failed: Exception) {
            invoke.reject(NOT_KEPT)
        } finally {
            plaintext.fill(0)
        }
    }

    @Command
    fun open(invoke: Invoke) {
        val req = invoke.parseArgs(OpenRequest::class.java)
        val id = req.identifier ?: return invoke.reject("Missing identifier")
        val sealed = req.sealed ?: return invoke.reject("Missing sealed secret")

        val payload = try {
            SealedString.payloadOf(sealed)
        } catch (refused: Refused) {
            return invoke.reject(refused.message)
        }

        val key = try {
            val ks = keyStore()
            val entry = sealAlias(id)
            if (!ks.containsAlias(entry)) return invoke.reject(NO_SECRET)
            ks.getKey(entry, null) as SecretKey
        } catch (missing: Exception) {
            return invoke.reject(NO_SECRET)
        }

        var plaintext: ByteArray? = null
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION).apply {
                init(
                    Cipher.DECRYPT_MODE,
                    key,
                    GCMParameterSpec(TAG_BITS, payload, 0, SealedString.NONCE_LEN)
                )
            }
            val opened = cipher.doFinal(
                payload,
                SealedString.NONCE_LEN,
                payload.size - SealedString.NONCE_LEN
            )
            plaintext = opened
            invoke.resolve(JSObject().apply {
                put("plaintext", String(opened, Charsets.UTF_8))
                put("backing", backingOf(key))
            })
        } catch (failed: Exception) {
            invoke.reject(UNREADABLE)
        } finally {
            plaintext?.fill(0)
        }
    }

    @Command
    fun delete(invoke: Invoke) {
        val id = invoke.parseArgs(IncludesIdentifier::class.java).identifier
            ?: return invoke.reject("Missing identifier")
        try {
            val ks = keyStore()
            val seal = sealAlias(id)
            val deleted = ks.containsAlias(seal)
            if (deleted) ks.deleteEntry(seal)
            // The signing key `generate` made under the same identifier goes too, but the
            // answer is about the secret alone: a caller reads it as "a secret was removed".
            val signing = alias(id)
            if (ks.containsAlias(signing)) ks.deleteEntry(signing)
            invoke.resolve(JSObject().apply { put("deleted", deleted) })
        } catch (failed: Exception) {
            invoke.reject(NOT_REMOVED)
        }
    }
}
