package com.plugin.crypto

import org.junit.Assert.assertEquals
import org.junit.Test

private const val FOREIGN = "This was sealed on a different device or in a different way."
private const val MALFORMED = "This is not a sealed secret from this app."

class SealedStringTest {
    private fun refusal(sealed: String): String? = try {
        SealedString.payloadTextOf(sealed)
        null
    } catch (refused: Refused) {
        refused.message
    }

    @Test
    fun takesThePayloadOutOfAStringThisBackendWrote() {
        assertEquals("AAAA", SealedString.payloadTextOf("${SealedString.SCHEME}:AAAA"))
        assertEquals("", SealedString.payloadTextOf("${SealedString.SCHEME}:"))
    }

    @Test
    fun sendsAStringAnotherBackendWroteBackToWhereItCameFrom() {
        assertEquals(FOREIGN, refusal("ecies-p256:AAAA"))
        assertEquals(FOREIGN, refusal("dpapi:AAAA"))
        assertEquals(FOREIGN, refusal("aes-gcm-software:AAAA"))
    }

    @Test
    fun readsTheSchemeExactly() {
        assertEquals(FOREIGN, refusal("AES-GCM-KEYSTORE:AAAA"))
        assertEquals(FOREIGN, refusal("aes-gcm-keystore2:AAAA"))
        assertEquals(FOREIGN, refusal(" aes-gcm-keystore:AAAA"))
    }

    @Test
    fun refusesAStringThatIsNotTwoPartsAtAll() {
        assertEquals(MALFORMED, refusal(""))
        assertEquals(MALFORMED, refusal("aes-gcm-keystore"))
        assertEquals(MALFORMED, refusal(":AAAA"))
    }
}
