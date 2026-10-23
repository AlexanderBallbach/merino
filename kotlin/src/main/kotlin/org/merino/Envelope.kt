package org.merino

import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/** Envelopes, receipts, marks and disclosures (SPEC 7-8). */
object Envelope {
    private val DOMAIN = "merino/1\n".toByteArray()
    private val LEDGER_DOMAIN = "merino-ledger/1\n".toByteArray()
    private val DISCLOSE_DOMAIN = "merino-disclose/1\n".toByteArray()
    private val rng = SecureRandom()

    fun b64u(b: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(b)
    fun unb64u(s: String): ByteArray = Base64.getUrlDecoder().decode(s)
    fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it.toInt() and 0xFF) }
    fun unhex(s: String) = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
    fun sha256(vararg parts: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").run { parts.forEach { update(it) }; digest() }

    /** A fresh signing seed. By default every report gets its own, so reports cannot be linked to each other. */
    fun newSeed(): ByteArray = ByteArray(32).also { rng.nextBytes(it) }

    fun mediaEntry(clean: ByteArray, mime: String): Map<String, Any> =
        mapOf("sha256" to hex(sha256(clean)), "mime" to mime, "bytes" to clean.size)

    /** Build and sign. Returns the wire map {"env", "sig"} (serialise it with C14n.string or any JSON writer). */
    fun build(realm: String, kind: String, seed: ByteArray, t: Long, geo: Map<String, Any>? = null,
              body: Map<String, Any?>? = null, media: List<Map<String, Any>> = emptyList(), ref: String? = null,
              nonce: ByteArray = ByteArray(16).also { rng.nextBytes(it) }): Map<String, Any> {
        val env = linkedMapOf<String, Any>("v" to 1, "realm" to realm, "kind" to kind, "nonce" to b64u(nonce), "t" to t,
                                           "key" to b64u(Ed25519.publicKey(seed)))
        if (geo != null) env["geo"] = geo
        if (body != null) env["body"] = body
        if (media.isNotEmpty()) env["media"] = media
        if (ref != null) env["ref"] = ref
        return mapOf("env" to env, "sig" to b64u(Ed25519.sign(seed, DOMAIN + C14n.encode(env))))
    }

    fun hash(env: Map<String, Any?>): String = hex(sha256(C14n.encode(env)))

    fun verify(wire: Map<String, Any?>): Boolean {
        @Suppress("UNCHECKED_CAST") val env = wire["env"] as? Map<String, Any?> ?: return false
        val key = env["key"] as? String ?: return false
        val sig = wire["sig"] as? String ?: return false
        return try { Ed25519.verify(unb64u(key), DOMAIN + C14n.encode(env), unb64u(sig)) } catch (e: Exception) { false }
    }

    /** Body for a flag/confirm: sha256(install secret || target hash). The install secret never leaves the device. */
    fun markBody(installSecret: ByteArray, target: String): Map<String, Any> =
        mapOf("fh" to hex(sha256(installSecret, target.toByteArray())))

    fun discloseSig(seed: ByteArray, subject: String, data: Map<String, String>): String =
        b64u(Ed25519.sign(seed, DISCLOSE_DOMAIN + subject.toByteArray() + "\n".toByteArray() + C14n.encode(data)))

    /** Check a server receipt: entry hash matches and the realm key signed it. */
    fun verifyReceipt(serverPub: ByteArray, receipt: Map<String, Any?>): Boolean = try {
        @Suppress("UNCHECKED_CAST") val entry = receipt["entry"] as Map<String, Any?>
        val h = receipt["hash"] as String
        hex(sha256(C14n.encode(entry))) == h && Ed25519.verify(serverPub, LEDGER_DOMAIN + unhex(h), unb64u(receipt["sig"] as String))
    } catch (e: Exception) { false }

    /** Unix minutes floored to the realm granularity (SPEC 5). */
    fun coarseMinute(epochMs: Long, granularityMin: Int): Long = Math.floorDiv(Math.floorDiv(epochMs, 60_000L), granularityMin.toLong()) * granularityMin
}
