package org.merino

import java.math.BigInteger
import java.security.MessageDigest

/** Ed25519 (RFC 8032) on BigInteger. Small and dependency-free; a few ms per signature is fine for a report. */
object Ed25519 {
    private val P = BigInteger.ONE.shiftLeft(255) - BigInteger.valueOf(19)
    private val L = BigInteger.ONE.shiftLeft(252) + BigInteger("27742317777372353535851937790883648493")
    private val TWO = BigInteger.valueOf(2)
    private val D = (BigInteger.valueOf(-121665) * BigInteger.valueOf(121666).modInverse(P)).mod(P)
    private val I = TWO.modPow((P - BigInteger.ONE).shiftRight(2), P)

    private class Pt(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private val G: Pt = run {
        val gy = (BigInteger.valueOf(4) * BigInteger.valueOf(5).modInverse(P)).mod(P)
        val gx = recoverX(gy, 0)!!
        Pt(gx, gy, BigInteger.ONE, (gx * gy).mod(P))
    }
    private val O = Pt(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)

    private fun sha512(vararg parts: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-512").run { parts.forEach { update(it) }; digest() }

    private fun recoverX(y: BigInteger, sign: Int): BigInteger? {
        if (y >= P) return null
        val x2 = ((y * y - BigInteger.ONE) * (D * y * y + BigInteger.ONE).modInverse(P)).mod(P)
        if (x2.signum() == 0) return if (sign != 0) null else BigInteger.ZERO
        var x = x2.modPow((P + BigInteger.valueOf(3)).shiftRight(3), P)
        if ((x * x - x2).mod(P).signum() != 0) x = (x * I).mod(P)
        if ((x * x - x2).mod(P).signum() != 0) return null
        if (x.testBit(0) != (sign == 1)) x = P - x
        return x
    }

    private fun add(a: Pt, b: Pt): Pt {
        val A = ((a.y - a.x) * (b.y - b.x)).mod(P)
        val B = ((a.y + a.x) * (b.y + b.x)).mod(P)
        val C = (TWO * a.t * b.t * D).mod(P)
        val Dd = (TWO * a.z * b.z).mod(P)
        val E = B - A; val F = Dd - C; val Gg = Dd + C; val H = B + A
        return Pt((E * F).mod(P), (Gg * H).mod(P), (F * Gg).mod(P), (E * H).mod(P))
    }

    private fun mul(s0: BigInteger, p0: Pt): Pt {
        var q = O; var p = p0; var s = s0
        while (s.signum() > 0) {
            if (s.testBit(0)) q = add(q, p)
            p = add(p, p); s = s.shiftRight(1)
        }
        return q
    }

    private fun le(b: ByteArray) = BigInteger(1, b.reversedArray())

    private fun le32(n: BigInteger): ByteArray {
        val be = n.toByteArray().let { if (it.size > 32) it.copyOfRange(it.size - 32, it.size) else it }
        return (ByteArray(32 - be.size) + be).reversedArray()
    }

    private fun compress(p: Pt): ByteArray {
        val zi = p.z.modInverse(P)
        val x = (p.x * zi).mod(P); val y = (p.y * zi).mod(P)
        return le32(if (x.testBit(0)) y.setBit(255) else y)
    }

    private fun decompress(s: ByteArray): Pt? {
        if (s.size != 32) return null
        var y = le(s)
        val sign = if (y.testBit(255)) 1 else 0
        y = y.clearBit(255)
        val x = recoverX(y, sign) ?: return null
        return Pt(x, y, BigInteger.ONE, (x * y).mod(P))
    }

    private fun expand(seed: ByteArray): Pair<BigInteger, ByteArray> {
        require(seed.size == 32) { "seed must be 32 bytes" }
        val h = sha512(seed)
        var a = le(h.copyOfRange(0, 32))
        a = a.and(BigInteger.ONE.shiftLeft(254) - BigInteger.valueOf(8)).setBit(254)
        return a to h.copyOfRange(32, 64)
    }

    fun publicKey(seed: ByteArray): ByteArray = compress(mul(expand(seed).first, G))

    fun sign(seed: ByteArray, msg: ByteArray): ByteArray {
        val (a, prefix) = expand(seed)
        val pub = compress(mul(a, G))
        val r = le(sha512(prefix, msg)).mod(L)
        val R = compress(mul(r, G))
        val k = le(sha512(R, pub, msg)).mod(L)
        return R + le32((r + k * a).mod(L))
    }

    fun verify(pub: ByteArray, msg: ByteArray, sig: ByteArray): Boolean {
        if (pub.size != 32 || sig.size != 64) return false
        val A = decompress(pub) ?: return false
        val R = decompress(sig.copyOfRange(0, 32)) ?: return false
        val s = le(sig.copyOfRange(32, 64))
        if (s >= L) return false
        val k = le(sha512(sig.copyOfRange(0, 32), pub, msg)).mod(L)
        val lhs = mul(s, G); val rhs = add(R, mul(k, A))
        return ((lhs.x * rhs.z - rhs.x * lhs.z).mod(P).signum() == 0) && ((lhs.y * rhs.z - rhs.y * lhs.z).mod(P).signum() == 0)
    }
}
