package org.merino

import java.io.ByteArrayOutputStream

/**
 * Media cleaning (SPEC 6). Runs on the device before the file is hashed into an envelope; the server only checks.
 * Removes metadata at the container level (EXIF/XMP/ICC/COM in JPEG, text/time chunks in PNG, udta/meta in MP4)
 * without re-encoding, so it is exact and cheap. Apps should still re-encode photos to a sane size first.
 */
object Media {
    class Error(msg: String) : IllegalArgumentException(msg)

    private val JPEG_KEEP = setOf(0xE0, 0xEE, 0xDB, 0xC4, 0xCC, 0xDD, 0xDC) + ((0xC0..0xCF).toSet() - 0xC8)
    private val PNG_DROP = setOf("tEXt", "zTXt", "iTXt", "eXIf", "tIME")
    private val MP4_BLANK = setOf("udta", "meta")
    private val MP4_CONTAINERS = setOf("moov", "trak")
    private const val SCAN = -1
    private val PNG_SIG = byteArrayOf(0x89.toByte(), 'P'.code.toByte(), 'N'.code.toByte(), 'G'.code.toByte(), 13, 10, 26, 10)

    private fun u8(b: ByteArray, i: Int) = b[i].toInt() and 0xFF
    private fun u16(b: ByteArray, i: Int) = (u8(b, i) shl 8) or u8(b, i + 1)
    private fun u32(b: ByteArray, i: Int) = (u16(b, i).toLong() shl 16) or u16(b, i + 2).toLong()
    private fun ascii(b: ByteArray, i: Int) = String(b, i, 4, Charsets.ISO_8859_1)

    fun sniff(b: ByteArray): String? = when {
        b.size >= 3 && u8(b, 0) == 0xFF && u8(b, 1) == 0xD8 && u8(b, 2) == 0xFF -> "image/jpeg"
        b.size >= 8 && b.copyOfRange(0, 8).contentEquals(PNG_SIG) -> "image/png"
        b.size >= 12 && ascii(b, 4) == "ftyp" -> "video/mp4"
        else -> null
    }

    /** (marker, start, end) for every segment through SOS, then (SCAN, start, end) for entropy-coded data. */
    private fun jpegSegments(b: ByteArray): List<Triple<Int, Int, Int>> {
        if (b.size < 2 || u8(b, 0) != 0xFF || u8(b, 1) != 0xD8) throw Error("not a jpeg")
        val out = ArrayList<Triple<Int, Int, Int>>()
        var i = 2
        while (i < b.size) {
            if (u8(b, i) != 0xFF) throw Error("bad marker")
            while (i < b.size && u8(b, i) == 0xFF) i++
            if (i >= b.size) throw Error("truncated")
            val mk = u8(b, i); i++
            if (mk == 0xD9) { out.add(Triple(mk, i - 2, i)); return out }
            if (mk in 0xD0..0xD7 || mk == 0x01) { out.add(Triple(mk, i - 2, i)); continue }
            if (i + 2 > b.size) throw Error("truncated")
            val n = u16(b, i)
            if (n < 2 || i + n > b.size) throw Error("bad length")
            out.add(Triple(mk, i - 2, i + n))
            i += n
            if (mk == 0xDA) {
                var j = i
                while (j + 1 < b.size) {
                    val nx = u8(b, j + 1)
                    if (u8(b, j) == 0xFF && nx != 0x00 && nx != 0xFF && nx !in 0xD0..0xD7) break
                    j++
                }
                out.add(Triple(SCAN, i, j))
                i = j
            }
        }
        return out
    }

    private fun keep(mk: Int) = mk == SCAN || mk in JPEG_KEEP || mk == 0xDA || mk == 0xD9 || mk == 0x01 || mk in 0xD0..0xD7

    fun jpegClean(b: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(b.size)
        out.write(0xFF); out.write(0xD8)
        for ((mk, s, e) in jpegSegments(b)) if (keep(mk)) out.write(b, s, e - s)
        return out.toByteArray()
    }

    fun jpegIsClean(b: ByteArray) = jpegSegments(b).all { keep(it.first) }

    private fun pngChunks(b: ByteArray): List<Triple<String, Int, Int>> {
        if (sniff(b) != "image/png") throw Error("not a png")
        val out = ArrayList<Triple<String, Int, Int>>()
        var i = 8
        while (i + 12 <= b.size) {
            val n = u32(b, i)
            val t = ascii(b, i + 4)
            if (i + 12 + n > b.size) throw Error("bad chunk")
            out.add(Triple(t, i, (i + 12 + n).toInt()))
            i += (12 + n).toInt()
            if (t == "IEND") return out
        }
        throw Error("no IEND")
    }

    fun pngClean(b: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(b.size)
        out.write(b, 0, 8)
        for ((t, s, e) in pngChunks(b)) if (t !in PNG_DROP) out.write(b, s, e - s)
        return out.toByteArray()
    }

    fun pngIsClean(b: ByteArray) = pngChunks(b).none { it.first in PNG_DROP }

    private fun mp4Walk(b: ByteArray, start: Int, end: Int, fix: ByteArray?): Boolean {
        var dirty = false
        var i = start
        while (i + 8 <= end) {
            var size = u32(b, i)
            val typ = ascii(b, i + 4)
            var hdr = 8
            if (size == 1L) {
                if (i + 16 > end) throw Error("bad box")
                size = (u32(b, i + 8) shl 32) or u32(b, i + 12); hdr = 16
            } else if (size == 0L) size = (end - i).toLong()
            if (size < hdr || i + size > end) throw Error("bad box")
            val e = (i + size).toInt()
            if (typ in MP4_BLANK) {
                dirty = true
                if (fix != null) {
                    "free".toByteArray(Charsets.ISO_8859_1).copyInto(fix, i + 4)
                    java.util.Arrays.fill(fix, i + hdr, e, 0)
                }
            } else if (typ in MP4_CONTAINERS) {
                dirty = dirty or mp4Walk(b, i + hdr, e, fix)
            }
            i = e
        }
        return dirty
    }

    fun mp4Clean(b: ByteArray): ByteArray {
        if (sniff(b) != "video/mp4") throw Error("not an mp4")
        val fix = b.copyOf()
        mp4Walk(b, 0, b.size, fix)
        return fix
    }

    fun mp4IsClean(b: ByteArray): Boolean {
        if (sniff(b) != "video/mp4") throw Error("not an mp4")
        return !mp4Walk(b, 0, b.size, null)
    }

    /** Clean any supported file. Returns (mime, cleaned bytes); throws Error for anything else. */
    fun clean(b: ByteArray): Pair<String, ByteArray> = when (val t = sniff(b)) {
        "image/jpeg" -> t to jpegClean(b)
        "image/png" -> t to pngClean(b)
        "video/mp4" -> t to mp4Clean(b)
        else -> throw Error("unsupported media")
    }

    fun isClean(b: ByteArray, mime: String): Boolean = sniff(b) == mime && try {
        when (mime) { "image/jpeg" -> jpegIsClean(b); "image/png" -> pngIsClean(b); "video/mp4" -> mp4IsClean(b); else -> false }
    } catch (e: Error) { false }

    /** Clean a video file in place (same size: offsets do not move). For clips too large to hold in memory. */
    fun mp4CleanFile(f: java.io.File) {
        java.io.RandomAccessFile(f, "rw").use { raf ->
            fun walk(start: Long, end: Long) {
                var i = start
                val h = ByteArray(16)
                while (i + 8 <= end) {
                    raf.seek(i); raf.readFully(h, 0, 8)
                    var size = u32(h, 0); val typ = ascii(h, 4); var hdr = 8
                    if (size == 1L) { raf.readFully(h, 8, 8); size = (u32(h, 8) shl 32) or u32(h, 12); hdr = 16 }
                    else if (size == 0L) size = end - i
                    if (size < hdr || i + size > end) throw Error("bad box")
                    if (typ in MP4_BLANK) {
                        raf.seek(i + 4); raf.write("free".toByteArray(Charsets.ISO_8859_1))
                        raf.seek(i + hdr)
                        val zero = ByteArray(65536); var left = size - hdr
                        while (left > 0) { val n = minOf(left, zero.size.toLong()).toInt(); raf.write(zero, 0, n); left -= n }
                    } else if (typ in MP4_CONTAINERS) walk(i + hdr, i + size)
                    i += size
                }
            }
            walk(0, raf.length())
        }
    }
}
