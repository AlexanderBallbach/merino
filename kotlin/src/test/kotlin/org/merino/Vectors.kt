package org.merino

import java.io.File
import java.util.Base64

/** Minimal JSON reader for the vector files (numbers -> Long, so they round-trip through C14n). */
class Json(private val s: String) {
    private var i = 0
    fun parse(): Any? = value().also { ws() }
    private fun ws() { while (i < s.length && s[i].isWhitespace()) i++ }
    private fun value(): Any? {
        ws()
        when (s[i]) {
            '{' -> {
                i++; val m = LinkedHashMap<String, Any?>(); ws()
                if (s[i] == '}') { i++; return m }
                while (true) { ws(); val k = str(); ws(); i++; m[k] = value(); ws(); if (s[i++] == '}') return m }
            }
            '[' -> {
                i++; val l = ArrayList<Any?>(); ws()
                if (s[i] == ']') { i++; return l }
                while (true) { l.add(value()); ws(); if (s[i++] == ']') return l }
            }
            '"' -> return str()
            't' -> { i += 4; return true }
            'f' -> { i += 5; return false }
            'n' -> { i += 4; return null }
            else -> {
                val st = i
                while (i < s.length && (s[i] in "-+.eE" || s[i].isDigit())) i++
                val t = s.substring(st, i)
                return if (t.any { it in ".eE" }) t.toDouble() else t.toBigInteger().let { if (it.bitLength() < 63) it.toLong() else it }
            }
        }
    }
    private fun str(): String {
        i++
        val b = StringBuilder()
        while (s[i] != '"') {
            if (s[i] == '\\') {
                i++
                when (val e = s[i++]) {
                    'n' -> b.append('\n'); 't' -> b.append('\t'); 'r' -> b.append('\r'); 'b' -> b.append('\b'); 'f' -> b.append('\u000c')
                    'u' -> { b.append(s.substring(i, i + 4).toInt(16).toChar()); i += 4 }
                    else -> b.append(e)
                }
            } else b.append(s[i++])
        }
        i++
        return b.toString()
    }
}

var failures = 0
var checks = 0
fun check(ok: Boolean, what: () -> String) { checks++; if (!ok) { failures++; if (failures < 20) println("FAIL " + what()) } }

@Suppress("UNCHECKED_CAST")
fun main(args: Array<String>) {
    val dir = File(args.getOrElse(0) { "../vectors" })
    fun load(n: String) = Json(File(dir, "$n.json").readText()).parse()
    fun L(x: Any?) = (x as Number).toLong()
    fun I(x: Any?) = (x as Number).toInt()

    for (c in load("c14n") as List<Map<String, Any?>>) {
        if ("reject" in c) {
            val v = c["reject"]
            check(try { C14n.encode(v); false } catch (e: IllegalArgumentException) { true }) { "c14n should reject $v" }
        } else check(C14n.string(c["value"]) == c["c14n"]) { "c14n ${c["value"]} -> ${C14n.string(c["value"])}" }
    }

    for (c in load("ed25519") as List<Map<String, Any?>>) {
        val seed = Envelope.unhex(c["seed"] as String); val msg = Envelope.unhex(c["msg"] as String)
        check(Envelope.hex(Ed25519.publicKey(seed)) == c["pub"]) { "ed25519 pub" }
        val sig = Ed25519.sign(seed, msg)
        check(Envelope.hex(sig) == c["sig"]) { "ed25519 sig" }
        check(Ed25519.verify(Envelope.unhex(c["pub"] as String), msg, sig)) { "ed25519 verify" }
        check(!Ed25519.verify(Envelope.unhex(c["pub"] as String), msg + byteArrayOf(1), sig)) { "ed25519 verify tampered" }
    }

    val lm = load("lon_mult") as List<Any?>
    check(lm.map { L(it) } == Geo.LON_MULT.toList()) { "lon_mult" }
    for (r in (load("snaps") as Map<String, Any?>)["rows"] as List<List<Any?>>) {
        val got = Geo.snap(L(r[0]), L(r[1]), I(r[2]))
        check(got == (L(r[3]) to L(r[4]))) { "snap $r -> $got" }
    }
    fun zones(z: Any?) = (z as List<Map<String, Any?>>).map { Geo.Zone(L(it["lat"]), L(it["lon"]), I(it["radius_m"])) }
    fun norm(x: Any?): Any? = C14n.string(x)
    for (c in load("paths") as List<Map<String, Any?>>) {
        val pts = (c["points"] as List<List<Any?>>).map { Geo.Fix(L(it[0]), L(it[1]), L(it[2]), (it[3] as Number?)?.toDouble()) }
        val got = Geo.reducePath(pts, I(c["m"]), I(c["gran"]), zones(c["zones"]), c["keep_time"] as Boolean)
        check(norm(got) == norm(c["out"])) { "path m=${c["m"]}: ${norm(got)?.toString()?.take(120)} vs ${norm(c["out"]).toString().take(120)}" }
    }
    for (c in load("polygons") as List<Map<String, Any?>>) {
        val got = Geo.reducePolygon((c["vertices"] as List<List<Any?>>).map { L(it[0]) to L(it[1]) }, I(c["m"]))
        check(norm(got) == norm(c["out"])) { "polygon" }
    }
    for (c in load("keyed") as List<Map<String, Any?>>) {
        val key = Envelope.unhex(c["key"] as String)
        for (r in c["rows"] as List<List<Any?>>) {
            val got = Geo.keyedSnap(L(r[0]), L(r[1]), I(r[2]), key)
            check(got == (L(r[3]) to L(r[4]))) { "keyed $r -> $got" }
        }
    }
    for (c in load("points") as List<Map<String, Any?>>) {
        val got = Geo.reducePoint(L(c["lat"]), L(c["lon"]), I(c["m"]), zones(c["zones"]))
        check(norm(got) == norm(c["out"])) { "point ${c["lat"]},${c["lon"]}: ${norm(got)} vs ${norm(c["out"])}" }
    }

    val e = load("envelope") as Map<String, Any?>
    val env = e["env"] as Map<String, Any?>
    check(C14n.string(env) == e["c14n"]) { "envelope c14n" }
    check(Envelope.hash(env) == e["hash"]) { "envelope hash" }
    check(Envelope.verify(mapOf("env" to env, "sig" to e["sig"]))) { "envelope verify" }
    val seed = Envelope.unhex(e["seed"] as String)
    val rebuilt = Envelope.build("liftcharge", "report", seed, L(env["t"]), env["geo"] as Map<String, Any>,
        env["body"] as Map<String, Any?>, env["media"] as List<Map<String, Any>>, nonce = ByteArray(16))
    check(rebuilt["sig"] == e["sig"]) { "envelope rebuild sig" }

    val led = load("ledger") as Map<String, Any?>
    val spub = Envelope.unb64u(led["server_pub"] as String)
    var prev = "0".repeat(64)
    for (r in led["receipts"] as List<Map<String, Any?>>) {
        check(Envelope.verifyReceipt(spub, r)) { "receipt" }
        check((r["entry"] as Map<String, Any?>)["prev"] == prev) { "chain" }
        prev = r["hash"] as String
    }

    val b64 = Base64.getDecoder()
    for (c in load("media") as List<Map<String, Any?>>) {
        val input = b64.decode(c["in"] as String); val out = b64.decode(c["out"] as String)
        val (mime, got) = Media.clean(input)
        check(mime == c["mime"] && got.contentEquals(out)) { "media ${c["name"]}" }
        check(Media.isClean(out, mime) && !Media.isClean(input, mime)) { "media isClean ${c["name"]}" }
        if (mime == "video/mp4") {
            val f = File.createTempFile("merino", ".mp4"); f.writeBytes(input); Media.mp4CleanFile(f)
            check(f.readBytes().contentEquals(out)) { "mp4 file clean" }; f.delete()
        }
    }

    // properties
    val r = java.util.Random(11)
    repeat(5000) {
        val m = Geo.LEVELS[r.nextInt(5)]
        val la = r.nextInt(180_000_001).toLong() - 90_000_000; val lo = r.nextInt(360_000_001).toLong() - 180_000_000
        val (a, b) = Geo.snap(la, lo, m)
        check(Geo.onGrid(a, b, m)) { "idempotent $la,$lo,$m" }
    }
    val t0 = System.nanoTime()
    val s2 = Envelope.newSeed()
    repeat(5) { Ed25519.sign(s2, "x".toByteArray()) }
    println("sign: %.1f ms".format((System.nanoTime() - t0) / 5e6))

    println("$checks checks, $failures failures")
    if (failures > 0) kotlin.system.exitProcess(1)
}
