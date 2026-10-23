package org.merino

/** merino-c14n (SPEC 3). Accepts Map<String, *>, List<*>, String, Int, Long, Boolean and null. No floating point. */
object C14n {
    const val MAX_INT = 9007199254740991L
    private val KEY = Regex("[a-z0-9_]{1,32}")

    class Error(msg: String) : IllegalArgumentException(msg)

    fun encode(v: Any?): ByteArray = StringBuilder().also { enc(v, it) }.toString().toByteArray(Charsets.UTF_8)

    fun string(v: Any?): String = StringBuilder().also { enc(v, it) }.toString()

    private fun str(s: String, out: StringBuilder) {
        out.append('"')
        for (ch in s) {
            when {
                ch == '"' -> out.append("\\\"")
                ch == '\\' -> out.append("\\\\")
                ch.code < 0x20 -> out.append("\\u%04x".format(ch.code))
                else -> out.append(ch)
            }
        }
        out.append('"')
    }

    private fun enc(v: Any?, out: StringBuilder) {
        when (v) {
            null -> out.append("null")
            is Boolean -> out.append(if (v) "true" else "false")
            is Int, is Long -> {
                val n = (v as Number).toLong()
                if (n < -MAX_INT || n > MAX_INT) throw Error("integer out of range")
                out.append(n)
            }
            is String -> str(v, out)
            is List<*> -> {
                out.append('[')
                v.forEachIndexed { i, x -> if (i > 0) out.append(','); enc(x, out) }
                out.append(']')
            }
            is Map<*, *> -> {
                val keys = v.keys.map { k -> (k as? String)?.takeIf { KEY.matches(it) } ?: throw Error("bad key $k") }
                out.append('{')
                keys.sorted().forEachIndexed { i, k ->
                    if (i > 0) out.append(',')
                    str(k, out); out.append(':'); enc(v[k], out)
                }
                out.append('}')
            }
            else -> throw Error("unsupported type ${v::class.simpleName}")
        }
    }
}
