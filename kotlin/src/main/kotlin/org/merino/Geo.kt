package org.merino

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/** Location reduction (SPEC 4). Integer microdegrees; runs on the device before anything is uploaded. */
object Geo {
    const val EXACT = 1
    const val BLOCK = 100
    const val NEIGHBORHOOD = 1000
    const val TOWN = 5000
    const val REGION = 25000
    val LEVELS = listOf(EXACT, BLOCK, NEIGHBORHOOD, TOWN, REGION)

    const val ZONE_MARGIN_M = 500
    const val PATH_TRIM_M = 300
    const val PATH_MAX_ACCURACY_M = 100
    const val POLY_MAX = 2000
    const val PATH_MAX = 20000
    private const val LAT_MAX = 90_000_000L
    private const val LON_MAX = 180_000_000L

    /** ceil(1000 / cos(min(d + 1, 89) deg)); a table so every implementation is bit-identical (vectors/lon_mult.json). */
    val LON_MULT = longArrayOf(1001, 1001, 1002, 1003, 1004, 1006, 1008, 1010, 1013, 1016, 1019, 1023, 1027, 1031, 1036, 1041, 1046, 1052, 1058, 1065, 1072, 1079, 1087, 1095, 1104, 1113, 1123, 1133, 1144, 1155, 1167, 1180, 1193, 1207, 1221, 1237, 1253, 1270, 1287, 1306, 1326, 1346, 1368, 1391, 1415, 1440, 1467, 1495, 1525, 1556, 1590, 1625, 1662, 1702, 1744, 1789, 1837, 1888, 1942, 2000, 2063, 2131, 2203, 2282, 2367, 2459, 2560, 2670, 2791, 2924, 3072, 3237, 3421, 3628, 3864, 4134, 4446, 4810, 5241, 5759, 6393, 7186, 8206, 9567, 11474, 14336, 19108, 28654, 57299, 57299)

    /** A circle the user never wants pinpointed (home, work). Stored only on the device; never uploaded. */
    data class Zone(val lat: Long, val lon: Long, val radiusM: Int)

    /** One GPS fix for a path: microdegrees, epoch ms, accuracy radius in metres (null if unknown). */
    data class Fix(val lat: Long, val lon: Long, val timeMs: Long, val accuracyM: Double?)

    fun toE6(deg: Double): Long = Math.round(deg * 1_000_000)

    fun latStep(m: Int): Long = maxOf(1L, (m * 1_000_000L + 55_660) / 111_320)

    private fun clamp(v: Long, lo: Long, hi: Long) = if (v < lo) lo else if (v > hi) hi else v

    fun snap(lat: Long, lon: Long, m: Int): Pair<Long, Long> {
        val ls = latStep(m)
        val latC = clamp(Math.floorDiv(lat, ls) * ls + ls / 2, -LAT_MAX, LAT_MAX)
        val band = min(89L, Math.abs(latC) / 1_000_000).toInt()
        val lo = min(360_000_000L, ls * LON_MULT[band] / 1000)
        val x = lon + LON_MAX
        val lonC = clamp(Math.floorDiv(x, lo) * lo + lo / 2 - LON_MAX, -LON_MAX, LON_MAX)
        return latC to lonC
    }

    fun onGrid(lat: Long, lon: Long, m: Int) = snap(lat, lon, m) == (lat to lon)

    fun distM(aLat: Long, aLon: Long, bLat: Long, bLon: Long): Double {
        val la1 = Math.toRadians(aLat / 1e6); val lo1 = Math.toRadians(aLon / 1e6)
        val la2 = Math.toRadians(bLat / 1e6); val lo2 = Math.toRadians(bLon / 1e6)
        val s1 = sin((la2 - la1) / 2); val s2 = sin((lo2 - lo1) / 2)
        val h = s1 * s1 + cos(la1) * cos(la2) * s2 * s2
        return 2 * 6_371_000 * asin(min(1.0, sqrt(h)))
    }

    fun inZone(lat: Long, lon: Long, zones: List<Zone>, margin: Int = 0) =
        zones.any { distM(lat, lon, it.lat, it.lon) <= it.radiusM + margin }

    /** Snap a report location. Inside a privacy zone (+500 m) the cell is raised to at least TOWN. */
    fun reducePoint(lat: Long, lon: Long, m: Int, zones: List<Zone> = emptyList()): Map<String, Any> {
        var cell = m
        if (zones.isNotEmpty() && inZone(lat, lon, zones, ZONE_MARGIN_M)) {
            var need = maxOf(m, TOWN)
            zones.filter { distM(lat, lon, it.lat, it.lon) <= it.radiusM + ZONE_MARGIN_M }.forEach { need = maxOf(need, 2 * it.radiusM) }
            cell = LEVELS.firstOrNull { it >= need } ?: REGION
        }
        val (a, b) = snap(lat, lon, cell)
        return mapOf("type" to "point", "p" to listOf(a, b), "prec" to cell)
    }

    /** SPEC 4.4. Returns null when nothing worth uploading is left. */
    fun reducePath(points: List<Fix>, m: Int, t0GranularityMin: Int, zones: List<Zone> = emptyList(),
                   keepTime: Boolean = true, trimM: Int = PATH_TRIM_M): Map<String, Any>? {
        var pts = points.filter { it.accuracyM == null || it.accuracyM <= PATH_MAX_ACCURACY_M }
        if (zones.isNotEmpty()) pts = pts.filter { !inZone(it.lat, it.lon, zones) }
        if (pts.size < 2) return null
        val cum = DoubleArray(pts.size)
        for (i in 1 until pts.size) cum[i] = cum[i - 1] + distM(pts[i - 1].lat, pts[i - 1].lon, pts[i].lat, pts[i].lon)
        val total = cum.last()
        if (total <= 2 * trimM) return null
        pts = pts.filterIndexed { i, _ -> cum[i] >= trimM && cum[i] <= total - trimM }
        if (pts.size < 2) return null
        val tFirst = pts[0].timeMs
        val out = ArrayList<List<Long>>()
        for (p in pts) {
            val (a, b) = snap(p.lat, p.lon, m)
            val dt = if (keepTime) (Math.floorDiv(p.timeMs - tFirst, 1000L) + 30).let { Math.floorDiv(it, 60L) * 60 } else 0L
            if (out.isNotEmpty() && out.last()[0] == a && out.last()[1] == b) continue
            out.add(listOf(a, b, dt))
        }
        if (out.size < 2) return null
        val t0 = if (keepTime) Math.floorDiv(Math.floorDiv(tFirst, 60_000L), t0GranularityMin.toLong()) * t0GranularityMin else 0L
        return mapOf("type" to "path", "p" to out.take(PATH_MAX), "prec" to m, "t0" to t0)
    }

    /** SPEC 4.5. Returns null for a degenerate polygon. */
    fun reducePolygon(vertices: List<Pair<Long, Long>>, m: Int): Map<String, Any>? {
        val out = ArrayList<List<Long>>()
        for ((la, lo) in vertices) {
            val (a, b) = snap(la, lo, m)
            val s = listOf(a, b)
            if (out.isEmpty() || out.last() != s) out.add(s)
        }
        if (out.size > 1 && out.first() == out.last()) out.removeAt(out.size - 1)
        if (out.toSet().size < 3 || out.size > POLY_MAX) return null
        return mapOf("type" to "polygon", "p" to out, "prec" to m)
    }
}
