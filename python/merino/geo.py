"""Location reduction (SPEC section 4). Integer microdegrees throughout; no floats in anything that is hashed."""
import hashlib
import hmac
import math

LEVELS = {"exact": 1, "block": 100, "neighborhood": 1000, "town": 5000, "region": 25000}
LEVEL_OF = {m: n for n, m in LEVELS.items()}

# ceil(1000 / cos(min(d + 1, 89) deg)) for d = 0..89. Fixed table, so every implementation is bit-identical.
LON_MULT = [math.ceil(1000 / math.cos(math.radians(min(d + 1, 89))) - 1e-9) for d in range(90)]

LAT_MAX, LON_MAX = 90_000_000, 180_000_000
ZONE_MARGIN_M = 500
PATH_TRIM_M = 300
PATH_MAX_ACCURACY_M = 100
POLY_MAX = 2000
PATH_MAX = 20000


def _clamp(v, lo, hi):
    return lo if v < lo else hi if v > hi else v


def lat_step(m):
    return max(1, (m * 1_000_000 + 55_660) // 111_320)   # round half up of m * 1e6 / 111320


def snap(lat, lon, m):
    """Centre of the grid cell of size m metres that holds (lat, lon) microdegrees."""
    ls = lat_step(m)
    lat_c = _clamp((lat // ls) * ls + ls // 2, -LAT_MAX, LAT_MAX)
    band = min(89, abs(lat_c) // 1_000_000)
    lo = min(360_000_000, ls * LON_MULT[band] // 1000)
    x = lon + LON_MAX
    lon_c = _clamp((x // lo) * lo + lo // 2 - LON_MAX, -LON_MAX, LON_MAX)
    return lat_c, lon_c


def on_grid(lat, lon, m):
    return snap(lat, lon, m) == (lat, lon)


def _h64(key, *parts):
    d = hmac.new(key, "|".join(str(p) for p in parts).encode(), hashlib.sha256).digest()
    return int.from_bytes(d[:8], "big"), int.from_bytes(d[8:16], "big")


def keyed_snap(lat, lon, m, key):
    """SPEC 4.6. A point in the same-sized cell, but on a grid shifted by a device secret, at a keyed spot inside
    the cell rather than its centre: no visible grid, no one-way drift, and still the same answer every time."""
    ls = lat_step(m)
    oa, ob = _h64(key, "merino-keyed-offset", m)
    oy = oa % ls
    i = (lat - oy) // ls
    s = i * ls + oy
    band = min(89, abs(_clamp(s + ls // 2, -LAT_MAX, LAT_MAX)) // 1_000_000)
    lo = min(360_000_000, ls * LON_MULT[band] // 1000)
    ox = ob % lo
    j = (lon + LON_MAX - ox) // lo
    w = j * lo + ox
    pa, pb = _h64(key, "merino-keyed-point", m, i, j)
    return _clamp(s + pa % ls, -LAT_MAX, LAT_MAX), _clamp(w + pb % lo - LON_MAX, -LON_MAX, LON_MAX)


def _snapper(m, key):
    """Exact (1 m) has nothing to hide, so it always uses the plain grid."""
    if key and m > 1:
        return lambda la, lo: keyed_snap(la, lo, m, key)
    return lambda la, lo: snap(la, lo, m)


def _mode(g, m, key):
    if key and m > 1:
        g["mode"] = "keyed"
    return g


def to_e6(deg):
    return int(round(deg * 1_000_000))


def valid(lat, lon):
    return isinstance(lat, int) and isinstance(lon, int) and -LAT_MAX <= lat <= LAT_MAX and -LON_MAX <= lon <= LON_MAX


def dist_m(a, b):
    """Haversine metres between two (lat_e6, lon_e6). Used for decisions on the device, never hashed."""
    la1, lo1, la2, lo2 = (math.radians(v / 1e6) for v in (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * 6_371_000 * math.asin(min(1.0, math.sqrt(h)))


def in_zone(pt, zones, margin=0):
    return any(dist_m(pt, (z["lat"], z["lon"])) <= z["radius_m"] + margin for z in zones)


def reduce_point(lat, lon, m, zones=(), key=None):
    """Device-side point reduction: snap, raising the cell to at least 'town' inside a privacy zone."""
    if zones and in_zone((lat, lon), zones, ZONE_MARGIN_M):
        m = max(m, LEVELS["town"], *[2 * z["radius_m"] for z in zones if dist_m((lat, lon), (z["lat"], z["lon"])) <= z["radius_m"] + ZONE_MARGIN_M])
        m = min((v for v in LEVELS.values() if v >= m), default=LEVELS["region"])
    la, lo = _snapper(m, key)(lat, lon)
    return _mode({"type": "point", "p": [la, lo], "prec": m}, m, key)


def reduce_path(points, m, t0_granularity_min, zones=(), keep_time=True, trim_m=PATH_TRIM_M, key=None):
    """points: [(lat_e6, lon_e6, unix_ms, accuracy_m or None)] in time order. Returns a geo dict or None (too short)."""
    pts = [p for p in points if p[3] is None or p[3] <= PATH_MAX_ACCURACY_M]
    pts = [p for p in pts if not (zones and in_zone(p, zones))]
    if len(pts) < 2:
        return None
    # trim the first and last trim_m metres of travelled distance
    cum = [0.0]
    for a, b in zip(pts, pts[1:]):
        cum.append(cum[-1] + dist_m(a, b))
    total = cum[-1]
    if trim_m and total <= 2 * trim_m:
        return None
    pts = [p for p, c in zip(pts, cum) if trim_m <= c <= total - trim_m]
    if len(pts) < 2:
        return None
    t_first = pts[0][2]
    sn = _snapper(m, key)
    out = []
    for p in pts:
        la, lo = sn(p[0], p[1])
        dt = ((p[2] - t_first) // 1000 + 30) // 60 * 60 if keep_time else 0
        if out and out[-1][0] == la and out[-1][1] == lo:
            continue
        out.append([la, lo, dt])
    if len(out) < 2:
        return None
    out = out[:PATH_MAX]
    t0 = (t_first // 60000) // t0_granularity_min * t0_granularity_min if keep_time else 0
    return _mode({"type": "path", "p": out, "prec": m, "t0": t0}, m, key)


def reduce_polygon(vertices, m, key=None):
    """vertices: [(lat_e6, lon_e6)]. Returns a geo dict or None (degenerate)."""
    sn = _snapper(m, key)
    out = []
    for la, lo in vertices:
        s = list(sn(la, lo))
        if not out or out[-1] != s:
            out.append(s)
    if len(out) > 1 and out[0] == out[-1]:
        out.pop()
    if len({tuple(v) for v in out}) < 3 or len(out) > POLY_MAX:
        return None
    return _mode({"type": "polygon", "p": out, "prec": m}, m, key)


def check_geo(g, min_prec):
    """Server-side re-check (never a re-transform): the geo is well formed, coarse enough, and every point on its grid.
    A keyed geo (SPEC 4.6) is on a grid only its device knows, so its declared precision is taken as given."""
    if not isinstance(g, dict) or g.get("prec") not in LEVEL_OF or g["prec"] < min_prec:
        return "precision"
    grid = on_grid
    if "mode" in g:
        if g["mode"] != "keyed" or g["prec"] == 1:
            return "mode"
        g = {k: v for k, v in g.items() if k != "mode"}
        grid = lambda la, lo, m: True   # noqa: E731
    t, pts, m = g.get("type"), g.get("p"), g["prec"]
    if t == "point":
        if set(g) != {"type", "p", "prec"} or not isinstance(pts, list) or len(pts) != 2 or not valid(*pts):
            return "point"
        return None if grid(pts[0], pts[1], m) else "off_grid"
    if t == "path":
        if set(g) != {"type", "p", "prec", "t0"} or not isinstance(g["t0"], int) or not isinstance(pts, list) or not 2 <= len(pts) <= PATH_MAX:
            return "path"
        last = -1
        for q in pts:
            if not isinstance(q, list) or len(q) != 3 or not valid(q[0], q[1]) or not isinstance(q[2], int) or q[2] < last or q[2] % 60:
                return "path"
            last = q[2]
            if not grid(q[0], q[1], m):
                return "off_grid"
        return None
    if t == "polygon":
        if set(g) != {"type", "p", "prec"} or not isinstance(pts, list) or not 3 <= len(pts) <= POLY_MAX:
            return "polygon"
        for q in pts:
            if not isinstance(q, list) or len(q) != 2 or not valid(*q):
                return "polygon"
            if not grid(q[0], q[1], m):
                return "off_grid"
        return None
    return "type"
