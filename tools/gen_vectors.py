"""Regenerate vectors/*.json from the Python reference engine. Deterministic (fixed seeds)."""
import hashlib
import io
import json
import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
from merino import c14n, ed25519, envelope, geo, ledger, media  # noqa: E402

OUT = os.path.join(os.path.dirname(__file__), "..", "vectors")


def dump(name, obj):
    with open(os.path.join(OUT, name + ".json"), "w") as f:
        json.dump(obj, f, indent=1, ensure_ascii=False)
        f.write("\n")


r = random.Random(20261023)

dump("c14n", [{"value": v, "c14n": c14n.encode(v).decode()} for v in [
    {"b": 1, "a": [True, False, None, -0, 9007199254740991]},
    {"s": "quote\" back\\ nl\n tab\t unié emoji\U0001F32A ctl\u001f del\u007f"},
    [], {}, "", -9007199254740991,
    {"realm": "liftcharge", "geo": {"type": "point", "p": [44982372, -93209765], "prec": 1000}},
]] + [{"reject": v} for v in [1.5, {"A": 1}, {"": 1}, 9007199254740992, {"a" * 33: 1}]])

eds = []
for seed_hex, msg_hex in [("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", ""),
                          ("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "af82")]:
    seed, msg = bytes.fromhex(seed_hex), bytes.fromhex(msg_hex)
    eds.append({"seed": seed_hex, "pub": ed25519.public_key(seed).hex(), "msg": msg_hex, "sig": ed25519.sign(seed, msg).hex()})
for i in range(6):
    seed, msg = bytes(r.getrandbits(8) for _ in range(32)), bytes(r.getrandbits(8) for _ in range(r.randint(0, 200)))
    eds.append({"seed": seed.hex(), "pub": ed25519.public_key(seed).hex(), "msg": msg.hex(), "sig": ed25519.sign(seed, msg).hex()})
dump("ed25519", eds)

dump("lon_mult", geo.LON_MULT)

snaps = []
edge = [(0, 0), (90_000_000, 180_000_000), (-90_000_000, -180_000_000), (44985072, -93214144),
        (-33868820, 151209290), (89_999_999, 179_999_999), (1, -1), (-1, 1)]
pts = edge + [(r.randint(-90_000_000, 90_000_000), r.randint(-180_000_000, 180_000_000)) for _ in range(120)]
for la, lo in pts:
    for m in geo.LEVELS.values():
        snaps.append([la, lo, m] + list(geo.snap(la, lo, m)))
dump("snaps", {"cols": ["lat", "lon", "m", "lat_c", "lon_c"], "rows": snaps})

paths = []
for k in range(6):
    la, lo, t = r.randint(-60_000_000, 60_000_000), r.randint(-170_000_000, 170_000_000), 1_790_000_000_000 + k * 7_777
    raw = []
    for i in range(r.randint(20, 120)):
        la += r.randint(-1500, 1500); lo += r.randint(-1500, 1500); t += r.randint(3_000, 60_000)
        raw.append([la, lo, t, r.choice([3, 8, 15, 40, 150])])
    zones = [{"lat": raw[len(raw) // 2][0], "lon": raw[len(raw) // 2][1], "radius_m": 150}] if k % 2 else []
    m = [100, 1000][k % 2]
    paths.append({"points": raw, "m": m, "gran": 15, "zones": zones, "keep_time": k != 4,
                  "out": geo.reduce_path([tuple(p) for p in raw], m, 15, zones, keep_time=k != 4)})
dump("paths", paths)

polys = []
for k in range(4):
    la, lo = r.randint(-60_000_000, 60_000_000), r.randint(-170_000_000, 170_000_000)
    v = [[la + r.randint(-20000, 20000), lo + r.randint(-20000, 20000)] for _ in range(r.randint(3, 12))]
    polys.append({"vertices": v, "m": 100, "out": geo.reduce_polygon([tuple(x) for x in v], 100)})
dump("polygons", polys)

zone_cases = []
zones = [{"lat": 44985000, "lon": -93214000, "radius_m": 200}, {"lat": 45100000, "lon": -93300000, "radius_m": 3000}]
for la, lo, m in [(44985100, -93214100, 1), (44990000, -93214000, 1000), (45000000, -93214000, 1000),
                  (45100000, -93300000, 1), (46000000, -93000000, 100)]:
    zone_cases.append({"lat": la, "lon": lo, "m": m, "zones": zones, "out": geo.reduce_point(la, lo, m, zones)})
dump("points", zone_cases)

env_seed = bytes(range(32))
env = {"v": 1, "realm": "liftcharge", "kind": "report", "nonce": envelope.b64u(bytes(16)), "t": 29833330,
       "geo": {"type": "point", "p": [44982372, -93209765], "prec": 1000},
       "body": {"type": "Hail", "magnitude": "1.00 in", "notes": "Pea to marble é"},
       "media": [{"sha256": "ab" * 32, "mime": "image/jpeg", "bytes": 1234}],
       "key": envelope.b64u(ed25519.public_key(env_seed))}
raw = envelope.DOMAIN + c14n.encode(env)
dump("envelope", {"seed": env_seed.hex(), "env": env, "c14n": c14n.encode(env).decode(), "hash": envelope.env_hash(env),
                  "sig": envelope.b64u(ed25519.sign(env_seed, raw))})

srv_seed = b"\x07" * 32
import sqlite3  # noqa: E402
c = sqlite3.connect(":memory:")
ledger.schema(c)
recs = [ledger.append(c, "liftcharge", srv_seed, k, hashlib.sha256(bytes([i])).hexdigest(), 29833330 + i * 5, a)
        for i, (k, a) in enumerate([("report", "key"), ("flag", "key"), ("hide", "sys:flags"), ("unhide", "op:andrew"), ("delete", "key")])]
dump("ledger", {"server_seed": srv_seed.hex(), "server_pub": envelope.b64u(ed25519.public_key(srv_seed)), "receipts": recs})


def jpeg_with_exif():
    from PIL import Image
    im = Image.new("RGB", (8, 8), (10, 20, 30))
    ex = Image.Exif()
    ex[0x010f] = "MakerX"
    b = io.BytesIO()
    im.save(b, "JPEG", exif=ex.tobytes(), comment=b"hello", quality=90)
    return b.getvalue()


def png_with_text():
    from PIL import Image
    from PIL.PngImagePlugin import PngInfo
    p = PngInfo()
    p.add_text("Comment", "where")
    b = io.BytesIO()
    Image.new("RGB", (4, 4), (1, 2, 3)).save(b, "PNG", pnginfo=p)
    return b.getvalue()


import base64  # noqa: E402
mv = []
for name, data in (("jpeg", jpeg_with_exif()), ("png", png_with_text())):
    mime, clean = media.clean(data)
    mv.append({"name": name, "mime": mime, "in": base64.b64encode(data).decode(), "out": base64.b64encode(clean).decode(),
               "sha256": hashlib.sha256(clean).hexdigest()})
mp4 = os.environ.get("MERINO_MP4")
if mp4 and os.path.exists(mp4):
    data = open(mp4, "rb").read()
    if len(data) < 60000:
        mime, clean = media.clean(data)
        mv.append({"name": "mp4", "mime": mime, "in": base64.b64encode(data).decode(), "out": base64.b64encode(clean).decode(),
                   "sha256": hashlib.sha256(clean).hexdigest()})
dump("media", mv)
print("ok", len(snaps), "snaps", len(paths), "paths")

# SPEC 4.6 keyed rounding. Its own generator so adding it left every earlier vector unchanged.
rk = random.Random(20261024)
keyed = []
for k in range(3):
    key = bytes(rk.getrandbits(8) for _ in range(32))
    rows = []
    for la, lo in edge + [(rk.randint(-90_000_000, 90_000_000), rk.randint(-180_000_000, 180_000_000)) for _ in range(40)]:
        for m in (100, 1000, 5000, 25000):
            rows.append([la, lo, m] + list(geo.keyed_snap(la, lo, m, key)))
    keyed.append({"key": key.hex(), "cols": ["lat", "lon", "m", "lat_k", "lon_k"], "rows": rows})
dump("keyed", keyed)
