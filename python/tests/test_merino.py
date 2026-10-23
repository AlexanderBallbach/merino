import hashlib
import io
import json
import os
import random
import tempfile
import threading
import unittest
import urllib.request

from merino import c14n, ed25519, envelope, geo, ledger, media, policy, store, timeq
from merino.envelope import Reject
from merino.ratelimit import Limiter

NOW = 1_790_000_000  # a fixed clock (unix s)


class Clock:
    def __init__(self, t=NOW):
        self.t = t

    def __call__(self):
        return self.t


class C14n(unittest.TestCase):
    def test_canonical(self):
        self.assertEqual(c14n.encode({"b": [1, -2, True, None], "a": "x\"\\\né"}),
                         b'{"a":"x\\"\\\\\\u000a\xc3\xa9","b":[1,-2,true,null]}')

    def test_rejects(self):
        for bad in (1.5, {"A": 1}, {"a-b": 1}, 2 ** 53, {"x" * 33: 1}):
            with self.assertRaises(c14n.C14nError):
                c14n.encode(bad)


class Ed(unittest.TestCase):
    def test_rfc8032_1(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pk = ed25519.public_key(sk)
        self.assertEqual(pk.hex(), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig = ed25519.sign(sk, b"")
        self.assertTrue(sig.hex().startswith("e5564300c360ac729086e2cc806e828a"))
        self.assertTrue(ed25519.verify(pk, b"", sig))
        self.assertFalse(ed25519.verify(pk, b"x", sig))
        self.assertFalse(ed25519.verify(pk, b"", sig[:63] + bytes([sig[63] ^ 1])))


class Geo(unittest.TestCase):
    def test_snap_idempotent_random(self):
        r = random.Random(7)
        for _ in range(3000):
            m = r.choice(list(geo.LEVELS.values()))
            la, lo = r.randint(-90_000_000, 90_000_000), r.randint(-180_000_000, 180_000_000)
            a = geo.snap(la, lo, m)
            self.assertEqual(geo.snap(*a, m), a, (la, lo, m))
            self.assertTrue(geo.on_grid(*a, m))

    def test_known(self):
        self.assertEqual(geo.snap(44985072, -93214144, 1000), (44982372, -93209765))

    def test_same_cell_same_output(self):
        a = geo.snap(44985072, -93214144, 1000)
        self.assertEqual(geo.snap(44985072 + 300, -93214144 - 300, 1000), a)

    def test_zone_raises(self):
        zones = [{"lat": 44985000, "lon": -93214000, "radius_m": 200}]
        self.assertEqual(geo.reduce_point(44985100, -93214100, 1, zones)["prec"], 5000)
        self.assertEqual(geo.reduce_point(45985100, -93214100, 1, zones)["prec"], 1)

    def test_path(self):
        pts = [(44_980_000 + i * 900, -93_200_000, 1_700_000_000_000 + i * 20_000, 5) for i in range(60)]
        pts[10] = pts[10][:3] + (500,)   # bad accuracy, dropped
        g = geo.reduce_path(pts, 100, 15)
        self.assertIsNone(geo.check_geo(g, 100))
        first_lat = min(q[0] for q in g["p"])
        self.assertGreater(first_lat - 44_980_000, 2_000)   # ~300 m trimmed from the start
        self.assertEqual(g["p"][0][2], 0)
        self.assertEqual(g["t0"] % 15, 0)
        self.assertIsNone(geo.reduce_path(pts[:3], 100, 15))

    def test_path_zone(self):
        pts = [(44_980_000 + i * 900, -93_200_000, i * 20_000, 5) for i in range(60)]
        zone = [{"lat": 44_980_000 + 30 * 900, "lon": -93_200_000, "radius_m": 300}]
        g = geo.reduce_path(pts, 100, 15, zone)
        for q in g["p"]:
            self.assertGreater(geo.dist_m((q[0], q[1]), (zone[0]["lat"], zone[0]["lon"])), 240)

    def test_polygon(self):
        g = geo.reduce_polygon([(1000, 1000), (1001, 1001), (5_000_000, 0), (0, 5_000_000), (1000, 1000)], 100)
        self.assertEqual(len(g["p"]), 3)
        self.assertIsNone(geo.check_geo(g, 100))
        self.assertIsNone(geo.reduce_polygon([(0, 0), (1, 1), (2, 2)], 100))

    def test_check(self):
        self.assertEqual(geo.check_geo({"type": "point", "p": [44985072, -93214144], "prec": 1000}, 1), "off_grid")
        self.assertEqual(geo.check_geo({"type": "point", "p": [0, 0], "prec": 100}, 1000), "precision")


class Media(unittest.TestCase):
    def test_jpeg_png(self):
        from PIL import Image
        from PIL.PngImagePlugin import PngInfo
        im = Image.new("RGB", (32, 24), (9, 90, 200))
        ex = Image.Exif()
        ex[0x0110] = "SECRET-MODEL"
        b = io.BytesIO()
        im.save(b, "JPEG", exif=ex.tobytes(), comment=b"SECRET-COM")
        j = b.getvalue()
        c = media.jpeg_clean(j)
        self.assertFalse(media.jpeg_is_clean(j))
        self.assertTrue(media.jpeg_is_clean(c))
        self.assertNotIn(b"SECRET", c)
        Image.open(io.BytesIO(c)).load()
        info = PngInfo()
        info.add_text("where", "SECRET")
        b = io.BytesIO()
        im.save(b, "PNG", pnginfo=info)
        mime, c = media.clean(b.getvalue())
        self.assertEqual(mime, "image/png")
        self.assertNotIn(b"SECRET", c)
        self.assertTrue(media.is_clean(c, mime))


def make_jpeg(color=(1, 2, 3)):
    from PIL import Image
    b = io.BytesIO()
    Image.new("RGB", (16, 16), color).save(b, "JPEG")
    return media.jpeg_clean(b.getvalue())


class ServerBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.srv = store.Server(os.path.join(self.tmp.name, "m.db"), policy.REALMS,
                                {"liftcharge": b"\1" * 32, "aether": b"\2" * 32},
                                os.path.join(self.tmp.name, "media"), clock=self.clock)
        self.t = timeq.coarsen(timeq.minute(NOW), 5)

    def tearDown(self):
        self.srv.c.close()
        self.tmp.cleanup()

    def report(self, seed=None, media_=(), ref=None, typ="Hail", t=None):
        seed = seed or os.urandom(32)
        g = geo.reduce_point(44985072, -93214144, 1000)
        return seed, envelope.build("liftcharge", "report", seed, self.t if t is None else t, g,
                                    {"type": typ, "magnitude": "1.00 in", "notes": ""}, media_, ref)


class Server(ServerBase):
    def test_submit_query_receipt_chain(self):
        _, w = self.report()
        out = self.srv.submit(w, "1.2.3.4")
        self.assertFalse(out["duplicate"])
        self.assertTrue(ledger.verify_receipt(self.srv.pub("liftcharge"), out["receipt"]))
        self.assertEqual(self.srv.submit(w)["receipt"], out["receipt"])  # retry is idempotent
        items = self.srv.query("liftcharge", (44_000_000, -94_000_000, 46_000_000, -93_000_000))
        self.assertEqual([i["hash"] for i in items], [out["hash"]])
        self.assertEqual(self.srv.query("liftcharge", (0, 0, 1, 1)), [])
        for _ in range(3):
            self.srv.submit(self.report()[1])
        rows = self.srv.ledger("liftcharge")
        self.assertTrue(ledger.verify_chain(self.srv.pub("liftcharge"), rows, prev=ledger.ZERO))
        rows[1]["entry"]["subject"] = "0" * 64
        self.assertFalse(ledger.verify_chain(self.srv.pub("liftcharge"), rows))

    def test_rejections(self):
        seed, w = self.report()
        bad = json.loads(json.dumps(w))
        bad["env"]["body"]["notes"] = "edited"
        self.assertRaisesRegex(Reject, "signature", self.srv.submit, bad)
        cases = [
            ("time", envelope.build("liftcharge", "report", seed, self.t + 1, geo.reduce_point(0, 0, 1000), {"type": "Hail"})),
            ("time", envelope.build("liftcharge", "report", seed, self.t + 60, geo.reduce_point(0, 0, 1000), {"type": "Hail"})),
            ("geo", envelope.build("liftcharge", "report", seed, self.t, {"type": "point", "p": [1, 1], "prec": 1000}, {"type": "Hail"})),
            ("body", envelope.build("liftcharge", "report", seed, self.t, geo.reduce_point(0, 0, 1000), {"type": "Alien"})),
            ("realm", envelope.build("nope", "report", seed, self.t, geo.reduce_point(0, 0, 1000), {"type": "Hail"})),
        ]
        for code, wire in cases:
            with self.assertRaises(Reject) as cm:
                self.srv.submit(wire)
            self.assertEqual(cm.exception.code, code)

    def test_delete_needs_owner_and_erases(self):
        seed, w = self.report()
        h = self.srv.submit(w)["hash"]
        other = envelope.build("liftcharge", "delete", os.urandom(32), self.t, ref=h)
        self.assertRaisesRegex(Reject, "ref", self.srv.submit, other)
        self.srv.submit(envelope.build("liftcharge", "delete", seed, self.t, ref=h))
        self.assertEqual(self.srv.get(h), {"hash": h, "status": "deleted", "wire": None})
        row = self.srv.c.execute("SELECT wire, key FROM m_items WHERE hash=?", (h,)).fetchone()
        self.assertEqual(row, (None, ""))
        self.assertEqual([r["entry"]["kind"] for r in self.srv.receipt("liftcharge", h)], ["report", "delete"])

    def test_supersede(self):
        seed, w = self.report()
        h = self.srv.submit(w)["hash"]
        _, w2 = self.report(seed=seed, ref=h, typ="Tornado")
        h2 = self.srv.submit(w2)["hash"]
        self.assertEqual([i["hash"] for i in self.srv.query("liftcharge")], [h2])
        _, w3 = self.report(ref=h2, typ="Lightning")   # different key
        self.assertRaises(Reject, self.srv.submit, w3)

    def test_flags_hide_and_dedupe(self):
        _, w = self.report()
        h = self.srv.submit(w)["hash"]
        fh = hashlib.sha256(b"install-a" + h.encode()).hexdigest()
        self.srv.submit(envelope.build("liftcharge", "flag", os.urandom(32), self.t, body={"fh": fh}, ref=h))
        self.assertTrue(self.srv.submit(envelope.build("liftcharge", "flag", os.urandom(32), self.t, body={"fh": fh}, ref=h))["duplicate"])
        for k in (b"b", b"c"):
            self.srv.submit(envelope.build("liftcharge", "flag", os.urandom(32), self.t,
                                           body={"fh": hashlib.sha256(k + h.encode()).hexdigest()}, ref=h))
        self.assertEqual(self.srv.query("liftcharge"), [])
        self.assertEqual(self.srv.receipt("liftcharge", h)[-1]["entry"]["actor"], "sys:flags")
        self.srv.moderate(h, "unhide", "andrew")
        self.assertEqual(len(self.srv.query("liftcharge")), 1)
        self.assertEqual(self.srv.receipt("liftcharge", h)[-1]["entry"]["actor"], "op:andrew")

    def test_media(self):
        jpg = make_jpeg()
        _, w = self.report(media_=[envelope.media_entry(jpg, "image/jpeg")])
        h = self.srv.submit(w)["hash"]
        sha = hashlib.sha256(jpg).hexdigest()
        self.assertIsNone(self.srv.get_media(sha))
        self.srv.put_media(sha, jpg)
        self.assertEqual(self.srv.get_media(sha)[0], "image/jpeg")
        self.assertEqual(self.srv.query("liftcharge")[0]["media"], [sha])
        other = make_jpeg((200, 0, 0))
        self.assertRaisesRegex(Reject, "media", self.srv.put_media, hashlib.sha256(other).hexdigest(), other)
        from PIL import Image
        b = io.BytesIO()
        ex = Image.Exif()
        ex[0x0110] = "X"
        Image.new("RGB", (8, 8)).save(b, "JPEG", exif=ex.tobytes())
        dirty = b.getvalue()
        _, w2 = self.report(media_=[envelope.media_entry(dirty, "image/jpeg")])
        self.srv.submit(w2)
        with self.assertRaises(Reject) as cm:
            self.srv.put_media(hashlib.sha256(dirty).hexdigest(), dirty)
        self.assertEqual(cm.exception.detail, "unclean")
        # media retention: bytes go after 30 days, the item stays
        self.clock.t += 31 * 86400
        self.srv.purge()
        self.assertIsNone(self.srv.get_media(sha))
        self.assertFalse(os.path.exists(self.srv._media_path(sha)))

    def test_disclosure(self):
        seed, w = self.report()
        h = self.srv.submit(w)["hash"]
        data = {"name": "A Spotter", "phone": "555-0100"}
        sig = envelope.b64u(ed25519.sign(seed, store.DISCLOSE_DOMAIN + h.encode() + b"\n" + c14n.encode(data)))
        self.assertRaisesRegex(Reject, "signature", self.srv.disclose, h, data,
                               envelope.b64u(ed25519.sign(os.urandom(32), b"x")))
        self.srv.disclose(h, data, sig)
        self.assertEqual(self.srv.disclosures("liftcharge")[0]["contact"], data)
        self.assertNotIn("555-0100", json.dumps(self.srv.query("liftcharge")))
        self.srv.submit(envelope.build("liftcharge", "delete", seed, self.t, body={"scope": "disclosure"}, ref=h))
        self.assertEqual(self.srv.disclosures("liftcharge"), [])
        self.assertEqual(len(self.srv.query("liftcharge")), 1)

    def test_presence_memory_town(self):
        cell = self.srv.presence("liftcharge", "t" * 20, 44985072, -93214144)
        self.assertTrue(geo.on_grid(*cell, 5000))
        self.srv.presence("liftcharge", "u" * 20, 44985000, -93214000)
        self.assertEqual(self.srv.presence_list("liftcharge"), [[cell[0], cell[1], 2]])
        self.clock.t += 16 * 60
        self.assertEqual(self.srv.presence_list("liftcharge"), [])
        names = [r[0] for r in self.srv.c.execute("SELECT name FROM sqlite_master")]
        self.assertFalse(any("presence" in n for n in names))

    def test_aether_path(self):
        seed = os.urandom(32)
        pts = [(44_980_000 + i * 900, -93_200_000, NOW * 1000 + i * 20_000, 5) for i in range(60)]
        g = geo.reduce_path(pts, 100, 15)
        w = envelope.build("aether", "path", seed, timeq.coarsen(timeq.minute(NOW), 15), g, {"name": "Night walk"})
        self.srv.submit(w)
        self.assertEqual(self.srv.query("aether", kinds=["path"])[0]["wire"]["env"]["geo"], g)
        bad = envelope.build("aether", "report", seed, timeq.coarsen(timeq.minute(NOW), 15), geo.reduce_point(0, 0, 1000),
                             {"category": "UAP", "audience": "private"})
        self.assertRaisesRegex(Reject, "body", self.srv.submit, bad)

    def test_rate_limit(self):
        for _ in range(30):
            self.srv.submit(self.report()[1], "9.9.9.9")
        self.assertRaisesRegex(Reject, "rate", self.srv.submit, self.report()[1], "9.9.9.9")
        self.srv.submit(self.report()[1], "8.8.8.8")


class Limits(unittest.TestCase):
    def test_rotation_forgets(self):
        c = Clock()
        lim = Limiter(c)
        self.assertFalse(lim.hit("x", 1))
        self.assertTrue(lim.hit("x", 1))
        c.t += 86400
        self.assertFalse(lim.hit("x", 1))


class Http(ServerBase):
    def test_roundtrip(self):
        from http.server import ThreadingHTTPServer
        from merino import service
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), service.handler(self.srv, "/api/merino"))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d/api/merino" % httpd.server_port
        try:
            jpg = make_jpeg()
            _, w = self.report(media_=[envelope.media_entry(jpg, "image/jpeg")])
            req = urllib.request.Request(base + "/v1/submit", json.dumps(w).encode(), {"Content-Type": "application/json"})
            out = json.load(urllib.request.urlopen(req))
            sha = hashlib.sha256(jpg).hexdigest()
            urllib.request.urlopen(urllib.request.Request(base + "/v1/media/" + sha, jpg, method="PUT"))
            self.assertEqual(urllib.request.urlopen(base + "/v1/media/" + sha).read(), jpg)
            items = json.load(urllib.request.urlopen(base + "/v1/liftcharge/items"))["items"]
            self.assertEqual(items[0]["hash"], out["hash"])
            head = json.load(urllib.request.urlopen(base + "/v1/liftcharge/head"))
            self.assertEqual(head["head"]["hash"], out["receipt"]["hash"])
            bad = json.loads(json.dumps(w))
            bad["env"]["t"] -= 5
            with self.assertRaises(urllib.error.HTTPError) as cm:
                urllib.request.urlopen(urllib.request.Request(base + "/v1/submit", json.dumps(bad).encode()))
            self.assertEqual(json.load(cm.exception)["error"], "signature")
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
