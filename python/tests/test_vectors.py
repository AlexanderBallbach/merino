"""The Python engine against vectors/ (as every other implementation is)."""
import base64
import json
import os
import unittest

from merino import c14n, ed25519, envelope, geo, ledger, media

V = os.path.join(os.path.dirname(__file__), "..", "..", "vectors")


def load(n):
    with open(os.path.join(V, n + ".json")) as f:
        return json.load(f)


class Vectors(unittest.TestCase):
    def test_c14n(self):
        for case in load("c14n"):
            if "reject" in case:
                self.assertRaises(c14n.C14nError, c14n.encode, case["reject"])
            else:
                self.assertEqual(c14n.encode(case["value"]).decode(), case["c14n"])

    def test_ed25519(self):
        for c in load("ed25519"):
            seed, msg = bytes.fromhex(c["seed"]), bytes.fromhex(c["msg"])
            self.assertEqual(ed25519.public_key(seed).hex(), c["pub"])
            self.assertEqual(ed25519.sign(seed, msg).hex(), c["sig"])
            self.assertTrue(ed25519.verify(bytes.fromhex(c["pub"]), msg, bytes.fromhex(c["sig"])))

    def test_geo(self):
        self.assertEqual(load("lon_mult"), geo.LON_MULT)
        for la, lo, m, a, b in load("snaps")["rows"]:
            self.assertEqual(geo.snap(la, lo, m), (a, b))
        for c in load("paths"):
            self.assertEqual(geo.reduce_path([tuple(p) for p in c["points"]], c["m"], c["gran"], c["zones"], c["keep_time"]), c["out"])
        for c in load("polygons"):
            self.assertEqual(geo.reduce_polygon([tuple(v) for v in c["vertices"]], c["m"]), c["out"])
        for c in load("points"):
            self.assertEqual(geo.reduce_point(c["lat"], c["lon"], c["m"], c["zones"]), c["out"])
        for c in load("keyed"):
            for la, lo, m, a, b in c["rows"]:
                self.assertEqual(geo.keyed_snap(la, lo, m, bytes.fromhex(c["key"])), (a, b))

    def test_envelope_ledger(self):
        e = load("envelope")
        self.assertEqual(c14n.encode(e["env"]).decode(), e["c14n"])
        self.assertEqual(envelope.env_hash(e["env"]), e["hash"])
        env, h, _ = envelope.open_wire({"env": e["env"], "sig": e["sig"]})
        self.assertEqual(h, e["hash"])
        L = load("ledger")
        pub = envelope.unb64u(L["server_pub"])
        self.assertTrue(ledger.verify_chain(pub, L["receipts"], prev=ledger.ZERO))

    def test_media(self):
        for c in load("media"):
            out = base64.b64decode(c["out"])
            self.assertEqual(media.clean(base64.b64decode(c["in"])), (c["mime"], out))
            self.assertTrue(media.is_clean(out, c["mime"]))
            self.assertFalse(media.is_clean(base64.b64decode(c["in"]), c["mime"]))


if __name__ == "__main__":
    unittest.main()
