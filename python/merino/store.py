"""A Merino server: SQLite storage + the accept/delete/flag/moderate/query rules. Framework-agnostic; an HTTP
layer (see service.py) only translates requests into these calls."""
import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time

from . import c14n, ed25519, geo, ledger, media as mediamod, timeq
from .envelope import HEX64, GEO_KINDS, Reject, b64u, open_wire, unb64u
from .ratelimit import Limiter

SCHEMA = """
CREATE TABLE IF NOT EXISTS m_items(
  hash TEXT PRIMARY KEY, realm TEXT NOT NULL, kind TEXT NOT NULL, key TEXT NOT NULL,
  t INTEGER NOT NULL, recv INTEGER NOT NULL, seq INTEGER NOT NULL,
  status TEXT NOT NULL,                  -- visible | hidden | superseded | deleted
  wire TEXT,                             -- NULL once deleted: only the hash survives, in the ledger
  s INTEGER, w INTEGER, n INTEGER, e INTEGER);
CREATE INDEX IF NOT EXISTS m_items_q ON m_items(realm, status, t);
CREATE TABLE IF NOT EXISTS m_media(
  sha256 TEXT NOT NULL, item TEXT NOT NULL, mime TEXT NOT NULL, bytes INTEGER NOT NULL,
  state INTEGER NOT NULL DEFAULT 0,      -- 0 awaiting upload, 1 stored, 2 expired
  stored INTEGER, PRIMARY KEY(item, sha256));
CREATE INDEX IF NOT EXISTS m_media_sha ON m_media(sha256);
CREATE TABLE IF NOT EXISTS m_marks(subject TEXT NOT NULL, fh TEXT NOT NULL, kind TEXT NOT NULL,
  PRIMARY KEY(subject, kind, fh));        -- fh = sha256(install secret + subject), computed on the device
CREATE TABLE IF NOT EXISTS m_disclosures(subject TEXT PRIMARY KEY, realm TEXT NOT NULL, data TEXT NOT NULL,
  created INTEGER NOT NULL);
"""
DISCLOSE_DOMAIN = b"merino-disclose/1\n"
PRESENCE_TTL_S = 15 * 60


def ident_hmac(secret, s):
    """Accounts: store this, never the email / OAuth subject itself (SPEC 9)."""
    return hmac.new(secret, s.strip().lower().encode(), hashlib.sha256).hexdigest()


class Server:
    def __init__(self, db_path, realms, seeds, media_dir, hide_at_flags=3, clock=time.time):
        """realms: {name: policy.Realm}; seeds: {name: 32-byte ledger signing seed}."""
        self.realms, self.seeds, self.media_dir = realms, seeds, media_dir
        self.hide_at = hide_at_flags
        self.clock = clock
        self.limiter = Limiter(clock)
        self.lock = threading.RLock()
        self.c = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.c.execute("PRAGMA journal_mode=WAL")
        self.c.executescript(SCHEMA)
        ledger.schema(self.c)
        os.makedirs(media_dir, exist_ok=True)
        self._presence = {}
        self._psecret = os.urandom(32)   # process lifetime, never written: tokens are unlinkable after a restart

    # ---- helpers ------------------------------------------------------------
    def now_min(self):
        return timeq.minute(self.clock())

    def pub(self, realm):
        return ed25519.public_key(self.seeds[realm])

    def _limit(self, realm, what, ident):
        n, win = realm.rate[what]
        if ident and self.limiter.hit("%s:%s:%s" % (realm.name, what, ident), n, win):
            raise Reject("rate")

    def _append(self, realm, kind, subject, actor):
        return ledger.append(self.c, realm, self.seeds[realm], kind, subject,
                             timeq.coarsen(self.now_min(), self.realms[realm].time_gran), actor)

    def _item(self, h):
        r = self.c.execute("SELECT hash, realm, kind, key, status, wire FROM m_items WHERE hash=?", (h,)).fetchone()
        return dict(zip(("hash", "realm", "kind", "key", "status", "wire"), r)) if r else None

    def _media_path(self, sha):
        return os.path.join(self.media_dir, sha[:2], sha)

    def _drop_media(self, item):
        for (sha,) in self.c.execute("SELECT sha256 FROM m_media WHERE item=?", (item,)).fetchall():
            self.c.execute("DELETE FROM m_media WHERE item=? AND sha256=?", (item, sha))
            if not self.c.execute("SELECT 1 FROM m_media WHERE sha256=? AND state=1", (sha,)).fetchone():
                try:
                    os.remove(self._media_path(sha))
                except FileNotFoundError:
                    pass

    def _erase(self, h):
        """Deletion means deletion: content, media, marks and disclosures go; the hash stays in the ledger."""
        self._drop_media(h)
        self.c.execute("DELETE FROM m_marks WHERE subject=?", (h,))
        self.c.execute("DELETE FROM m_disclosures WHERE subject=?", (h,))
        self.c.execute("UPDATE m_items SET status='deleted', wire=NULL, key='', s=NULL, w=NULL, n=NULL, e=NULL WHERE hash=?", (h,))

    # ---- submit ---------------------------------------------------------------
    def submit(self, wire, ident=None):
        """Accept a signed envelope. ident (an IP or similar) is used only for in-memory rate limiting.
        Returns {"hash", "receipt", "duplicate"}; raises Reject."""
        env, h, _ = open_wire(wire)
        realm = self.realms.get(env["realm"])
        if realm is None or env["realm"] not in self.seeds:
            raise Reject("realm")
        kind = env["kind"]
        self._limit(realm, "flag" if kind in ("flag", "confirm") else "submit", ident)
        err = realm.body(kind, env.get("body"))
        if err:
            raise Reject("body", err)
        now = self.now_min()
        t = env["t"]
        if t % realm.time_gran or t > now + realm.time_gran or t < now - realm.max_age_min:
            raise Reject("time")
        if kind in GEO_KINDS:
            err = geo.check_geo(env["geo"], realm.min_prec[kind])
            if err:
                raise Reject("geo", err)
            if kind == "path" and not realm.keep_path_time and any(q[2] for q in env["geo"]["p"]):
                raise Reject("geo", "path_time")
            if len(env.get("media", [])) > realm.media_per_item or any(m["bytes"] > realm.media_max for m in env.get("media", [])):
                raise Reject("media")
        with self.lock:
            self.c.execute("BEGIN IMMEDIATE")
            try:
                out = self._accept(realm, env, h, wire)
                self.c.execute("COMMIT")
                return out
            except BaseException:
                self.c.execute("ROLLBACK")
                raise

    def _accept(self, realm, env, h, wire):
        kind, R = env["kind"], realm.name
        if kind in GEO_KINDS and self._item(h):    # an offline queue retrying: answer with the original receipt
            return {"hash": h, "receipt": self.receipt(R, h)[0], "duplicate": True}
        target = self._item(env["ref"]) if "ref" in env else None
        if "ref" in env and (target is None or target["realm"] != R):
            raise Reject("ref")
        if kind in GEO_KINDS:
            if target is not None:      # supersede (edit): same key, same kind, still live
                if target["key"] != env["key"] or target["kind"] != kind or target["status"] not in ("visible", "hidden"):
                    raise Reject("ref", "supersede")
                status = target["status"]
                self.c.execute("UPDATE m_items SET status='superseded' WHERE hash=?", (target["hash"],))
                self._drop_media(target["hash"])
                self.c.execute("UPDATE m_disclosures SET subject=? WHERE subject=?", (h, target["hash"]))
            else:
                status = "visible"
            pts = [env["geo"]["p"]] if kind == "report" else env["geo"]["p"]
            s, n = min(q[0] for q in pts), max(q[0] for q in pts)
            w, e = min(q[1] for q in pts), max(q[1] for q in pts)
            rec = self._append(R, kind, h, "key")
            self.c.execute("INSERT INTO m_items VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                           (h, R, kind, env["key"], env["t"], rec["entry"]["t"], rec["entry"]["seq"], status,
                            json.dumps(wire, separators=(",", ":")), s, w, n, e))
            for m in env.get("media", []):
                self.c.execute("INSERT OR IGNORE INTO m_media(sha256, item, mime, bytes) VALUES(?,?,?,?)",
                               (m["sha256"], h, m["mime"], m["bytes"]))
            if target is not None:
                self._append(R, "supersede", target["hash"], "key")
            return {"hash": h, "receipt": rec, "duplicate": False}
        if kind == "delete":
            if target["key"] != env["key"] or target["status"] == "deleted":
                raise Reject("ref", "owner")
            scope = (env.get("body") or {}).get("scope", "item")
            if scope == "disclosure":
                self.c.execute("DELETE FROM m_disclosures WHERE subject=?", (target["hash"],))
                return {"hash": h, "receipt": None, "duplicate": False}
            if scope != "item":
                raise Reject("body", "scope")
            self._erase(target["hash"])
            return {"hash": h, "receipt": self._append(R, "delete", target["hash"], "key"), "duplicate": False}
        # flag / confirm
        fh = (env.get("body") or {}).get("fh")
        if not isinstance(fh, str) or not HEX64.match(fh):
            raise Reject("body", "fh")
        if target["status"] not in ("visible", "hidden"):
            raise Reject("ref", "gone")
        if self.c.execute("INSERT OR IGNORE INTO m_marks VALUES(?,?,?)", (target["hash"], fh, kind)).rowcount == 0:
            return {"hash": h, "receipt": None, "duplicate": True}
        rec = self._append(R, kind, target["hash"], "key")
        if kind == "flag" and target["status"] == "visible" and self.c.execute(
                "SELECT COUNT(*) FROM m_marks WHERE subject=? AND kind='flag'", (target["hash"],)).fetchone()[0] >= self.hide_at:
            self.c.execute("UPDATE m_items SET status='hidden' WHERE hash=?", (target["hash"],))
            self._append(R, "hide", target["hash"], "sys:flags")
        return {"hash": h, "receipt": rec, "duplicate": False}

    # ---- media ------------------------------------------------------------------
    def put_media(self, sha, data, ident=None):
        """Upload bytes an accepted envelope already committed to. Unreferenced or unclean bytes are refused."""
        if not HEX64.match(sha) or hashlib.sha256(data).hexdigest() != sha:
            raise Reject("media", "hash")
        with self.lock:
            rows = self.c.execute("SELECT m.mime, m.bytes, m.state, i.realm FROM m_media m JOIN m_items i ON i.hash=m.item "
                                  "WHERE m.sha256=? AND i.status IN ('visible','hidden')", (sha,)).fetchall()
            if not rows:
                raise Reject("media", "unreferenced")
            mime, size, _, rname = rows[0]
            self._limit(self.realms[rname], "media", ident)
            if len(data) != size or mediamod.sniff(data) != mime or not mediamod.is_clean(data, mime):
                raise Reject("media", "unclean")
            p = self._media_path(sha)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            if not os.path.exists(p):
                with open(p + ".tmp", "wb") as f:
                    f.write(data)
                os.replace(p + ".tmp", p)
            self.c.execute("UPDATE m_media SET state=1, stored=? WHERE sha256=? AND state=0", (self.now_min(), sha))
            return True

    def get_media(self, sha):
        """(mime, path) if the bytes belong to a visible item, else None."""
        if not HEX64.match(sha or ""):
            return None
        r = self.c.execute("SELECT m.mime FROM m_media m JOIN m_items i ON i.hash=m.item WHERE m.sha256=? AND m.state=1 "
                           "AND i.status='visible' LIMIT 1", (sha,)).fetchone()
        return (r[0], self._media_path(sha)) if r else None

    # ---- disclosures ---------------------------------------------------------------
    def disclose(self, subject, data, sig):
        """Opt-in, revocable contact details tied to one item, signed by that item's key. Never public."""
        if not isinstance(data, dict) or not data or len(data) > 8 or \
                any(not isinstance(v, str) or len(v) > 500 for v in data.values()):
            raise Reject("body", "disclosure")
        with self.lock:
            it = self._item(subject)
            if it is None or it["status"] not in ("visible", "hidden"):
                raise Reject("ref")
            try:
                ok = ed25519.verify(unb64u(it["key"]), DISCLOSE_DOMAIN + subject.encode() + b"\n" + c14n.encode(data), unb64u(sig))
            except c14n.C14nError:
                ok = False
            if not ok:
                raise Reject("signature")
            self.c.execute("INSERT OR REPLACE INTO m_disclosures VALUES(?,?,?,?)",
                           (subject, it["realm"], json.dumps(data), self.now_min()))
            return True

    def disclosures(self, realm, since_min=0):
        """Operator-only export (e.g. forwarding a report to the NWS). Not for any public endpoint."""
        q = ("SELECT d.subject, d.data, i.wire FROM m_disclosures d JOIN m_items i ON i.hash=d.subject "
             "WHERE d.realm=? AND i.status='visible' AND i.t>=? ORDER BY i.t")
        return [{"hash": h, "contact": json.loads(d), "wire": json.loads(w)} for h, d, w in self.c.execute(q, (realm, since_min))]

    # ---- moderation / retention ---------------------------------------------------------
    def moderate(self, subject, action, operator):
        """Operator hide / unhide / delete. Always ledgered with the operator's name."""
        if action not in ("hide", "unhide", "delete") or not operator.replace("_", "").isalnum():
            raise Reject("moderate")
        with self.lock:
            it = self._item(subject)
            if it is None or it["status"] not in ("visible", "hidden"):
                raise Reject("ref")
            self.c.execute("BEGIN IMMEDIATE")
            try:
                if action == "delete":
                    self._erase(subject)
                else:
                    self.c.execute("UPDATE m_items SET status=? WHERE hash=?", ("hidden" if action == "hide" else "visible", subject))
                rec = self._append(it["realm"], action, subject, "op:" + operator)
                self.c.execute("COMMIT")
                return rec
            except BaseException:
                self.c.execute("ROLLBACK")
                raise

    def purge(self):
        """Retention: delete items past the realm's retention and media past its media retention. Ledgered as sys:retention."""
        now = self.now_min()
        n = 0
        with self.lock:
            for name, realm in self.realms.items():
                if realm.retention_days:
                    cutoff = now - realm.retention_days * 1440
                    for (h,) in self.c.execute("SELECT hash FROM m_items WHERE realm=? AND recv<? AND status IN ('visible','hidden','superseded')",
                                               (name, cutoff)).fetchall():
                        self.c.execute("BEGIN IMMEDIATE")
                        self._erase(h)
                        self._append(name, "expire", h, "sys:retention")
                        self.c.execute("COMMIT")
                        n += 1
                for mime, days in realm.media_days.items():
                    for item, sha in self.c.execute("SELECT m.item, m.sha256 FROM m_media m JOIN m_items i ON i.hash=m.item "
                                                    "WHERE i.realm=? AND m.mime=? AND m.state=1 AND m.stored<?",
                                                    (name, mime, now - days * 1440)).fetchall():
                        self.c.execute("UPDATE m_media SET state=2 WHERE item=? AND sha256=?", (item, sha))
                        if not self.c.execute("SELECT 1 FROM m_media WHERE sha256=? AND state=1", (sha,)).fetchone():
                            try:
                                os.remove(self._media_path(sha))
                            except FileNotFoundError:
                                pass
        return n

    # ---- reads -------------------------------------------------------------------------
    def query(self, realm, bbox=None, since_min=None, kinds=None, limit=500):
        """Public feed. bbox = (s, w, n, e) in microdegrees. Hidden/superseded/deleted items are not returned."""
        q = "SELECT hash, seq, wire FROM m_items WHERE realm=? AND status='visible'"
        a = [realm]
        if since_min is not None:
            q += " AND t>=?"
            a.append(since_min)
        if kinds:
            q += " AND kind IN (%s)" % ",".join("?" * len(kinds))
            a += list(kinds)
        if bbox:
            q += " AND n>=? AND s<=? AND e>=? AND w<=?"
            a += [bbox[0], bbox[2], bbox[1], bbox[3]]
        q += " ORDER BY t DESC LIMIT ?"
        a.append(min(int(limit), 2000))
        out = []
        for h, seq, w in self.c.execute(q, a).fetchall():
            marks = dict(self.c.execute("SELECT kind, COUNT(*) FROM m_marks WHERE subject=? GROUP BY kind", (h,)).fetchall())
            ready = [r[0] for r in self.c.execute("SELECT sha256 FROM m_media WHERE item=? AND state=1", (h,))]
            out.append({"hash": h, "seq": seq, "wire": json.loads(w), "flags": marks.get("flag", 0),
                        "confirms": marks.get("confirm", 0), "media": ready})
        return out

    def get(self, h):
        it = self._item(h)
        if it is None:
            return None
        return {"hash": h, "status": it["status"], "wire": json.loads(it["wire"]) if it["wire"] and it["status"] == "visible" else None}

    def receipt(self, realm, h):
        r = self.c.execute("SELECT seq FROM m_ledger WHERE realm=? AND subject=? ORDER BY seq", (realm, h)).fetchall()
        return [ledger.rows(self.c, realm, s, s)[0] for (s,) in r]

    def head(self, realm):
        last = self.c.execute("SELECT MAX(seq) FROM m_ledger WHERE realm=?", (realm,)).fetchone()[0]
        return {"realm": realm, "pub": b64u(self.pub(realm)), "head": ledger.rows(self.c, realm, last, last)[0] if last else None}

    def ledger(self, realm, start=1, limit=1000):
        return ledger.rows(self.c, realm, start, limit=min(limit, 5000))

    # ---- presence (memory only) -------------------------------------------------------------
    def _ptoken(self, realm, token):
        if not isinstance(token, str) or not 16 <= len(token) <= 64:
            raise Reject("presence", "token")
        return hmac.new(self._psecret, ("%s:%s" % (realm, token)).encode(), hashlib.sha256).digest()[:16]

    def presence(self, realm, token, lat_e6, lon_e6):
        """Opt-in live position. The device sends a town cell centre (it never sends the fix); kept only in
        memory, for 15 minutes after the last update; token is a random per-session value held in RAM too."""
        if realm not in self.realms or not geo.valid(lat_e6, lon_e6) or not geo.on_grid(lat_e6, lon_e6, geo.LEVELS["town"]):
            raise Reject("presence", "send a town cell centre")
        k = self._ptoken(realm, token)
        with self.lock:
            self._presence[k] = (realm, (lat_e6, lon_e6), self.clock())
        return lat_e6, lon_e6

    def presence_stop(self, realm, token):
        k = self._ptoken(realm, token)
        with self.lock:
            self._presence.pop(k, None)

    def presence_list(self, realm, token):
        """Cells with spotters sharing now: [[lat, lon, count, age_s]]. Mutual: empty unless `token` is sharing
        too, and the caller's own entry is left out."""
        me = self._ptoken(realm, token)
        now, cells = self.clock(), {}
        with self.lock:
            for k, (r, cell, at) in list(self._presence.items()):
                if at + PRESENCE_TTL_S < now:
                    del self._presence[k]
            if me not in self._presence or self._presence[me][0] != realm:
                return []
            for k, (r, cell, at) in self._presence.items():
                if r == realm and k != me:
                    n, age = cells.get(cell, (0, None))
                    a = int(now - at)
                    cells[cell] = (n + 1, a if age is None else min(age, a))
        return [[a, b, n, age] for (a, b), (n, age) in sorted(cells.items())]
