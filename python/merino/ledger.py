"""Hash-chained, signed ledger (SPEC section 8). Hashes only; never content."""
import hashlib

from . import c14n, ed25519
from .envelope import b64u, unb64u

ZERO = "0" * 64


def entry_hash(e):
    return hashlib.sha256(c14n.encode(e)).hexdigest()


def schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS m_ledger(
        realm TEXT NOT NULL, seq INTEGER NOT NULL, prev TEXT NOT NULL, kind TEXT NOT NULL, subject TEXT NOT NULL,
        t INTEGER NOT NULL, actor TEXT NOT NULL, hash TEXT NOT NULL, sig TEXT NOT NULL, PRIMARY KEY(realm, seq))""")
    c.execute("CREATE INDEX IF NOT EXISTS m_ledger_subject ON m_ledger(subject)")


def append(c, realm, seed, kind, subject, t, actor):
    """Caller holds a write transaction. Returns the receipt."""
    row = c.execute("SELECT seq, hash FROM m_ledger WHERE realm=? ORDER BY seq DESC LIMIT 1", (realm,)).fetchone()
    seq, prev = (row[0] + 1, row[1]) if row else (1, ZERO)
    e = {"seq": seq, "prev": prev, "kind": kind, "subject": subject, "t": t, "actor": actor}
    h = entry_hash(e)
    sig = b64u(ed25519.sign(seed, b"merino-ledger/1\n" + bytes.fromhex(h)))
    c.execute("INSERT INTO m_ledger VALUES(?,?,?,?,?,?,?,?,?)", (realm, seq, prev, kind, subject, t, actor, h, sig))
    return {"entry": e, "hash": h, "sig": sig}


def rows(c, realm, start=1, end=None, limit=1000):
    q = "SELECT seq, prev, kind, subject, t, actor, hash, sig FROM m_ledger WHERE realm=? AND seq>=?"
    args = [realm, start]
    if end is not None:
        q += " AND seq<=?"
        args.append(end)
    q += " ORDER BY seq LIMIT ?"
    args.append(limit)
    return [{"entry": {"seq": r[0], "prev": r[1], "kind": r[2], "subject": r[3], "t": r[4], "actor": r[5]},
             "hash": r[6], "sig": r[7]} for r in c.execute(q, args)]


def verify_receipt(server_pub, receipt):
    return entry_hash(receipt["entry"]) == receipt["hash"] and \
        ed25519.verify(server_pub, b"merino-ledger/1\n" + bytes.fromhex(receipt["hash"]), unb64u(receipt["sig"]))


def verify_chain(server_pub, receipts, prev=None, check_sigs=True):
    """True if receipts are consecutive, correctly linked and (optionally) signed. prev: hash before the first."""
    for r in receipts:
        e = r["entry"]
        if prev is not None and e["prev"] != prev:
            return False
        if e["seq"] == 1 and e["prev"] != ZERO:
            return False
        if entry_hash(e) != r["hash"] or (check_sigs and not verify_receipt(server_pub, r)):
            return False
        prev = r["hash"]
    return True
