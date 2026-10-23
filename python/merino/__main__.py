"""merino CLI.

    python3 -m merino serve   --db D --media M --keys K [--port 8795] [--prefix /api/merino] [--realms liftcharge,aether]
    python3 -m merino keygen  --keys K --realm R          # creates K/R.seed (0600) if missing, prints the public key
    python3 -m merino purge   --db D --media M --keys K   # retention; run daily from a timer
    python3 -m merino moderate --db D --media M --keys K HASH hide|unhide|delete OPERATOR
    python3 -m merino audit   URL REALM                   # fetch a server's ledger and check every link + signature
    python3 -m merino pg-sign --keys K --realm R -- PSQL_ARGS...
                                                          # sign merino.ledger rows in Postgres (sql/merino.sql);
                                                          # the realm key never enters the database
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.request

from . import ed25519, ledger, policy, service, store
from .envelope import b64u, unb64u


def seeds(keys, realms):
    out = {}
    for r in realms:
        with open(os.path.join(keys, r + ".seed"), "rb") as f:
            out[r] = f.read()
    return out


def server(a):
    names = a.realms.split(",")
    return store.Server(a.db, {n: policy.REALMS[n] for n in names}, seeds(a.keys, names), a.media)


def main(argv=None):
    p = argparse.ArgumentParser(prog="merino")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("serve", "purge", "moderate"):
        s = sub.add_parser(name)
        s.add_argument("--db", required=True)
        s.add_argument("--media", required=True)
        s.add_argument("--keys", required=True)
        s.add_argument("--realms", default="liftcharge")
        if name == "serve":
            s.add_argument("--host", default="127.0.0.1")
            s.add_argument("--port", type=int, default=8795)
            s.add_argument("--prefix", default="")
        if name == "moderate":
            s.add_argument("hash")
            s.add_argument("action", choices=["hide", "unhide", "delete"])
            s.add_argument("operator")
    k = sub.add_parser("keygen")
    k.add_argument("--keys", required=True)
    k.add_argument("--realm", required=True)
    au = sub.add_parser("audit")
    au.add_argument("url")
    au.add_argument("realm")
    pg = sub.add_parser("pg-sign")
    pg.add_argument("--keys", required=True)
    pg.add_argument("--realm", required=True)
    pg.add_argument("psql", nargs="+", help="psql command line, e.g. psql -h host -U user db")
    a = p.parse_args(argv)

    if a.cmd == "keygen":
        os.makedirs(a.keys, mode=0o700, exist_ok=True)
        path = os.path.join(a.keys, a.realm + ".seed")
        if not os.path.exists(path):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.write(fd, os.urandom(32))
            os.close(fd)
        print(b64u(ed25519.public_key(open(path, "rb").read())))
    elif a.cmd == "serve":
        service.serve(server(a), a.host, a.port, a.prefix)
    elif a.cmd == "purge":
        print("expired", server(a).purge())
    elif a.cmd == "moderate":
        print(json.dumps(server(a).moderate(a.hash, a.action, a.operator)))
    elif a.cmd == "audit":
        base = a.url.rstrip("/")
        head = json.load(urllib.request.urlopen("%s/v1/%s/head" % (base, a.realm)))
        pub, start, prev, n = unb64u(head["pub"]), 1, ledger.ZERO, 0
        while True:
            rows = json.load(urllib.request.urlopen("%s/v1/%s/ledger?start=%d" % (base, a.realm, start)))["entries"]
            if not rows:
                break
            if rows[0]["entry"]["seq"] != start or not ledger.verify_chain(pub, rows, prev):
                print("BROKEN near seq", start)
                return 1
            prev, start, n = rows[-1]["hash"], rows[-1]["entry"]["seq"] + 1, n + len(rows)
        ok = head["head"] is None and n == 0 or head["head"]["hash"] == prev
        print("ok" if ok else "HEAD MISMATCH", n, "entries, head", prev)
        return 0 if ok else 1
    elif a.cmd == "pg-sign":
        return pg_sign(a)


def pg_sign(a):
    """Sign unsigned merino.ledger rows. Every row from seq 1 is re-hashed and its link checked first, so a
    tampered or forked chain is refused rather than signed: a signature then vouches for the whole history."""
    seed = seeds(a.keys, [a.realm])[a.realm]

    def psql(sql):
        r = subprocess.run(a.psql + ["-X", "-q", "-At", "-v", "ON_ERROR_STOP=1"], input=sql, text=True,
                           capture_output=True)
        if r.returncode:
            sys.exit(r.stderr.strip())
        return r.stdout

    lit = "'" + a.realm.replace("'", "''") + "'"
    out = psql("select coalesce(json_agg(json_build_object('seq',seq,'prev',prev,'kind',kind,'subject',subject,"
               "'t',t,'actor',actor,'hash',hash,'sig',sig) order by seq), '[]') from merino.ledger where realm=%s;" % lit)
    prev, todo = ledger.ZERO, []
    for i, r in enumerate(json.loads(out)):
        e = {k: r[k] for k in ("seq", "prev", "kind", "subject", "t", "actor")}
        if e["seq"] != i + 1 or e["prev"] != prev or ledger.entry_hash(e) != r["hash"]:
            print("REFUSED: chain broken at seq", e["seq"])
            return 1
        if r["sig"] is None:
            todo.append((e["seq"], b64u(ed25519.sign(seed, b"merino-ledger/1\n" + bytes.fromhex(r["hash"])))))
        elif not ledger.verify_receipt(ed25519.public_key(seed), {"entry": e, "hash": r["hash"], "sig": r["sig"]}):
            print("REFUSED: bad existing signature at seq", e["seq"])
            return 1
        prev = r["hash"]
    if todo:
        psql("begin;\n" + "".join("update merino.ledger set sig='%s' where realm=%s and seq=%d and sig is null;\n"
                                   % (sig, lit, seq) for seq, sig in todo) + "commit;\n")
    print("signed", len(todo))
    return 0


if __name__ == "__main__":
    sys.exit(main())
