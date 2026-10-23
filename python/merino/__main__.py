"""merino CLI.

    python3 -m merino serve   --db D --media M --keys K [--port 8795] [--prefix /api/merino] [--realms liftcharge,aether]
    python3 -m merino keygen  --keys K --realm R          # creates K/R.seed (0600) if missing, prints the public key
    python3 -m merino purge   --db D --media M --keys K   # retention; run daily from a timer
    python3 -m merino moderate --db D --media M --keys K HASH hide|unhide|delete OPERATOR
    python3 -m merino audit   URL REALM                   # fetch a server's ledger and check every link + signature
"""
import argparse
import json
import os
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


if __name__ == "__main__":
    sys.exit(main())
