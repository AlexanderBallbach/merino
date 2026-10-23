"""Stdlib HTTP front for store.Server. Writes no access log; the client address is used only for in-memory rate limits.

    POST /v1/submit                  {"env":…, "sig":…}           -> {"hash", "receipt", "duplicate"}
    PUT  /v1/media/<sha256>          raw cleaned bytes
    GET  /v1/media/<sha256>
    POST /v1/disclose                {"subject", "data", "sig"}
    POST /v1/presence                {"realm", "token", "lat", "lon"} town cell centre (or "stop": true)
    GET  /v1/<realm>/items?s=&w=&n=&e=&since=&kinds=
    GET  /v1/<realm>/presence?token=   (mutual: empty unless that token is sharing)
    GET  /v1/<realm>/head | /v1/<realm>/ledger?start= | /v1/<realm>/receipt/<hash>
    GET  /v1/item/<hash>
"""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from .envelope import Reject

MAX_JSON = 2_000_000


def handler(server, prefix=""):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def ident(self):
            return self.headers.get("X-Real-IP") or self.client_address[0]

        def send(self, code, obj=None, raw=None, ctype="application/json"):
            body = raw if raw is not None else json.dumps(obj, separators=(",", ":")).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store" if code != 200 or raw is None else "public, max-age=86400, immutable")
            self.end_headers()
            self.wfile.write(body)

        def body(self, cap):
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > cap:
                raise Reject("size")
            return self.rfile.read(n)

        def route(self):
            u = urlparse(self.path)
            p = u.path[len(prefix):] if u.path.startswith(prefix) else None
            return p, {k: v[0] for k, v in parse_qs(u.query).items()}

        def run(self, fn):
            try:
                fn()
            except Reject as e:
                self.send(429 if e.code == "rate" else 400, {"error": e.code, "detail": e.detail})
            except (ValueError, KeyError, TypeError):
                self.send(400, {"error": "bad_request"})

        def do_POST(self):
            p, _ = self.route()

            def go():
                d = json.loads(self.body(MAX_JSON))
                if p == "/v1/submit":
                    self.send(200, server.submit(d, self.ident()))
                elif p == "/v1/disclose":
                    server.disclose(d["subject"], d["data"], d["sig"])
                    self.send(200, {"ok": True})
                elif p == "/v1/presence":
                    if d.get("stop"):
                        server.presence_stop(d["realm"], d["token"])
                        self.send(200, {"ok": True})
                    else:
                        cell = server.presence(d["realm"], d["token"], int(d["lat"]), int(d["lon"]))
                        self.send(200, {"cell": list(cell)})
                else:
                    self.send(404, {"error": "not_found"})
            self.run(go)

        def do_PUT(self):
            p, _ = self.route()
            m = re.fullmatch(r"/v1/media/([0-9a-f]{64})", p or "")
            if not m:
                return self.send(404, {"error": "not_found"})
            cap = max(r.media_max for r in server.realms.values())
            self.run(lambda: (server.put_media(m.group(1), self.body(cap), self.ident()), self.send(200, {"ok": True})))

        def do_GET(self):
            p, q = self.route()
            p = p or ""

            def go():
                m = re.fullmatch(r"/v1/media/([0-9a-f]{64})", p)
                if m:
                    r = server.get_media(m.group(1))
                    if not r:
                        return self.send(404, {"error": "not_found"})
                    with open(r[1], "rb") as f:
                        return self.send(200, raw=f.read(), ctype=r[0])
                m = re.fullmatch(r"/v1/item/([0-9a-f]{64})", p)
                if m:
                    it = server.get(m.group(1))
                    return self.send(200 if it else 404, it or {"error": "not_found"})
                m = re.fullmatch(r"/v1/([a-z0-9_]+)/(items|presence|head|ledger|receipt/([0-9a-f]{64}))", p)
                if not m or m.group(1) not in server.realms:
                    return self.send(404, {"error": "not_found"})
                realm, what = m.group(1), m.group(2)
                if what == "items":
                    bbox = tuple(int(q[k]) for k in "swne") if all(k in q for k in "swne") else None
                    kinds = q["kinds"].split(",") if q.get("kinds") else None
                    since = int(q["since"]) if "since" in q else None
                    self.send(200, {"items": server.query(realm, bbox, since, kinds, int(q.get("limit", 500)))})
                elif what == "presence":
                    self.send(200, {"cells": server.presence_list(realm, q.get("token"))})
                elif what == "head":
                    self.send(200, server.head(realm))
                elif what == "ledger":
                    self.send(200, {"entries": server.ledger(realm, int(q.get("start", 1)), int(q.get("limit", 1000)))})
                else:
                    self.send(200, {"receipts": server.receipt(realm, m.group(3))})
            self.run(go)
    return H


def serve(server, host="127.0.0.1", port=8795, prefix=""):
    ThreadingHTTPServer((host, port), handler(server, prefix)).serve_forever()
