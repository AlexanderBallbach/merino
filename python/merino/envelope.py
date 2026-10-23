"""Envelopes, signatures and hashes (SPEC section 7)."""
import base64
import hashlib
import os
import re

from . import c14n, ed25519

DOMAIN = b"merino/1\n"
KINDS = {"report", "path", "polygon", "delete", "flag", "confirm"}
GEO_KINDS = {"report": "point", "path": "path", "polygon": "polygon"}
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MIMES = {"image/jpeg", "image/png", "video/mp4"}


class Reject(ValueError):
    def __init__(self, code, detail=""):
        super().__init__(code)
        self.code, self.detail = code, detail


def b64u(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def unb64u(s):
    if not isinstance(s, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", s):
        raise Reject("encoding")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def env_hash(env):
    return hashlib.sha256(c14n.encode(env)).hexdigest()


def new_key():
    seed = os.urandom(32)
    return seed, ed25519.public_key(seed)


def build(realm, kind, seed, t, geo=None, body=None, media=(), ref=None):
    env = {"v": 1, "realm": realm, "kind": kind, "nonce": b64u(os.urandom(16)), "t": t,
           "key": b64u(ed25519.public_key(seed))}
    if geo is not None:
        env["geo"] = geo
    if body is not None:
        env["body"] = body
    if media:
        env["media"] = list(media)
    if ref is not None:
        env["ref"] = ref
    return {"env": env, "sig": b64u(ed25519.sign(seed, DOMAIN + c14n.encode(env)))}


def media_entry(data, mime):
    return {"sha256": hashlib.sha256(data).hexdigest(), "mime": mime, "bytes": len(data)}


def open_wire(wire):
    """Structural + signature check. Returns (env, hash, pubkey). Policy checks are the realm's job."""
    if not isinstance(wire, dict) or set(wire) != {"env", "sig"} or not isinstance(wire["env"], dict):
        raise Reject("shape")
    env = wire["env"]
    allowed = {"v", "realm", "kind", "nonce", "t", "key", "geo", "body", "media", "ref"}
    if not set(env) <= allowed or not {"v", "realm", "kind", "nonce", "t", "key"} <= set(env):
        raise Reject("shape", "fields")
    if env["v"] != 1:
        raise Reject("version")
    if env["kind"] not in KINDS:
        raise Reject("kind")
    if not isinstance(env["t"], int) or isinstance(env["t"], bool):
        raise Reject("time")
    if len(unb64u(env["nonce"])) != 16:
        raise Reject("nonce")
    pub = unb64u(env["key"])
    if len(pub) != 32:
        raise Reject("key")
    try:
        raw = c14n.encode(env)
    except c14n.C14nError as e:
        raise Reject("c14n", str(e))
    sig = unb64u(wire["sig"])
    if not ed25519.verify(pub, DOMAIN + raw, sig):
        raise Reject("signature")
    kind = env["kind"]
    if kind in GEO_KINDS:
        if not isinstance(env.get("geo"), dict) or env["geo"].get("type") != GEO_KINDS[kind]:
            raise Reject("shape", "geo")
        if "ref" in env and not (isinstance(env["ref"], str) and HEX64.match(env["ref"])):   # ref on a geo kind = supersedes
            raise Reject("shape", "ref")
    else:
        if "geo" in env or "media" in env or not isinstance(env.get("ref"), str) or not HEX64.match(env["ref"]):
            raise Reject("shape", "ref")
    if "body" in env and not isinstance(env["body"], dict):
        raise Reject("shape", "body")
    media = env.get("media", [])
    if not isinstance(media, list) or len(media) > 4:
        raise Reject("media")
    for m in media:
        if not isinstance(m, dict) or set(m) != {"sha256", "mime", "bytes"} or not HEX64.match(str(m["sha256"])) \
                or m["mime"] not in MIMES or not isinstance(m["bytes"], int) or m["bytes"] <= 0:
            raise Reject("media")
    return env, hashlib.sha256(raw).hexdigest(), pub
