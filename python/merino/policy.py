"""Realm policies: what each app accepts. A realm is one app's namespace on a Merino server."""
from dataclasses import dataclass, field


def _str(v, n):
    return isinstance(v, str) and len(v) <= n


@dataclass
class Realm:
    name: str
    time_gran: int                         # minutes (SPEC 5)
    min_prec: dict                         # kind -> smallest allowed cell (m)
    body: object                           # callable(kind, body) -> None | error
    max_age_min: int = 7 * 24 * 60         # oldest observation accepted (offline queues)
    retention_days: int = 0                # 0 = keep until deleted
    media_max: int = 25 * 1024 * 1024
    media_per_item: int = 4
    rate: dict = field(default_factory=lambda: {"submit": (30, 3600), "media": (60, 3600), "flag": (60, 3600)})
    keep_path_time: bool = True
    media_days: dict = field(default_factory=dict)   # mime -> days the bytes are kept (the envelope keeps the hash)


# --- LiftCharge / Storm Spotter -------------------------------------------------
LC_TYPES = {"Tornado", "Funnel cloud", "Wall cloud", "Hail", "Damaging wind", "Flash flood", "Lightning",
            "Heavy rain", "Snow / ice", "Other"}


def lc_types(t):
    """'Tornado' or 'Tornado + Hail': 1..3 distinct known types."""
    parts = str(t).split(" + ")
    return 1 <= len(parts) <= 3 and len(set(parts)) == len(parts) and all(x in LC_TYPES for x in parts)


def lc_body(kind, b):
    if kind in ("delete", "flag", "confirm"):
        return None if b is None or (isinstance(b, dict) and set(b) <= {"fh", "scope"}) else "body"
    if kind != "report" or not isinstance(b, dict):
        return "kind"
    if not set(b) <= {"type", "magnitude", "notes"} or not lc_types(b.get("type")):
        return "body.type"
    if not _str(b.get("magnitude", ""), 40) or not _str(b.get("notes", ""), 500):
        return "body.text"
    return None


LIFTCHARGE = Realm("liftcharge", time_gran=5, body=lc_body, media_max=20_000_000,
                   media_days={"image/jpeg": 30, "image/png": 30, "video/mp4": 14},
                   min_prec={"report": 1, "path": 1, "polygon": 1},
                   retention_days=90)


# --- Aether Guild Atlas / Field Companion ----------------------------------------
AETHER_AUDIENCE = {"public", "community"}   # "private" never leaves the device under Merino


def ae_body(kind, b):
    if kind in ("delete", "flag", "confirm"):
        return None if b is None or (isinstance(b, dict) and set(b) <= {"fh", "scope"}) else "body"
    if not isinstance(b, dict) or b.get("audience", "public") not in AETHER_AUDIENCE:
        return "body.audience"
    if kind == "report":
        if not set(b) <= {"category", "title", "description", "audience", "intensity", "duration_min", "witnesses"}:
            return "body.keys"
        if not (_str(b.get("category"), 64) and b["category"]) or not _str(b.get("title", ""), 200) \
                or not _str(b.get("description", ""), 10000):
            return "body.text"
        for k, hi in (("intensity", 10), ("duration_min", 100000), ("witnesses", 1000)):
            if k in b and not (isinstance(b[k], int) and 0 <= b[k] <= hi):
                return "body." + k
        return None
    if kind in ("path", "polygon"):
        if not set(b) <= {"name", "description", "category", "audience"}:
            return "body.keys"
        if not _str(b.get("name", ""), 200) or not _str(b.get("description", ""), 10000) or not _str(b.get("category", ""), 64):
            return "body.text"
        return None
    return "kind"


AETHER = Realm("aether", time_gran=15, body=ae_body,
               min_prec={"report": 1, "path": 1, "polygon": 1})   # exact or coarse is the user's choice

REALMS = {r.name: r for r in (LIFTCHARGE, AETHER)}
