"""merino-c14n (SPEC section 3): the one byte encoding every signature and hash is computed over."""
import re

_KEY = re.compile(r"[a-z0-9_]{1,32}\Z")
MAX_INT = 2 ** 53 - 1


class C14nError(ValueError):
    pass


def _str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif o < 0x20:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _enc(v, out):
    if v is None:
        out.append("null")
    elif v is True:
        out.append("true")
    elif v is False:
        out.append("false")
    elif isinstance(v, int):
        if not -MAX_INT <= v <= MAX_INT:
            raise C14nError("integer out of range")
        out.append(str(v))
    elif isinstance(v, str):
        out.append(_str(v))
    elif isinstance(v, (list, tuple)):
        out.append("[")
        for i, x in enumerate(v):
            if i:
                out.append(",")
            _enc(x, out)
        out.append("]")
    elif isinstance(v, dict):
        keys = list(v)
        for k in keys:
            if not isinstance(k, str) or not _KEY.match(k):
                raise C14nError("bad key %r" % (k,))
        out.append("{")
        for i, k in enumerate(sorted(keys, key=lambda s: s.encode())):
            if i:
                out.append(",")
            out.append(_str(k))
            out.append(":")
            _enc(v[k], out)
        out.append("}")
    else:
        raise C14nError("unsupported type %s" % type(v).__name__)


def encode(v):
    """Canonical bytes of v. Floats are rejected on purpose: coordinates travel as integer microdegrees."""
    out = []
    _enc(v, out)
    return "".join(out).encode("utf-8")
