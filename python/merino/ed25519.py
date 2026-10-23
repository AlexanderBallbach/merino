"""Ed25519 (RFC 8032), pure Python so the engine has no dependencies to audit or install.

Uses the `cryptography` package when it is present (fast path); results are identical.
"""
import hashlib

p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _h(m):
    return hashlib.sha512(m).digest()


def _recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y * y - 1) * pow(d * y * y + 1, p - 2, p)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * I % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


_gy = 4 * pow(5, p - 2, p) % p
_gx = _recover_x(_gy, 0)
G = (_gx, _gy, 1, _gx * _gy % p)
O = (0, 1, 1, 0)


def _add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G_, H = B - A, D - C, D + C, B + A
    return (E * F % p, G_ * H % p, F * G_ % p, E * H % p)


def _mul(s, P):
    Q = O
    while s > 0:
        if s & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        s >>= 1
    return Q


def _eq(P, Q):
    return (P[0] * Q[2] - Q[0] * P[2]) % p == 0 and (P[1] * Q[2] - Q[1] * P[2]) % p == 0


def _compress(P):
    zinv = pow(P[2], p - 2, p)
    x, y = P[0] * zinv % p, P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _expand(seed):
    if len(seed) != 32:
        raise ValueError("seed must be 32 bytes")
    h = _h(seed)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:]


try:  # fast path
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives import serialization as _ser
    from cryptography.exceptions import InvalidSignature as _Invalid
except Exception:  # pragma: no cover - depends on host
    Ed25519PrivateKey = None


def public_key(seed):
    if Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(_ser.Encoding.Raw, _ser.PublicFormat.Raw)
    a, _ = _expand(seed)
    return _compress(_mul(a, G))


def sign(seed, msg):
    if Ed25519PrivateKey:
        return Ed25519PrivateKey.from_private_bytes(seed).sign(msg)
    a, prefix = _expand(seed)
    A = _compress(_mul(a, G))
    r = int.from_bytes(_h(prefix + msg), "little") % L
    R = _compress(_mul(r, G))
    k = int.from_bytes(_h(R + A + msg), "little") % L
    s = (r + k * a) % L
    return R + int.to_bytes(s, 32, "little")


def verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64:
        return False
    if Ed25519PrivateKey:
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, msg)
            return True
        except (_Invalid, ValueError):
            return False
    A = _decompress(pub)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(_h(sig[:32] + pub + msg), "little") % L
    return _eq(_mul(s, G), _add(R, _mul(k, A)))
