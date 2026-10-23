"""In-memory rate limiting keyed by HMAC under a secret that rotates daily and never touches disk (SPEC section 9)."""
import hashlib
import hmac
import os
import threading
import time


class Limiter:
    def __init__(self, clock=time.time):
        self._clock = clock
        self._lock = threading.Lock()
        self._day = None
        self._secret = b""
        self._hits = {}

    def _key(self, ident):
        day = int(self._clock()) // 86400
        if day != self._day:   # rotate: yesterday's keys become unlinkable and are dropped
            self._day, self._secret, self._hits = day, os.urandom(32), {}
        return hmac.new(self._secret, ident.encode(), hashlib.sha256).digest()[:16]

    def hit(self, ident, limit, window=3600):
        """Record one hit; True if over the limit. ident is e.g. 'ip:1.2.3.4' or 'install:...'."""
        with self._lock:
            now = self._clock()
            k = self._key(ident)
            ts = [t for t in self._hits.get(k, ()) if now - t < window]
            over = len(ts) >= limit
            if not over:
                ts.append(now)
            self._hits[k] = ts
            return over
