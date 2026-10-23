"""Time reduction (SPEC section 5): integer unix minutes floored to a realm granularity."""
import time


def minute(ts=None):
    return int(time.time() if ts is None else ts) // 60


def coarsen(unix_min, granularity):
    return unix_min // granularity * granularity
