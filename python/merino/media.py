"""Media cleaning (SPEC section 6). Devices clean before hashing; servers only check (rewriting would break custody)."""
import struct

# APP0 (JFIF), APP14 (Adobe colour transform), DQT, DHT, DAC, DRI, DNL and every SOFn. Everything else (EXIF, XMP, ICC, COM...) goes.
JPEG_KEEP = {0xE0, 0xEE, 0xDB, 0xC4, 0xCC, 0xDD, 0xDC} | (set(range(0xC0, 0xD0)) - {0xC8})
PNG_DROP = {b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"tIME"}
MP4_BLANK = {b"udta", b"meta"}
MP4_CONTAINERS = {b"moov", b"trak"}


class MediaError(ValueError):
    pass


def sniff(b):
    if b[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if b[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if len(b) >= 12 and b[4:8] == b"ftyp":
        return "video/mp4"
    return None


def _jpeg_segments(b):
    """Yield (marker, start, end) for every segment up to and including SOS; then ('scan', start, len)."""
    if b[:2] != b"\xff\xd8":
        raise MediaError("not a jpeg")
    i = 2
    while i < len(b):
        if b[i] != 0xFF:
            raise MediaError("bad marker")
        while i < len(b) and b[i] == 0xFF:
            i += 1
        if i >= len(b):
            raise MediaError("truncated")
        mk = b[i]
        i += 1
        if mk == 0xD9:
            yield mk, i - 2, i
            return
        if 0xD0 <= mk <= 0xD7 or mk == 0x01:
            yield mk, i - 2, i
            continue
        if i + 2 > len(b):
            raise MediaError("truncated")
        n = struct.unpack(">H", b[i:i + 2])[0]
        if n < 2 or i + n > len(b):
            raise MediaError("bad length")
        yield mk, i - 2, i + n
        i += n
        if mk == 0xDA:   # entropy-coded data runs to the next non-RST marker
            j = i
            while j + 1 < len(b):
                if b[j] == 0xFF and b[j + 1] not in (0x00, 0xFF) and not 0xD0 <= b[j + 1] <= 0xD7:
                    break
                j += 1
            yield "scan", i, j
            i = j


def _keep(mk):
    return mk == "scan" or mk in JPEG_KEEP or mk in (0xDA, 0xD9, 0x01) or 0xD0 <= mk <= 0xD7


def jpeg_clean(b):
    out = bytearray(b"\xff\xd8")
    for mk, s, e in _jpeg_segments(b):
        if _keep(mk):
            out += b[s:e]
    return bytes(out)


def jpeg_is_clean(b):
    return all(_keep(mk) for mk, _, _ in _jpeg_segments(b))


def _png_chunks(b):
    if b[:8] != b"\x89PNG\r\n\x1a\n":
        raise MediaError("not a png")
    i = 8
    while i + 12 <= len(b):
        n = struct.unpack(">I", b[i:i + 4])[0]
        t = b[i + 4:i + 8]
        if i + 12 + n > len(b):
            raise MediaError("bad chunk")
        yield t, i, i + 12 + n
        i += 12 + n
        if t == b"IEND":
            return
    raise MediaError("no IEND")


def png_clean(b):
    return b[:8] + b"".join(b[s:e] for t, s, e in _png_chunks(b) if t not in PNG_DROP)


def png_is_clean(b):
    return all(t not in PNG_DROP for t, _, _ in _png_chunks(b))


def _boxes(b, start, end):
    i = start
    while i + 8 <= end:
        size, typ = struct.unpack(">I4s", b[i:i + 8])
        hdr = 8
        if size == 1:
            if i + 16 > end:
                raise MediaError("bad box")
            size, hdr = struct.unpack(">Q", b[i + 8:i + 16])[0], 16
        elif size == 0:
            size = end - i
        if size < hdr or i + size > end:
            raise MediaError("bad box")
        yield typ, i, hdr, i + size
        i += size


def _mp4_walk(b, start, end, fix):
    dirty = False
    for typ, s, hdr, e in _boxes(b, start, end):
        if typ in MP4_BLANK:
            dirty = True
            if fix is not None:
                fix[s + 4:s + 8] = b"free"
                fix[s + hdr:e] = bytes(e - s - hdr)
        elif typ in MP4_CONTAINERS:
            dirty |= _mp4_walk(b, s + hdr, e, fix)
    return dirty


def mp4_clean(b):
    if sniff(b) != "video/mp4":
        raise MediaError("not an mp4")
    fix = bytearray(b)
    _mp4_walk(b, 0, len(b), fix)
    return bytes(fix)


def mp4_is_clean(b):
    if sniff(b) != "video/mp4":
        raise MediaError("not an mp4")
    return not _mp4_walk(b, 0, len(b), None)


CLEAN = {"image/jpeg": jpeg_clean, "image/png": png_clean, "video/mp4": mp4_clean}
IS_CLEAN = {"image/jpeg": jpeg_is_clean, "image/png": png_is_clean, "video/mp4": mp4_is_clean}


def clean(b):
    t = sniff(b)
    if t not in CLEAN:
        raise MediaError("unsupported media")
    return t, CLEAN[t](b)


def is_clean(b, mime):
    if sniff(b) != mime or mime not in IS_CLEAN:
        return False
    try:
        return IS_CLEAN[mime](b)
    except MediaError:
        return False
