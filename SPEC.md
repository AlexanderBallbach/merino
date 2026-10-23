# Merino 1 — specification

Merino is the shared engine under citizen-science reporting apps (first users:
LiftCharge / Storm Spotter and the Aether Guild Atlas + Field Companion). It
covers what a report *is* on the wire, how location, time and media are reduced
before they leave the phone, how a report keeps a verifiable chain of custody
without naming its author, and what a server is allowed to keep.

## 1. Principles

1. **Everything that leaves the device is public.** Assume every byte a server
   receives will eventually be read by someone hostile: a breach, a subpoena,
   a future owner. Privacy reductions therefore run **on the device, before
   upload**. A server re-checks them (defence in depth) but never relies on
   keeping a more precise copy secret, because it never has one.
2. **Custody without identity.** A report can be proven unaltered since
   submission, and its place in the server's history proven, with no name,
   account, device id or IP attached.
3. **Hold nothing worth subpoenaing.** No IP addresses, no exact positions the
   user did not deliberately publish, no device fingerprints, no access logs
   with coordinates. Short, written retention. Deletion means deletion.
4. **No brokers.** No third-party SDKs, analytics, ad ids or data sales.
   Third-party fetches that would reveal a user's location (tiles, weather
   APIs) go through the operator's server where practical.
5. **Consent is per disclosure.** Any disclosure beyond the default (an exact
   pin, contact details for an agency, live position) is opt-in, visible at the
   moment it happens, scoped to a purpose, and revocable.

## 2. Threat model

| Adversary | Gets | Merino's answer |
|---|---|---|
| Anyone reading the public API | Everything public | Public data is already reduced; nothing links two anonymous reports |
| Database breach / seizure / subpoena of the operator | Every table, every log | Tables hold only reduced data; no IPs; no device ids on rows; contact details only for users who opted in, deletable |
| Operator tampering with a report or its history | Write access to the DB | Signed envelopes + a hash-chained ledger whose head is published; any edit or silent deletion breaks verification |
| Forger posting fake reports as someone else | API access | Ed25519 signatures; edits/deletes need the original report key |
| Data broker / SDK | Nothing, unless an app ships an SDK | Rule 4; apps carry no analytics |
| Network observer / CDN (Cloudflare) | TLS terminates at the CDN, so it sees request contents and client IPs | Cannot be solved by the app; reduced-on-device data limits what it sees. Documented, not hidden |
| Averaging attack (many reports from one home) | Repeated reduced points | Deterministic grid: the same place always snaps to the same cell centre, so repeated reports do not narrow it down |

Out of scope: a compromised phone, and a user who chooses to publish an exact
pin of their home. Merino makes that choice explicit; it does not forbid it.

## 3. Canonical encoding (`merino-c14n`)

Everything signed or hashed is encoded this way, identically in every
implementation:

- Values: objects, arrays, strings, integers, `true`, `false`, `null`.
  **No floating point anywhere** — coordinates are integer microdegrees.
- Integers: `-(2^53-1) .. 2^53-1`, plain decimal, no leading zeros, `-0` is `0`.
- Object keys: `[a-z0-9_]{1,32}`, sorted by byte value, no duplicates.
- Strings: UTF-8. Escape `"` as `\"`, `\` as `\\`, and code points below
  U+0020 as `\u00XX` (lower-case hex). Nothing else is escaped.
- No whitespace.

## 4. Location reduction

### 4.1 Precision ladder

| Level | Cell | Typical use |
|---|---|---|
| `exact` | ~1 m | Only when the user explicitly picks it, every time |
| `block` | 100 m | Paths, phenomena the user is not standing at |
| `neighborhood` | 1 km | **Default for reports** |
| `town` | 5 km | Default inside a privacy zone; live presence |
| `region` | 25 km | Sensitive reports |

### 4.2 Grid snap

Coordinates are integer microdegrees (`lat_e6`, `lon_e6`). For a cell size of
`m` metres:

```
lat_step = max(1, round(m * 1_000_000 / 111_320))        (round half up)
lat_c    = floor(lat_e6 / lat_step) * lat_step + lat_step // 2, clamped to ±90_000_000
band     = min(89, abs(lat_c) // 1_000_000)
lon_step = min(360_000_000, lat_step * LON_MULT[band] // 1000)
x        = lon_e6 + 180_000_000
lon_c    = floor(x / lon_step) * lon_step + lon_step // 2 - 180_000_000, clamped to ±180_000_000
```

`LON_MULT[d] = ceil(1000 / cos(min(d + 1, 89) degrees))` is a fixed 90-entry
table (in `vectors/lon_mult.json`), using the band's poleward edge so a cell is
never narrower east-west than it is north-south. A table rather than a runtime
`cos()` keeps every implementation bit-identical.

Properties every implementation must keep: a cell centre snaps to itself
(so a server can check `snap(p) == p` to confirm a point is reduced), and the
same input always gives the same output (no randomness — random jitter is
averaged away by repeated reports, a fixed grid is not).

### 4.3 Privacy zones (device only)

The user can mark circles (home, work, a friend's house). They are stored only
on the device and never uploaded. A report placed inside a zone (plus a 500 m
margin) is raised to at least `town`; a path drops every point inside one.

### 4.4 Paths

Before upload, in order:
1. Drop points with a GPS accuracy worse than 100 m.
2. Drop points inside privacy zones.
3. Trim the first and last 300 m of travelled distance (where a walk starts and
   ends is usually where someone lives or parked).
4. Snap each point to the path precision (default `block`).
5. Drop consecutive duplicates.
6. Time: absolute timestamps are replaced by seconds since the first kept
   point, rounded to 60 s; the start time is coarsened like any other time.
   A realm may drop times entirely.

A path that has fewer than 2 points after this is not uploaded.

### 4.5 Polygons

Vertices snapped to the polygon precision (default `block`), consecutive
duplicates removed, at least 3 distinct vertices, at most 2,000.

## 5. Time reduction

Times are integer **unix minutes**, floored to the realm's granularity
(LiftCharge 5, Aether 15). The server records receipt time at the same
granularity. Ordering comes from the ledger sequence, not from timestamps.

## 6. Media

Media is cleaned **before** it is hashed into the envelope, so the server can
check the hash and then check the bytes are clean; it never rewrites them
(rewriting would break the hash and the custody chain).

- JPEG: keep `SOI`, `APP0` (JFIF), `APP14` (Adobe), `DQT`, `DHT`, `DRI`,
  `SOFn`, `SOS` + scan data, `EOI`. Drop every other `APPn` (EXIF, XMP, ICC
  thumbnails, maker notes) and `COM`.
- PNG: drop `tEXt`, `zTXt`, `iTXt`, `eXIf`, `tIME`.
- MP4/MOV: every `udta` and `meta` box (top level, in `moov`, in each `trak`)
  becomes a `free` box of the same size with a zeroed payload, so chunk offsets
  do not move.

## 7. Envelopes and signatures

```json
{
  "v": 1,
  "realm": "liftcharge",
  "kind": "report",
  "nonce": "<16 random bytes, base64url>",
  "t": 29812345,
  "geo": {"type": "point", "p": [44985000, -93214000], "prec": 1000},
  "body": {"type": "Hail", "magnitude": "1.00 in", "notes": ""},
  "media": [{"sha256": "<hex>", "mime": "image/jpeg", "bytes": 182311}],
  "key": "<Ed25519 public key, base64url, 32 bytes>"
}
```

- `kind`: `report`, `path`, `polygon`, `delete`, `flag`, `confirm`.
- `geo.type`: `point` (`p` = `[lat, lon]`), `path` (`p` = `[[lat, lon, dt], ...]`
  plus `t0`), `polygon` (`p` = `[[lat, lon], ...]`).
- `delete`, `flag` and `confirm` carry `ref` (the target's envelope hash) and no `geo`.
  A `report`/`path`/`polygon` may also carry `ref`: it **supersedes** (edits) the
  target, and must be signed by the target's key.
- `delete` body may be `{"scope": "disclosure"}` to revoke only a disclosure.
- `flag` / `confirm` body is `{"fh": sha256(install_secret ‖ target hash)}`,
  computed on the device, so the server can de-duplicate one install's marks on
  one item without ever seeing an install id, and marks on different items are
  unlinkable. Each mark is signed with a throwaway key.
- `t` is the observation time (SPEC 5). A server refuses `t` off the realm's
  granularity, in the future, or older than the realm's offline window (7 days).
- Signature: `Ed25519(key, "merino/1\n" + c14n(envelope))`. Wire form:
  `{"env": {...}, "sig": "<base64url>"}`.
- **Envelope hash** = `sha256(c14n(envelope))`, lower-case hex. It is the
  report's permanent custody id.
- The nonce makes envelope hashes unguessable, so a hash left in the ledger
  after deletion reveals nothing about the deleted content.

### Keys

By default each report gets **its own key**, generated on the device and kept
there. Two reports from one phone are therefore unlinkable server-side, yet the
phone can still prove ownership to edit or delete either. An app may offer an
opt-in persistent pseudonym (for reputation) or an account (for recovery across
phones); both are explained to the user as linking their reports.

### Media upload

The envelope commits to each file's `sha256`, `mime` and size. After it is
accepted the client `PUT`s the bytes; the server refuses bytes that no live
envelope references, that do not hash to the committed value, or that are not
clean (SPEC 6). Orphan uploads are therefore impossible, and deleting an item
deletes its files.

### Disclosures

Opt-in contact details for one item (for example a spotter's phone number for
the NWS) are sent separately from the envelope, never published, and signed by
the item's key: `Ed25519(key, "merino-disclose/1\n" + hash + "\n" + c14n(data))`.
They are revoked by a `delete` with scope `disclosure`, and erased with the item.

## 8. Ledger and receipts

Every accepted envelope, deletion, flag and operator action appends a ledger
entry:

```json
{"seq": 41, "prev": "<hex>", "kind": "report", "subject": "<envelope hash>", "t": 29812345, "actor": "key"}
```

`kind` is one of `report`, `path`, `polygon`, `supersede`, `delete`, `flag`,
`confirm`, `hide`, `unhide`, `expire`. `actor` is `key` (the signer of the
causing envelope), `op:<name>` (an operator), or `sys:<job>` (`sys:flags`
auto-hide, `sys:retention`). `t` is receipt time at the realm granularity. Entry hash = `sha256(c14n(entry))`; `prev` is the
previous entry's hash (64 zeros for `seq` 1). The server signs each entry hash
with its realm key — `Ed25519(realm_key, "merino-ledger/1\n" + entry_hash_bytes)` —
and returns it as a **receipt**. `python3 -m merino audit URL REALM` walks a
server's whole public ledger and checks every link and signature. A Postgres
server (`sql/merino.sql`) computes the chain in the inserting transaction but
holds no key; `merino pg-sign` re-verifies the whole chain and only then signs,
so a database dump cannot mint receipts. The ledger is public
(hashes only), and so is its head. Anyone holding a report, its receipt and the
ledger can check that the report is unaltered, was accepted at a given position,
and — if missing from the public feed — was removed by a recorded action, not
silently.

Moderation is part of custody: hiding, unhiding and deleting are ledgered with
the operator's name.

## 9. What a server may keep

| Data | Kept | Never |
|---|---|---|
| Envelope + signature | Until deleted or retention ends | — |
| Media | Realm retention | Original (uncleaned) files |
| Ledger | Forever (hashes only) | Content |
| Rate-limit state | In memory, keyed by HMAC with a secret rotated daily and never written to disk | IPs, device ids on disk |
| Flags | sha256(install id + envelope hash), so one install's flags on different reports are unlinkable | Raw install ids |
| Accounts (opt-in) | HMAC of email / OAuth subject, report links the user chose | Plain emails used only for sign-in |
| Disclosures (opt-in contact details for an agency) | Until revoked; never in a public response | Anything the user did not type |
| Live presence (opt-in) | `town` cell sent already snapped, in memory only, 15 minutes; visible only to others who are sharing | History, the fix itself |
| Access logs | Method, path without query, status | Client IP, query strings |

## 10. Conformance

`vectors/` holds generated test vectors (c14n, Ed25519 incl. RFC 8032, grid
snaps, path and polygon reductions, media cleaning, ledger chains). The Python
engine, the Kotlin client and the Postgres functions each run against the same
files; an implementation that disagrees with a vector is wrong.
