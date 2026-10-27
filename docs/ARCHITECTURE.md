# Merino data architecture

Where every piece of data lives, how it moves, and what each system is able to
know. `SPEC.md` is the normative protocol; this document is the map of the
deployed system. Rule zero applies throughout: **anything that leaves the device
is treated as public**, so each store below is designed to hold nothing a
subpoena or a breach could turn into a person or an exact place.

## 1. The three tiers

```
 DEVICE (phone)                   SERVER (per realm)                  AUDITOR (anyone)
 ───────────────                  ──────────────────                  ────────────────
 exact fix, privacy zones,        pre-reduced envelope + sig,         GET /head, /ledger
 install secret, per-report       cleaned media, hash-only ledger     → merino audit
 key, private reports             (no IPs, no install ids)            verifies every link
        │  reduce, clean, sign          ▲                                 and signature
        └────────────────────────────── ┘  HTTPS, public by design
```

| Tier | Holds | Never holds |
|---|---|---|
| **Device** | Exact location, privacy zones, per-report Ed25519 seeds, install secret (for flag/confirm de-dup), private-only reports, original photos | Nothing it does not need; this is the only place precise data exists |
| **Server** | Reduced geometry (grid-snapped, optionally keyed-rounded), minute-granular time, body, signature, cleaned media, ledger | Exact coordinates, original media, IP addresses, install ids, plain emails |
| **Auditor** | The public ledger (hashes), signed receipts, public key | Content of deleted reports |

The server *re-checks* everything the device claims (grid alignment, time
granularity, media cleanliness, signature) and rejects what does not fit. It
never snaps, coarsens or backfills on the client's behalf: a server that snaps
has already received the exact input (SPEC 4.7, 1).

## 2. Realms and where each one lives

A **realm** is one app's namespace and policy (`python/merino/policy.py`).
Apps share the engine, never accounts or data.

| Realm | Backend | Host | Ledger signing | Retention |
|---|---|---|---|---|
| `liftcharge` (Storm Spotter) | **SQLite** via the Python service (`merino serve`), media on disk | CT139 `192.168.1.184`, public at `https://app.liftcharge.co/api/merino/` | In-process, key `/etc/merino/liftcharge.seed` | Items 90 days; photos 30 days, video 14 days |
| `aether` (Atlas + Field Companion) | **Postgres**: schema `merino` + triggers in the Supabase DB | CT103 `192.168.1.103` | **Outside the DB**: `merino pg-sign` on CT109 every 15 min, key `/root/.credentials/merino/aether.seed` | Ledger forever; report retention is the Atlas's own |

The difference is deliberate. LiftCharge is a standalone server, so the engine
owns the whole pipeline. Aether's reports already live in Supabase tables
(`public.reports/paths/polygons`) behind RLS, so Merino attaches as an
**additive layer**: triggers that enforce immutability and append a hash-only
ledger row, with signing kept out of the database so a dump cannot mint receipts.

## 3. The LiftCharge store (SQLite, `store.py`)

One file, `/var/lib/merino/merino.db` (WAL), plus a media directory.

| Table | Purpose | Key facts |
|---|---|---|
| `m_items` | One row per accepted envelope | `hash` (PK) = sha256(c14n(envelope)); `key` = signer's per-report public key; `t` observation minute; `recv` receipt minute; `seq` ledger position; `status` ∈ visible / hidden / superseded / deleted; `wire` = the signed envelope, **set to NULL on delete**; `s,w,n,e` = bounding box in microdegrees for map queries |
| `m_media` | Media committed to by an envelope | `state` 0 awaiting upload, 1 stored, 2 expired; keyed `(item, sha256)`; bytes live at a path derived from the sha |
| `m_marks` | Flags and confirms | `fh = sha256(install secret ‖ subject)`, so one install's marks on one item de-duplicate, and marks on different items are unlinkable. 3 distinct flags auto-hide (`sys:flags`) |
| `m_disclosures` | Opt-in contact details for an agency (e.g. NWS) | Signed by the item's key; never in a public response; erased with the item |
| ledger tables | Hash chain (`ledger.py`) | One row per accepted action, signed receipt per entry |

Not in SQLite at all: rate-limit state and live presence are **in memory only**
(rate limits keyed by an HMAC whose secret rotates daily and is never written
to disk; presence is a pre-snapped `town` cell with a 15-minute TTL).

### Item lifecycle

```
submit ──► visible ──► superseded   (edit: new envelope with ref=old, same key, SAME geo)
              │  └───► hidden       (3 flags → sys:flags, or operator hide; unhide reverses)
              ├──────► deleted      (owner `delete` envelope, or operator): wire := NULL, media removed
              └──────► deleted      (retention: `expire`, sys:retention)
```

A deleted item keeps only its envelope hash, in the ledger. The envelope's
random nonce makes that hash unguessable, so it reveals nothing about what was
deleted.

## 4. The Aether store (Postgres, `sql/merino.sql` + Atlas migrations)

Applied on CT103 from two files, in order:

1. `infrastructure/sql/2026-10-24-01-merino-core.sql` — this repo's `sql/merino.sql`
   (schema `merino`): `lon_mult`, `fdiv`, `lat_step`, `snap`, `on_grid`, `int_of`,
   `valid_pt`, `check_geo`, `c14n*`, `minute`, the append-only `merino.ledger`
   table, `ledger_append()` and the `ledger_guard` trigger that forbids DELETE and any UPDATE except filling an
   unset `sig`.
2. `infrastructure/sql/2026-10-24-02-merino-aether.sql` — Atlas-specific:
   - `public.merino_placed_immutable()` trigger on reports/paths/polygons: once
     `privacy_level` is anything but `private`, lat/lng or points can never change,
     **not even by service_role** (SPEC 4.7). Name, notes and privacy may change.
   - `public.merino_ledger_row()` trigger: one ledger row per insert/delete (and a
     `supersede` row when a private draft's geometry changes). Subject =
     `sha256(c14n({t:"aether.<table>", id, g: sha256(stored geometry)}))`, time at
     15-minute granularity, actor always `sys:atlas`. **No AGU id or user id ever
     enters the ledger.**

`merino.ledger(realm, seq, prev, kind, subject, t, actor, hash, sig)`, PK
`(realm, seq)`. `sig` is NULL until `pg-sign` fills it.

Field Companion 0.8.0+ reduces on the phone (Exact / 100 m / 1 km / 5 km per
tier, optional keyed rounding) and keeps *Private* reports on the device. Rows
that already existed before Merino were left in place (owner's decision).

## 5. The ledger

Both backends produce the same structure (SPEC 8):

```
entry = {seq, prev, kind, subject, t, actor}      hash = sha256(c14n(entry))
receipt = Ed25519(realm_key, "merino-ledger/1\n" + hash_bytes)
```

Properties an auditor can check with only the public key and the HTTP API:

- Each `prev` equals the previous entry's hash (genesis `prev` = 64 zeros).
- Each signature verifies.
- The head equals the last entry; nothing can be removed from the middle without
  breaking a link or a signature.
- A report missing from the public feed has a matching `delete` / `hide` /
  `expire` entry naming its actor (`key`, `op:<name>`, `sys:<job>`).

`pg-sign` re-hashes and re-links the **entire** chain from seq 1 before it signs
anything new, so a tampered or forked database is refused rather than
endorsed. The ledger is public and holds hashes only.

## 6. Data flows

| Flow | Device | Server |
|---|---|---|
| **Submit** | Reduce geometry, round time, clean media, build envelope with fresh per-report key, sign | Verify v/realm/kind, signature, grid, time granularity/window, body schema, rate limit → store → ledger append → return signed receipt |
| **Media** | `PUT /v1/media/<sha>` after the envelope is accepted | Refuse bytes no live envelope references, wrong hash, or unclean files (EXIF/GPS, metadata atoms) |
| **Edit** | New envelope with `ref` = old hash, signed by the same key, same geometry | Old → `superseded`, `supersede` ledger entry |
| **Delete** | `delete` envelope (`ref`) signed by the item's key | `wire := NULL`, media and disclosure erased, `delete` ledger entry |
| **Flag / confirm** | Throwaway key, `fh` computed locally | De-duplicate by `fh`; ≥3 flags auto-hide |
| **Disclose** | Contact details signed with the item key | Stored privately; revoked by `delete` with scope `disclosure` |
| **Presence** (opt-in) | Sends `town`-snapped cell + a token | In memory, 15 min; visible only to others who are sharing |
| **Lookup relay** (opt-in) | Rewrites third-party weather/geocoding/map requests to `/px/<host>/…` on `app.liftcharge.co` (CT100 → CT139 nginx) or the Atlas vhost (CT100) | Fixed allow-list of upstream hosts, others 404; no client headers forwarded, fixed User-Agent, Set-Cookie dropped, `access_log off`. Hides the phone from those providers; Merino itself does not depend on it |
| **Moderate** | — | `merino moderate HASH hide\|unhide\|delete OPERATOR`; always ledgered with the operator name |
| **Retention** | — | Hourly `merino purge`: items past `retention_days` → `expire`; media past its per-mime days removed (envelope keeps the hash) |
| **Audit** | — | `merino audit URL REALM` walks `/head` and `/ledger` |

## 7. Public API (`service.py`, behind `--prefix /api/merino`)

```
POST /v1/submit            POST /v1/disclose         POST /v1/presence
PUT  /v1/media/<sha>       GET  /v1/media/<sha>
GET  /v1/<realm>/items     GET  /v1/<realm>/presence
GET  /v1/<realm>/head      GET  /v1/<realm>/ledger?start=N
GET  /v1/<realm>/receipt/<hash>      GET /v1/item/<hash>
```

The service writes **no access log** (method, path without query, status at
most, per SPEC 9). Behind Cloudflare, CT100 hands the real client address to
CT139 only as an `X-Real-IP` header that the service uses for in-memory rate
limiting and never stores.

## 8. Keys and custody

| Key | Where | Purpose | Backup |
|---|---|---|---|
| `liftcharge.seed` | CT139 `/etc/merino/` (0600, `merino`) | Signs LiftCharge ledger receipts | Copy in `/root/.credentials/merino/`; **not** in the nightly `backup-liftcharge` (deliberately) |
| `aether.seed` | CT109 `/root/.credentials/merino/` | Signs Aether ledger receipts (`pg-sign`) | Offline copy via `VAULTWARDEN-IMPORT.txt` (owner action, see OPERATIONS.md) |
| `accounts.hmac` | CT139 `/etc/merino/`, copy on CT109 | HMAC for opt-in accounts (not yet used by anything) | As above |
| Per-report seeds | Device only | Prove ownership for edit/delete | None; lose the phone, lose the ability to edit |
| Install secret | Device only | Flag/confirm de-dup hash | None |

Losing a realm seed does not lose data, but it ends the ability to extend that
realm's signed chain under the same public key; the old chain still verifies.
Keys are never committed (`.gitignore` blocks `*.seed`, `*.hmac`).

## 9. Backups and what they cover

- `/usr/local/sbin/backup-liftcharge` (CT109, nightly) covers the spotter DB,
  photos, feedback, `merino.db` and the media tree. It excludes realm keys.
- Aether ledger rows are in the Supabase `pg_dumpall` taken to
  `Main-Storage/backups/supabase`.
- Because the ledger is public, any auditor's copy is also a backup of the chain.

## 10. Threat model mapping

| Threat (SPEC 2) | Mitigation here |
|---|---|
| Subpoena of the server | Only reduced geometry, no IPs or install ids on disk, deleted content gone (`wire` NULL), ledger holds hashes |
| Database breach | Same; plus realm keys are not in the DB (Aether) or the backup (LiftCharge) |
| Malicious operator | Every hide/unhide/delete is ledgered with the operator's name; the ledger is public and signed |
| Silent edit of a placed report | Immutable placement (SQL trigger + signed envelopes with `ref` requiring identical `geo`) |
| Cross-report linkage | Per-report keys, throwaway flag keys, `fh` scoped per item, keyed rounding |
| Photo metadata leaks | Media cleaned on device and re-checked on the server before hashing |
| Data brokers | No third parties receive data; lookups go through the no-header relay |

## 11. Known gaps

- The Aether ledger has not yet recorded real data (0 rows at the time of
  writing); the signing path is tested against the conformance vectors and a
  throwaway cluster (`sql/test.py`) but not yet against production traffic.
- Accounts are specified (SPEC 9) but not implemented.
- Nothing yet mirrors the public ledger off-site automatically.
