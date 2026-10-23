# Merino

Shared engine for citizen-science reporting: geographic reports, paths and
polygons that keep a verifiable chain of custody without exposing who made
them or exactly where they live. First users: **LiftCharge / Storm Spotter**
and **The Aether Guild** (Atlas + Field Companion).

Rule zero: **everything that leaves the device is public.** Reduction happens
on the phone; servers re-check and never hold a more precise copy. Expect
subpoenas; avoid data brokers. See `SPEC.md`.

| Dir | What |
|---|---|
| `SPEC.md` | The protocol: c14n, grid, paths, time, media, envelopes, ledger, retention |
| `python/merino` | Reference engine + SQLite server + stdlib HTTP service + CLI (no dependencies; uses `cryptography` for speed if present) |
| `kotlin/` | Pure-Kotlin client (JVM/Android): reduction, media cleaning, signing |
| `sql/merino.sql` | Postgres port of the grid, checks and ledger (for Supabase) |
| `vectors/` | Conformance vectors; every implementation tests against them |
| `tools/gen_vectors.py` | Regenerates `vectors/` from the Python engine |

```
cd python && python3 -m unittest discover -s tests
python3 -m merino keygen --keys /etc/merino --realm liftcharge
python3 -m merino serve --db /var/lib/merino/merino.db --media /var/lib/merino/media --keys /etc/merino
python3 -m merino audit https://app.liftcharge.co/api/merino liftcharge
```
