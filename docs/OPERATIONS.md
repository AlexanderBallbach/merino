# Operating Merino

Runbook for the two live deployments. Architecture and rationale:
`ARCHITECTURE.md`. Hostnames/IPs are the AEGServitor cluster's (`CT139`
LiftCharge, `CT103` Supabase, `CT109` management).

## 1. LiftCharge realm (CT139, SQLite)

| Thing | Value |
|---|---|
| Code | `/opt/merino/merino/*.py` (a copy of `python/merino/`, **no git, no VERSION file**; compare with `diff -r python/merino /opt/merino/merino`) |
| Service | `lcmerino.service` — `python3 -m merino serve --db /var/lib/merino/merino.db --media /var/lib/merino/media --keys /etc/merino --realms liftcharge --prefix /api/merino`, user `merino`, port `127.0.0.1:8795`, hardened (`ProtectSystem=strict`, `NoNewPrivileges`) |
| Purge | `lcmerino-purge.timer` hourly → `merino purge` (retention + media expiry, ledgered as `sys:retention`) |
| Keys | `/etc/merino/liftcharge.seed`, `accounts.hmac` (0600, owner `merino`) |
| Data | `/var/lib/merino/merino.db` (+ `-wal`, `-shm`), `/var/lib/merino/media/` |
| Front door | nginx `location /api/merino/` → `:8795`, `client_max_body_size 21m`; CT100 + the Cloudflare tunnel put it at `https://app.liftcharge.co/api/merino/` |
| Backup | `/usr/local/sbin/backup-liftcharge` on CT109, nightly; includes `merino.db` and media, **excludes keys** |

### Deploy a new engine version

```
# from the repo (the worktree you deploy from)
(cd python && python3 -m unittest discover -s tests)
ssh -4 192.168.1.184 'rm -rf /tmp/merino-new && mkdir /tmp/merino-new'
scp -4 python/merino/*.py 192.168.1.184:/tmp/merino-new/
ssh -4 192.168.1.184 'cp -a /opt/merino/merino /opt/merino/merino.bak-$(date +%F) &&
  install -m 644 /tmp/merino-new/*.py /opt/merino/merino/ && systemctl restart lcmerino'
ssh -4 192.168.1.184 "echo $(git rev-parse --short HEAD) > /opt/merino/VERSION"
python3 -m merino audit https://app.liftcharge.co/api/merino liftcharge --ipv4   # from python/
```

Restarting drops only in-memory state (rate limits, presence). Always run the
audit afterwards: it must print `ok N entries`.

`--ipv4` is needed from CT109 (IPv6 with no route hangs for 60 s). Cloudflare
returns 403 to the default Python User-Agent, so the audit sends
`merino-audit/1`.

### Moderation

```
ssh 192.168.1.184 'cd /opt/merino && sudo -u merino python3 -m merino moderate \
  --db /var/lib/merino/merino.db --media /var/lib/merino/media --keys /etc/merino \
  <hash> hide|unhide|delete <operator>'
```

Every action is ledgered with `op:<operator>`; `delete` erases the stored
envelope and its media.

### Restore

Restore `merino.db` and `media/` from the nightly archive, put the seed back at
`/etc/merino/liftcharge.seed` (0600, `merino`), start the service, then run the
audit. The ledger is public, so an auditor's copy can verify a restored chain
and show exactly which entries were lost.

## 2. Aether realm (CT103 Postgres, signed from CT109)

| Thing | Value |
|---|---|
| Schema | `merino` in the Supabase DB (`supabase-db` container, db `postgres`) |
| Triggers | `public.merino_placed_immutable`, `public.merino_ledger_row` on `reports`, `paths`, `polygons` |
| Signer | `merino-pg-sign.timer` on CT109, every 15 min (+5 min after boot) |
| Key | `/root/.credentials/merino/aether.seed` (CT109 only) |

The signer command:

```
python3 -m merino pg-sign --keys /root/.credentials/merino --realm aether -- \
  ssh -o BatchMode=yes 192.168.1.93 pct exec 103 -- docker exec -i supabase-db psql -U postgres -d postgres
```

It re-verifies the **whole** chain from seq 1 and refuses to sign if anything
does not link. Unsigned rows can sit for up to 15 minutes. Check:

```
systemctl status merino-pg-sign.timer
ssh 192.168.1.93 "pct exec 103 -- docker exec supabase-db psql -U postgres -c \
  \"select count(*), count(sig), max(seq) from merino.ledger where realm='aether'\""
```

### Applying/updating the SQL

Both files are idempotent (`create or replace`, `if not exists`). Take a
`pg_dumpall` first (Main-Storage/backups/supabase), apply core then Aether, then
run the immutability smoke test: an `UPDATE public.reports SET lat=… WHERE
privacy_level <> 'private'` must raise `merino: a placed report's location
cannot be changed`. To test the SQL port against the vectors on a throwaway
cluster: `python3 sql/test.py`.

Gotcha: a Postgres `BEFORE UPDATE OF col` trigger does not see columns changed by
another trigger, so the supersede ledger row uses a separate `AFTER UPDATE …
WHEN (old.x IS DISTINCT FROM new.x)` trigger.

## 3. Key custody

- **Never commit** `*.seed`, `*.hmac`, or `VAULTWARDEN-IMPORT.txt` (all in `.gitignore`).
- `/root/.credentials/merino/VAULTWARDEN-IMPORT.txt` is a one-time bundle for the
  owner to paste into Vaultwarden and keep an offline copy of, then delete.
  **Still pending owner action** as of 2026-10-27.
- Rotating a realm key: generate a new key with `merino keygen`, announce the new
  public key, and start a new realm chain or document the key change as a
  signed operator entry; old entries remain verifiable with the old public key.
  There is no automated rotation yet.

## 4. Routine checks

| Check | Command | Healthy |
|---|---|---|
| Public chain | `python3 -m merino audit https://app.liftcharge.co/api/merino liftcharge --ipv4` | `ok N entries, head …` |
| Service | `ssh 192.168.1.184 systemctl is-active lcmerino lcmerino-purge.timer` | active/active |
| Aether signer | `systemctl list-timers merino-pg-sign.timer` (CT109) | next run within 15 min |
| Deployed = repo | `diff -r python/merino` vs `/opt/merino/merino` | no output |
| Tests | `cd python && python3 -m unittest discover -s tests` | all pass |

Tests must be run from `python/` (`-s tests`), not from the repo root.
