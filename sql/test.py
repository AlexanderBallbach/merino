"""Run sql/merino.sql against vectors/ on a throwaway PostgreSQL cluster.

Usage: python3 sql/test.py            (needs initdb/pg_ctl/psql, runs as the postgres user if root)
       python3 sql/test.py --dsn ...  (an existing scratch database; never point this at production)
"""
import glob, json, os, shutil, subprocess, sys, tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
V = lambda n: json.load(open(os.path.join(ROOT, "vectors", n + ".json")))


def lit(s):
    return "'" + s.replace("'", "''") + "'"


def jl(v):
    return lit(json.dumps(v, ensure_ascii=False)) + "::jsonb"


def cases():
    """Yield (label, sql returning boolean)."""
    for i, r in enumerate(V("snaps")["rows"]):
        la, lo, m, lc, oc = r
        yield "snap%d" % i, "merino.snap(%d,%d,%d) = array[%d,%d]::bigint[]" % (la, lo, m, lc, oc)
        yield "grid%d" % i, "merino.on_grid(%d,%d,%d)" % (lc, oc, m)
    for i, c in enumerate(V("c14n")):
        if "reject" in c:
            yield "c14n_reject%d" % i, "pg_temp.rejects(%s)" % lit(json.dumps(c["reject"]))
        else:
            yield "c14n%d" % i, "merino.c14n_text(%s) = %s" % (jl(c["value"]), lit(c["c14n"]))
    e = V("envelope")
    yield "env_c14n", "merino.c14n_text(%s) = %s" % (jl(e["env"]), lit(e["c14n"]))
    yield "env_hash", "encode(sha256(merino.c14n(%s)),'hex') = %s" % (jl(e["env"]), lit(e["hash"]))
    for name in ("points", "paths", "polygons"):
        for i, c in enumerate(V(name)):
            g = c.get("out")
            if not g:
                continue
            yield "%s%d_ok" % (name, i), "merino.check_geo(%s, 1) is null" % jl(g)
            if g["prec"] > 1:
                bad = json.loads(json.dumps(g))
                p = bad["p"] if g["type"] == "point" else bad["p"][0]
                p[0] += 1
                yield "%s%d_off" % (name, i), "merino.check_geo(%s, 1) = 'off_grid'" % jl(bad)
            yield "%s%d_coarse" % (name, i), "merino.check_geo(%s, 25001) = 'precision'" % jl(g)
    yield "type", "merino.check_geo('{\"type\":\"blob\",\"p\":[],\"prec\":100}', 1) = 'type'"
    yield "float", "merino.check_geo('{\"type\":\"point\",\"p\":[0.5,0],\"prec\":1}', 1) = 'point'"
    for i, r in enumerate(V("keyed")[0]["rows"][:20]):
        if r[2] == 1:
            continue
        g = {"type": "point", "p": [r[3], r[4]], "prec": r[2], "mode": "keyed"}
        yield "keyed%d" % i, "merino.check_geo(%s, 1) is null" % jl(g)
        yield "keyed%d_floor" % i, "merino.check_geo(%s, %d) = 'precision'" % (jl(g), r[2] + 1)
    yield "keyed_exact", "merino.check_geo('{\"type\":\"point\",\"p\":[4,4],\"prec\":1,\"mode\":\"keyed\"}', 1) = 'mode'"
    yield "mode_other", "merino.check_geo('{\"type\":\"point\",\"p\":[0,0],\"prec\":100,\"mode\":\"x\"}', 1) = 'mode'"
    yield "extra", "merino.check_geo('{\"type\":\"point\",\"p\":[4,4],\"prec\":1,\"x\":1}', 1) = 'point'"


def ledger_sql():
    out = []
    for r in V("ledger")["receipts"]:
        e = r["entry"]
        out.append("select merino.ledger_append('vec', %s, %s, %d, %s) = %s as ok, 'ledger%d' as label"
                   % (lit(e["kind"]), lit(e["subject"]), e["t"], lit(e["actor"]), lit(r["hash"]), e["seq"]))
    return out


def run(psql):
    body = ["\\set ON_ERROR_STOP 1", open(os.path.join(ROOT, "sql", "merino.sql")).read(), "create function pg_temp.rejects(t text) returns boolean language plpgsql as $$ begin "
            "perform merino.c14n(t::jsonb); return false; exception when invalid_parameter_value then return true; end $$;",
            "\\pset tuples_only on", "\\pset format unaligned"]
    for label, expr in cases():
        body.append("select (%s)::text || ' %s';" % (expr, label))
    for s in ledger_sql():
        body.append("select ok::text || ' ' || label from (%s) x;" % s)
    body += [
        "do $$ begin delete from merino.ledger; raise exception 'deleted'; exception when others then "
        "if sqlerrm like '%append-only%' then raise notice 'guard ok'; else raise; end if; end $$;",
        "select merino.ledger_append('guard', 'report', repeat('a', 64), 0, 'key');",
        "update merino.ledger set sig='x' where seq=1 and realm='guard';",
        "do $$ begin update merino.ledger set sig='y' where seq=1 and realm='guard'; raise exception 'resigned'; "
        "exception when others then if sqlerrm like '%append-only%' then raise notice 'guard ok'; else raise; end if; end $$;",
    ]
    res = subprocess.run(psql, cwd="/", input="\n".join(body) + "\n", text=True, capture_output=True)
    if res.returncode:
        sys.exit(res.stderr)
    lines = [l for l in res.stdout.splitlines() if l.startswith(("true ", "false "))]
    bad = [l for l in lines if not l.startswith("true ")]
    guards = res.stderr.count("guard ok")
    print("%d checks, %d failures, %d/2 ledger guards" % (len(lines), len(bad), guards))
    for l in bad[:20]:
        print("  FAIL", l)
    return 0 if not bad and guards == 2 else 1


def pg_sign(psql, d, pre):
    """`merino pg-sign` over the vector chain must reproduce the vector receipts' signatures exactly."""
    lv = V("ledger")
    keys = os.path.join(d, "keys")
    os.makedirs(keys)
    with open(os.path.join(keys, "vec.seed"), "wb") as f:
        f.write(bytes.fromhex(lv["server_seed"]))
    env = dict(os.environ, PYTHONPATH=os.path.join(ROOT, "python"))
    cmd = [sys.executable, "-m", "merino", "pg-sign", "--keys", keys, "--realm", "vec", "--"] + psql
    for want in ("signed %d" % len(lv["receipts"]), "signed 0"):
        r = subprocess.run(cmd, env=env, text=True, capture_output=True, cwd="/")
        if r.stdout.strip() != want:
            print("pg-sign: expected %r, got %r %s" % (want, r.stdout.strip(), r.stderr.strip()))
            return 1
    got = subprocess.run(psql + ["-X", "-At", "-c", "select sig from merino.ledger where realm='vec' order by seq"],
                         text=True, capture_output=True, cwd="/").stdout.split()
    if got != [x["sig"] for x in lv["receipts"]]:
        print("pg-sign: signatures differ from vectors")
        return 1
    # a tampered chain must be refused, not signed
    subprocess.run(psql + ["-X", "-q", "-c", "alter table merino.ledger disable trigger ledger_guard; "
                           "update merino.ledger set t=t+5 where realm='vec' and seq=2; "
                           "update merino.ledger set sig=null where realm='vec' and seq=3"], cwd="/", capture_output=True)
    r = subprocess.run(cmd, env=env, text=True, capture_output=True, cwd="/")
    if "REFUSED" not in r.stdout:
        print("pg-sign signed a tampered chain:", r.stdout)
        return 1
    print("pg-sign: %d signatures match vectors; tampered chain refused" % len(got))
    return 0


def main():
    if "--dsn" in sys.argv:
        return run(["psql", "-X", "-q", sys.argv[sys.argv.index("--dsn") + 1]])
    bins = sorted(glob.glob("/usr/lib/postgresql/*/bin"))[-1]
    d = tempfile.mkdtemp(prefix="merino-pg-")
    pre = ["runuser", "-u", "postgres", "--"] if os.geteuid() == 0 else []
    if pre:
        shutil.chown(d, "postgres")
    data, sock = os.path.join(d, "data"), d
    try:
        subprocess.run(pre + [bins + "/initdb", "-A", "trust", "-U", "postgres", "-E", "UTF8", "--locale=C", "-D", data],
                       check=True, capture_output=True, cwd="/")
        # the postmaster inherits stdout/stderr, so they must not be pipes we wait on
        subprocess.run(pre + [bins + "/pg_ctl", "-D", data, "-o", "-k %s -c listen_addresses=''" % sock,
                              "-l", os.path.join(d, "log"), "-w", "start"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd="/")
        try:
            psql = pre + [bins + "/psql", "-h", sock, "-U", "postgres", "postgres"]
            return run(psql + ["-X", "-q"]) or pg_sign(psql, d, pre)
        finally:
            subprocess.run(pre + [bins + "/pg_ctl", "-D", data, "-m", "fast", "stop"], capture_output=True, cwd="/")
    finally:
        shutil.rmtree(d, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
