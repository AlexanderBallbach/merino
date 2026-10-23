-- Merino 1 for PostgreSQL (>= 13): grid re-check, c14n, hash-chained ledger.
--
-- What this is for: a Postgres-backed service (Supabase) can enforce SPEC 4
-- server-side -- "every coordinate I was given is already on its grid, at
-- least as coarse as the realm requires" -- and keep the SPEC 8 ledger,
-- without a separate Merino process. It never re-transforms a location: a
-- server that snaps exact input has, by definition, received exact input.
--
-- Receipt signatures are NOT computed here. The realm key stays out of the
-- database (a dump or a subpoena of the DB must not be able to forge
-- receipts); `python3 -m merino pg-sign` fills merino.ledger.sig from outside.
-- The chain itself (seq, prev, hash) is computed here, inside the inserting
-- transaction, so it cannot be skipped.
--
-- Bit-identical to the Python and Kotlin implementations; sql/test.sh runs it
-- against vectors/.

create schema if not exists merino;

-- SPEC 4.2 --------------------------------------------------------------------

create or replace function merino.lon_mult(band int) returns int
language sql immutable strict parallel safe as $$
  select (array[1001,1001,1002,1003,1004,1006,1008,1010,1013,1016,1019,1023,1027,1031,1036,1041,1046,1052,1058,1065,1072,1079,1087,1095,1104,1113,1123,1133,1144,1155,1167,1180,1193,1207,1221,1237,1253,1270,1287,1306,1326,1346,1368,1391,1415,1440,1467,1495,1525,1556,1590,1625,1662,1702,1744,1789,1837,1888,1942,2000,2063,2131,2203,2282,2367,2459,2560,2670,2791,2924,3072,3237,3421,3628,3864,4134,4446,4810,5241,5759,6393,7186,8206,9567,11474,14336,19108,28654,57299,57299])[band + 1]
$$;

create or replace function merino.fdiv(a bigint, b bigint) returns bigint
language sql immutable strict parallel safe as $$
  select case when a >= 0 then a / b else -((-a + b - 1) / b) end
$$;

create or replace function merino.lat_step(m int) returns bigint
language sql immutable strict parallel safe as $$
  select greatest(1, (m::bigint * 1000000 + 55660) / 111320)
$$;

-- Returns [lat_c, lon_c] in microdegrees.
create or replace function merino.snap(lat bigint, lon bigint, m int) returns bigint[]
language plpgsql immutable strict parallel safe as $$
declare
  ls bigint := merino.lat_step(m);
  lat_c bigint;
  lo bigint;
  lon_c bigint;
begin
  lat_c := least(90000000, greatest(-90000000, merino.fdiv(lat, ls) * ls + ls / 2));
  lo := least(360000000, ls * merino.lon_mult(least(89, (abs(lat_c) / 1000000)::int)) / 1000);
  lon_c := least(180000000, greatest(-180000000,
             merino.fdiv(lon + 180000000, lo) * lo + lo / 2 - 180000000));
  return array[lat_c, lon_c];
end $$;

create or replace function merino.on_grid(lat bigint, lon bigint, m int) returns boolean
language sql immutable strict parallel safe as $$
  select merino.snap(lat, lon, m) = array[lat, lon]
$$;

-- jsonb integer -> bigint, or null if it is not an integer in range.
create or replace function merino.int_of(v jsonb) returns bigint
language sql immutable parallel safe as $$
  select case when jsonb_typeof(v) = 'number'
               and (v::text)::numeric = trunc((v::text)::numeric)
               and abs((v::text)::numeric) <= 9007199254740991
              then (v::text)::bigint end
$$;

create or replace function merino.valid_pt(lat bigint, lon bigint) returns boolean
language sql immutable parallel safe as $$
  select lat is not null and lon is not null
     and lat between -90000000 and 90000000 and lon between -180000000 and 180000000
$$;

-- SPEC 4 server re-check. Null = acceptable; otherwise the same reason codes
-- as python/merino/geo.py check_geo.
create or replace function merino.check_geo(g jsonb, min_prec int) returns text
language plpgsql immutable parallel safe as $$
declare
  m bigint := merino.int_of(g -> 'prec');
  t text := g ->> 'type';
  pts jsonb := g -> 'p';
  keys text[];
  q jsonb;
  la bigint; lo bigint; dt bigint;
  last bigint := -1;
  n int;
begin
  if jsonb_typeof(g) is distinct from 'object' or m is null
     or m not in (1, 100, 1000, 5000, 25000) or m < min_prec then
    return 'precision';
  end if;
  select array_agg(k order by k) into keys from jsonb_object_keys(g) k;
  n := case when jsonb_typeof(pts) = 'array' then jsonb_array_length(pts) else -1 end;

  if t = 'point' then
    la := merino.int_of(pts -> 0); lo := merino.int_of(pts -> 1);
    if keys <> array['p','prec','type'] or n <> 2 or not merino.valid_pt(la, lo) then
      return 'point';
    end if;
    return case when merino.on_grid(la, lo, m::int) then null else 'off_grid' end;

  elsif t = 'path' then
    if keys <> array['p','prec','t0','type'] or merino.int_of(g -> 't0') is null
       or n < 2 or n > 20000 then
      return 'path';
    end if;
    for q in select value from jsonb_array_elements(pts) loop
      la := merino.int_of(q -> 0); lo := merino.int_of(q -> 1); dt := merino.int_of(q -> 2);
      if jsonb_typeof(q) is distinct from 'array' or jsonb_array_length(q) <> 3
         or not merino.valid_pt(la, lo) or dt is null or dt < last or dt % 60 <> 0 then
        return 'path';
      end if;
      last := dt;
      if not merino.on_grid(la, lo, m::int) then return 'off_grid'; end if;
    end loop;
    return null;

  elsif t = 'polygon' then
    if keys <> array['p','prec','type'] or n < 3 or n > 2000 then
      return 'polygon';
    end if;
    for q in select value from jsonb_array_elements(pts) loop
      la := merino.int_of(q -> 0); lo := merino.int_of(q -> 1);
      if jsonb_typeof(q) is distinct from 'array' or jsonb_array_length(q) <> 2
         or not merino.valid_pt(la, lo) then
        return 'polygon';
      end if;
      if not merino.on_grid(la, lo, m::int) then return 'off_grid'; end if;
    end loop;
    return null;
  end if;
  return 'type';
end $$;

-- SPEC 3 ----------------------------------------------------------------------
-- jsonb -> canonical bytes. Raises on floats, out-of-range ints and bad keys,
-- exactly as the other implementations do. jsonb has already collapsed
-- duplicate keys, so a duplicate cannot be detected here; callers that verify
-- signatures over client bytes must do it before parsing into jsonb.

create or replace function merino.c14n_str(s text) returns text
language sql immutable strict parallel safe as $$
  select '"' || coalesce(string_agg(
           case when c = '"' then '\"'
                when c = '\' then '\\'
                when ascii(c) < 32 then '\u' || lpad(to_hex(ascii(c)), 4, '0')
                else c end, '' order by i), '') || '"'
    from unnest(regexp_split_to_array(s, '')) with ordinality as x(c, i)
   where c <> ''
$$;

create or replace function merino.c14n_text(v jsonb) returns text
language plpgsql immutable strict parallel safe as $$
declare
  out text;
  bad text;
begin
  case jsonb_typeof(v)
    when 'null' then return 'null';
    when 'boolean' then return v::text;
    when 'number' then
      if merino.int_of(v) is null then
        raise exception 'merino c14n: not an integer in range: %', v using errcode = '22023';
      end if;
      return merino.int_of(v)::text;
    when 'string' then return merino.c14n_str(v #>> '{}');
    when 'array' then
      select '[' || coalesce(string_agg(merino.c14n_text(e), ',' order by i), '') || ']'
        into out from jsonb_array_elements(v) with ordinality as x(e, i);
      return out;
    else
      select k into bad from jsonb_object_keys(v) k where k !~ '^[a-z0-9_]{1,32}$' limit 1;
      if bad is not null then
        raise exception 'merino c14n: bad key %', bad using errcode = '22023';
      end if;
      select '{' || coalesce(string_agg(merino.c14n_str(k) || ':' || merino.c14n_text(v -> k), ','
                                        order by convert_to(k, 'UTF8')), '') || '}'
        into out from jsonb_object_keys(v) k;
      return out;
  end case;
end $$;

create or replace function merino.c14n(v jsonb) returns bytea
language sql immutable strict parallel safe as $$
  select convert_to(merino.c14n_text(v), 'UTF8')
$$;

-- SPEC 8 ----------------------------------------------------------------------

create table if not exists merino.ledger (
  realm   text   not null,
  seq     bigint not null,
  prev    text   not null,
  kind    text   not null check (kind in ('report','path','polygon','supersede','delete',
                                            'flag','confirm','hide','unhide','expire')),
  subject text   not null check (subject ~ '^[0-9a-f]{64}$'),
  t       bigint not null,
  actor   text   not null check (actor = 'key' or actor ~ '^(op|sys):[a-z0-9_.-]{1,64}$'),
  hash    text   not null,
  sig     text,                       -- filled by `merino pg-sign`, which holds the realm key
  primary key (realm, seq)
);
create index if not exists ledger_subject on merino.ledger (subject);
create index if not exists ledger_unsigned on merino.ledger (realm, seq) where sig is null;

comment on table merino.ledger is
  'Merino SPEC 8 custody ledger: hashes only, never content. Append with '
  'merino.ledger_append(); rows are never updated except to set sig once, and never deleted.';

create or replace function merino.ledger_entry(l merino.ledger) returns jsonb
language sql immutable parallel safe as $$
  select jsonb_build_object('seq', l.seq, 'prev', l.prev, 'kind', l.kind,
                            'subject', l.subject, 't', l.t, 'actor', l.actor)
$$;

-- Appends one entry and returns its hash. Serialised per realm by an advisory
-- transaction lock, so concurrent inserts cannot fork the chain.
create or replace function merino.ledger_append(p_realm text, p_kind text, p_subject text,
                                                p_t bigint, p_actor text) returns text
language plpgsql volatile as $$
declare
  last merino.ledger;
  r merino.ledger;
begin
  perform pg_advisory_xact_lock(hashtextextended('merino.ledger:' || p_realm, 0));
  select * into last from merino.ledger where realm = p_realm order by seq desc limit 1;
  r.realm := p_realm;
  r.seq := coalesce(last.seq, 0) + 1;
  r.prev := coalesce(last.hash, repeat('0', 64));
  r.kind := p_kind; r.subject := p_subject; r.t := p_t; r.actor := p_actor;
  r.hash := encode(sha256(merino.c14n(merino.ledger_entry(r))), 'hex');
  insert into merino.ledger values (r.*);
  return r.hash;
end $$;

-- Append-only: block UPDATE (except setting sig once on an unsigned row) and DELETE.
create or replace function merino.ledger_guard() returns trigger
language plpgsql as $$
begin
  if tg_op = 'DELETE' then
    raise exception 'merino.ledger is append-only';
  end if;
  if old.sig is not null or (to_jsonb(new) - 'sig') <> (to_jsonb(old) - 'sig') then
    raise exception 'merino.ledger is append-only (only an unset sig may be filled)';
  end if;
  return new;
end $$;

drop trigger if exists ledger_guard on merino.ledger;
create trigger ledger_guard before update or delete on merino.ledger
  for each row execute function merino.ledger_guard();

-- Time (SPEC 5): unix minutes floored to the realm granularity.
create or replace function merino.minute(ts timestamptz, gran int) returns bigint
language sql stable strict parallel safe as $$
  select merino.fdiv(floor(extract(epoch from ts) / 60)::bigint, gran) * gran
$$;
