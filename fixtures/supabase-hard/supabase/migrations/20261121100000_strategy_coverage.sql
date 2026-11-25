-- Strategy coverage: test-data steps and argument strategies (scripts/rules.json "strategies") that no
-- other planted case needed. Each block names the strategy it exists for.

-- check/* (the CHECK solver): the first try fails this rule, so the solver works out the first
-- branch atom by atom. The second branch can never hold, so it cannot win instead.
create table public.solver_cases (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  kind text not null,
  priority integer not null,
  region text not null,
  score integer not null,
  tags text[] not null,
  code text not null,
  variant text not null,
  is_visible boolean not null,
  staff_reviewed boolean not null,
  constraint solver_cases_branch check (
    (kind = 'x'
      and priority = any (array[3, 7])
      and region = any (array['eu', 'us'])
      and score >= 10
      and tags <@ array['a', 'b']
      and cardinality(tags) >= 1
      and code ~ '^[A-Z]{3}$'
      and variant <> all (array['p', 'q'])
      and not is_visible
      and staff_reviewed)
    or (kind = 'y' and priority < 0 and priority > 0)
  )
);
alter table public.solver_cases enable row level security;
create policy solver_cases_own on public.solver_cases for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- value/check-length, value/check-pattern-generated, value/not-privileged: chosen when the row is
-- first built, from the column's own rule or name.
create table public.vouchers (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  short_code text not null check (char_length(short_code) = 3),
  reference text not null check (reference ~ '^INV-[0-9]{4}$'),
  is_admin boolean not null
);
alter table public.vouchers enable row level security;
create policy vouchers_own on public.vouchers for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- row/exclusion-shift: one room, no overlapping bookings, so the second user's booking is moved on.
create extension if not exists btree_gist with schema extensions;
create table public.room_bookings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  room text not null check (room = 'main'),
  -- Defaults put every new booking in the same slot, as a booking form's "next free hour" would:
  -- deterministic, so the two test users' bookings always collide.
  starts_at timestamptz not null default date_trunc('hour', now()) + interval '1 hour',
  ends_at timestamptz not null default date_trunc('hour', now()) + interval '2 hours',
  check (ends_at > starts_at),
  exclude using gist (room with =, tstzrange(starts_at, ends_at) with &&)
);
alter table public.room_bookings enable row level security;
create policy room_bookings_own on public.room_bookings for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- args/named-table: the argument is named after the table (p_sync_job_id, sync_jobs), no check.
create function public.get_sync_job(p_sync_job_id uuid) returns setof public.sync_jobs
language sql stable security definer set search_path = ''
as $$ select * from public.sync_jobs where id = p_sync_job_id $$;

-- args/scope-word: anything but "mine" returns everyone's notes.
create function public.search_member_notes(p_scope text) returns setof public.member_notes
language sql stable security definer set search_path = ''
as $$ select * from public.member_notes where coalesce(nullif(p_scope, ''), 'mine') <> 'mine' or user_id = auth.uid() $$;

-- args/month: a month's time entries, for anyone.
create function public.time_report(p_month text) returns setof public.time_entries
language sql stable security definer set search_path = ''
as $$ select * from public.time_entries where to_char(started_at, 'YYYY-MM') = p_month $$;

-- owner-control/accepted: refuses non-members, answers members with a number only.
create function public.org_note_total(p_org_id uuid) returns bigint
language plpgsql stable security definer set search_path = ''
as $$
begin
  if not exists (select 1 from private.my_orgs o where o.org_id = p_org_id) then
    raise exception 'not a member of this organization';
  end if;
  return (select count(*) from public.notes where org_id = p_org_id);
end;
$$;
revoke execute on function public.org_note_total(uuid) from public, anon;
grant execute on function public.org_note_total(uuid) to authenticated;
