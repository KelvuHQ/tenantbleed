-- Arguments inserted straight into a table: a usage counter keyed by (owner, key, period date),
-- bumped by an upsert, copied from a field-test app (names changed). The arguments only meet the
-- table in INSERT (columns) VALUES (arguments), never in a WHERE, and the test row leaves its
-- optional key link empty, so ids taken by name never agreed: every call hit a foreign key error and
-- the function stayed untested. Here the argument names differ from the columns, so only the INSERT
-- column list ties them together. The unguarded upsert has no caller check (planted); its twin checks
-- the caller and must stay clean.
create table public.studio_keys (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  label text not null
);
alter table public.studio_keys enable row level security;
create policy studio_keys_own on public.studio_keys for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create table public.studio_usage (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  key_id uuid references public.studio_keys(id) on delete set null,
  period_start date not null,
  request_count bigint not null default 0,
  unique (studio_id, key_id, period_start)
);
alter table public.studio_usage enable row level security;
create policy studio_usage_own on public.studio_usage for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.bump_studio_usage(p_owner uuid, p_token uuid, p_day date, p_n bigint) returns void
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.studio_usage (studio_id, key_id, period_start, request_count)
  values (p_owner, p_token, p_day, p_n)
  on conflict (studio_id, key_id, period_start) do update set
    request_count = public.studio_usage.request_count + p_n;
end;
$$;

create function public.bump_my_studio_usage(p_owner uuid, p_token uuid, p_day date, p_n bigint) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.studios s where s.id = p_owner and s.created_by = auth.uid()) then
    raise exception 'not your studio' using errcode = '42501';
  end if;
  insert into public.studio_usage (studio_id, key_id, period_start, request_count)
  values (p_owner, p_token, p_day, p_n)
  on conflict (studio_id, key_id, period_start) do update set
    request_count = public.studio_usage.request_count + p_n;
end;
$$;
