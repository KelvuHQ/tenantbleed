-- rpc-write/cache-refresh: a usage check anyone can call for any studio refreshes that studio's
-- cached usage from its sessions as a side effect (copied from a field-test app, names changed).
-- The caller makes the cache recompute, but every value comes from the studio's own data: found,
-- and only low. The control sets a cached number the caller picks: that stays a real write.
create table public.studio_usage_cache (
  studio_id uuid primary key references public.studios(id) on delete cascade,
  sessions integer not null default 0,
  booked_minutes bigint not null default 0,
  period_end date not null default current_date,
  cached_at timestamptz not null default now()
);
alter table public.studio_usage_cache enable row level security;
create policy studio_usage_cache_own on public.studio_usage_cache for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.studio_usage_fits(p_studio_id uuid) returns boolean
language plpgsql volatile security definer set search_path = '' as $$
declare n integer;
begin
  select count(*) into n from public.studio_sessions where studio_id = p_studio_id;
  insert into public.studio_usage_cache (studio_id, sessions, booked_minutes, period_end, cached_at)
  values (p_studio_id, n, n * 60, current_date + 14, now())
  on conflict (studio_id) do update set sessions = excluded.sessions, booked_minutes = excluded.booked_minutes,
    period_end = excluded.period_end, cached_at = excluded.cached_at;
  return n < 100;
end;
$$;

create function public.forget_studio_usage(p_studio_id uuid) returns void
language sql volatile security definer set search_path = '' as $$
  delete from public.studio_usage_cache where studio_id = p_studio_id
$$;

-- Control: the caller picks the number written into the cache.
create function public.set_studio_usage(p_studio_id uuid, p_minutes bigint) returns void
language sql volatile security definer set search_path = '' as $$
  update public.studio_usage_cache set booked_minutes = p_minutes where studio_id = p_studio_id
$$;
