-- Opening hours: two time-of-day columns ordered by a check rule, and one with a time zone.
-- A time of day is not a date: "09:00:00" must be compared and moved as a clock time.
create table public.studio_hours (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  opens_at time without time zone not null,
  closes_at time without time zone not null,
  last_call time with time zone,
  constraint studio_hours_order check (opens_at < closes_at),
  constraint studio_hours_last_call check (last_call is null or last_call > opens_at),
  constraint studio_hours_daytime check (opens_at >= '10:30'::time)
);
alter table public.studio_hours enable row level security;
create policy studio_hours_own on public.studio_hours for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
grant select, insert, update, delete on public.studio_hours to authenticated;
