-- value/well-known-format: columns whose values the database checks against a list of its own,
-- copied from a field-test app (names changed). The time zone is not a CHECK (a subquery is not
-- allowed there) but a trigger asking pg_timezone_names, so no CHECK hint exists; country and
-- currency are pattern CHECKs. Every other table of such an app hangs off this one row, so a made-up
-- time zone leaves the whole app without test data.
create table public.studios (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 120),
  country_code text not null check (country_code ~ '^[A-Z]{2}$'),
  currency_code text not null check (currency_code ~ '^[A-Z]{3}$'),
  timezone text not null,
  created_by uuid not null default auth.uid() references auth.users(id)
);
alter table public.studios enable row level security;
create policy studios_own on public.studios for all to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());

create function public.validate_studio_timezone() returns trigger
language plpgsql as $$
begin
  if not exists (select 1 from pg_timezone_names where name = new.timezone) then
    raise exception 'unknown time zone: %', new.timezone using hint = 'use an IANA name such as Europe/Paris';
  end if;
  return new;
end;
$$;
create trigger studios_validate_timezone before insert or update of timezone on public.studios for each row execute function public.validate_studio_timezone();

-- The paper size depends on the country on the studio's local date. Runs first (triggers fire in
-- name order) and turns a made-up time zone into Postgres's own error (22023, time zone not
-- recognized), which no "pause the app's rules" fallback catches.
alter table public.studios add column paper text check (paper is null or paper in ('A4', 'Letter'));
create function public.studio_paper_in_country() returns trigger
language plpgsql as $$
begin
  if new.paper is not null and (now() at time zone coalesce(nullif(new.timezone, ''), 'UTC'))::date < date '2000-01-01' then
    raise exception 'paper not used in %', new.country_code using errcode = '22023';
  end if;
  return new;
end;
$$;
create trigger studios_a_paper_in_country before insert or update of paper, country_code on public.studios for each row execute function public.studio_paper_in_country();

-- A child that needs the studio, as most of that app's tables do.
create table public.studio_sessions (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  title text not null
);
alter table public.studio_sessions enable row level security;
create policy studio_sessions_own on public.studio_sessions for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

-- args/well-known-format: a report on any studio's sessions in a time zone the caller picks. No
-- caller check (planted), but it only answers when the time zone is real.
create function public.studio_day_report(p_studio_id uuid, p_timezone text)
returns table (title text, local_day date)
language sql stable security definer set search_path = ''
as $$
  select s.title, (now() at time zone p_timezone)::date from public.studio_sessions s where s.studio_id = p_studio_id
$$;

-- value/domain-base and time columns: an amount kept in a domain with its own rule (the table shows
-- only the domain's name), and an opening hour.
create domain public.cents as bigint check (value >= 100 and value <= 500000);
create table public.studio_rates (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  amount public.cents not null,
  opens_at time without time zone not null,
  closes_at time with time zone not null
);
alter table public.studio_rates enable row level security;
create policy studio_rates_own on public.studio_rates for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
