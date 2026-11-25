-- row/short-markers: a trigger that checks the shape and length of text columns and raises its own
-- error (not a CHECK, so no hint and no "rules paused" fallback), copied from a field-test app's chart
-- of accounts (names changed). An account code is at most 32 characters, longer than the scan's
-- usual marker text; every ledger table of that app hangs off this one.
create table public.gl_accounts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  code text not null,
  name text not null,
  report_group text not null,
  unique (user_id, code)
);
alter table public.gl_accounts enable row level security;
create policy gl_accounts_own on public.gl_accounts for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.guard_gl_account() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  if new.code !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$'
     or btrim(new.name) = '' or length(new.name) > 160
     or btrim(new.report_group) = '' or length(new.report_group) > 80 then
    raise exception 'invalid account fields' using errcode = '22023';
  end if;
  return new;
end;
$$;
create trigger gl_accounts_guard before insert or update on public.gl_accounts for each row execute function public.guard_gl_account();

create table public.gl_entries (
  id uuid primary key default gen_random_uuid(),
  account_id uuid not null references public.gl_accounts(id) on delete cascade,
  memo text not null
);
alter table public.gl_entries enable row level security;
create policy gl_entries_own on public.gl_entries for all to authenticated
  using (exists (select 1 from public.gl_accounts a where a.id = account_id and a.user_id = auth.uid()))
  with check (exists (select 1 from public.gl_accounts a where a.id = account_id and a.user_id = auth.uid()));

-- check/case: a CASE rule that picks which columns must be filled by the kind of metric, copied from
-- a field-test app (names changed). The solver once put an enum word into a number column here.
create type public.metric_kind as enum ('verified_spend', 'estimated_spend', 'credit_balance', 'revenue', 'recurring_revenue', 'usage_count');
create table public.metric_snapshots (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  metric_key text not null check (metric_key ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$'),
  kind public.metric_kind not null,
  value double precision,
  unit text,
  amount_minor bigint,
  currency character(3) check (currency ~ '^[A-Z]{3}$'),
  period_start timestamptz,
  period_end timestamptz,
  point_at timestamptz,
  provenance_source text not null check (provenance_source = any (array['provider_api', 'derived'])),
  pricing_source text,
  check (value is null or (value >= 0 and value < 'Infinity'::double precision)),
  check (kind <> 'estimated_spend' or (pricing_source is not null and provenance_source = 'derived')),
  check ((period_start is not null and period_end is not null and period_end > period_start and point_at is null) or (point_at is not null and period_start is null and period_end is null)),
  check (case when kind = any (array['verified_spend'::public.metric_kind, 'estimated_spend', 'credit_balance', 'revenue', 'recurring_revenue'])
    then amount_minor is not null and currency is not null and value is null and unit is null
    else value is not null and unit is not null and amount_minor is null and currency is null end),
  check (kind <> all (array['verified_spend'::public.metric_kind, 'estimated_spend', 'recurring_revenue']) or amount_minor >= 0)
);
alter table public.metric_snapshots enable row level security;
create policy metric_snapshots_own on public.metric_snapshots for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- row/optional-left-empty after the app's own error: an optional link adds a business rule, copied
-- from a field-test app (names changed). A debt "I owe" may only be linked to an expense; the first
-- choice for the kind of entry is income, so a filled link is refused with the app's own error. The
-- link is optional and the trigger only checks it when it is set.
create table public.debts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  direction text not null check (direction in ('i_owe', 'owed_to_me')),
  is_archived boolean not null default false
);
alter table public.debts enable row level security;
create policy debts_own on public.debts for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create table public.cash_entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  type text not null check (type in ('income', 'expense', 'salary')),
  amount numeric not null,
  debt_id uuid references public.debts(id) on delete set null
);
alter table public.cash_entries enable row level security;
create policy cash_entries_own on public.cash_entries for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.check_entry_debt() returns trigger
language plpgsql security definer set search_path = '' as $$
declare
  v_debt public.debts%rowtype;
begin
  if new.debt_id is null then
    return new;
  end if;
  select * into v_debt from public.debts where id = new.debt_id;
  if v_debt.direction = 'i_owe' and new.type <> 'expense' then
    raise exception 'a debt you owe can only be linked to an expense';
  end if;
  return new;
end;
$$;
create trigger cash_entries_debt before insert or update on public.cash_entries for each row execute function public.check_entry_debt();

create table public.cash_entry_notes (
  id uuid primary key default gen_random_uuid(),
  entry_id uuid not null references public.cash_entries(id) on delete cascade,
  body text not null
);
alter table public.cash_entry_notes enable row level security;
create policy cash_entry_notes_own on public.cash_entry_notes for all to authenticated
  using (exists (select 1 from public.cash_entries e where e.id = entry_id and e.user_id = auth.uid()))
  with check (exists (select 1 from public.cash_entries e where e.id = entry_id and e.user_id = auth.uid()));

-- Unique columns that must match a pattern (payment references), copied from a field-test app whose
-- second test user once got no row here (names changed). Both users must get one.
create table public.addon_orders (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  checkout_ref text unique check (checkout_ref ~ '^cs_[A-Za-z0-9_]{1,250}$'),
  item_ref text unique check (item_ref ~ '^si_[A-Za-z0-9_]{1,250}$'),
  status text not null default 'pending' check (status in ('pending', 'paid'))
);
alter table public.addon_orders enable row level security;
create policy addon_orders_own on public.addon_orders for select to authenticated using (user_id = auth.uid());

create table public.addon_grants (
  id uuid primary key default gen_random_uuid(),
  order_id uuid not null unique references public.addon_orders(id) on delete cascade,
  credits integer not null check (credits >= 0)
);
alter table public.addon_grants enable row level security;
create policy addon_grants_own on public.addon_grants for select to authenticated
  using (exists (select 1 from public.addon_orders o where o.id = order_id and o.user_id = auth.uid()));
