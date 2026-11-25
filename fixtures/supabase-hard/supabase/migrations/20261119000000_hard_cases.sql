-- Hard cases for tenantbleed: the shapes the 169-app field test could not settle, each in miniature.
-- Every planted bug is tagged "PLANTED" and expected in scripts/check-hard.mjs; "CONTROL" objects
-- are safe and must stay clean. Tables with a planted read leak exist to prove the scan could fill
-- them with test data: the leak only shows if a row was written.

-- ---------------------------------------------------------------- tenants
create table public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null
);
create table public.memberships (
  org_id uuid not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner',
  primary key (org_id, user_id)
);
create function public.is_member(o uuid) returns boolean
language sql security definer stable set search_path = ''
as $$ select exists (select 1 from public.memberships m where m.org_id = o and m.user_id = auth.uid()) $$;
revoke execute on function public.is_member(uuid) from anon;

create function public.add_creator_membership() returns trigger
language plpgsql security definer set search_path = ''
as $$ begin insert into public.memberships (org_id, user_id) values (new.id, auth.uid()); return new; end $$;
revoke execute on function public.add_creator_membership() from anon, authenticated, public;
create trigger orgs_add_creator after insert on public.orgs for each row execute function public.add_creator_membership();

alter table public.orgs enable row level security;
create policy orgs_select on public.orgs for select to authenticated using (public.is_member(id));
create policy orgs_insert on public.orgs for insert to authenticated with check (true);
alter table public.memberships enable row level security;
create policy memberships_select on public.memberships for select to authenticated using (user_id = auth.uid() or public.is_member(org_id));

-- A macro for the "leaky table" pattern: members insert, everyone signed in reads (PLANTED read leak).
-- Written out per table below.

-- ---------------------------------------------------------------- H1: JSON shape checks
-- PLANTED read leak. Test data must satisfy: steps is a JSON array of 1 to 6 items, scope a JSON
-- object under 1 KB, and links either null or a non-empty array.
create table public.agent_runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  steps jsonb not null check (jsonb_typeof(steps) = 'array' and jsonb_array_length(steps) >= 1 and jsonb_array_length(steps) <= 6),
  scope jsonb not null check (jsonb_typeof(scope) = 'object' and octet_length(scope::text) <= 1024),
  links jsonb check (links is null or (jsonb_typeof(links) = 'array' and jsonb_array_length(links) >= 1)),
  note text not null
);
alter table public.agent_runs enable row level security;
create policy agent_runs_insert on public.agent_runs for insert to authenticated with check (public.is_member(org_id));
create policy agent_runs_select on public.agent_runs for select to authenticated using (true);

-- ---------------------------------------------------------------- H2: number from a fixed list
-- PLANTED read leak. run_day must be one of 1, 7, 14, 21, 28; period_days one of 7 or 28.
create table public.audit_schedules (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  run_day integer not null check (run_day = any (array[1, 7, 14, 21, 28])),
  period_days smallint not null check (period_days = any (array[7, 28])),
  label text not null
);
alter table public.audit_schedules enable row level security;
create policy audit_schedules_insert on public.audit_schedules for insert to authenticated with check (public.is_member(org_id));
create policy audit_schedules_select on public.audit_schedules for select to authenticated using (true);

-- ---------------------------------------------------------------- H3: text arrays
-- PLANTED read leak. focus must be a subset of a word list, at most 3 long; topics at most 5 and
-- without empty strings; home_view is plain text from a list (not an array).
create table public.user_prefs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  focus text[] not null check (focus <@ array['lead', 'growth', 'seo'] and cardinality(focus) <= 3),
  topics text[] not null default '{}' check (cardinality(topics) <= 5 and not ('' = any (topics))),
  home_view text not null default 'default' check (home_view = any (array['default', 'focus'])),
  title text not null
);
alter table public.user_prefs enable row level security;
create policy user_prefs_insert on public.user_prefs for insert to authenticated with check (public.is_member(org_id));
create policy user_prefs_select on public.user_prefs for select to authenticated using (true);

-- ---------------------------------------------------------------- H4: ordered dates
-- PLANTED read leak. Two periods in order: a_start <= a_end < b_start <= b_end.
create table public.period_reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  a_start date not null,
  a_end date not null,
  b_start date not null,
  b_end date not null,
  summary text not null,
  check (a_start <= a_end and a_end < b_start and b_start <= b_end)
);
alter table public.period_reports enable row level security;
create policy period_reports_insert on public.period_reports for insert to authenticated with check (public.is_member(org_id));
create policy period_reports_select on public.period_reports for select to authenticated using (true);

-- ---------------------------------------------------------------- H5: parents must agree
-- PLANTED read leak. A trigger requires the brand to belong to the same org as the row.
create table public.brands (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  name text not null
);
alter table public.brands enable row level security;
create policy brands_all on public.brands for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

create table public.member_brands (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  brand_id uuid not null references public.brands(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  label text not null
);
create function public.check_member_brand_org() returns trigger
language plpgsql set search_path = ''
as $$
begin
  if not exists (select 1 from public.brands b where b.id = new.brand_id and b.org_id = new.org_id) then
    raise exception 'member_brands: brand % is not in organization %', new.brand_id, new.org_id using errcode = '23514';
  end if;
  return new;
end $$;
create trigger member_brands_org before insert or update on public.member_brands for each row execute function public.check_member_brand_org();
alter table public.member_brands enable row level security;
create policy member_brands_insert on public.member_brands for insert to authenticated with check (public.is_member(org_id));
create policy member_brands_select on public.member_brands for select to authenticated using (true);

-- ---------------------------------------------------------------- H6: quarterly partitions
-- PLANTED: RLS never enabled on the partitions, so anyone can read them directly. Rows must fall
-- inside each partition's date range.
create table public.location_events (
  id uuid not null default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  happened_at timestamptz not null,
  place text not null,
  primary key (id, happened_at)
) partition by range (happened_at);
create table public.location_events_2026_q1 partition of public.location_events for values from ('2026-01-01') to ('2026-04-01');
create table public.location_events_2026_q2 partition of public.location_events for values from ('2026-04-01') to ('2026-07-01');
alter table public.location_events enable row level security;
create policy location_events_member on public.location_events for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- ---------------------------------------------------------------- H7: tables in a schema the API does not expose
-- The API only reaches these through the public wrappers below.
create schema ledger;
grant usage on schema ledger to authenticated, anon;
create table ledger.accounts (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  code text not null,
  name text not null
);
grant select, insert, update, delete on ledger.accounts to authenticated;
alter table ledger.accounts enable row level security;
create policy accounts_member on ledger.accounts for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- PLANTED: renames any org's account; never checks the caller.
create function public.rename_account(p_org_id uuid, p_account_id uuid, p_name text) returns void
language plpgsql security definer set search_path = ''
as $$ begin update ledger.accounts set name = p_name where id = p_account_id and org_id = p_org_id; end $$;

-- PLANTED: lists any org's accounts.
create function public.list_accounts(p_org_id uuid) returns setof ledger.accounts
language sql security definer stable set search_path = ''
as $$ select * from ledger.accounts where org_id = p_org_id $$;

-- CONTROL: checks membership first.
create function public.close_account(p_org_id uuid, p_account_id uuid) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if not public.is_member(p_org_id) then raise exception 'not a member' using errcode = '42501'; end if;
  delete from ledger.accounts where id = p_account_id and org_id = p_org_id;
end $$;

-- ---------------------------------------------------------------- F1: arguments named after their table
create table public.shipments (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  weight_kg numeric not null default 1,
  rate numeric not null default 2
);
alter table public.shipments enable row level security;
create policy shipments_member on public.shipments for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  shipment_id uuid not null references public.shipments(id) on delete cascade,
  total numeric not null
);
alter table public.invoices enable row level security;
create policy invoices_member on public.invoices for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- PLANTED: bills any org's shipment. Rejects ids that are not shipments, so a random id fails.
create function public.generate_invoice(p_shipment_id uuid, p_discount numeric) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare s public.shipments; v uuid;
begin
  select * into s from public.shipments where id = p_shipment_id;
  if s.id is null then raise exception 'Shipment not found: %', p_shipment_id; end if;
  insert into public.invoices (org_id, shipment_id, total) values (s.org_id, s.id, greatest(0, s.weight_kg * s.rate - p_discount)) returning id into v;
  return v;
end $$;

-- ---------------------------------------------------------------- F2: a write behind a word
create table public.usage_daily (
  org_id uuid not null references public.orgs(id) on delete cascade,
  day date not null default current_date,
  voice_minutes numeric not null default 0,
  ai_calls numeric not null default 0,
  primary key (org_id, day)
);
alter table public.usage_daily enable row level security;
create policy usage_daily_member on public.usage_daily for select to authenticated using (public.is_member(org_id));

-- PLANTED: adds usage to any org's bill, but only when resource is 'voice' or 'ai'.
create function public.increment_usage(p_org_id uuid, resource text, amount numeric) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if resource = 'voice' then
    insert into public.usage_daily (org_id, voice_minutes) values (p_org_id, amount)
    on conflict (org_id, day) do update set voice_minutes = public.usage_daily.voice_minutes + amount;
  elsif resource = 'ai' then
    insert into public.usage_daily (org_id, ai_calls) values (p_org_id, amount)
    on conflict (org_id, day) do update set ai_calls = public.usage_daily.ai_calls + amount;
  end if;
end $$;

-- ---------------------------------------------------------------- F3: shared configuration
create table public.webhook_config (
  key text primary key,
  value text not null,
  updated_at timestamptz default now()
);
insert into public.webhook_config (key, value) values ('extract_webhook_url', ''), ('extract_webhook_secret', '');
alter table public.webhook_config enable row level security;

-- PLANTED: anyone can point the app's webhook at their own server.
create function public.update_webhook_config(url text, secret text) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  update public.webhook_config set value = url, updated_at = now() where key = 'extract_webhook_url';
  update public.webhook_config set value = secret, updated_at = now() where key = 'extract_webhook_secret';
end $$;

-- ---------------------------------------------------------------- F4: counter on the right parent only
create table public.runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  children_count integer not null default 0,
  title text not null
);
alter table public.runs enable row level security;
create policy runs_member on public.runs for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- PLANTED (low): bumps a counter on any org's run. Raises for an id that is not a run.
create function public.runs_increment_children(p_parent_id uuid) returns integer
language plpgsql security definer set search_path = ''
as $$
declare v integer;
begin
  update public.runs set children_count = children_count + 1 where id = p_parent_id returning children_count into v;
  if v is null then raise exception 'parent run % not found', p_parent_id; end if;
  return v;
end $$;

-- ---------------------------------------------------------------- controls that must stay clean
create table public.invites (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  token text not null unique default encode(gen_random_bytes(24), 'hex'),
  email text not null
);
alter table public.invites enable row level security;
create policy invites_member on public.invites for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- CONTROL: needs the secret token.
create function public.lookup_invite(p_token text) returns json
language sql security definer stable set search_path = ''
as $$ select json_build_object('org', i.org_id, 'email', i.email) from public.invites i where i.token = p_token $$;

-- CONTROL: touches no table.
create function public.make_code() returns text
language sql security definer volatile set search_path = ''
as $$ select substr(md5(random()::text), 1, 8) $$;

create table public.shops (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  slug text not null unique,
  published boolean not null default false,
  blurb text not null
);
alter table public.shops enable row level security;
create policy shops_member on public.shops for all to authenticated using (public.is_member(org_id)) with check (public.is_member(org_id));

-- CONTROL: returns only published shops.
create function public.shop_public_get(p_slug text) returns json
language sql security definer stable set search_path = ''
as $$ select json_build_object('slug', s.slug, 'blurb', s.blurb) from public.shops s where s.slug = p_slug and s.published $$;

-- ---------------------------------------------------------------- R: regressions from the 169-app run
-- Shapes copied from the apps where each bug appeared (names changed).

-- R1 CONTROL: an admin-only function. Test users must never be made admins by the test data.
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  display_name text,
  created_at timestamptz not null default now(),
  is_admin boolean not null default false,
  disabled boolean not null default false
);
alter table public.profiles enable row level security;
create policy profiles_self on public.profiles for select to authenticated using (id = auth.uid());
create policy profiles_admin_read on public.profiles for select to authenticated
  using (exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin = true));
create policy profiles_self_update on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());
create policy profiles_self_insert on public.profiles for insert to authenticated with check (id = auth.uid());
-- The first user to sign up becomes the app's admin (a common bootstrap). Test user A is created
-- first, so the scan must still treat both test users as ordinary users.
create function public.bootstrap_first_admin() returns trigger
language plpgsql security definer set search_path = public
as $$
begin
  if (select count(*) from public.profiles where is_admin) = 0 then new.is_admin := true; end if;
  return new;
end $$;
revoke execute on function public.bootstrap_first_admin() from anon, authenticated, public;
create trigger profiles_first_admin before insert on public.profiles for each row execute function public.bootstrap_first_admin();
create function public.create_profile_for_user() returns trigger
language plpgsql security definer set search_path = public
as $$ begin insert into public.profiles (id, email) values (new.id, new.email); return new; end $$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.create_profile_for_user();

create function public.promote_to_admin(target_user_id uuid) returns void
language plpgsql security definer set search_path = public
as $$
begin
  if not exists (select 1 from public.profiles where id = auth.uid() and is_admin = true) then
    raise exception 'Only admins can promote users to admin' using errcode = 'insufficient_privilege';
  end if;
  update public.profiles set is_admin = true where id = target_user_id;
end $$;

-- R2 CONTROL: a row shared by two users (my block of you), through profiles, with no self-block.
create schema if not exists private;
create function private.require_user(strict boolean) returns uuid
language plpgsql stable set search_path = ''
as $$ begin if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if; return auth.uid(); end $$;
create table public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
alter table public.blocks enable row level security;
create policy blocks_mine on public.blocks for all to authenticated using (blocker_id = auth.uid()) with check (blocker_id = auth.uid());
create function public.unblock_user(p_user_id uuid) returns void
language plpgsql security definer set search_path = ''
as $$
declare v_uid uuid := private.require_user(true);
begin
  if p_user_id = v_uid then raise exception using errcode = 'P0001', message = 'SELF_ACTION'; end if;
  delete from public.blocks where blocker_id = v_uid and blocked_id = p_user_id;
end $$;

-- R3 (low only): a recompute of shared analytics. Anyone can run it; it rewrites derived numbers.
create table public.analytics_snapshots (
  snapshot_date date not null,
  time_range text not null check (time_range = any (array['7d', 'all_time'])),
  category text not null check (category = any (array['users', 'content'])),
  payload jsonb not null,
  computed_at timestamptz not null default now(),
  primary key (snapshot_date, time_range, category)
);
insert into public.analytics_snapshots (snapshot_date, time_range, category, payload) values (current_date, '7d', 'users', '{"total": 0}');
alter table public.analytics_snapshots enable row level security;
create function public.compute_analytics_snapshot(force_now boolean) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  update public.analytics_snapshots set payload = jsonb_build_object('total', (select count(*) from public.profiles)), computed_at = now()
  where snapshot_date = current_date;
end $$;

-- R4 PLANTED: spends any user's credits. Rejects amounts outside 1 to 100, so a random large
-- amount fails and the scan must try a small one.
create table public.credit_balances (
  user_id uuid primary key references auth.users(id) on delete cascade,
  credits_used integer not null default 0
);
alter table public.credit_balances enable row level security;
create policy credit_balances_self on public.credit_balances for select to authenticated using (user_id = auth.uid());
create function public.consume_daily_credits(target_user_id uuid, credit_cost integer) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if credit_cost < 1 or credit_cost > 100 then raise exception 'credit_cost out of range'; end if;
  insert into public.credit_balances (user_id, credits_used) values (target_user_id, credit_cost)
  on conflict (user_id) do update set credits_used = public.credit_balances.credits_used + credit_cost;
end $$;

-- R5 CONTROL: claims a device by its token. Only someone holding the secret token can do it.
create table public.device_tokens (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  token text not null unique default encode(gen_random_bytes(24), 'hex')
);
alter table public.device_tokens enable row level security;
create policy device_tokens_self on public.device_tokens for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
create function public.register_device_token(p_token text) returns void
language sql security definer set search_path = ''
as $$ update public.device_tokens set user_id = auth.uid() where token = p_token $$;

-- R6 (low only): returns only another user's record id (a membership check), no data.
create table public.workspace_members (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  nickname text not null default 'member'
);
alter table public.workspace_members enable row level security;
create policy workspace_members_member on public.workspace_members for select to authenticated using (public.is_member(org_id));
create function public.member_id_if_allowed(p_org_id uuid, p_member_user_id uuid) returns jsonb
language sql security definer stable set search_path = ''
as $$ select jsonb_build_object('allowed', true, 'member_id', (select id from public.workspace_members where org_id = p_org_id and user_id = p_member_user_id)) $$;

-- R7 (low only): creates an org's default records if missing (idempotent seeding).
create table public.workflow_templates (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  name text not null,
  unique (org_id, name)
);
alter table public.workflow_templates enable row level security;
create policy workflow_templates_member on public.workflow_templates for select to authenticated using (public.is_member(org_id));
create function public.seed_core_workflow_templates(p_org_id uuid) returns void
language sql security definer set search_path = ''
as $$ insert into public.workflow_templates (org_id, name) values (p_org_id, 'Intake'), (p_org_id, 'Review') on conflict do nothing $$;

-- R8 (low only): a cleanup job that deletes expired rows of a shared table. It takes an optional
-- batch size, so a caller can only make the cleanup run early, never pick which rows go.
create table public.platform_sessions (
  session_id uuid primary key default gen_random_uuid(),
  note text not null default 'support',
  expires_at timestamptz not null
);
alter table public.platform_sessions enable row level security;
create function public.cleanup_expired_platform_sessions(batch_size integer default 1000) returns void
language plpgsql security definer set search_path = ''
as $$
declare v_batch integer := greatest(1, coalesce(batch_size, 1000));
begin
  delete from public.platform_sessions where session_id in (
    select session_id from public.platform_sessions where expires_at <= now() order by expires_at limit v_batch);
end;
$$;
revoke all on function public.cleanup_expired_platform_sessions(integer) from public;
grant execute on function public.cleanup_expired_platform_sessions(integer) to service_role;

-- R9 (low only): a scheduled reminder job (copied from a field-sales app). Its only argument is an
-- optional day window; it writes a fixed message for each org's owners once per cheque.
create table public.cheques (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  amount numeric not null default 100,
  status text not null default 'portfolio',
  due_date date not null default current_date
);
alter table public.cheques enable row level security;
create policy cheques_member on public.cheques for select to authenticated using (public.is_member(org_id));
create table public.org_notifications (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  event text not null,
  title text not null,
  target_id uuid
);
alter table public.org_notifications enable row level security;
create policy org_notifications_self on public.org_notifications for select to authenticated using (user_id = auth.uid());
create function public.notify_due_cheques(p_days integer default 7) returns integer
language plpgsql security definer set search_path = public
as $$
declare r record; v_n int := 0;
begin
  for r in
    select c.id, c.org_id, c.amount, c.due_date from cheques c
    where c.status = 'portfolio'
      and c.due_date between current_date and current_date + p_days
      and not exists (select 1 from org_notifications n where n.target_id = c.id and n.event = 'cheque_due')
  loop
    insert into org_notifications (org_id, user_id, event, title, target_id)
    select r.org_id, m.user_id, 'cheque_due', 'Cheque due: ' || to_char(r.amount, 'FM999G990D00'), r.id
    from memberships m where m.org_id = r.org_id and m.role = 'owner';
    v_n := v_n + 1;
  end loop;
  return v_n;
end $$;
grant execute on function public.notify_due_cheques(integer) to authenticated;

-- R10 (low only): creates the shared demo org once and logs who asked (copied from a CRM).
create table public.org_activity (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  actor_user_id uuid references auth.users(id) on delete set null,
  message text not null
);
alter table public.org_activity enable row level security;
create policy org_activity_member on public.org_activity for select to authenticated using (public.is_member(org_id));
create function public.bootstrap_demonstration_org(p_initiator_user_id uuid) returns uuid
language plpgsql security definer set search_path = public
as $$
declare v_org_id uuid;
begin
  select id into v_org_id from public.orgs where name = 'Demonstration';
  if v_org_id is not null then return v_org_id; end if;
  insert into public.orgs (name) values ('Demonstration') returning id into v_org_id;
  insert into public.org_activity (org_id, actor_user_id, message) values (v_org_id, p_initiator_user_id, 'Demonstration org created');
  return v_org_id;
end $$;

-- R11 (must stay medium or high): a shared daily quota; the caller picks how many credits to use, so
-- one call can use up the whole day's quota for everyone (copied from an outreach app).
create table public.daily_api_usage (
  usage_date date primary key,
  used_today integer not null default 0,
  daily_cap integer not null default 500,
  updated_at timestamptz not null default now()
);
alter table public.daily_api_usage enable row level security;
create function public.consume_api_credit(p_count int default 1) returns boolean
language plpgsql security definer set search_path = 'public'
as $$
declare v_today date := (now() at time zone 'UTC')::date; v_row public.daily_api_usage%rowtype;
begin
  insert into public.daily_api_usage (usage_date, used_today, updated_at) values (v_today, 0, now()) on conflict (usage_date) do nothing;
  select * into v_row from public.daily_api_usage where usage_date = v_today for update;
  if v_row.used_today + p_count > v_row.daily_cap then return false; end if;
  update public.daily_api_usage set used_today = used_today + p_count, updated_at = now() where usage_date = v_today;
  return true;
end;
$$;
revoke all on function public.consume_api_credit(int) from public;
grant execute on function public.consume_api_credit(int) to service_role;
