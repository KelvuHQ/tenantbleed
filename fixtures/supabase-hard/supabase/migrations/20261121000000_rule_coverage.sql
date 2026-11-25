-- Rule coverage: one planted case for each judge rule, severity and scan path that no other case
-- reached (scripts/rules.json lists them all; scripts/check-rules.mjs checks they are produced).
-- Each block names the rule it exists for.

-- ---------------------------------------------------------------- table reads
-- read/open-policy (high for a visitor): a policy that lets everyone read, not named as public.
create table public.member_notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default 'note'
);
alter table public.member_notes enable row level security;
create policy "Members can read notes" on public.member_notes for select to anon, authenticated using (true);
create policy member_notes_own_write on public.member_notes for insert to authenticated with check (user_id = auth.uid());

-- read/backend-only-policy: named for the service role, but with no TO, so it applies to everyone.
create table public.sync_jobs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  payload text not null default 'job'
);
alter table public.sync_jobs enable row level security;
create policy "Service role can manage sync jobs" on public.sync_jobs for all using (true);

-- read/declared-public: the policy says the rows are public on purpose, and no column is private.
create table public.listings (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'listing'
);
alter table public.listings enable row level security;
create policy "Public can view listings" on public.listings for select to anon, authenticated using (true);
create policy listings_own_write on public.listings for insert to authenticated with check (user_id = auth.uid());

-- read/profile-only (low signed in, medium for a visitor): only a profile's own fields come back.
create policy "Members read team profiles" on public.team_profiles for select to anon, authenticated using (true);

-- ---------------------------------------------------------------- inserts and moves into shared or unseen parents
-- insert/shared-parent and reparent/shared-parent: channels are readable by every signed-in user
-- (a public chat), and posts only check their author.
create table public.channels (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null default 'general'
);
alter table public.channels enable row level security;
create policy "Signed-in users read channels" on public.channels for select to authenticated using (true);
create policy channels_own_write on public.channels for insert to authenticated with check (user_id = auth.uid());
create table public.channel_posts (
  id uuid primary key default gen_random_uuid(),
  channel_id uuid not null references public.channels(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default 'hi'
);
alter table public.channel_posts enable row level security;
create policy channel_posts_read on public.channel_posts for select to authenticated using (true);
create policy channel_posts_insert on public.channel_posts for insert to authenticated with check (user_id = auth.uid());
create policy channel_posts_update on public.channel_posts for update to authenticated using (user_id = auth.uid());

-- insert/unseen-parent: a comment on someone else's note is accepted, but only its author sees it.
create table public.note_comments (
  id uuid primary key default gen_random_uuid(),
  note_id uuid not null references public.notes(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default 'comment'
);
alter table public.note_comments enable row level security;
create policy note_comments_own on public.note_comments for select to authenticated using (user_id = auth.uid());
create policy note_comments_insert on public.note_comments for insert to authenticated with check (user_id = auth.uid());

-- ---------------------------------------------------------------- functions
-- rpc-leak/profile-only (low signed in, medium for a visitor): a member directory that returns each
-- person's display name and nothing private.
create table public.member_cards (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null
);
alter table public.member_cards enable row level security;
create policy member_cards_own on public.member_cards for all to authenticated using (id = auth.uid()) with check (id = auth.uid());
create function public.list_member_cards() returns setof public.member_cards
language sql stable security definer set search_path = ''
as $$ select * from public.member_cards $$;

-- rpc-write/time-based-cleanup: no arguments, deletes users' rows past a time limit.
create function public.cleanup_old_time_entries() returns void
language sql security definer set search_path = ''
as $$ delete from public.time_entries where started_at < now() + interval '1 day' $$;

-- rpc-write/shared-counters: only counters and timestamps move on a shared table.
create table public.api_stats (
  id uuid primary key default gen_random_uuid(),
  label text not null default 'all',
  total integer not null default 0,
  updated_at timestamptz not null default now()
);
alter table public.api_stats enable row level security;
create function public.bump_api_stats() returns void
language sql security definer set search_path = ''
as $$ update public.api_stats set total = total + 1, updated_at = now() $$;

-- rpc-leak/derived-value (anon) and static/definer-unchecked (medium): callable by visitors only, no
-- caller check. Its answer for an organization's id differs from its answer for an id that exists
-- nowhere, so a visitor learns how many notes that organization has.
create function public.visitor_note_count(p_org_id uuid) returns bigint
language sql stable security definer set search_path = ''
as $$ select count(*) from public.notes where org_id = p_org_id $$;
revoke execute on function public.visitor_note_count(uuid) from public, authenticated;
grant execute on function public.visitor_note_count(uuid) to anon;

-- triage/function-flagged: callable by visitors only, no caller check, and its answer does not
-- depend on the id it is given (a total over every organization). Signed-in users cannot call it,
-- so there is no owner to compare with: the owner must decide.
create function public.visitor_notes_total(p_org_id uuid) returns bigint
language sql stable security definer set search_path = ''
as $$ select count(*) from public.notes $$;
revoke execute on function public.visitor_notes_total(uuid) from public, authenticated;
grant execute on function public.visitor_notes_total(uuid) to anon;

-- static/definer-unchecked (low): no caller check, signed-in users only.
create function public.rename_channel(p_channel_id uuid, p_name text) returns void
language sql security definer set search_path = ''
as $$ update public.channels set name = p_name where id = p_channel_id $$;
revoke execute on function public.rename_channel(uuid, text) from public, anon;
grant execute on function public.rename_channel(uuid, text) to authenticated;

-- static/definer-cannot-target: a read with no arguments cannot be aimed at one user.
create function public.channel_count() returns bigint
language sql stable security definer set search_path = ''
as $$ select count(*) from public.channels $$;

-- static/auth-writer (high: visitors can call it; medium: signed-in only) and
-- static/auth-writer-checked (it checks the caller).
create function public.set_user_locale(p_user_id uuid, p_locale text) returns void
language sql security definer set search_path = ''
as $$ update auth.users set raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb) || jsonb_build_object('locale', p_locale) where id = p_user_id $$;
create function public.set_user_theme(p_user_id uuid, p_theme text) returns void
language sql security definer set search_path = ''
as $$ update auth.users set raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb) || jsonb_build_object('theme', p_theme) where id = p_user_id $$;
revoke execute on function public.set_user_theme(uuid, text) from public, anon;
grant execute on function public.set_user_theme(uuid, text) to authenticated;
create function public.set_my_timezone(p_timezone text) returns void
language sql security definer set search_path = ''
as $$ update auth.users set raw_user_meta_data = coalesce(raw_user_meta_data, '{}'::jsonb) || jsonb_build_object('tz', p_timezone) where id = auth.uid() $$;

-- triage/function-unnamed-args: the API cannot pass arguments without names.
create function public.note_body(uuid) returns text
language sql stable security definer set search_path = ''
as $$ select body from public.notes where id = $1 $$;

-- triage/function-not-called: an argument type the scan has no value for.
create function public.notes_in_ranges(p_ranges tstzmultirange) returns bigint
language sql stable security definer set search_path = ''
as $$ select count(*) from public.notes where p_ranges is not null $$;

-- triage/function-refused-for-everyone: refuses every caller, the owner included.
create function public.archive_note(p_note_id uuid) returns void
language plpgsql security definer set search_path = ''
as $$ begin raise exception 'permission denied' using errcode = '42501'; end $$;

-- triage/function-no-execute-right: runs as a role that may not call the helper it needs, so the
-- database refuses every call ("permission denied for function").
create role tp_limited_owner nologin;
grant usage on schema public, private to tp_limited_owner;
grant create on schema public to tp_limited_owner;
grant tp_limited_owner to postgres;
create function private.audit_secret() returns text
language sql security definer set search_path = ''
as $$ select 'secret' $$;
revoke all on function private.audit_secret() from public, anon, authenticated, tp_limited_owner;
create function public.note_audit(p_note_id uuid) returns text
language sql security definer set search_path = ''
as $$ select private.audit_secret() || p_note_id::text $$;
alter function public.note_audit(uuid) owner to tp_limited_owner;
grant execute on function public.note_audit(uuid) to anon, authenticated;

-- ---------------------------------------------------------------- tables the linter warns about
-- static/policy-always-true (high): an update policy open to every signed-in user, exploited.
create table public.shared_todos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'todo'
);
alter table public.shared_todos enable row level security;
-- Postgres applies the read policy to updates too, so it is open as well (a shared board).
create policy shared_todos_read on public.shared_todos for select to authenticated using (true);
create policy shared_todos_insert on public.shared_todos for insert to authenticated with check (user_id = auth.uid());
create policy shared_todos_update on public.shared_todos for update to authenticated using (true);

-- triage/table-flagged: a definer view that filters by the caller, so nothing leaks, but the code
-- check still flags it.
create view public.my_time_entries as select id, note, started_at from public.time_entries where user_id = auth.uid();

-- triage/table-no-api-role: RLS off, but no API role may touch it.
create table public.ledger_exports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  file text not null default 'export.csv'
);
revoke all on public.ledger_exports from anon, authenticated;
-- A policy on a table with RLS off: the linter warns (policy_exists_rls_disabled).
create policy ledger_exports_own on public.ledger_exports for select to authenticated using (user_id = auth.uid());

-- triage/table-no-test-data: RLS off and no row can ever be written: a required column whose type
-- accepts no value at all (a rule of the type itself, which pausing the table's rules does not lift).
create domain public.never_text as text check (false);
create table public.frozen_records (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body public.never_text not null
);

-- note backend-write: a trigger refuses inserts from a user session; the app's backend writes them.
create table public.invoices_out (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  amount numeric not null default 10
);
alter table public.invoices_out enable row level security;
create policy invoices_out_own on public.invoices_out for select to authenticated using (user_id = auth.uid());
create function public.server_only_invoices() returns trigger
language plpgsql set search_path = ''
as $$ begin if auth.uid() is not null then raise exception 'invoices are issued by the server' using errcode = '42501'; end if; return new; end $$;
create trigger invoices_out_server_only before insert on public.invoices_out for each row execute function public.server_only_invoices();

-- note existing-rows-as-parents: a lookup table its migrations fill, which refuses new rows.
create table public.regions (
  id uuid primary key default gen_random_uuid(),
  code text not null unique
);
insert into public.regions (code) values ('eu'), ('us');
create function public.refuse_regions() returns trigger
language plpgsql set search_path = ''
as $$ begin raise exception 'regions are fixed' using errcode = '42501'; end $$;
create trigger regions_fixed before insert on public.regions for each row execute function public.refuse_regions();
create table public.region_prefs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  region_id uuid not null references public.regions(id)
);
alter table public.region_prefs enable row level security;
create policy region_prefs_own on public.region_prefs for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

-- note hidden-schema-unreached: a schema that grants table access to API roles, is not exposed,
-- and no exposed function uses.
create schema reporting;
grant usage on schema reporting to authenticated;
create table reporting.daily_totals (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  total integer not null default 0
);
grant select on reporting.daily_totals to authenticated;

-- triage/extension: an extension installed in the public schema (its spatial_ref_sys table has RLS off).
create extension if not exists postgis with schema public;

-- ---------------------------------------------------------------- storage
-- contracts: read, list, replace and upload only check the bucket (file-download for visitors and
-- users, file-list, file-overwrite, file-upload the victim can see).
-- gallery: a public bucket anyone can list (file-list/public-bucket).
-- dropbox: anyone may drop a file in any folder, but only its uploader sees it (file-upload/unseen).
insert into storage.buckets (id, name, public) values ('contracts', 'contracts', false), ('gallery', 'gallery', true), ('dropbox', 'dropbox', false);
create policy contracts_select on storage.objects for select to anon, authenticated using (bucket_id = 'contracts');
create policy contracts_insert on storage.objects for insert to authenticated with check (bucket_id = 'contracts');
create policy contracts_update on storage.objects for update to authenticated using (bucket_id = 'contracts');
create policy gallery_select on storage.objects for select to anon, authenticated using (bucket_id = 'gallery');
create policy gallery_insert on storage.objects for insert to authenticated with check (bucket_id = 'gallery' and (storage.foldername(name))[1] = auth.uid()::text);
create policy dropbox_insert on storage.objects for insert to authenticated with check (bucket_id = 'dropbox');
create policy dropbox_select on storage.objects for select to authenticated using (bucket_id = 'dropbox' and owner_id = auth.uid()::text);
