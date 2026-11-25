-- Spec 08c: an app that exposes a Supabase-managed schema to the Data API.
-- The [api] schemas list in config.toml includes "auth", and the migration grants the API roles a
-- read on auth.users (the classic "let the frontend read the users table" mistake). auth.users is
-- Supabase's own table, not the app's: tenantbleed must never try to build or write test rows in it
-- (the builder runs as a privileged role), and must report the exposure as the thing to fix, not as a
-- table it attacked. A plain, correctly scoped app table is here too, so the rest of the scan still runs.

-- MANAGED: the app exposes auth and lets authenticated read auth.users directly.
grant usage on schema auth to anon, authenticated;
grant select on auth.users to authenticated;

-- A normal, correctly owner-scoped table, so buildWorld still has real work to do.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  body text not null
);
alter table public.notes enable row level security;
create policy notes_owner on public.notes for all to authenticated
  using (owner_id = auth.uid()) with check (owner_id = auth.uid());
