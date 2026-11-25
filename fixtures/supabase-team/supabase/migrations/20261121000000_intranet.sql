-- A company intranet: one workspace, everyone who can sign in is staff, and most tables are open to
-- all staff on purpose. Cases (scripts/check-team.mjs):
--   note signup-refused: signup only accepts invited emails, so the scan creates its test users
--     directly and says so.
--   note single-workspace-heads-up: most tables are readable by every signed-in user, so the report
--     suggests "tenancy": "single" in tenantbleed.json.
--   modifier/single-workspace: replaying the same scan facts with "tenancy": "single" turns every
--     user-to-user finding low, while what a visitor can do keeps its severity.

create table public.invited_emails (email text primary key);
alter table public.invited_emails enable row level security;

create function public.only_invited() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if not exists (select 1 from public.invited_emails i where i.email = lower(new.email)) then
    raise exception 'This intranet is invite-only. Ask an admin to invite %.', new.email;
  end if;
  return new;
end;
$$;
create trigger before_signup_only_invited before insert on auth.users for each row execute function public.only_invited();

create table public.announcements (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'news'
);
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'doc'
);
create table public.contacts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  name text not null default 'contact'
);
create table public.tasks (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null default 'task'
);
create table public.wiki_pages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default 'page'
);
-- Open to staff and, by mistake, to visitors: keeps its severity even in a single-workspace app.
create table public.meeting_notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  body text not null default 'minutes'
);

do $$
declare t text;
begin
  foreach t in array array['announcements', 'documents', 'contacts', 'tasks', 'wiki_pages'] loop
    execute format('alter table public.%I enable row level security', t);
    execute format('create policy "Staff read %s" on public.%I for select to authenticated using (true)', t, t);
    execute format('create policy "Staff write own %s" on public.%I for insert to authenticated with check (user_id = auth.uid())', t, t);
  end loop;
end $$;
alter table public.meeting_notes enable row level security;
create policy "Staff read meeting notes" on public.meeting_notes for select to anon, authenticated using (true);
create policy "Staff write own meeting notes" on public.meeting_notes for insert to authenticated with check (user_id = auth.uid());
