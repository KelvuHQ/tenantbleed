-- An app whose exposed schemas list another schema before public (shape from a field-test app, names
-- changed). PostgREST serves the first exposed schema when a request names none, so every request
-- for a public object went to the archive schema and answered 404: 46 objects counted as not served.
create schema archive;
grant usage on schema archive to anon, authenticated;
create table archive.snapshots (id uuid primary key default gen_random_uuid(), note text);
alter table archive.snapshots enable row level security;
create policy snapshots_read on archive.snapshots for select using (true);
grant select on archive.snapshots to anon, authenticated;

create table public.boards (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null
);
alter table public.boards enable row level security;
-- Planted: any signed-in user reads every board.
create policy boards_read on public.boards for select to authenticated using (auth.uid() is not null);
create policy boards_own on public.boards for insert to authenticated with check (owner_id = auth.uid());

-- Planted: hands every board title to any caller.
create function public.board_titles() returns setof text
language sql stable security definer set search_path = '' as $$
  select title from public.boards
$$;
