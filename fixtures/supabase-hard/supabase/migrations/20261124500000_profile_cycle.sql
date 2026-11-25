-- A cycle through the user's profile table (shape from a field-test app, names changed): a team has
-- an optional reminder person that points at the profile table, and the profile row needs a team.
-- Filling the optional person column before the profile row existed failed the team insert, and
-- every table below a team went without test data (4 of 54 tables tested on that app). The team,
-- the profile and the task below it must all be filled; the task list's read policy is open
-- (planted) so the check also proves the child table is reached.
create table public.crew_teams (
  id bigint generated always as identity primary key,
  name text not null
);
create table public.crew_members (
  id uuid primary key references auth.users(id) on delete cascade,
  team_id bigint not null references public.crew_teams(id) on delete cascade,
  display_name text not null
);
alter table public.crew_teams add column reminder_member_id uuid references public.crew_members(id) on delete set null;

create table public.crew_tasks (
  id uuid primary key default gen_random_uuid(),
  team_id bigint not null references public.crew_teams(id) on delete cascade,
  body text not null
);

alter table public.crew_teams enable row level security;
alter table public.crew_members enable row level security;
alter table public.crew_tasks enable row level security;
create policy crew_teams_members on public.crew_teams for select to authenticated
  using (reminder_member_id = auth.uid() or exists (select 1 from public.crew_members m where m.team_id = crew_teams.id and m.id = auth.uid()));
create policy crew_members_self on public.crew_members for select to authenticated
  using (id = auth.uid());
create policy crew_tasks_read on public.crew_tasks for select to authenticated
  using (true);

-- Two smaller gaps from the same batch: a required transaction id column (xid8), and one column
-- with two foreign keys to different tables (the row must satisfy both). Both tables must be filled.
create table public.crew_boards (
  team_id bigint primary key references public.crew_teams(id) on delete cascade,
  title text not null
);
create table public.crew_notes (
  id uuid primary key default gen_random_uuid(),
  team_id bigint not null references public.crew_teams(id) on delete cascade,
  body text not null,
  transaction_xid xid8 not null,
  constraint crew_notes_board_fkey foreign key (team_id) references public.crew_boards(team_id) on delete cascade
);
alter table public.crew_boards enable row level security;
alter table public.crew_notes enable row level security;
create policy crew_boards_members on public.crew_boards for select to authenticated
  using (exists (select 1 from public.crew_members m where m.team_id = crew_boards.team_id and m.id = auth.uid()));
create policy crew_notes_members on public.crew_notes for select to authenticated
  using (exists (select 1 from public.crew_members m where m.team_id = crew_notes.team_id and m.id = auth.uid()));

-- An optional key back to a child that includes the row's own id: a binding remembers its last run
-- through (last_run_id, id, team_id), and a run needs its binding. The key back is optional (one
-- empty column switches it off), so bindings come first; counting it as required built runs first,
-- and runs never got a binding. Both must be filled.
create table public.crew_bindings (
  id uuid primary key default gen_random_uuid(),
  team_id bigint not null references public.crew_teams(id) on delete cascade,
  label text not null,
  last_run_id uuid,
  unique (id, team_id)
);
create table public.crew_runs (
  id uuid primary key default gen_random_uuid(),
  binding_id uuid not null,
  team_id bigint not null,
  started_at timestamptz not null default now(),
  unique (id, binding_id, team_id),
  foreign key (binding_id, team_id) references public.crew_bindings(id, team_id) on delete cascade
);
alter table public.crew_bindings add constraint crew_bindings_last_run_fkey
  foreign key (last_run_id, id, team_id) references public.crew_runs(id, binding_id, team_id);
alter table public.crew_bindings enable row level security;
alter table public.crew_runs enable row level security;
create policy crew_bindings_members on public.crew_bindings for select to authenticated
  using (exists (select 1 from public.crew_members m where m.team_id = crew_bindings.team_id and m.id = auth.uid()));
create policy crew_runs_members on public.crew_runs for select to authenticated
  using (exists (select 1 from public.crew_members m where m.team_id = crew_runs.team_id and m.id = auth.uid()));

-- A function whose body reads a table a later migration dropped: the API serves it, every call fails
-- inside it (42P01, which PostgREST passes on as 404). It is not "not served by the API"; it cannot
-- hand out anyone's data as the schema stands, so it must be settled as not callable (broken).
create table public.crew_archive (id uuid primary key default gen_random_uuid(), team_id bigint, body text);
create function public.crew_archive_counts(p_team_ids text[]) returns table (team_id bigint, n bigint)
language plpgsql security definer as $$
begin
  return query select a.team_id, count(*) from public.crew_archive a where a.team_id::text = any(p_team_ids) group by a.team_id;
end;
$$;
drop table public.crew_archive;
