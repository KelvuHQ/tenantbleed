-- Self-enrollment as admin (shape from a field-test app, names changed): the insert policy on the
-- member table has a branch "you may add yourself with role admin" that never ties the row to a
-- team the caller owns. So anyone can add themselves as admin to any team, and every is_team_admin
-- check then passes: a critical cross-tenant write. The control table crew_members adds the missing
-- "and the team is yours" clause and must stay clean.
create type public.gteam_role as enum ('member', 'admin');

create table public.gov_teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null default auth.uid() references auth.users(id) on delete cascade
);
create table public.gov_team_members (
  team_id uuid not null references public.gov_teams(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.gteam_role not null default 'member',
  primary key (team_id, user_id)
);
create table public.gov_team_notes (
  id uuid primary key default gen_random_uuid(),
  team_id uuid not null references public.gov_teams(id) on delete cascade,
  body text not null
);
create function public.is_gov_team_admin(t uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.gov_team_members m where m.team_id = t and m.user_id = auth.uid() and m.role = 'admin')
$$;

alter table public.gov_teams enable row level security;
alter table public.gov_team_members enable row level security;
alter table public.gov_team_notes enable row level security;
create policy gov_teams_admin on public.gov_teams for select to authenticated using (public.is_gov_team_admin(id));
create policy gov_teams_insert on public.gov_teams for insert to authenticated with check (created_by = auth.uid());
create policy gov_notes_admin on public.gov_team_notes for all to authenticated
  using (public.is_gov_team_admin(team_id)) with check (public.is_gov_team_admin(team_id));
create policy gov_members_read on public.gov_team_members for select to authenticated using (public.is_gov_team_admin(team_id) or user_id = auth.uid());
-- PLANTED hole: the self branch does not check that the team is the caller's.
create policy gov_members_insert on public.gov_team_members for insert to authenticated
  with check (public.is_gov_team_admin(team_id) or (user_id = auth.uid() and role = 'admin'));

-- Control: the same shape, but the self branch requires the team to be the caller's. Must stay clean.
create table public.crew_squads (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  created_by uuid not null default auth.uid() references auth.users(id) on delete cascade
);
create table public.crew_squad_members (
  squad_id uuid not null references public.crew_squads(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.gteam_role not null default 'member',
  primary key (squad_id, user_id)
);
alter table public.crew_squads enable row level security;
alter table public.crew_squad_members enable row level security;
create policy crew_squads_own on public.crew_squads for all to authenticated using (created_by = auth.uid()) with check (created_by = auth.uid());
create policy crew_members_read on public.crew_squad_members for select to authenticated using (user_id = auth.uid());
create policy crew_members_insert on public.crew_squad_members for insert to authenticated
  with check (user_id = auth.uid() and role = 'admin' and exists (select 1 from public.crew_squads s where s.id = squad_id and s.created_by = auth.uid()));
