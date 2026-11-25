-- Personal and team workspaces, a common shape: signup gives every user a personal workspace, and
-- joining any other workspace takes an invitation. Cases (scripts/check-workspaces.mjs):
--   row/composite-keys: a project member row must agree with its project and its membership on the
--     workspace. The scan's second workspace gets a project but no membership (no invitation), so
--     the first pick mixes two workspaces and the scan must re-pick parents that agree.
--   row/helper-parent: no membership exists in the project's workspace, so the scan must create a
--     parent (a project in the personal workspace, where the membership is).
--   planted: project members are readable by every signed-in user (a cross-tenant read).

create table public.workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  is_personal boolean not null default false
);
alter table public.workspaces enable row level security;

create table public.workspace_members (
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'owner' check (role in ('owner', 'member')),
  primary key (workspace_id, user_id)
);
alter table public.workspace_members enable row level security;
create policy workspace_members_own on public.workspace_members for select to authenticated using (user_id = auth.uid());

create function public.is_workspace_member(w uuid) returns boolean
language sql security definer stable set search_path = ''
as $$ select exists (select 1 from public.workspace_members m where m.workspace_id = w and m.user_id = auth.uid()) $$;
revoke execute on function public.is_workspace_member(uuid) from public, anon;
grant execute on function public.is_workspace_member(uuid) to authenticated;
create policy workspaces_member on public.workspaces for select to authenticated using (public.is_workspace_member(id));

-- Signup: a personal workspace, owned by the new user.
create function public.create_personal_workspace() returns trigger
language plpgsql security definer set search_path = ''
as $$
declare w uuid;
begin
  insert into public.workspaces (name, is_personal) values ('Personal', true) returning id into w;
  insert into public.workspace_members (workspace_id, user_id, role) values (w, new.id, 'owner');
  return new;
end;
$$;
create trigger on_auth_user_personal_workspace after insert on auth.users for each row execute function public.create_personal_workspace();

-- Joining a workspace that is not personal takes an invitation (none exist in a fresh database), even
-- for the app's backend. The error code is not a CHECK failure, so no test-data fallback bypasses it.
create table public.workspace_invitations (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  email text not null
);
alter table public.workspace_invitations enable row level security;
create function public.members_join_by_invitation() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  if not exists (select 1 from public.workspaces w where w.id = new.workspace_id and w.is_personal)
     and not exists (select 1 from public.workspace_invitations i where i.workspace_id = new.workspace_id) then
    raise exception 'members join a workspace by invitation' using errcode = '42501';
  end if;
  return new;
end;
$$;
create trigger workspace_members_by_invitation before insert on public.workspace_members for each row execute function public.members_join_by_invitation();

create table public.projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references public.workspaces(id) on delete cascade,
  name text not null,
  unique (workspace_id, id)
);
alter table public.projects enable row level security;
create policy projects_member on public.projects for all to authenticated using (public.is_workspace_member(workspace_id)) with check (public.is_workspace_member(workspace_id));

create table public.project_members (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null,
  project_id uuid not null,
  user_id uuid not null,
  foreign key (workspace_id, project_id) references public.projects (workspace_id, id) on delete cascade,
  foreign key (workspace_id, user_id) references public.workspace_members (workspace_id, user_id) on delete cascade
);
alter table public.project_members enable row level security;
-- PLANTED: meant to be "members of the workspace", written as every signed-in user.
create policy project_members_read on public.project_members for select to authenticated using (true);
create policy project_members_write on public.project_members for insert to authenticated with check (public.is_workspace_member(workspace_id));
