-- Regression cases for tenantbleed: real bugs found in the 169-app field run, copied in the shape
-- the apps shipped them (tables, policies, grants, function bodies, search_path, security definer).
-- Names are neutral; where two source apps used the same table name, one of them got a prefix.
-- Every bug is tagged "CASE n" and expected in scripts/check-regress.mjs; "CONTROL" objects are the
-- fixed twin of a case and must stay clean. Do not tidy these up: a cleaner copy stops reproducing.

-- =================================================================================================
-- CASES 1-3: a notes-and-artifacts workspace (owner_id per row, shared "workspace" visibility).
-- =================================================================================================
create type public.visibility as enum ('private', 'unlisted', 'public', 'workspace');
create type public.artifact_type as enum ('markdown', 'code', 'html', 'text');

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  email text,
  display_name text,
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  is_admin boolean not null default false
);
alter table public.profiles enable row level security;
create policy "Profiles are viewable by their owner" on public.profiles for select using (id = auth.uid());
create policy "Users can insert their own profile" on public.profiles for insert with check (id = auth.uid());
create policy "Users can update their own profile" on public.profiles for update using (id = auth.uid());
create trigger profiles_set_updated_at before update on public.profiles for each row execute function public.set_updated_at();

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, display_name)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data ->> 'display_name', split_part(new.email, '@', 1))
  )
  on conflict (id) do nothing;
  return new;
end;
$$;
create trigger on_auth_user_created after insert on auth.users for each row execute function public.handle_new_user();
revoke execute on function public.handle_new_user() from anon, authenticated, public;

create table public.artifacts (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  conversation_id uuid,
  title text not null default 'Untitled artifact',
  type public.artifact_type not null default 'markdown',
  language text,
  content text not null default '',
  visibility public.visibility not null default 'private',
  public_slug text unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  share_password_hash text,
  deleted_at timestamptz
);
create index artifacts_owner_idx on public.artifacts (owner_id, updated_at desc);
alter table public.artifacts enable row level security;
create policy "Read own or shared artifacts"
  on public.artifacts for select
  using (
    owner_id = auth.uid()
    or (
      deleted_at is null
      and (
        (visibility = 'workspace' and auth.role() = 'authenticated')
        or (visibility in ('unlisted', 'public') and share_password_hash is null)
        or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin)
      )
    )
  );
create policy "Owners insert artifacts" on public.artifacts for insert with check (owner_id = auth.uid());
create policy "Owners update artifacts" on public.artifacts for update using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "Owners delete artifacts" on public.artifacts for delete using (owner_id = auth.uid());
create trigger artifacts_set_updated_at before update on public.artifacts for each row execute function public.set_updated_at();

create table public.collections (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null,
  description text not null default '',
  color text,
  visibility text not null default 'private' check (visibility in ('private', 'workspace')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.collections enable row level security;
grant select, insert, update, delete on public.collections to authenticated;
create policy "Read own or shared collections" on public.collections for select
  using (owner_id = auth.uid() or visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));
create policy "Insert own collections" on public.collections for insert with check (owner_id = auth.uid());
create policy "Update own collections" on public.collections for update
  using (owner_id = auth.uid() or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));
create policy "Delete own collections" on public.collections for delete
  using (owner_id = auth.uid() or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));

create table public.collection_artifacts (
  collection_id uuid not null references public.collections (id) on delete cascade,
  artifact_id uuid not null references public.artifacts (id) on delete cascade,
  added_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (collection_id, artifact_id)
);
alter table public.collection_artifacts enable row level security;
grant select, insert, delete on public.collection_artifacts to authenticated;
create policy "Read memberships of visible collections" on public.collection_artifacts for select
  using (exists (select 1 from public.collections c where c.id = collection_id));
create policy "Add to collaborable collections" on public.collection_artifacts for insert
  with check (exists (select 1 from public.collections c where c.id = collection_id
    and (c.owner_id = auth.uid() or c.visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin))));
create policy "Remove from collaborable collections" on public.collection_artifacts for delete
  using (exists (select 1 from public.collections c where c.id = collection_id
    and (c.owner_id = auth.uid() or c.visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin))));

create table public.todos (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  notes text not null default '',
  due_date date,
  done boolean not null default false,
  completed_at timestamptz,
  position double precision not null default 0,
  visibility text not null default 'private' check (visibility in ('private', 'workspace')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
alter table public.todos enable row level security;
grant select, insert, update, delete on public.todos to authenticated;
create policy "Read own or shared todos" on public.todos for select
  using (owner_id = auth.uid() or visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));
create policy "Insert own todos" on public.todos for insert with check (owner_id = auth.uid());
create policy "Update own or shared todos" on public.todos for update
  using (owner_id = auth.uid() or visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));
create policy "Delete own todos" on public.todos for delete
  using (owner_id = auth.uid() or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin));
create trigger todos_set_updated_at before update on public.todos for each row execute function public.set_updated_at();

create table public.collection_todos (
  collection_id uuid not null references public.collections (id) on delete cascade,
  todo_id uuid not null references public.todos (id) on delete cascade,
  added_by uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (collection_id, todo_id)
);
alter table public.collection_todos enable row level security;
grant select, insert, delete on public.collection_todos to authenticated;
create policy "Read todo memberships of visible collections" on public.collection_todos for select
  using (exists (select 1 from public.collections c where c.id = collection_id));
create policy "Add todos to collaborable collections" on public.collection_todos for insert
  with check (exists (select 1 from public.collections c where c.id = collection_id
    and (c.owner_id = auth.uid() or c.visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin))));
create policy "Remove todos from collaborable collections" on public.collection_todos for delete
  using (exists (select 1 from public.collections c where c.id = collection_id
    and (c.owner_id = auth.uid() or c.visibility = 'workspace' or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin))));

-- CASE 2: no caller check at all. Anyone flips every private item in someone else's collection to
-- shared. (The source app had six item tables; two are kept.)
create or replace function public.propagate_workspace_visibility_to_items(p_collection_id uuid)
  returns void
  language plpgsql
  security definer
  set search_path = public
as $$
begin
  -- Update todos in this collection
  update public.todos t
  set visibility = 'workspace'
  from public.collection_todos ct
  where ct.collection_id = p_collection_id
    and ct.todo_id = t.id
    and t.visibility = 'private';

  -- Update artifacts in this collection (private → unlisted)
  update public.artifacts a
  set visibility = 'unlisted'
  from public.collection_artifacts ca
  where ca.collection_id = p_collection_id
    and ca.artifact_id = a.id
    and a.visibility = 'private';
end;
$$;

create or replace function public.on_collection_visibility_change()
  returns trigger
  language plpgsql
  security definer
  set search_path = public
as $$
begin
  if NEW.visibility = 'workspace' and (OLD is null or OLD.visibility <> 'workspace') then
    perform public.propagate_workspace_visibility_to_items(NEW.id);
  end if;
  return NEW;
end;
$$;
create trigger collection_visibility_change
  after insert or update of visibility on public.collections
  for each row execute function public.on_collection_visibility_change();

create or replace function public.on_todo_added_to_collection()
  returns trigger
  language plpgsql
  security definer
  set search_path = public
as $$
declare
  v_collection_visibility text;
begin
  select visibility into v_collection_visibility from public.collections where id = NEW.collection_id;
  if v_collection_visibility = 'workspace' then
    update public.todos set visibility = 'workspace' where id = NEW.todo_id and visibility = 'private';
  end if;
  return NEW;
end;
$$;
create trigger todo_added_to_collection after insert on public.collection_todos
  for each row execute function public.on_todo_added_to_collection();

create or replace function public.on_artifact_added_to_collection()
  returns trigger
  language plpgsql
  security definer
  set search_path = public
as $$
declare
  v_collection_visibility text;
begin
  select visibility into v_collection_visibility from public.collections where id = NEW.collection_id;
  if v_collection_visibility = 'workspace' then
    update public.artifacts set visibility = 'unlisted' where id = NEW.artifact_id and visibility = 'private';
  end if;
  return NEW;
end;
$$;
create trigger artifact_added_to_collection after insert on public.collection_artifacts
  for each row execute function public.on_artifact_added_to_collection();

-- CASE 1: `v_owner <> auth.uid()` is null (not true) when the caller is anonymous, so the owner
-- check is skipped and anon sets the password on anyone's artifact. Granted to authenticated only,
-- but the default privileges still give anon EXECUTE.
create or replace function public.set_artifact_password(p_id uuid, p_password text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_owner uuid;
begin
  select owner_id into v_owner from public.artifacts where id = p_id;
  if v_owner is null then
    raise exception 'Artifact not found';
  end if;
  if v_owner <> auth.uid() then
    raise exception 'Only the owner can set a share password';
  end if;

  update public.artifacts
    set share_password_hash = case
      when p_password is null or length(trim(p_password)) = 0 then null
      else extensions.crypt(p_password, extensions.gen_salt('bf'))
    end
    where id = p_id;
end;
$$;
grant execute on function public.set_artifact_password(uuid, text) to authenticated;

-- CONTROL for case 1: the null-safe comparison.
create or replace function public.set_artifact_password_safe(p_id uuid, p_password text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_owner uuid;
begin
  select owner_id into v_owner from public.artifacts where id = p_id;
  if v_owner is null then
    raise exception 'Artifact not found';
  end if;
  if v_owner is distinct from auth.uid() then
    raise exception 'Only the owner can set a share password';
  end if;

  update public.artifacts
    set share_password_hash = case
      when p_password is null or length(trim(p_password)) = 0 then null
      else extensions.crypt(p_password, extensions.gen_salt('bf'))
    end
    where id = p_id;
end;
$$;
grant execute on function public.set_artifact_password_safe(uuid, text) to authenticated;

-- CASE 3: `scope = 'workspace'` has no role check, so anon reads every shared secret's metadata.
create table public.vault_secrets (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text not null default '',
  secret_id uuid not null,
  scope text not null default 'workspace' check (scope in ('workspace', 'private')),
  owner_id uuid references auth.users (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  allowed_hosts text[] not null default '{}'
);
create unique index vault_secrets_name_key on public.vault_secrets (lower(name));
alter table public.vault_secrets enable row level security;
create policy "Read vault secrets"
  on public.vault_secrets for select
  using (
    scope = 'workspace'
    or owner_id = auth.uid()
    or exists (select 1 from public.profiles p where p.id = auth.uid() and p.is_admin)
  );

-- =================================================================================================
-- CASE 4: a team workspace with agent members. The admin function is meant for the service role
-- only: it revokes from PUBLIC and grants to service_role, but Supabase's default privileges have
-- already granted EXECUTE to anon and authenticated by name, and those grants survive.
-- =================================================================================================
create extension if not exists citext with schema extensions;

create table public.teams (
  id              uuid primary key default gen_random_uuid(),
  slug            extensions.citext not null unique,
  name            text not null,
  plan            text not null default 'free',
  settings        jsonb not null default '{}'::jsonb,
  created_at      timestamptz not null default now()
);

create table public.team_members (
  team_id    uuid not null references public.teams(id) on delete cascade,
  user_id    uuid references auth.users(id) on delete cascade,
  role       text not null check (role in ('owner', 'admin', 'member')),
  joined_at  timestamptz not null default now(),
  invited_by uuid references auth.users(id) on delete set null,
  member_id uuid not null,
  member_type text not null default 'human',
  display_name text,
  scopes jsonb not null default '[]'::jsonb,
  created_by_user_id uuid references auth.users(id) on delete set null,
  last_seen_at timestamptz,
  active boolean not null default true,
  revoked_at timestamptz,
  description text,
  constraint team_members_pkey primary key (team_id, member_id),
  constraint team_members_member_type_check check (member_type in ('human', 'agent')),
  constraint team_members_scopes_array_check check (jsonb_typeof(scopes) = 'array'),
  constraint team_members_human_or_agent_identity_check check (
    (member_type = 'human' and user_id is not null and member_id = user_id)
    or (member_type = 'agent' and user_id is null and display_name is not null and role <> 'owner')
  )
);
create index team_members_user_id_idx on public.team_members (user_id);

create table public.team_member_api_keys (
  id                  uuid primary key default gen_random_uuid(),
  team_id             uuid not null,
  member_id           uuid not null,
  name                text not null,
  key_prefix          text,
  key_hash            text not null,
  scopes              jsonb not null default '[]'::jsonb,
  created_by_user_id  uuid references auth.users(id) on delete set null,
  rotated_from_key_id uuid references public.team_member_api_keys(id) on delete set null,
  last_used_at        timestamptz,
  expires_at          timestamptz,
  revoked_at          timestamptz,
  created_at          timestamptz not null default now(),
  foreign key (team_id, member_id) references public.team_members (team_id, member_id) on delete cascade,
  check (jsonb_typeof(scopes) = 'array'),
  check (expires_at is null or expires_at > created_at),
  check (revoked_at is null or revoked_at >= created_at)
);

create or replace function public.app_current_team()
returns uuid
language sql
stable
as $$
  select nullif(current_setting('app.team_id', true), '')::uuid
$$;

create or replace function public.app_is_team_admin()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.team_members
    where team_id = public.app_current_team()
      and user_id = auth.uid()
      and role in ('owner', 'admin')
  )
$$;

create or replace function public.app_is_team_owner()
returns boolean
language sql
stable
security definer
set search_path = public, pg_temp
as $$
  select exists (
    select 1
    from public.team_members
    where team_id = public.app_current_team()
      and user_id = auth.uid()
      and role = 'owner'
  )
$$;

alter table public.teams enable row level security;
alter table public.team_members enable row level security;
alter table public.team_member_api_keys enable row level security;

create policy teams_select_member on public.teams for select to authenticated
using (exists (select 1 from public.team_members m where m.team_id = teams.id and m.user_id = auth.uid()));
create policy teams_insert_authenticated on public.teams for insert to authenticated with check (auth.uid() is not null);
create policy teams_update_owner on public.teams for update to authenticated
using (id = public.app_current_team() and public.app_is_team_owner())
with check (id = public.app_current_team() and public.app_is_team_owner());

create policy team_members_select_self_or_active_team on public.team_members for select to authenticated
using (user_id = auth.uid() or team_id = public.app_current_team());
create policy team_members_insert_owner on public.team_members for insert to authenticated
with check (team_id = public.app_current_team() and public.app_is_team_owner());
create policy team_members_update_owner on public.team_members for update to authenticated
using (team_id = public.app_current_team() and public.app_is_team_owner())
with check (team_id = public.app_current_team() and public.app_is_team_owner());

create policy team_member_api_keys_select_admin on public.team_member_api_keys for select to authenticated
using (team_id = public.app_current_team() and public.app_is_team_admin());
create policy team_member_api_keys_insert_admin on public.team_member_api_keys for insert to authenticated
with check (team_id = public.app_current_team() and public.app_is_team_admin());
create policy team_member_api_keys_update_admin on public.team_member_api_keys for update to authenticated
using (team_id = public.app_current_team() and public.app_is_team_admin())
with check (team_id = public.app_current_team() and public.app_is_team_admin());

create or replace function public.admin_revoke_agent_member(
  p_team_id uuid,
  p_member_id uuid,
  p_revoked_at timestamptz
)
returns table (
  member_id uuid,
  display_name text,
  description text,
  scopes jsonb,
  created_by_user_id uuid,
  last_seen_at timestamptz,
  active boolean,
  revoked_at timestamptz,
  joined_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not exists (
    select 1
    from public.team_members tm
    where tm.team_id = p_team_id
      and tm.member_id = p_member_id
      and tm.member_type = 'agent'
  ) then
    return;
  end if;

  update public.team_members tm
     set active = false,
         revoked_at = p_revoked_at
   where tm.team_id = p_team_id
     and tm.member_id = p_member_id
     and tm.member_type = 'agent';

  update public.team_member_api_keys api_key
     set revoked_at = p_revoked_at
   where api_key.team_id = p_team_id
     and api_key.member_id = p_member_id
     and api_key.revoked_at is null;

  return query
  select
    tm.member_id,
    tm.display_name,
    tm.description,
    tm.scopes,
    tm.created_by_user_id,
    tm.last_seen_at,
    tm.active,
    tm.revoked_at,
    tm.joined_at
  from public.team_members tm
  where tm.team_id = p_team_id
    and tm.member_id = p_member_id
    and tm.member_type = 'agent';
end;
$$;
revoke all on function public.admin_revoke_agent_member(uuid, uuid, timestamptz) from public;
grant execute on function public.admin_revoke_agent_member(uuid, uuid, timestamptz) to service_role;

-- CONTROL for case 4: the same function with the grants the app meant to have.
create or replace function public.admin_revoke_agent_member_locked(
  p_team_id uuid,
  p_member_id uuid,
  p_revoked_at timestamptz
)
returns table (
  member_id uuid,
  display_name text,
  description text,
  scopes jsonb,
  created_by_user_id uuid,
  last_seen_at timestamptz,
  active boolean,
  revoked_at timestamptz,
  joined_at timestamptz
)
language plpgsql
security definer
set search_path = public, pg_temp
as $$
begin
  if not exists (
    select 1
    from public.team_members tm
    where tm.team_id = p_team_id
      and tm.member_id = p_member_id
      and tm.member_type = 'agent'
  ) then
    return;
  end if;

  update public.team_members tm
     set active = false,
         revoked_at = p_revoked_at
   where tm.team_id = p_team_id
     and tm.member_id = p_member_id
     and tm.member_type = 'agent';

  update public.team_member_api_keys api_key
     set revoked_at = p_revoked_at
   where api_key.team_id = p_team_id
     and api_key.member_id = p_member_id
     and api_key.revoked_at is null;

  return query
  select
    tm.member_id,
    tm.display_name,
    tm.description,
    tm.scopes,
    tm.created_by_user_id,
    tm.last_seen_at,
    tm.active,
    tm.revoked_at,
    tm.joined_at
  from public.team_members tm
  where tm.team_id = p_team_id
    and tm.member_id = p_member_id
    and tm.member_type = 'agent';
end;
$$;
revoke all on function public.admin_revoke_agent_member_locked(uuid, uuid, timestamptz) from public, anon, authenticated;
grant execute on function public.admin_revoke_agent_member_locked(uuid, uuid, timestamptz) to service_role;

-- =================================================================================================
-- CASE 5: a hosting reseller's SaaS core. Customers ("clientes") are created by an auth trigger with
-- the auth user's id but no foreign key; tenants hang off them. Audit log and invoice numbering
-- functions take the tenant id from the caller and check nothing.
-- =================================================================================================
create or replace function public.handle_updated_at()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language 'plpgsql';

create table if not exists public.clientes (
  id uuid primary key default gen_random_uuid(),
  nombre text,
  email text unique,
  telefono text,
  avatar_url text,
  direccion text,
  ciudad text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create trigger set_updated_at before update on public.clientes for each row execute function public.handle_updated_at();
alter table public.clientes enable row level security;
create policy "Clientes ven su perfil" on public.clientes for select using (auth.uid() = id);
create policy "Clientes actualizan su perfil" on public.clientes for update using (auth.uid() = id);

create or replace function public.handle_new_cliente()
returns trigger as $$
begin
  insert into public.clientes (id, email, nombre, avatar_url)
  values (
    new.id,
    new.email,
    coalesce(new.raw_user_meta_data->>'full_name', new.raw_user_meta_data->>'name', 'Nuevo Usuario'),
    new.raw_user_meta_data->>'avatar_url'
  )
  on conflict (email) do update set
    nombre = coalesce(excluded.nombre, public.clientes.nombre),
    avatar_url = coalesce(excluded.avatar_url, public.clientes.avatar_url);
  return new;
end;
$$ language plpgsql security definer set search_path = public;
create trigger on_auth_user_created_cliente after insert on auth.users for each row execute function public.handle_new_cliente();

create table if not exists public.user_roles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid unique not null references auth.users(id) on delete cascade,
  role text not null default 'client' check (role in ('admin', 'client')),
  created_at timestamptz default now()
);
alter table public.user_roles enable row level security;
create policy "Users read own role" on public.user_roles for select to authenticated using (user_id = auth.uid());

create or replace function public.is_admin()
returns boolean as $$
begin
  return exists (select 1 from public.user_roles where user_id = auth.uid() and role = 'admin');
end;
$$ language plpgsql security definer set search_path = public;

create table if not exists public.planes (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  nombre text not null,
  precio numeric,
  caracteristicas text[] not null default '{}',
  intervalo_meses int default 1,
  activo boolean default true,
  moneda text default 'ARS',
  created_at timestamptz default now()
);
alter table public.planes enable row level security;
create policy "Planes publicos" on public.planes for select using (true);

create table if not exists public.tenants (
  id uuid primary key default gen_random_uuid(),
  slug text unique not null,
  nombre text not null,
  plan_id uuid references public.planes(id) on delete set null,
  dueno_id uuid not null references public.clientes(id) on delete cascade,
  estado text not null default 'activo' check (estado in ('activo', 'suspendido', 'cancelado', 'trial')),
  trial_ends_at timestamptz,
  settings jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create trigger set_updated_at before update on public.tenants for each row execute function public.handle_updated_at();

create table if not exists public.work_groups (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  nombre text not null,
  descripcion text,
  color text default '#6366f1',
  icono text default 'users',
  activo boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, nombre)
);

create table if not exists public.work_members (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  work_group_id uuid references public.work_groups(id) on delete set null,
  user_id uuid references auth.users(id) on delete set null,
  email text not null,
  nombre text not null,
  telefono text,
  rol text not null default 'member' check (rol in ('owner', 'admin', 'member', 'viewer')),
  avatar_url text,
  activo boolean not null default true,
  ultimaconexion_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(tenant_id, email)
);

create or replace function public.user_belongs_to_tenant(p_tenant_id uuid)
returns boolean as $$
  select exists (
    select 1 from public.work_members
    where tenant_id = p_tenant_id
      and user_id = auth.uid()
      and activo = true
  );
$$ language sql security definer stable;
alter function public.user_belongs_to_tenant(uuid) set search_path = public;
revoke execute on function public.user_belongs_to_tenant(uuid) from public;
grant execute on function public.user_belongs_to_tenant(uuid) to authenticated, service_role;

alter table public.tenants enable row level security;
create policy "Tenant owner full access" on public.tenants for all to authenticated
  using (dueno_id = auth.uid()) with check (dueno_id = auth.uid());
create policy "Tenant members read" on public.tenants for select to authenticated
  using (public.user_belongs_to_tenant(id));
alter table public.work_groups enable row level security;
create policy "Work groups tenant read" on public.work_groups for select to authenticated
  using (public.user_belongs_to_tenant(tenant_id));
alter table public.work_members enable row level security;
create policy "Work members owner manage" on public.work_members for all to authenticated
  using (public.user_belongs_to_tenant(tenant_id) or tenant_id in (select id from public.tenants where dueno_id = auth.uid()))
  with check (public.user_belongs_to_tenant(tenant_id) or tenant_id in (select id from public.tenants where dueno_id = auth.uid()));
create policy "Work members read own" on public.work_members for select to authenticated using (user_id = auth.uid());

create table if not exists public.invoice_sequences (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id) on delete cascade,
  tipo text not null check (tipo in ('A', 'B', 'C', 'ticket', 'proforma')),
  prefijo text not null default '',
  secuencial int not null default 1,
  created_at timestamptz not null default now(),
  unique(tenant_id, tipo, prefijo)
);
alter table public.invoice_sequences enable row level security;
create policy "Invoice sequences admin" on public.invoice_sequences for all to authenticated
  using (is_admin()) with check (is_admin());

create table if not exists public.audit_log (
  id bigint generated always as identity primary key,
  tenant_id uuid references public.tenants(id) on delete set null,
  user_id uuid references auth.users(id) on delete set null,
  action text not null,
  entity text not null,
  entity_id uuid,
  old_data jsonb,
  new_data jsonb,
  ip_address inet,
  user_agent text,
  created_at timestamptz not null default now()
);
alter table public.audit_log enable row level security;
create policy "Audit log admin read" on public.audit_log for select to authenticated using (is_admin());
create policy "Audit log tenant owner read" on public.audit_log for select to authenticated
  using (tenant_id in (select id from public.tenants where dueno_id = auth.uid()));
create policy "Audit log system insert" on public.audit_log for insert to authenticated with check (true);

CREATE OR REPLACE FUNCTION public.log_audit(
  p_tenant_id UUID,
  p_action TEXT,
  p_entity TEXT,
  p_entity_id UUID,
  p_old_data JSONB DEFAULT NULL,
  p_new_data JSONB DEFAULT NULL
)
RETURNS void AS $$
BEGIN
  INSERT INTO public.audit_log (
    tenant_id, user_id, action, entity, entity_id,
    old_data, new_data, ip_address, user_agent
  ) VALUES (
    p_tenant_id,
    auth.uid(),
    p_action,
    p_entity,
    p_entity_id,
    p_old_data,
    p_new_data,
    inet_client_addr(),
    current_setting('request.headers', true)::jsonb->>'user-agent'
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

CREATE OR REPLACE FUNCTION public.generate_invoice_number(
  p_tenant_id UUID,
  p_tipo TEXT DEFAULT 'B'
)
RETURNS TEXT AS $$
DECLARE
  v_prefijo TEXT;
  v_secuencial INT;
  v_numero TEXT;
BEGIN
  -- Get or create sequence
  INSERT INTO public.invoice_sequences (tenant_id, tipo, prefijo, secuencial)
  VALUES (p_tenant_id, p_tipo, p_tipo || '-', 1)
  ON CONFLICT (tenant_id, tipo, prefijo) DO NOTHING;

  -- Increment and return
  UPDATE public.invoice_sequences
  SET secuencial = secuencial + 1
  WHERE tenant_id = p_tenant_id AND tipo = p_tipo
  RETURNING secuencial, prefijo INTO v_secuencial, v_prefijo;

  v_numero := p_tipo || '-' || LPAD(v_secuencial::TEXT, 8, '0');
  RETURN v_numero;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;

-- CONTROL for case 5: what the app did for its other billing function.
CREATE OR REPLACE FUNCTION public.generate_invoice_number_locked(
  p_tenant_id UUID,
  p_tipo TEXT DEFAULT 'B'
)
RETURNS TEXT AS $$
DECLARE
  v_prefijo TEXT;
  v_secuencial INT;
  v_numero TEXT;
BEGIN
  INSERT INTO public.invoice_sequences (tenant_id, tipo, prefijo, secuencial)
  VALUES (p_tenant_id, p_tipo, p_tipo || '-', 1)
  ON CONFLICT (tenant_id, tipo, prefijo) DO NOTHING;

  UPDATE public.invoice_sequences
  SET secuencial = secuencial + 1
  WHERE tenant_id = p_tenant_id AND tipo = p_tipo
  RETURNING secuencial, prefijo INTO v_secuencial, v_prefijo;

  v_numero := p_tipo || '-' || LPAD(v_secuencial::TEXT, 8, '0');
  RETURN v_numero;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = public;
REVOKE EXECUTE ON FUNCTION public.generate_invoice_number_locked(UUID, TEXT) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.generate_invoice_number_locked(UUID, TEXT) TO service_role;

-- =================================================================================================
-- CASE 6: a headless CMS studio. Quota functions trust the workspace id and the limit the caller
-- passes. The app's own grants file hands every function to anon.
-- =================================================================================================
create table public.studio_profiles (
    id uuid not null primary key references auth.users(id) on delete cascade,
    display_name text,
    email text,
    avatar_url text,
    created_at timestamp with time zone default now(),
    theme text default 'system'::text not null,
    constraint profiles_theme_check check ((theme = any (array['light'::text, 'dark'::text, 'system'::text])))
);

create table public.workspaces (
    id uuid default gen_random_uuid() not null primary key,
    name text not null,
    slug text not null unique,
    type text default 'primary'::text not null,
    owner_id uuid not null references public.studio_profiles(id) on delete cascade,
    logo_url text,
    github_installation_id bigint,
    plan text default 'free'::text not null,
    created_at timestamp with time zone default now(),
    media_storage_bytes bigint default 0 not null,
    trial_ends_at timestamp with time zone,
    stripe_customer_id text,
    stripe_subscription_id text,
    subscription_status text,
    subscription_current_period_end timestamp with time zone,
    subscription_cancel_at_period_end boolean default false,
    grace_period_ends_at timestamp with time zone,
    overage_settings jsonb default '{}'::jsonb not null,
    trial_reminder_stage integer default 0 not null,
    constraint workspaces_plan_check check ((plan = any (array['free'::text, 'starter'::text, 'pro'::text, 'enterprise'::text]))),
    constraint workspaces_subscription_status_check check (((subscription_status is null) or (subscription_status = any (array['trialing'::text, 'active'::text, 'past_due'::text, 'canceled'::text, 'unpaid'::text, 'incomplete'::text])))),
    constraint workspaces_type_check check ((type = any (array['primary'::text, 'secondary'::text])))
);

create table public.workspace_members (
    id uuid default gen_random_uuid() not null primary key,
    workspace_id uuid not null references public.workspaces(id) on delete cascade,
    user_id uuid references public.studio_profiles(id) on delete cascade,
    role text not null,
    invited_email text,
    invited_at timestamp with time zone default now(),
    accepted_at timestamp with time zone,
    constraint workspace_members_role_check check ((role = any (array['owner'::text, 'admin'::text, 'member'::text])))
);

create function public.handle_new_workspace() returns trigger
    language plpgsql security definer
    set search_path to ''
    as $$
begin
  insert into public.workspace_members (workspace_id, user_id, role, accepted_at)
  values (new.id, new.owner_id, 'owner', now());
  return new;
end;
$$;
create trigger on_workspace_created after insert on public.workspaces for each row execute function public.handle_new_workspace();

-- Signup creates the profile and a primary workspace. Case 6a relies on it: the signup workspace has
-- no submissions yet, so a limit of 1 lets the forged submission in.
CREATE OR REPLACE FUNCTION public.handle_new_studio_user() RETURNS trigger
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  ws_id uuid;
  ws_slug text;
BEGIN
  INSERT INTO public.studio_profiles (id, display_name, email, avatar_url)
  VALUES (
    new.id,
    coalesce(
      new.raw_user_meta_data ->> 'full_name',
      new.raw_user_meta_data ->> 'name',
      split_part(new.email, '@', 1)
    ),
    new.email,
    new.raw_user_meta_data ->> 'avatar_url'
  );

  ws_slug := coalesce(nullif(trim(BOTH '-' FROM regexp_replace(lower(
    coalesce(
      new.raw_user_meta_data ->> 'user_name',
      new.raw_user_meta_data ->> 'preferred_username',
      split_part(new.email, '@', 1)
    )
  ), '[^a-z0-9]+', '-', 'g')), ''), 'user');
  ws_slug := trim(BOTH '-' FROM left(ws_slug, 40)) || '-' || substr(new.id::text, 1, 8);

  ws_id := gen_random_uuid();
  INSERT INTO public.workspaces (id, name, slug, type, owner_id, plan)
  VALUES (
    ws_id,
    coalesce(
      new.raw_user_meta_data ->> 'full_name',
      new.raw_user_meta_data ->> 'name',
      split_part(new.email, '@', 1)
    ) || '''s Workspace',
    ws_slug,
    'primary',
    new.id,
    'free'
  );

  RETURN new;
END;
$$;
CREATE TRIGGER on_auth_user_created_studio AFTER INSERT ON auth.users FOR EACH ROW EXECUTE FUNCTION public.handle_new_studio_user();

create table public.projects (
    id uuid default gen_random_uuid() not null primary key,
    workspace_id uuid not null references public.workspaces(id) on delete cascade,
    repo_full_name text not null,
    default_branch text default 'main'::text not null,
    content_root text default '/'::text not null,
    detected_stack text,
    status text default 'active'::text not null,
    created_at timestamp with time zone default now(),
    content_updated_at timestamp with time zone,
    cdn_enabled boolean default false not null,
    cdn_branch text,
    constraint projects_status_check check ((status = any (array['active'::text, 'setup'::text, 'error'::text])))
);
create unique index idx_projects_workspace_repo on public.projects using btree (workspace_id, repo_full_name);

create table public.form_submissions (
    id uuid default gen_random_uuid() not null primary key,
    project_id uuid not null references public.projects(id) on delete cascade,
    workspace_id uuid not null references public.workspaces(id) on delete cascade,
    model_id text not null,
    data jsonb not null,
    status text default 'pending'::text not null,
    source_ip inet,
    user_agent text,
    referrer text,
    locale text default 'en'::text,
    approved_at timestamp with time zone,
    approved_by uuid references public.studio_profiles(id),
    entry_id text,
    created_at timestamp with time zone default now() not null,
    constraint form_submissions_status_check check ((status = any (array['pending'::text, 'approved'::text, 'rejected'::text, 'spam'::text])))
);

alter table public.studio_profiles enable row level security;
alter table public.workspaces enable row level security;
alter table public.workspace_members enable row level security;
alter table public.projects enable row level security;
alter table public.form_submissions enable row level security;
create policy "Users can view own profile" on public.studio_profiles for select using ((id = auth.uid()));
create policy "Users can update own profile" on public.studio_profiles for update using ((id = auth.uid()));
create policy "Authenticated users can create workspaces" on public.workspaces for insert with check ((auth.uid() = owner_id));
create policy "Members can view workspaces" on public.workspaces for select using ((owner_id = auth.uid()));
create policy "Owner can update workspace" on public.workspaces for update using ((owner_id = auth.uid()));
create policy "Owner can delete workspace" on public.workspaces for delete using ((owner_id = auth.uid()));
create policy wm_select_own on public.workspace_members for select using ((user_id = auth.uid()));
create policy "Workspace members can view projects" on public.projects for select using ((exists ( select 1
   from public.workspace_members wm
  where ((wm.workspace_id = projects.workspace_id) and (wm.user_id = auth.uid())))));
create policy "Owner/Admin can create projects" on public.projects for insert with check ((exists ( select 1
   from public.workspace_members wm
  where ((wm.workspace_id = projects.workspace_id) and (wm.user_id = auth.uid()) and (wm.role = any (array['owner'::text, 'admin'::text]))))));
create policy "Workspace members can view form submissions" on public.form_submissions for select using ((workspace_id in ( select wm.workspace_id
   from public.workspace_members wm
  where (wm.user_id = auth.uid()))));
create policy "Workspace admin can insert form submissions" on public.form_submissions for insert with check ((exists ( select 1
   from public.workspace_members wm
  where ((wm.workspace_id = form_submissions.workspace_id) and (wm.user_id = auth.uid()) and (wm.role = any (array['owner'::text, 'admin'::text]))))));

CREATE FUNCTION public.create_form_submission_if_allowed(p_workspace_id uuid, p_monthly_limit integer, p_project_id uuid, p_model_id text, p_data jsonb, p_status text DEFAULT 'pending'::text, p_source_ip inet DEFAULT NULL::inet, p_user_agent text DEFAULT NULL::text, p_referrer text DEFAULT NULL::text, p_locale text DEFAULT 'en'::text, p_window_start timestamp with time zone DEFAULT NULL::timestamp with time zone, p_window_end timestamp with time zone DEFAULT NULL::timestamp with time zone) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_count INTEGER;
  v_submission public.form_submissions;
  v_start TIMESTAMPTZ := COALESCE(p_window_start, date_trunc('month', now()));
  v_end TIMESTAMPTZ := COALESCE(p_window_end, date_trunc('month', now()) + interval '1 month');
BEGIN
  -- Serialize concurrent submissions for same workspace
  PERFORM pg_advisory_xact_lock(
    hashtext('fs:' || p_workspace_id::text)
  );

  SELECT COUNT(*) INTO v_count
  FROM public.form_submissions
  WHERE workspace_id = p_workspace_id
    AND created_at >= v_start
    AND created_at < v_end;

  -- Reject if at or over limit
  IF v_count >= p_monthly_limit THEN
    RETURN jsonb_build_object('allowed', false, 'current_count', v_count);
  END IF;

  -- Insert the submission
  INSERT INTO public.form_submissions (
    project_id, workspace_id, model_id, data, status,
    source_ip, user_agent, referrer, locale
  )
  VALUES (
    p_project_id, p_workspace_id, p_model_id, p_data, p_status,
    p_source_ip, p_user_agent, p_referrer, p_locale
  )
  RETURNING * INTO v_submission;

  RETURN jsonb_build_object(
    'allowed', true,
    'current_count', v_count + 1,
    'submission', to_jsonb(v_submission)
  );
END;
$$;

CREATE FUNCTION public.increment_storage_bytes(p_workspace_id uuid, p_delta bigint) RETURNS void
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
BEGIN
  UPDATE public.workspaces
  SET media_storage_bytes = GREATEST(0, media_storage_bytes + p_delta)
  WHERE id = p_workspace_id;
END;
$$;

CREATE FUNCTION public.reserve_storage_if_allowed(p_workspace_id uuid, p_reserve_bytes bigint, p_limit_bytes bigint) RETURNS jsonb
    LANGUAGE plpgsql SECURITY DEFINER
    SET search_path TO ''
    AS $$
DECLARE
  v_current BIGINT;
BEGIN
  -- Serialize concurrent uploads for same workspace
  PERFORM pg_advisory_xact_lock(
    hashtext('storage:' || p_workspace_id::text)
  );

  -- Get current usage
  SELECT COALESCE(media_storage_bytes, 0) INTO v_current
  FROM public.workspaces
  WHERE id = p_workspace_id;

  -- Reject if reservation would exceed limit
  IF p_limit_bytes > 0 AND v_current + p_reserve_bytes > p_limit_bytes THEN
    RETURN jsonb_build_object('allowed', false, 'current_bytes', v_current);
  END IF;

  -- Reserve: atomically increment storage counter
  UPDATE public.workspaces
  SET media_storage_bytes = v_current + p_reserve_bytes
  WHERE id = p_workspace_id;

  RETURN jsonb_build_object('allowed', true, 'current_bytes', v_current + p_reserve_bytes);
END;
$$;

-- The app's grants file ran GRANT ALL ON ALL FUNCTIONS IN SCHEMA public TO anon, authenticated,
-- service_role; scoped to its own functions here so it does not undo the other cases' controls.
GRANT ALL ON FUNCTION public.create_form_submission_if_allowed(uuid, integer, uuid, text, jsonb, text, inet, text, text, text, timestamptz, timestamptz) TO anon, authenticated, service_role;
GRANT ALL ON FUNCTION public.increment_storage_bytes(uuid, bigint) TO anon, authenticated, service_role;
GRANT ALL ON FUNCTION public.reserve_storage_if_allowed(uuid, bigint, bigint) TO anon, authenticated, service_role;

-- =================================================================================================
-- CASE 7: field sales for book distributors. Notifications are written by a SQL function that
-- takes tenant and user from the caller; report views run as their owner, so RLS never applies.
-- (Source table names "tenants" and "profiles" are "firms" and "rep_profiles" here.)
-- =================================================================================================
create type app_role      as enum ('platform_admin','isletme_sahibi','dukkan_muduru', 'pazarlamaci','hazirlik');
create type member_status as enum ('davet_edildi','onay_bekliyor','aktif','pasif');
create type kurum_tipi    as enum ('okul','kurs_merkezi','diger');
create type kademe_tipi   as enum ('anaokulu','ilkokul','ortaokul','lise');
create type period_durum  as enum ('planlandi','aktif','kapali');

create table rep_profiles (
  id           uuid primary key references auth.users(id) on delete cascade,
  ad_soyad     text not null,
  telefon      text unique,
  eposta       text,
  created_at   timestamptz not null default now(),
  updated_at   timestamptz not null default now()
);

create table firms (
  id           uuid primary key default gen_random_uuid(),
  unvan        text not null,
  vergi_no     text,
  vergi_dairesi text,
  created_at   timestamptz not null default now()
);

create table stores (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references firms(id) on delete cascade,
  ad           text not null,
  il           text,
  ilce         text,
  adres        text,
  aktif        boolean not null default true,
  created_at   timestamptz not null default now()
);

create table memberships (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references rep_profiles(id) on delete cascade,
  tenant_id    uuid not null references firms(id) on delete cascade,
  store_id     uuid references stores(id) on delete cascade,
  role         app_role not null,
  status       member_status not null default 'aktif',
  devralan_user_id uuid references rep_profiles(id),
  pasife_alindi_at timestamptz,
  created_at   timestamptz not null default now(),
  unique (user_id, tenant_id, store_id, role)
);

create table periods (
  id            uuid primary key default gen_random_uuid(),
  tenant_id     uuid not null references firms(id) on delete cascade,
  academic_year text not null,
  term          smallint not null,
  ad            text not null,
  starts_on     date not null,
  ends_on       date not null,
  status        period_durum not null default 'planlandi',
  created_at    timestamptz not null default now(),
  unique (tenant_id, academic_year, term),
  check (ends_on > starts_on)
);

create table institutions (
  id            uuid primary key default gen_random_uuid(),
  kurum_tipi    kurum_tipi not null default 'okul',
  ad            text not null,
  parent_id     uuid references institutions(id),
  il            text,
  ilce          text,
  adres         text,
  meb_kodu      text,
  host          text unique,
  latitude      double precision,
  longitude     double precision,
  kademe        kademe_tipi,
  tur           text,
  hedef_sinavlar text[],
  ogrenci_sayisi integer,
  dogrulandi    boolean not null default false,
  ekleyen_tenant_id uuid references firms(id),
  merged_into_id uuid references institutions(id),
  created_at    timestamptz not null default now(),
  check (kademe is null or kurum_tipi = 'okul'),
  check (hedef_sinavlar is null or kurum_tipi = 'kurs_merkezi')
);

create table visits (
  id             uuid primary key default gen_random_uuid(),
  tenant_id      uuid not null references firms(id) on delete cascade,
  store_id       uuid not null references stores(id) on delete cascade,
  institution_id uuid not null references institutions(id),
  user_id        uuid not null references rep_profiles(id),
  period_id      uuid not null references periods(id),
  checked_in_at  timestamptz not null,
  checked_out_at timestamptz,
  gorusulen_contact_id uuid,
  not_metni      text,
  sonuc          text,
  created_at     timestamptz not null default now()
);

-- The visit report counts what each visit produced. The source app's request, order, shipment and
-- payment tables are much wider; only the columns the report reads are kept.
create table requests  (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references firms(id) on delete cascade, visit_id uuid references visits(id), created_at timestamptz not null default now());
create table orders    (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references firms(id) on delete cascade, visit_id uuid references visits(id), created_at timestamptz not null default now());
create table shipments (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references firms(id) on delete cascade, visit_id uuid references visits(id), created_at timestamptz not null default now());
create table payments  (id uuid primary key default gen_random_uuid(), tenant_id uuid not null references firms(id) on delete cascade, visit_id uuid references visits(id), tutar numeric(12,2) not null default 0, created_at timestamptz not null default now());

create table notifications (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references firms(id) on delete cascade,
  user_id     uuid not null references rep_profiles(id) on delete cascade,
  olay        text not null,
  baslik      text not null,
  govde       text,
  hedef_tur   text,
  hedef_id    uuid,
  okundu_at   timestamptz,
  created_at  timestamptz not null default now()
);

create or replace function auth_tenant_ids() returns setof uuid
language sql stable security definer set search_path = public as $$
  select distinct tenant_id from memberships
  where user_id = auth.uid() and status = 'aktif';
$$;

create or replace function auth_store_ids() returns setof uuid
language sql stable security definer set search_path = public as $$
  select s.id from stores s
  where s.tenant_id in (select tenant_id from memberships
                        where user_id = auth.uid() and status='aktif' and store_id is null)
  union
  select store_id from memberships
  where user_id = auth.uid() and status='aktif' and store_id is not null;
$$;

alter table rep_profiles enable row level security;
create policy p_self on rep_profiles for select using (id = auth.uid());
create policy p_self_upd on rep_profiles for update using (id = auth.uid());
alter table firms enable row level security;
create policy t_read on firms for select using (id in (select auth_tenant_ids()));
alter table stores enable row level security;
create policy s_read on stores for select using (tenant_id in (select auth_tenant_ids()));
alter table memberships enable row level security;
create policy m_read on memberships for select using (user_id = auth.uid() or tenant_id in (select auth_tenant_ids()));
alter table periods enable row level security;
create policy pr_read on periods for select using (tenant_id in (select auth_tenant_ids()));
alter table institutions enable row level security;
create policy i_read on institutions for select using (dogrulandi or ekleyen_tenant_id in (select auth_tenant_ids()));
do $$
declare t text;
begin
  foreach t in array array['visits']
  loop
    execute format('alter table %I enable row level security', t);
    execute format($f$create policy %I_all on %I for all
      using (store_id in (select auth_store_ids()))
      with check (store_id in (select auth_store_ids()))$f$, t, t);
  end loop;
  foreach t in array array['notifications', 'requests', 'orders', 'shipments', 'payments']
  loop
    execute format('alter table %I enable row level security', t);
    execute format($f$create policy %I_all on %I for all
      using (tenant_id in (select auth_tenant_ids()))
      with check (tenant_id in (select auth_tenant_ids()))$f$, t, t);
  end loop;
end $$;

create or replace function notify_user(
  p_tenant uuid, p_user uuid, p_olay text, p_baslik text,
  p_govde text default null, p_hedef_tur text default null,
  p_hedef_id uuid default null) returns void
language sql security definer set search_path = public as $$
  insert into notifications (tenant_id, user_id, olay, baslik, govde,
                             hedef_tur, hedef_id)
  select p_tenant, p_user, p_olay, p_baslik, p_govde, p_hedef_tur, p_hedef_id
  where p_user is not null;
$$;
grant execute on function notify_user(uuid, uuid, text, text, text, text, uuid) to authenticated;

create or replace view report_ziyaret as
select
  v.id                                 as satir_id,
  v.store_id, v.tenant_id, v.institution_id, v.period_id,
  null::uuid                           as account_id,
  v.checked_in_at                      as tarih,
  v.sonuc,
  case when v.checked_out_at is null then null
       else extract(epoch from v.checked_out_at - v.checked_in_at) / 60 end
                                       as dakika,
  (select count(*) from requests  r where r.visit_id = v.id) as talep,
  (select count(*) from orders    o where o.visit_id = v.id) as siparis,
  (select count(*) from shipments s where s.visit_id = v.id) as teslimat,
  (select count(*) from payments  p where p.visit_id = v.id) as tahsilat_adet,
  coalesce((select sum(p.tutar) from payments p where p.visit_id = v.id), 0)
                                       as tahsilat_tutar,
  i.ad                                 as kurum_ad,
  i.kurum_tipi::text                   as kurum_tipi,
  i.kademe::text                       as kademe,
  i.il, i.ilce,
  st.ad                                as dukkan_ad,
  v.user_id                            as pazarlamaci_id,
  pr.ad_soyad                          as pazarlamaci_ad,
  v.not_metni
from visits v
join institutions i on i.id = v.institution_id
join stores st      on st.id = v.store_id
left join rep_profiles pr on pr.id = v.user_id;

-- CONTROL for case 7: the same view, run as the caller.
create or replace view report_ziyaret_safe with (security_invoker = true) as
select
  v.id                                 as satir_id,
  v.store_id, v.tenant_id, v.institution_id, v.period_id,
  null::uuid                           as account_id,
  v.checked_in_at                      as tarih,
  v.sonuc,
  case when v.checked_out_at is null then null
       else extract(epoch from v.checked_out_at - v.checked_in_at) / 60 end
                                       as dakika,
  (select count(*) from requests  r where r.visit_id = v.id) as talep,
  (select count(*) from orders    o where o.visit_id = v.id) as siparis,
  (select count(*) from shipments s where s.visit_id = v.id) as teslimat,
  (select count(*) from payments  p where p.visit_id = v.id) as tahsilat_adet,
  coalesce((select sum(p.tutar) from payments p where p.visit_id = v.id), 0)
                                       as tahsilat_tutar,
  i.ad                                 as kurum_ad,
  i.kurum_tipi::text                   as kurum_tipi,
  i.kademe::text                       as kademe,
  i.il, i.ilce,
  st.ad                                as dukkan_ad,
  v.user_id                            as pazarlamaci_id,
  pr.ad_soyad                          as pazarlamaci_ad,
  v.not_metni
from visits v
join institutions i on i.id = v.institution_id
join stores st      on st.id = v.store_id
left join rep_profiles pr on pr.id = v.user_id;

-- =================================================================================================
-- CASE 8: a SaaS starter kit. "Get a user's teams" takes the user id as an argument.
-- (Source table names "teams" and "team_members" are "crews" and "crew_members" here.)
-- =================================================================================================
CREATE TYPE public.team_role AS ENUM ('owner', 'admin', 'member');
CREATE TYPE public.subscription_tier AS ENUM ('free', 'basic', 'pro', 'enterprise');

CREATE TABLE public.crews (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  slug TEXT NOT NULL UNIQUE,
  description TEXT,
  logo_url TEXT,
  is_personal BOOLEAN NOT NULL DEFAULT FALSE,
  personal_user_id UUID REFERENCES auth.users(id),
  subscription_tier subscription_tier NOT NULL DEFAULT 'free',
  subscription_id TEXT,
  max_members INTEGER NOT NULL DEFAULT 5,
  metadata JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  CONSTRAINT personal_teams_have_user_id CHECK (
    (is_personal = FALSE) OR (is_personal = TRUE AND personal_user_id IS NOT NULL)
  )
);

CREATE TABLE public.crew_members (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  team_id UUID NOT NULL REFERENCES public.crews(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  role team_role NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE(team_id, user_id)
);

CREATE OR REPLACE FUNCTION public.is_team_member(team_id UUID, user_id UUID)
RETURNS BOOLEAN AS $$
BEGIN
  RETURN EXISTS (
    SELECT 1 FROM public.crew_members tm
    WHERE tm.team_id = $1 AND tm.user_id = $2
  );
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

ALTER TABLE public.crews ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.crew_members ENABLE ROW LEVEL SECURITY;
CREATE POLICY "Users can view teams they belong to" ON public.crews FOR SELECT TO authenticated
USING (public.is_team_member(id, auth.uid()));
CREATE POLICY "Users can create teams" ON public.crews FOR INSERT TO authenticated
WITH CHECK (auth.uid() IS NOT NULL AND is_personal = FALSE);
CREATE POLICY "Users can view members of their teams" ON public.crew_members FOR SELECT TO authenticated
USING (public.is_team_member(team_id, auth.uid()));

CREATE OR REPLACE FUNCTION public.get_user_teams(user_id UUID)
RETURNS SETOF public.crews AS $$
BEGIN
  RETURN QUERY
    SELECT t.*
    FROM public.crews t
    JOIN public.crew_members tm ON t.id = tm.team_id
    WHERE tm.user_id = $1;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- CONTROL for case 8: the argument must be the caller.
CREATE OR REPLACE FUNCTION public.get_user_teams_safe(user_id UUID)
RETURNS SETOF public.crews AS $$
BEGIN
  RETURN QUERY
    SELECT t.*
    FROM public.crews t
    JOIN public.crew_members tm ON t.id = tm.team_id
    WHERE tm.user_id = $1 AND $1 = auth.uid();
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- =================================================================================================
-- CASE 9: a memory store for coding agents. Policy functions take p_user_id instead of auth.uid()
-- so an API-key caller can use them; nothing checks that the caller is that user.
-- =================================================================================================
create table if not exists retention_policies (
  id             uuid primary key default gen_random_uuid(),
  user_id        uuid not null references auth.users on delete cascade,
  scope          text not null,
  name           text not null,
  mode           text not null default 'review' check (mode in ('review', 'auto')),
  enabled        boolean not null default false,
  min_age_days   integer check (min_age_days is null or min_age_days > 0),
  unseen_days    integer check (unseen_days is null or unseen_days > 0),
  max_seen_count integer check (max_seen_count is null or max_seen_count >= 0),
  created_at     timestamptz not null default now(),
  updated_at     timestamptz not null default now()
);
create index if not exists retention_policies_user_id_idx on retention_policies (user_id);
alter table retention_policies enable row level security;
create policy "rls_retention_policies_owner"
  on retention_policies for all
  using (user_id = auth.uid())
  with check (user_id = auth.uid());
create or replace trigger retention_policies_updated_at
  before update on retention_policies
  for each row execute function set_updated_at();
alter table retention_policies
  add column if not exists tags                text[],
  add column if not exists tags_mode           text default 'any',
  add column if not exists source_agent        text[],
  add column if not exists source_agent_mode   text default 'in',
  add column if not exists trigger             text[],
  add column if not exists trigger_mode        text default 'in',
  add column if not exists kind                text[],
  add column if not exists kind_mode           text default 'in',
  add column if not exists host                text[],
  add column if not exists host_mode           text default 'in',
  add column if not exists origin_repo         text[],
  add column if not exists origin_repo_mode    text default 'in',
  add column if not exists origin_branch       text[],
  add column if not exists origin_branch_mode  text default 'in',
  add column if not exists origin_pr           text[],
  add column if not exists origin_pr_mode      text default 'in';
alter table retention_policies add column if not exists max_read_count integer;
alter table retention_policies add constraint retention_policies_max_read_count_non_negative
  check (max_read_count is null or max_read_count >= 0);
alter table retention_policies add column if not exists max_opened_count integer;
alter table retention_policies add constraint retention_policies_max_opened_count_non_negative
  check (max_opened_count is null or max_opened_count >= 0);

create or replace function memo_policy_update(
  p_user_id uuid,
  p_id      uuid,
  p_patch   jsonb
)
returns setof retention_policies
language sql
security definer
set search_path = public
as $$
  update retention_policies
     set name                = case when p_patch ? 'name'                then p_patch ->> 'name'                          else name end,
         mode                 = case when p_patch ? 'mode'                then p_patch ->> 'mode'                          else mode end,
         enabled              = case when p_patch ? 'enabled'             then (p_patch ->> 'enabled')::boolean            else enabled end,
         min_age_days         = case when p_patch ? 'min_age_days'        then (p_patch ->> 'min_age_days')::integer       else min_age_days end,
         unseen_days          = case when p_patch ? 'unseen_days'         then (p_patch ->> 'unseen_days')::integer        else unseen_days end,
         max_seen_count       = case when p_patch ? 'max_seen_count'      then (p_patch ->> 'max_seen_count')::integer     else max_seen_count end,
         max_read_count       = case when p_patch ? 'max_read_count'      then (p_patch ->> 'max_read_count')::integer     else max_read_count end,
         max_opened_count     = case when p_patch ? 'max_opened_count'    then (p_patch ->> 'max_opened_count')::integer   else max_opened_count end,
         tags                 = case when p_patch ? 'tags'                then (case when p_patch -> 'tags'                = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'tags')) end)                else tags end,
         tags_mode            = case when p_patch ? 'tags_mode'           then p_patch ->> 'tags_mode'                     else tags_mode end,
         source_agent         = case when p_patch ? 'source_agent'        then (case when p_patch -> 'source_agent'        = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'source_agent')) end)         else source_agent end,
         source_agent_mode    = case when p_patch ? 'source_agent_mode'   then p_patch ->> 'source_agent_mode'             else source_agent_mode end,
         trigger              = case when p_patch ? 'trigger'             then (case when p_patch -> 'trigger'             = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'trigger')) end)              else trigger end,
         trigger_mode         = case when p_patch ? 'trigger_mode'        then p_patch ->> 'trigger_mode'                  else trigger_mode end,
         kind                 = case when p_patch ? 'kind'                then (case when p_patch -> 'kind'                = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'kind')) end)                 else kind end,
         kind_mode            = case when p_patch ? 'kind_mode'           then p_patch ->> 'kind_mode'                     else kind_mode end,
         host                 = case when p_patch ? 'host'                then (case when p_patch -> 'host'                = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'host')) end)                 else host end,
         host_mode            = case when p_patch ? 'host_mode'           then p_patch ->> 'host_mode'                     else host_mode end,
         origin_repo          = case when p_patch ? 'origin_repo'         then (case when p_patch -> 'origin_repo'         = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'origin_repo')) end)          else origin_repo end,
         origin_repo_mode     = case when p_patch ? 'origin_repo_mode'    then p_patch ->> 'origin_repo_mode'              else origin_repo_mode end,
         origin_branch        = case when p_patch ? 'origin_branch'       then (case when p_patch -> 'origin_branch'       = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'origin_branch')) end)        else origin_branch end,
         origin_branch_mode   = case when p_patch ? 'origin_branch_mode'  then p_patch ->> 'origin_branch_mode'            else origin_branch_mode end,
         origin_pr            = case when p_patch ? 'origin_pr'           then (case when p_patch -> 'origin_pr'           = 'null'::jsonb then null else array(select jsonb_array_elements_text(p_patch -> 'origin_pr')) end)            else origin_pr end,
         origin_pr_mode       = case when p_patch ? 'origin_pr_mode'      then p_patch ->> 'origin_pr_mode'                else origin_pr_mode end
   where id = p_id and user_id = p_user_id
  returning *;
$$;
grant execute on function memo_policy_update(uuid, uuid, jsonb) to authenticated, service_role;

create or replace function memo_policy_delete(p_user_id uuid, p_id uuid)
returns setof retention_policies
language sql
security definer
set search_path = public
as $$
  delete from retention_policies
   where id = p_id and user_id = p_user_id
  returning *;
$$;
grant execute on function memo_policy_delete(uuid, uuid) to authenticated, service_role;

-- =================================================================================================
-- CASE 10: an agent work board. The runner's verification upsert takes every id from the caller;
-- it was meant for the API route only. (Source table name "tenants" is "board_tenants" here.)
-- =================================================================================================
create table public.board_tenants (
  id          uuid primary key default gen_random_uuid(),
  name        text not null,
  created_at  timestamptz not null default now()
);

create table public.tenant_members (
  tenant_id   uuid not null references public.board_tenants(id) on delete cascade,
  user_id     uuid not null references auth.users(id)     on delete cascade,
  role        text not null default 'member',
  created_at  timestamptz not null default now(),
  primary key (tenant_id, user_id)
);

create or replace function public.current_user_tenants()
returns setof uuid
language sql
stable
security definer
set search_path = public
as $$
  select tenant_id from public.tenant_members where user_id = auth.uid();
$$;
revoke all on function public.current_user_tenants() from public;
grant execute on function public.current_user_tenants() to authenticated, service_role;

create table public.agents (
  id           uuid primary key default gen_random_uuid(),
  tenant_id    uuid not null references public.board_tenants(id) on delete cascade,
  name         text not null,
  role         text,
  version      int  not null default 1,
  config       jsonb not null default '{}'::jsonb,
  created_at   timestamptz not null default now()
);

create type public.ticket_status as enum (
  'backlog', 'ready', 'assigned', 'in_progress', 'input_required', 'blocked', 'in_review', 'done', 'failed'
);

create table public.tickets (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references public.board_tenants(id) on delete cascade,
  title               text not null,
  description         text,
  acceptance_criteria text,
  status              public.ticket_status not null default 'backlog',
  priority            int default 3,
  retry_count         int not null default 0,
  column_position     int not null default 0,
  assignee_agent_id   uuid references public.agents(id) on delete set null,
  parent_ticket_id    uuid references public.tickets(id) on delete cascade,
  created_at          timestamptz not null default now(),
  updated_at          timestamptz not null default now(),
  gate_retry_count    int not null default 0
);
alter table public.tickets add constraint tickets_retry_count_ceiling check (retry_count <= 10);

create table public.runners (
  id                  uuid primary key default gen_random_uuid(),
  tenant_id           uuid not null references public.board_tenants(id) on delete cascade,
  kind                text not null check (kind in ('api','local-cc')),
  name                text not null,
  capabilities        jsonb not null default '[]'::jsonb,
  status              text not null default 'idle',
  last_heartbeat_at   timestamptz,
  created_at          timestamptz not null default now()
);

create table public.runs (
  id              uuid primary key default gen_random_uuid(),
  tenant_id       uuid not null references public.board_tenants(id) on delete cascade,
  agent_id        uuid references public.agents(id)   on delete set null,
  ticket_id       uuid references public.tickets(id)  on delete set null,
  parent_run_id   uuid references public.runs(id)     on delete set null,
  runner_id       uuid references public.runners(id)  on delete set null,
  runner_kind     text check (runner_kind in ('api','local-cc')),
  depth           int  not null default 0,
  status          text not null default 'running',
  budget_cents    int  not null,
  spent_cents     int  not null default 0,
  last_event_at   timestamptz not null default now(),
  created_at      timestamptz not null default now()
);

do $$
declare t text;
begin
  foreach t in array array['agents', 'tickets', 'runners', 'runs']
  loop
    execute format('alter table public.%I enable row level security', t);
    execute format($f$create policy %I_member_all on public.%I for all
      using (tenant_id in (select public.current_user_tenants()))
      with check (tenant_id in (select public.current_user_tenants()))$f$, t, t);
  end loop;
end $$;
alter table public.board_tenants enable row level security;
create policy board_tenants_member_read on public.board_tenants for select using (id in (select public.current_user_tenants()));
alter table public.tenant_members enable row level security;
create policy tenant_members_self_read on public.tenant_members for select using (user_id = auth.uid());

create table if not exists public.run_verifications (
  id          uuid primary key default gen_random_uuid(),
  tenant_id   uuid not null references public.board_tenants(id) on delete cascade,
  run_id      uuid not null references public.runs(id)    on delete cascade,
  ticket_id   uuid references public.tickets(id)          on delete set null,
  command     text not null,
  exit_code   int  not null,
  head_sha    text not null,
  base_sha    text,
  pushed      boolean not null,
  output_tail text not null default '',
  ran_at      timestamptz not null default now(),
  created_at  timestamptz not null default now(),
  constraint run_verifications_run_uniq unique (run_id)
);
alter table public.run_verifications add column if not exists commits_ahead int;
alter table public.run_verifications enable row level security;
create policy run_verifications_member_read on public.run_verifications
  for select using (tenant_id in (select public.current_user_tenants()));
create policy run_verifications_member_write on public.run_verifications
  for all using (tenant_id in (select public.current_user_tenants()))
         with check (tenant_id in (select public.current_user_tenants()));

create or replace function public.upsert_run_verification(
  p_tenant_id     uuid,
  p_run_id        uuid,
  p_ticket_id     uuid,
  p_command       text,
  p_exit_code     int,
  p_head_sha      text,
  p_base_sha      text,
  p_pushed        boolean,
  p_output_tail   text,
  p_ran_at        timestamptz,
  p_commits_ahead int default null
) returns void
language sql
security definer
set search_path = public
as $$
  insert into public.run_verifications
    (tenant_id, run_id, ticket_id, command, exit_code, head_sha, base_sha,
     pushed, output_tail, ran_at, commits_ahead)
  values
    (p_tenant_id, p_run_id, p_ticket_id, p_command, p_exit_code, p_head_sha,
     p_base_sha, p_pushed, p_output_tail, p_ran_at, p_commits_ahead)
  on conflict (run_id) do update set
    ticket_id   = excluded.ticket_id,
    command     = excluded.command,
    exit_code   = excluded.exit_code,
    head_sha    = excluded.head_sha,
    base_sha    = coalesce(public.run_verifications.base_sha, excluded.base_sha),
    pushed      = excluded.pushed,
    output_tail = excluded.output_tail,
    ran_at      = excluded.ran_at,
    commits_ahead = coalesce(excluded.commits_ahead, public.run_verifications.commits_ahead);
$$;

-- =================================================================================================
-- CASE 11: field service management. The customer portal's "document denied" notifier takes any
-- document id and writes notifications to that workspace's staff. (Source names "workspaces",
-- "workspace_members", "projects", "notifications" and "users" carry a "job_" prefix here.)
-- =================================================================================================
create type workspace_member_role as enum ('master_admin', 'admin', 'project_manager', 'field_technician', 'client', 'vendor');
create type document_status as enum ('draft', 'sent', 'viewed', 'signed');

create table job_workspaces (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner_id uuid,
  avatar_url text,
  currency_code text default 'USD',
  created_at timestamptz default now()
);

create table job_users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text unique not null,
  display_name text,
  active_workspace_id uuid references job_workspaces(id),
  created_at timestamptz default now()
);
alter table job_workspaces add constraint job_workspaces_owner_id_fkey foreign key (owner_id) references job_users(id);

create table job_workspace_members (
  workspace_id uuid not null references job_workspaces(id) on delete cascade,
  user_id uuid not null references job_users(id) on delete cascade,
  role workspace_member_role not null default 'field_technician',
  created_at timestamptz default now(),
  primary key (workspace_id, user_id)
);

create table job_projects (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references job_workspaces(id) on delete cascade,
  name text not null,
  address text,
  description text,
  project_manager_id uuid references job_users(id),
  created_at timestamptz default now()
);

create table generated_documents (
  id uuid primary key default gen_random_uuid(),
  workspace_id uuid not null references job_workspaces(id) on delete cascade,
  project_id uuid references job_projects(id),
  customer_name text,
  template_name text,
  rendered_content text,
  status document_status default 'draft',
  created_by uuid references job_users(id),
  sent_at timestamptz,
  sent_to text,
  created_at timestamptz default now()
);

create table if not exists public.notification_types (
  code text primary key,
  description text,
  email_pref_key text,
  push_pref_key text,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);
insert into public.notification_types (code, description, email_pref_key, push_pref_key) values
  ('mention',                       'You were mentioned',                       'mentionsEmail',         'mentionsPush'),
  ('task_assignment',               'A task was assigned to you',               'taskAssignmentsEmail',  'taskAssignmentsPush'),
  ('document_signed',               'A document was signed',                    'projectUpdatesEmail',   'projectUpdatesPush'),
  ('document_denied',               'A document was denied',                    'projectUpdatesEmail',   'projectUpdatesPush'),
  ('document_changes_requested',    'Changes requested on a document',          'projectUpdatesEmail',   'projectUpdatesPush'),
  ('document_payment_completed',    'Payment completed for a document',         'projectUpdatesEmail',   'projectUpdatesPush'),
  ('document_bid_received',         'Vendor bid received on RFP',               'projectUpdatesEmail',   'projectUpdatesPush'),
  ('document_bid_applied',          'Vendor bid applied to budget',             'projectUpdatesEmail',   'projectUpdatesPush')
on conflict (code) do nothing;
alter table public.notification_types enable row level security;
create policy notification_types_read on public.notification_types for select using (true);

create table if not exists job_notifications (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references auth.users(id) on delete cascade,
    workspace_id uuid not null,
    type text not null,
    title text not null,
    body text,
    is_read boolean not null default false,
    metadata jsonb default '{}'::jsonb,
    created_at timestamptz not null default now()
);
alter table public.job_notifications
  add constraint notifications_type_fkey
  foreign key (type) references public.notification_types(code)
  on update cascade on delete restrict;
alter table public.job_notifications add column if not exists dedupe_key text;
alter table job_notifications enable row level security;
create policy "Users can view own notifications" on public.job_notifications as permissive for select using (((select auth.uid()) = user_id));
create policy "Users can update own notifications" on public.job_notifications as permissive for update using (((select auth.uid()) = user_id));
create policy notifications_service_role_insert on public.job_notifications for insert to service_role with check (true);

create or replace function public.is_job_workspace_member(p_workspace_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from job_workspace_members where workspace_id = p_workspace_id and user_id = auth.uid());
$$;
alter table job_users enable row level security;
create policy job_users_self on job_users for select using (id = auth.uid());
alter table job_workspaces enable row level security;
create policy job_workspaces_member on job_workspaces for select using (public.is_job_workspace_member(id));
alter table job_workspace_members enable row level security;
create policy job_workspace_members_member on job_workspace_members for select using (public.is_job_workspace_member(workspace_id));
alter table job_projects enable row level security;
create policy job_projects_member on job_projects for all using (public.is_job_workspace_member(workspace_id)) with check (public.is_job_workspace_member(workspace_id));
alter table generated_documents enable row level security;
create policy generated_documents_member on generated_documents for all using (public.is_job_workspace_member(workspace_id)) with check (public.is_job_workspace_member(workspace_id));

CREATE OR REPLACE FUNCTION public.create_document_action_notifications(
  p_document_id uuid,
  p_action text,
  p_actor_name text DEFAULT NULL,
  p_actor_email text DEFAULT NULL,
  p_reason text DEFAULT NULL
)
RETURNS integer
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path TO 'public'
AS $function$
DECLARE
  doc_row RECORD;
  project_manager_id UUID;
  actor_label TEXT;
  notif_type TEXT;
  notif_title TEXT;
  notif_body TEXT;
  inserted_count INTEGER := 0;
BEGIN
  SELECT
    gd.id,
    gd.workspace_id,
    gd.project_id,
    gd.created_by,
    COALESCE(NULLIF(TRIM(gd.template_name), ''), 'Document') AS template_name
  INTO doc_row
  FROM public.generated_documents gd
  WHERE gd.id = p_document_id
  LIMIT 1;

  IF NOT FOUND THEN
    RETURN 0;
  END IF;

  IF doc_row.project_id IS NOT NULL THEN
    SELECT p.project_manager_id
    INTO project_manager_id
    FROM public.job_projects p
    WHERE p.id = doc_row.project_id
    LIMIT 1;
  END IF;

  actor_label := COALESCE(
    NULLIF(TRIM(p_actor_name), ''),
    NULLIF(TRIM(p_actor_email), ''),
    'the customer'
  );

  CASE p_action
    WHEN 'denied' THEN
      notif_type := 'document_denied';
      notif_title := doc_row.template_name || ' was denied';
      notif_body := 'Denied by ' || actor_label || '.';
      IF p_reason IS NOT NULL AND TRIM(p_reason) <> '' THEN
        notif_body := notif_body || ' Reason: ' || TRIM(p_reason);
      END IF;
    WHEN 'changes_requested' THEN
      notif_type := 'document_changes_requested';
      notif_title := 'Changes requested on ' || doc_row.template_name;
      notif_body := 'Requested by ' || actor_label || '.';
      IF p_reason IS NOT NULL AND TRIM(p_reason) <> '' THEN
        notif_body := notif_body || ' Reason: ' || TRIM(p_reason);
      END IF;
    WHEN 'payment_completed' THEN
      notif_type := 'document_payment_completed';
      notif_title := doc_row.template_name || ' payment received';
      notif_body := 'Payment completed by ' || actor_label || '.';
    WHEN 'bid_received' THEN
      notif_type := 'document_bid_received';
      notif_title := 'Bid received on ' || doc_row.template_name;
      notif_body := actor_label || ' has submitted their bid. Review and apply to budget.';
    WHEN 'bid_applied' THEN
      notif_type := 'document_bid_applied';
      notif_title := doc_row.template_name || ' bid applied to budget';
      notif_body := actor_label || ' applied the vendor bid to the project budget.';
    ELSE
      RETURN 0;
  END CASE;

  INSERT INTO public.job_notifications (
    user_id,
    workspace_id,
    type,
    title,
    body,
    metadata
  )
  SELECT
    recipients.user_id,
    doc_row.workspace_id,
    notif_type,
    notif_title,
    notif_body,
    jsonb_build_object(
      'target_type', 'document',
      'document_id', doc_row.id,
      'project_id', doc_row.project_id,
      'action', p_action,
      'reason', NULLIF(TRIM(COALESCE(p_reason, '')), ''),
      'deeplink_path', '/documents/' || doc_row.id::TEXT
    )
  FROM (
    SELECT DISTINCT user_id
    FROM (
      SELECT doc_row.created_by AS user_id
      UNION ALL
      SELECT project_manager_id AS user_id
      UNION ALL
      SELECT wm.user_id
      FROM public.job_workspace_members wm
      WHERE wm.workspace_id = doc_row.workspace_id
        AND wm.role = 'admin'
    ) candidate_recipients
    WHERE user_id IS NOT NULL
  ) recipients;

  GET DIAGNOSTICS inserted_count = ROW_COUNT;
  RETURN inserted_count;
END;
$function$;
