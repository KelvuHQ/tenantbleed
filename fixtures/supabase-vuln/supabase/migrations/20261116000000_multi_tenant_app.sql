-- Deliberately vulnerable multi-tenant app used to measure tenantbleed.
-- Every planted bug is tagged with "PLANTED". Everything else is meant to be correct.

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
as $$
  select exists (
    select 1 from public.memberships m
    where m.org_id = o and m.user_id = auth.uid()
  )
$$;
revoke execute on function public.is_member(uuid) from anon;

-- Creator of an org becomes its owner.
create function public.add_creator_membership() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.memberships (org_id, user_id) values (new.id, auth.uid());
  return new;
end
$$;
revoke execute on function public.add_creator_membership() from anon, authenticated, public;

create trigger orgs_add_creator after insert on public.orgs
for each row execute function public.add_creator_membership();

alter table public.orgs enable row level security;
create policy orgs_select on public.orgs for select to authenticated using (public.is_member(id));
create policy orgs_insert on public.orgs for insert to authenticated with check (true);
create policy orgs_update on public.orgs for update to authenticated using (public.is_member(id));

alter table public.memberships enable row level security;
create policy memberships_select on public.memberships for select to authenticated
  using (user_id = auth.uid() or public.is_member(org_id));

-- ---------------------------------------------------------------- projects
-- PLANTED: select policy is `true`, so any signed-in user reads every tenant's projects.
create table public.projects (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  name text not null
);
alter table public.projects enable row level security;
create policy projects_select on public.projects for select to authenticated using (true);
create policy projects_insert on public.projects for insert to authenticated with check (public.is_member(org_id));
create policy projects_update on public.projects for update to authenticated using (public.is_member(org_id));
create policy projects_delete on public.projects for delete to authenticated using (public.is_member(org_id));

-- ---------------------------------------------------------------- invoices
-- PLANTED: RLS never enabled. With default Data API grants, anon can read and write everything.
create table public.invoices (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  amount_cents integer not null,
  memo text
);

-- ---------------------------------------------------------------- documents
-- PLANTED (latent): update policy is `true`. Not exploitable today because the SELECT policy hides
-- other tenants' rows and Postgres re-checks the new row; a scanner should call it latent, not proven.
create table public.documents (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  owner_id uuid not null default auth.uid() references auth.users(id),
  title text not null,
  body text
);
alter table public.documents enable row level security;
create policy documents_select on public.documents for select to authenticated using (public.is_member(org_id));
create policy documents_insert on public.documents for insert to authenticated with check (public.is_member(org_id));
create policy documents_update on public.documents for update to authenticated using (true) with check (true);
create policy documents_delete on public.documents for delete to authenticated using (public.is_member(org_id));

-- ---------------------------------------------------------------- notes (correct)
create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  body text not null
);
alter table public.notes enable row level security;
create policy notes_all on public.notes for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

-- ---------------------------------------------------------------- org_settings
-- PLANTED: policy trusts user_metadata, which every user can edit with auth.updateUser().
create table public.org_settings (
  org_id uuid primary key references public.orgs(id) on delete cascade,
  billing_email text not null
);
alter table public.org_settings enable row level security;
create policy org_settings_select on public.org_settings for select to authenticated
  using (org_id = ((auth.jwt() -> 'user_metadata') ->> 'org_id')::uuid);
create policy org_settings_insert on public.org_settings for insert to authenticated
  with check (public.is_member(org_id));

-- ---------------------------------------------------------------- products (intentionally public)
create table public.products (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  price_cents integer not null
);
alter table public.products enable row level security;
create policy products_public_read on public.products for select to anon, authenticated using (true);

-- ---------------------------------------------------------------- RPC
-- PLANTED: security definer, exposed through the API, no membership check.
create function public.get_org_documents(o uuid) returns setof public.documents
language sql security definer stable set search_path = ''
as $$
  select * from public.documents where org_id = o
$$;

-- ---------------------------------------------------------------- views
-- PLANTED: view without security_invoker runs as its owner and bypasses RLS on orgs and projects.
create view public.project_overview as
  select p.id, p.name as project_name, o.name as org_name
  from public.projects p join public.orgs o on o.id = p.org_id;
