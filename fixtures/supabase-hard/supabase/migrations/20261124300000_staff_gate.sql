-- A staff list the name does not give away: the installation's operators are the users with an active
-- row in a delegation table, checked by a gate function that other functions call before acting on
-- every tenant's rows (shape from a field-test app, names changed). Filling that table for the test
-- users made them operators, so an operator-only maintenance function looked like a cross-tenant
-- write. The table must stay empty and the function must stay clean.
create table public.studio_delegates (
  user_id uuid primary key references auth.users(id) on delete cascade,
  status text not null default 'active' check (status in ('active', 'withdrawn')),
  granted_by uuid references auth.users(id) on delete set null,
  granted_at timestamptz not null default now()
);
alter table public.studio_delegates enable row level security;
create policy studio_delegates_self on public.studio_delegates for select to authenticated
  using (user_id = auth.uid());

create function public.is_studio_operator() returns boolean
language sql stable security definer set search_path = '' as $$
  select auth.uid() is not null
     and exists (select 1 from public.studio_delegates where user_id = auth.uid() and status = 'active');
$$;

create table public.studio_flags (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  reason text not null,
  settled_at timestamptz
);
alter table public.studio_flags enable row level security;
create policy studio_flags_own on public.studio_flags for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

-- Operator-only: settles every open flag of every studio.
create function public.settle_studio_flags() returns integer
language plpgsql security definer set search_path = '' as $$
declare
  v_count integer;
begin
  if not public.is_studio_operator() then
    raise exception 'only the operator settles flags' using errcode = '42501';
  end if;
  update public.studio_flags set settled_at = now() where settled_at is null;
  get diagnostics v_count = row_count;
  return v_count;
end;
$$;

-- Operators hand the role on; nobody can add themselves.
create function public.delegate_studio_operator(p_user uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not public.is_studio_operator() then
    raise exception 'only the operator delegates' using errcode = '42501';
  end if;
  insert into public.studio_delegates (user_id, granted_by) values (p_user, auth.uid())
  on conflict (user_id) do update set status = 'active', granted_by = auth.uid();
end;
$$;
