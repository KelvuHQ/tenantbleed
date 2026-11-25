-- Text links survive short markers: a child row links to its parent by a text key (an app's own
-- identifier, not a uuid), and a trigger copies the owner from that parent, copied from a field-test
-- app (names changed). Another trigger refuses long text with its own error, so the row is retried
-- with short markers. The retry once shortened the link too: it then named no parent, the owner
-- came out empty, the table looked shared and was never attacked, and so was every table under it.
-- Read policy on builds open (planted).
create table public.studio_apps (
  app_key text primary key,
  studio_id uuid not null references public.studios(id) on delete cascade,
  title text not null
);
alter table public.studio_apps enable row level security;
create policy studio_apps_own on public.studio_apps for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create table public.studio_builds (
  id uuid primary key default gen_random_uuid(),
  app_key text not null references public.studio_apps(app_key) on delete cascade,
  studio_id uuid not null references public.studios(id) on delete cascade,
  label text not null
);
alter table public.studio_builds enable row level security;
create policy studio_builds_read on public.studio_builds for select to authenticated using (true);
create policy studio_builds_write on public.studio_builds for insert to authenticated
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.studio_build_owner_from_app() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  new.studio_id := (select a.studio_id from public.studio_apps a where a.app_key = new.app_key);
  return new;
end;
$$;
create trigger a_studio_build_owner before insert or update on public.studio_builds for each row execute function public.studio_build_owner_from_app();

create function public.guard_studio_build() returns trigger
language plpgsql as $$
begin
  if length(new.label) > 20 then
    raise exception 'label too long' using errcode = '22023';
  end if;
  return new;
end;
$$;
create trigger b_studio_build_guard before insert or update on public.studio_builds for each row execute function public.guard_studio_build();
