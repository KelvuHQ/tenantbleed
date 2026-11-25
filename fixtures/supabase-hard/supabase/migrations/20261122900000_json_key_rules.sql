-- check/json-key: a JSON document whose keys the CHECK pins down (copied from a field-test app,
-- names changed): a fixed kind, a version from a list, and a key that must repeat the row's own id.
-- Read policy open (planted), so the row must exist to show it.
create table public.studio_layouts (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  plan jsonb not null,
  plan_sha256 text not null check (plan_sha256 ~ '^[a-f0-9]{64}$'),
  check (coalesce(
    jsonb_typeof(plan) = 'object'
    and octet_length(plan::text) <= 1048576
    and (plan ->> 'planType') = 'floor-plan'
    and (plan ->> 'schemaVersion') = any (array['1', '2'])
    and (plan ->> 'layoutId') = id::text,
  false))
);
alter table public.studio_layouts enable row level security;
create policy studio_layouts_read on public.studio_layouts for select to authenticated using (true);
create policy studio_layouts_write on public.studio_layouts for insert to authenticated
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
