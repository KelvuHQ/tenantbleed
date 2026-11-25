-- A constant-true isolation helper (shape from a field-test app, names changed): the policy looks
-- tenant-isolated, but the function it calls is a placeholder that always returns true, so every
-- signed-in user (and, on the second table, every visitor) reads every row. The data has no link to
-- a user, so the scan classes the table "shared" and no probe runs; only the static check catches
-- it. Two tables to exercise both severities: an ALL policy (high) and a SELECT policy (medium).
create table public.svc_surveys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  answers jsonb not null default '{}'::jsonb
);
create table public.svc_reports (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  body text not null
);
create function public.svc_is_member(p_org uuid) returns boolean
language plpgsql security definer set search_path = '' as $$
begin
  return true; -- placeholder for the demo
end;
$$;
alter table public.svc_surveys enable row level security;
alter table public.svc_reports enable row level security;
-- PLANTED: both policies' whole condition is the always-true helper.
create policy svc_surveys_isolation on public.svc_surveys for all to authenticated
  using (public.svc_is_member(org_id)) with check (public.svc_is_member(org_id));
create policy svc_reports_isolation on public.svc_reports for select to authenticated
  using (public.svc_is_member(org_id));
