-- row/trigger-needs-column: an optional column the table itself does not need, which a trigger copies
-- into another table where it is required (a transactional outbox, copied from a field-test app,
-- names changed). Left empty, the insert fails on the other table. The parent has the same column,
-- so the test row takes the parent's value. Read policy open (planted), so the row must exist.
create table public.studio_jobs (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  tenant_ref uuid not null default gen_random_uuid()
);
alter table public.studio_jobs enable row level security;
create policy studio_jobs_own on public.studio_jobs for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create table public.studio_job_events (
  id bigint generated always as identity primary key,
  tenant_ref uuid not null,
  job_id uuid not null,
  kind text not null
);
alter table public.studio_job_events enable row level security;

create table public.studio_job_results (
  id uuid primary key default gen_random_uuid(),
  job_id uuid not null references public.studio_jobs(id) on delete cascade,
  output jsonb not null default '{}',
  tenant_ref uuid
);
alter table public.studio_job_results enable row level security;
create policy studio_job_results_read on public.studio_job_results for select to authenticated using (true);
create policy studio_job_results_write on public.studio_job_results for insert to authenticated
  with check (exists (select 1 from public.studio_jobs j join public.studios s on s.id = j.studio_id where j.id = job_id and s.created_by = auth.uid()));

create function public.studio_job_result_event() returns trigger
language plpgsql security definer set search_path = '' as $$
begin
  insert into public.studio_job_events (tenant_ref, job_id, kind) values (new.tenant_ref, new.job_id, 'job.completed');
  return new;
end;
$$;
create trigger studio_job_results_event after insert on public.studio_job_results for each row execute function public.studio_job_result_event();
