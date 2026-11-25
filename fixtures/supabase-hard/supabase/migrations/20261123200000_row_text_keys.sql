-- args/row-tries with a text key: usage counted per studio and month, updated by a function that
-- finds the row by both (copied from a field-test app, names changed). No caller check (planted).
-- Only the victim's own row's month, together with its studio id, reaches the row; a marker or this
-- month's name does not.
create table public.studio_usage_monthly (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  month text not null,
  minutes bigint not null default 0,
  unique (studio_id, month)
);
alter table public.studio_usage_monthly enable row level security;
create policy studio_usage_monthly_own on public.studio_usage_monthly for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.add_studio_minutes(p_studio_id uuid, p_month text, p_minutes bigint) returns void
language plpgsql volatile security definer set search_path = '' as $$
begin
  update public.studio_usage_monthly
  set minutes = minutes + p_minutes
  where studio_id = p_studio_id and month = p_month;
end;
$$;
