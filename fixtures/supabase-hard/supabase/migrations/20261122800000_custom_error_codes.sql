-- row/rules-paused for app rules raised with their own error codes (copied from field-test apps,
-- names changed). Triggers refuse direct inserts with 42501 ("only through the draft function") or
-- 55000 ("recorded in force"), not the usual P0001, so the test row needs the rules paused like any
-- other raise from the app's code. The read policy is open (planted): the rows must exist to show it.
create table public.studio_bills (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  memo text not null
);
alter table public.studio_bills enable row level security;
create policy studio_bills_read on public.studio_bills for select to authenticated using (true);
create policy studio_bills_write on public.studio_bills for insert to authenticated
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.studio_bills_only_through_draft() returns trigger
language plpgsql as $$
begin
  if coalesce(current_setting('app.bill_draft', true), '') <> 'on' then
    raise exception 'Bills must be created through the draft function' using errcode = '42501';
  end if;
  return new;
end;
$$;
create trigger studio_bills_draft_only before insert on public.studio_bills for each row execute function public.studio_bills_only_through_draft();

create table public.studio_strikes (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  standing text not null default 'pending'
);
alter table public.studio_strikes enable row level security;
create policy studio_strikes_own on public.studio_strikes for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
create function public.studio_strikes_recorded_in_force() returns trigger
language plpgsql as $$
begin
  if new.standing <> 'in_force' or current_setting('app.strike_review', true) is null then
    raise exception 'A strike is recorded in force' using errcode = '55000';
  end if;
  return new;
end;
$$;
create trigger studio_strikes_in_force before insert on public.studio_strikes for each row execute function public.studio_strikes_recorded_in_force();
