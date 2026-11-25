-- Arguments from a row and its parent: a function finds the parent by one value and the child row by
-- its id and revision, copied from a field-test app's live audience votes (names changed). The ids
-- and the revision live on the child row, the other value on its parent, so a call built from one row
-- never agreed and both functions stayed untested.
--   close_event_round: the parent value is its studio, no caller check (planted): must be proven.
--   cast_round_vote: the parent value is the event's join code, shared with the audience like an
--   invite link: the code is never sent as found; with the victim's stored code the vote counts, with
--   any other nothing, so it is settled as a lookup by a secret value (tested), not a finding.
create table public.studio_events (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  join_code text not null unique,
  title text not null
);
alter table public.studio_events enable row level security;
create policy studio_events_own on public.studio_events for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create table public.event_rounds (
  id uuid primary key default gen_random_uuid(),
  event_id uuid not null references public.studio_events(id) on delete cascade,
  revision integer not null default 3,
  votes integer not null default 0,
  closed_at timestamptz
);
alter table public.event_rounds enable row level security;
create policy event_rounds_own on public.event_rounds for all to authenticated
  using (exists (select 1 from public.studio_events e join public.studios s on s.id = e.studio_id where e.id = event_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studio_events e join public.studios s on s.id = e.studio_id where e.id = event_id and s.created_by = auth.uid()));

create function public.close_event_round(p_studio uuid, p_round uuid, p_revision integer) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.event_rounds r set closed_at = now()
    from public.studio_events e
   where e.id = r.event_id and e.studio_id = p_studio and r.id = p_round and r.revision = p_revision;
  if not found then
    raise exception 'that round is not open' using errcode = 'check_violation';
  end if;
end;
$$;

create function public.cast_round_vote(p_code text, p_round uuid, p_revision integer) returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_event uuid;
begin
  select e.id into v_event from public.studio_events e where e.join_code = p_code;
  if v_event is null then
    raise exception 'that vote could not be counted' using errcode = 'check_violation';
  end if;
  update public.event_rounds r set votes = votes + 1
   where r.id = p_round and r.event_id = v_event and r.revision = p_revision and r.closed_at is null;
  if not found then
    raise exception 'that question has closed' using errcode = 'check_violation';
  end if;
end;
$$;
