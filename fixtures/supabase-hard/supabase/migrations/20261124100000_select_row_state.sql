-- Row state checked in a SELECT: the function first finds the row with SELECT ... INTO in a given
-- state (a poll that is live: kind in a list, opened, not closed), raises when not found, and only then
-- writes, copied from a field-test app's live audience questions (names changed). The row-state step
-- once read only UPDATE and DELETE conditions, so a new test row (a draft, never opened) left the
-- function untested. No caller check (planted): must be proven with the poll first put in that state.
create table public.studio_polls (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  kind text not null default 'draft' check (kind in ('draft', 'poll', 'quiz')),
  opened_at timestamptz,
  closed_at timestamptz,
  votes integer not null default 0
);
alter table public.studio_polls enable row level security;
create policy studio_polls_own on public.studio_polls for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.vote_studio_poll(p_poll uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare
  v_poll uuid;
begin
  select p.id into v_poll from public.studio_polls p
   where p.id = p_poll and p.kind in ('poll', 'quiz') and p.opened_at is not null and p.closed_at is null
   for share;
  if v_poll is null then
    raise exception 'that question has closed' using errcode = 'check_violation';
  end if;
  update public.studio_polls set votes = votes + 1 where id = v_poll;
end;
$$;
