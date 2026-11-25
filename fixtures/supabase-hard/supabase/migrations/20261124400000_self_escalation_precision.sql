-- Own-row role columns where the test user is already privileged, or where the column grants nothing
-- (shapes from field-test apps, names changed).
--   studio_crew: a member list where a member may edit their own row (planted). The test user who
--   created the studio is its owner, so "owner -> admin" proves nothing; the scan steps down to member
--   first and climbs back: any plain member can make themselves owner. Must be found.
--   studio_roster: the same list where only owners and admins edit members. After stepping down, the
--   climb back is refused. Must stay clean.
--   studio_chat: a chat log whose role column says who wrote the message (user or assistant). It is
--   free text and no rule compares it to a privileged value, so there is no privilege to take. Must
--   stay clean.
create table public.studio_crew (
  studio_id uuid not null references public.studios(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member')),
  nickname text,
  primary key (studio_id, user_id)
);
alter table public.studio_crew enable row level security;
create policy studio_crew_read on public.studio_crew for select to authenticated
  using (user_id = auth.uid());
create policy studio_crew_self on public.studio_crew for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create table public.studio_crew_notes (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  body text not null
);
alter table public.studio_crew_notes enable row level security;
create policy studio_crew_notes_leads on public.studio_crew_notes for all to authenticated
  using (exists (select 1 from public.studio_crew c where c.studio_id = studio_crew_notes.studio_id and c.user_id = auth.uid() and c.role in ('owner', 'admin')))
  with check (exists (select 1 from public.studio_crew c where c.studio_id = studio_crew_notes.studio_id and c.user_id = auth.uid() and c.role in ('owner', 'admin')));

create table public.studio_roster (
  studio_id uuid not null references public.studios(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'admin', 'member')),
  nickname text,
  primary key (studio_id, user_id)
);
alter table public.studio_roster enable row level security;
create function public.is_roster_lead(p_studio uuid) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.studio_roster r where r.studio_id = p_studio and r.user_id = auth.uid() and r.role in ('owner', 'admin'));
$$;
create policy studio_roster_read on public.studio_roster for select to authenticated
  using (user_id = auth.uid() or public.is_roster_lead(studio_id));
create policy studio_roster_leads on public.studio_roster for update to authenticated
  using (public.is_roster_lead(studio_id)) with check (public.is_roster_lead(studio_id));

create table public.studio_chat (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (char_length(role) <= 40),
  body text not null
);
alter table public.studio_chat enable row level security;
create policy studio_chat_own on public.studio_chat for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.my_studio_chat_replies() returns bigint
language sql stable security definer set search_path = '' as $$
  select count(*) from public.studio_chat where user_id = auth.uid() and role = 'assistant';
$$;
