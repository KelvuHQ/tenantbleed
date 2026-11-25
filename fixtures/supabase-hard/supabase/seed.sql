-- Seed data for local and branch databases. modifier/seed-only: a table created only here, never by
-- a migration, so it usually does not exist in production; its leak is reported as low.
create table if not exists public.demo_feedback (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  message text not null default 'feedback'
);
alter table public.demo_feedback enable row level security;
create policy demo_feedback_read on public.demo_feedback for select to authenticated using (true);
create policy demo_feedback_insert on public.demo_feedback for insert to authenticated with check (user_id = auth.uid());
