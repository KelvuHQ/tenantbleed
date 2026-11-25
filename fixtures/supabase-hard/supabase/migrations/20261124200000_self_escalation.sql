-- Self-escalation on a flag only a function trusts: a user's own settings row carries is_staff, the
-- self-update policy covers every column (Supabase's default grants allow it), and a staff-only report
-- function reads the flag. Setting it on your own row is stored; no other user's rows open to a plain
-- read, so it is reported lower than the profiles case (is_admin trusted by a read policy, planted in
-- 20261119000000_hard_cases.sql), found by another public tester in the 2026-11-21 benchmark.
create table public.member_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  theme text not null default 'light',
  is_staff boolean not null default false
);
alter table public.member_settings enable row level security;
create policy member_settings_self on public.member_settings for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.staff_signup_report() returns bigint
language plpgsql stable security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.member_settings m where m.user_id = auth.uid() and m.is_staff) then
    raise exception 'staff only' using errcode = '42501';
  end if;
  return (select count(*) from auth.users);
end;
$$;

-- The same with an admin flag trusted by a read policy, through a SECURITY DEFINER helper (the usual
-- way to avoid the policy recursion that makes the profiles case in 20261119000000_hard_cases.sql
-- unusable through the API). Setting is_admin on your own row opens every member's profile: critical.
create table public.member_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null,
  phone text,
  is_admin boolean not null default false
);
alter table public.member_profiles enable row level security;

create function public.member_is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select m.is_admin from public.member_profiles m where m.id = auth.uid()), false);
$$;

create policy member_profiles_self on public.member_profiles for all to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
create policy member_profiles_admin_read on public.member_profiles for select to authenticated
  using (public.member_is_admin());
