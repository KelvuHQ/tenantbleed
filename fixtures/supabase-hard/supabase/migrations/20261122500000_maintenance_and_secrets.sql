-- triage/function-time-maintenance: maintenance that only changes rows past a time limit and takes
-- no argument that picks a user, copied from field-test apps (names changed). The test rows are new,
-- so nothing changes for anyone, the owner included; the conclusion comes from the body: a caller can
-- at most run it early.
create table public.access_keys (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  label text not null,
  expires_at timestamptz
);
alter table public.access_keys enable row level security;
create policy access_keys_own on public.access_keys for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.cleanup_expired_access_keys() returns void
language plpgsql security definer set search_path = '' as $$
begin
  delete from public.access_keys where expires_at is not null and expires_at < now() - interval '30 days';
end;
$$;

create function public.reap_stale_access_keys(retention_days integer, active_ttl_days integer) returns bigint
language plpgsql security definer set search_path = '' as $$
declare
  cutoff timestamptz := now() - make_interval(days => greatest(retention_days, 0));
  n bigint;
begin
  delete from public.access_keys where expires_at < cutoff and expires_at < now() - make_interval(days => greatest(active_ttl_days, 0));
  get diagnostics n = row_count;
  return n;
end;
$$;

-- triage/function-secret-gated: lookups by a secret value (a share slug, an invite code), copied from
-- field-test apps (names changed). Another user who has the exact value gets the answer, by design;
-- with any other value, nothing. The scan settles it by calling with the victim's stored value.
create table public.shared_docs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title text not null,
  content text not null,
  visibility text not null default 'link' check (visibility in ('link', 'private')),
  public_slug text unique
);
alter table public.shared_docs enable row level security;
create policy shared_docs_own on public.shared_docs for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.get_shared_doc(p_slug text) returns table (id uuid, title text, content text)
language sql stable security definer set search_path = '' as $$
  select d.id, d.title, d.content from public.shared_docs d where d.public_slug = p_slug and d.visibility <> 'private' limit 1
$$;

create table public.team_invites (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  method text not null default 'code' check (method in ('code', 'email')),
  value text not null
);
alter table public.team_invites enable row level security;
create policy team_invites_own on public.team_invites for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());

create function public.check_invite_value(code text) returns uuid
language plpgsql volatile security definer set search_path = '' as $$
declare
  found uuid;
begin
  select user_id from public.team_invites where method = 'code' and value = check_invite_value.code into found;
  return found;
end;
$$;
