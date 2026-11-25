-- Arguments whose name gives them a role, copied from field-test apps (names changed).

-- args/excluded-id: "notify everyone in the organization except this user". Given the victim's own
-- id, the victim is the one person left out and nothing they own changes; any other id lets the
-- call write notifications to every member of another organization. PLANTED: no caller check.
create function public.notify_org_members(p_org_id uuid, p_event text, p_title text, p_exclude_user_id uuid, p_owners_only boolean) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.org_notifications (org_id, user_id, event, title)
  select m.org_id, m.user_id, p_event, p_title
  from public.memberships m
  where m.org_id = p_org_id
    and (p_exclude_user_id is null or m.user_id <> p_exclude_user_id)
    and (not p_owners_only or m.role = 'owner');
end;
$$;
revoke execute on function public.notify_org_members(uuid, text, text, uuid, boolean) from public, anon;
grant execute on function public.notify_org_members(uuid, text, text, uuid, boolean) to authenticated;

-- triage/function-schema-risk: anyone can create a login account. The call creates a row nobody owns
-- (a new auth.users row), so neither the attack nor the owner's own call changes anyone's data, but
-- the schema check shows a definite risk on its own: the warning is flagged, not left untested.
create function public.create_login(email text) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare
  user_id uuid;
begin
  user_id := gen_random_uuid();
  insert into auth.users (id, email) values (user_id, email) returning id into user_id;
  return user_id;
end;
$$;
