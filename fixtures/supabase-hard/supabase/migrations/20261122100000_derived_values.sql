-- Functions that answer with a number or a word about an organization, not a row of it: nothing in
-- the answer carries the scan's markers, so "it returned their data" cannot be seen. Copied from
-- field-test apps (names changed). The scan compares the answer for the victim's id with the answer
-- for an id that exists nowhere, each asked twice.

-- PLANTED (rpc-leak/derived-value): anyone, even without an account, learns how many members any
-- organization has. Executable by everyone, as in the app it was copied from.
create function public.org_headcount(org_id uuid) returns integer
language plpgsql security definer set search_path = ''
as $$
declare
  member_count integer;
begin
  select count(*) into member_count from public.memberships where memberships.org_id = org_headcount.org_id;
  return member_count;
end;
$$;

-- Control: the same count behind a membership check. The owner's call is accepted, the attacker's refused.
create function public.my_org_headcount(p_org_id uuid) returns integer
language plpgsql security definer set search_path = ''
as $$
begin
  if not exists (select 1 from private.my_orgs o where o.org_id = p_org_id) then
    raise exception 'not a member of this organization';
  end if;
  return (select count(*) from public.memberships m where m.org_id = p_org_id);
end;
$$;
revoke execute on function public.my_org_headcount(uuid) from public, anon;
grant execute on function public.my_org_headcount(uuid) to authenticated;

-- Control: the answer does not depend on the organization (a plan default).
create function public.org_seat_limit(p_org_id uuid) returns integer
language sql stable security definer set search_path = ''
as $$ select 25 $$;
revoke execute on function public.org_seat_limit(uuid) from public, anon;
grant execute on function public.org_seat_limit(uuid) to authenticated;

-- Control: a different answer every time (a sample), whatever the id.
create function public.org_sample_size(p_org_id uuid) returns integer
language sql volatile security definer set search_path = ''
as $$ select (random() * 1000000)::integer $$;
revoke execute on function public.org_sample_size(uuid) from public, anon;
grant execute on function public.org_sample_size(uuid) to authenticated;
