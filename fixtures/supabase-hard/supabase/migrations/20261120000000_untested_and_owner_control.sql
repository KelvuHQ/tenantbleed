-- Cases from the 2026-11-20 field run: the 22 warnings that could not be tested, and the owner
-- control call (repeat a failed attack as the rightful owner to tell "checks the caller" from
-- "our test values reached nothing"). Shapes copied from real apps, names changed.

-- ---------------------------------------------------------------- T1: a binary primary key with a zero byte
-- (task app) Before the fix the scan turned the raw bytes into text and every before/after snapshot
-- failed with "invalid byte sequence for encoding UTF8: 0x00", so no function that writes was called.
create table public.email_receipts (
  key_hash bytea primary key,
  owner_id uuid not null references auth.users(id) on delete cascade
);
create function public.set_receipt_hash() returns trigger
language plpgsql set search_path = ''
as $$
begin
  new.key_hash := '\x00'::bytea || decode(md5(random()::text), 'hex');
  return new;
end;
$$;
create trigger email_receipts_hash before insert on public.email_receipts for each row execute function public.set_receipt_hash();
alter table public.email_receipts enable row level security;
revoke all on public.email_receipts from anon, authenticated;
create policy email_receipts_service on public.email_receipts for all to service_role using (true) with check (true);

create table public.time_entries (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  note text not null default 'work',
  started_at timestamptz not null default now()
);
alter table public.time_entries enable row level security;
create policy time_entries_own on public.time_entries for select to authenticated using (user_id = auth.uid());
create function public.time_entry_start(p_note text) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare v_id uuid;
begin
  if auth.uid() is null then raise exception 'authentication required'; end if;
  insert into public.time_entries (user_id, note) values (auth.uid(), p_note) returning id into v_id;
  return v_id;
end;
$$;
revoke all on function public.time_entry_start(text) from public, anon;
grant execute on function public.time_entry_start(text) to authenticated;

-- ---------------------------------------------------------------- T2: permissions kept in the app's own tables
-- (accounting app) A member needs a role whose permissions include the code the function asks for.
-- The test users had a membership but a role with no permissions, so every call was refused, even
-- the owner's own, and the warnings said "could not build its arguments".
create schema acct;
create schema acct_private;
create table acct.organizations (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique
);
create table acct.organization_members (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references acct.organizations(id) on delete restrict,
  user_id uuid references auth.users(id) on delete set null,
  display_name_snapshot text not null,
  status text not null default 'active' check (status in ('active', 'inactive')),
  unique (organization_id, id),
  unique (organization_id, user_id),
  check (status <> 'active' or user_id is not null)
);
create table acct.permissions (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  description text not null default ''
);
insert into acct.permissions (code, description) values
  ('company.read', 'Read company settings'),
  ('users.read', 'Read members and roles'),
  ('users.manage', 'Manage members and roles');
create table acct.roles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references acct.organizations(id) on delete restrict,
  name text not null,
  template_key text,
  is_system boolean not null default false,
  unique (organization_id, id),
  unique (organization_id, name)
);
create table acct.role_permissions (
  organization_id uuid not null references acct.organizations(id) on delete restrict,
  role_id uuid not null,
  permission_id uuid not null references acct.permissions(id) on delete restrict,
  primary key (organization_id, role_id, permission_id),
  foreign key (organization_id, role_id) references acct.roles (organization_id, id) on delete restrict
);
create table acct.member_roles (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references acct.organizations(id) on delete restrict,
  member_id uuid not null,
  role_id uuid not null,
  unique (organization_id, id),
  foreign key (organization_id, member_id) references acct.organization_members (organization_id, id) on delete restrict,
  foreign key (organization_id, role_id) references acct.roles (organization_id, id) on delete restrict,
  unique (organization_id, member_id, role_id)
);
create table acct.invitations (
  id uuid primary key default gen_random_uuid(),
  organization_id uuid not null references acct.organizations(id) on delete restrict,
  email_normalized text not null,
  status text not null default 'pending' check (status in ('pending', 'accepted', 'revoked'))
);

-- As in the real app: the API roles may use the schemas and read the tables, but the API does not serve them.
grant usage on schema acct, acct_private to authenticated;
grant select on acct.organizations, acct.organization_members, acct.permissions, acct.roles, acct.role_permissions, acct.member_roles to authenticated;
alter table acct.organizations enable row level security;
alter table acct.organization_members enable row level security;
alter table acct.permissions enable row level security;
alter table acct.roles enable row level security;
alter table acct.role_permissions enable row level security;
alter table acct.member_roles enable row level security;
alter table acct.invitations enable row level security;

create function acct_private.member_has_capability(p_organization_id uuid, p_member_id uuid, p_permission_code text) returns boolean
language sql stable security definer set search_path = ''
as $$
  select exists (
    select 1
    from acct.organization_members m
    join acct.member_roles mr on mr.organization_id = m.organization_id and mr.member_id = m.id
    join acct.role_permissions rp on rp.organization_id = mr.organization_id and rp.role_id = mr.role_id
    join acct.permissions p on p.id = rp.permission_id
    where m.organization_id = p_organization_id and m.id = p_member_id and m.status = 'active' and p.code = p_permission_code
  )
$$;
revoke all on function acct_private.member_has_capability(uuid, uuid, text) from public, anon, authenticated;
create function acct_private.require_capability(p_organization_id uuid, p_permission_code text) returns uuid
language plpgsql security definer set search_path = ''
as $$
declare
  v_user_id uuid := auth.uid();
  v_member_id uuid;
begin
  if v_user_id is null then
    raise exception 'authentication required' using errcode = '28000';
  end if;
  select m.id into v_member_id from acct.organization_members m
  where m.organization_id = p_organization_id and m.user_id = v_user_id and m.status = 'active';
  if v_member_id is null then
    raise exception 'permission denied' using errcode = '42501';
  end if;
  if not acct_private.member_has_capability(p_organization_id, v_member_id, p_permission_code) then
    raise exception 'permission denied' using errcode = '42501';
  end if;
  return v_member_id;
end
$$;
revoke all on function acct_private.require_capability(uuid, text) from public, anon, authenticated;

-- Control: checks the permission in the organization it reads.
create function public.list_company_invitations(p_organization_id uuid)
returns table (invitation_id uuid, email text, invitation_status text)
language plpgsql security definer set search_path = ''
as $$
begin
  perform acct_private.require_capability(p_organization_id, 'users.read');
  return query select i.id, i.email_normalized, i.status from acct.invitations i where i.organization_id = p_organization_id order by i.id;
end
$$;
revoke all on function public.list_company_invitations(uuid) from public, anon, authenticated;
grant execute on function public.list_company_invitations(uuid) to authenticated;

-- Planted: checks the permission in the caller's own organization, then reads the one asked for.
create function public.list_company_invitations_v1(p_organization_id uuid)
returns table (invitation_id uuid, email text, invitation_status text)
language plpgsql security definer set search_path = ''
as $$
begin
  perform acct_private.require_capability(
    (select m.organization_id from acct.organization_members m where m.user_id = auth.uid() limit 1), 'users.read');
  return query select i.id, i.email_normalized, i.status from acct.invitations i where i.organization_id = p_organization_id order by i.id;
end
$$;
revoke all on function public.list_company_invitations_v1(uuid) from public, anon, authenticated;
grant execute on function public.list_company_invitations_v1(uuid) to authenticated;

-- ---------------------------------------------------------------- T3: rows the app's own rules make hard to build
-- (content app) A JSON shape that depends on another column, a validation function over a JSON
-- list (2 to 5 options, exactly one recommended), and a trigger that needs the person's profile to
-- name the organization (null until onboarding). The scan's last resort writes its one test row
-- with these rules paused for that insert, and says so; every call it makes afterwards faces them.
create table public.brand_facts (
  id uuid primary key default gen_random_uuid(),
  brand_id uuid not null references public.brands(id) on delete cascade,
  kind text not null check (kind in ('price', 'trial', 'founded')),
  slot text not null check (char_length(slot) between 1 and 300),
  value jsonb not null default '{}'::jsonb check (jsonb_typeof(value) = 'object' and octet_length(value::text) <= 1024),
  source_url text not null check (char_length(source_url) <= 2048 and source_url ~ '^https?://'),
  constraint brand_facts_kind_value_check check (
    coalesce(
      case kind
        when 'price' then
          jsonb_typeof(value -> 'amount') = 'number'
          and (value ->> 'amount')::numeric >= 0
          and coalesce(value ->> 'currency', '') ~ '^[A-Z]{3}$'
          and jsonb_typeof(value -> 'plan') = 'string'
        when 'trial' then
          jsonb_typeof(value -> 'days') = 'number'
          and (value ->> 'days')::numeric between 1 and 365
        when 'founded' then
          jsonb_typeof(value -> 'year') = 'number'
          and (value ->> 'year')::numeric between 1800 and 2100
        else true
      end,
      false
    )
  )
);
alter table public.brand_facts enable row level security;
create policy brand_facts_member on public.brand_facts for select to authenticated
  using (brand_id in (select b.id from public.brands b where public.is_member(b.org_id)));

create function public.ask_options_valid(p_options jsonb) returns boolean
language sql immutable set search_path = ''
as $$
  select case
    when jsonb_typeof(p_options) <> 'array' then false
    when jsonb_array_length(p_options) not between 2 and 5 then false
    else coalesce(
      (
        select bool_and(
            jsonb_typeof(o) = 'object'
            and jsonb_typeof(o -> 'label') = 'string'
            and char_length(o ->> 'label') between 1 and 120
          )
          and count(*) filter (where o -> 'recommended' = 'true'::jsonb) = 1
        from jsonb_array_elements(p_options) as t(o)
      ),
      false
    )
  end;
$$;
create table public.asks (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  question text not null,
  options_json jsonb not null check (public.ask_options_valid(options_json) and octet_length(options_json::text) <= 8000),
  answer_json jsonb check (answer_json is null or (jsonb_typeof(answer_json) = 'object' and octet_length(answer_json::text) <= 4000)),
  answered_at timestamptz,
  check ((answer_json is null) = (answered_at is null))
);
alter table public.asks enable row level security;
create policy asks_own on public.asks for select to authenticated using (user_id = auth.uid());

create table public.team_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  organization_id uuid references public.orgs(id) on delete set null,
  full_name text not null default ''
);
alter table public.team_profiles enable row level security;
create policy team_profiles_own on public.team_profiles for select to authenticated using (id = auth.uid());
create function public.create_team_profile() returns trigger
language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.team_profiles (id) values (new.id) on conflict do nothing;
  return new;
end;
$$;
create trigger on_auth_user_team_profile after insert on auth.users for each row execute function public.create_team_profile();

create table public.brand_access (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  brand_id uuid not null references public.brands(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade
);
create function public.check_brand_access_org() returns trigger
language plpgsql set search_path = ''
as $$
begin
  if not exists (select 1 from public.brands b where b.id = new.brand_id and b.org_id = new.org_id) then
    raise exception 'brand_access: brand % is not in organization %', new.brand_id, new.org_id using errcode = '23514';
  end if;
  if not exists (select 1 from public.team_profiles p where p.id = new.user_id and p.organization_id = new.org_id) then
    raise exception 'brand_access: person % is not in organization %', new.user_id, new.org_id using errcode = '23514';
  end if;
  return new;
end;
$$;
create trigger brand_access_check_org before insert or update on public.brand_access for each row execute function public.check_brand_access_org();
alter table public.brand_access enable row level security;
create policy brand_access_member on public.brand_access for select to authenticated using (public.is_member(org_id));

-- ---------------------------------------------------------------- O1 to O3: the owner control call
-- The guard sits in a helper, so the code check sees no caller check and flags these functions.
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  body text not null default 'note'
);
alter table public.notes enable row level security;
create policy notes_member on public.notes for select to authenticated using (public.is_member(org_id));
-- The caller's organizations, behind a view: the code check reads function bodies, not views.
create view private.my_orgs as select m.org_id from public.memberships m where m.user_id = auth.uid();

-- O1 (settled): the owner's call changes their note, the attacker's identical call changes nothing.
create function public.rename_note(p_note_id uuid, p_body text) returns void
language sql security definer set search_path = ''
as $$ update public.notes set body = p_body where id = p_note_id and org_id in (select org_id from private.my_orgs) $$;

-- O2 (honest "could not test"): needs a code nobody can guess, so even the owner's call does nothing.
create function public.redeem_note_code(p_note_id uuid, p_code text) returns void
language sql security definer set search_path = ''
as $$ update public.notes set body = 'redeemed' where id = p_note_id and md5(p_code) = 'b3f0c7f6bb763af1be91d9e74eabfeb1' and org_id in (select org_id from private.my_orgs) $$;

-- O3 (settled): a read that returns the owner's note and nothing to anyone else.
create function public.get_note(p_note_id uuid) returns setof public.notes
language sql stable security definer set search_path = ''
as $$ select * from public.notes where id = p_note_id and org_id in (select org_id from private.my_orgs) $$;

-- O4 (settled): the permission check passes for the owner and the call then stops on a later rule
-- (the member to deactivate is not found), while the attacker's identical call stops at the check.
-- Same arguments, a different outcome, decided by who is calling (accounting app).
create function public.deactivate_note_member(p_org_id uuid, p_member_user_id uuid) returns void
language plpgsql security definer set search_path = ''
as $$
begin
  if not exists (select 1 from private.my_orgs o where o.org_id = p_org_id) then
    raise exception 'permission denied' using errcode = '42501';
  end if;
  if not exists (select 1 from public.memberships m where m.org_id = p_org_id and m.user_id = p_member_user_id and m.role = 'member') then
    raise exception 'active member not found';
  end if;
  delete from public.memberships where org_id = p_org_id and user_id = p_member_user_id;
end;
$$;

-- T4: JSON columns added later with their own CHECKs, on a table whose kind list was widened
-- (content app). In the field run this table got no test data ("invalid input syntax for type
-- json"); this copy does not reproduce that error (the cause is elsewhere in the app), but it keeps
-- the shape covered: it must get test data.
create table public.note_suggestions (
  id uuid primary key default gen_random_uuid(),
  note_id uuid not null references public.notes(id) on delete cascade,
  batch_id uuid not null,
  agent text not null default 'content_agent' check (agent in ('content_agent')),
  kind text not null check (kind in ('replace', 'insert')),
  block_text text not null check (char_length(block_text) between 1 and 5000),
  before_text text not null default '' check (char_length(before_text) <= 5000),
  after_text text not null check (char_length(after_text) between 1 and 20000),
  reason text not null check (char_length(reason) between 1 and 300),
  rule_keys text[] not null default '{}',
  position integer not null default 0,
  status text not null default 'open' check (status in ('open', 'accepted', 'rejected')),
  check (kind = 'insert' or before_text <> '')
);
alter table public.note_suggestions
  add column if not exists after_links jsonb
    check (after_links is null or (kind = 'replace' and jsonb_typeof(after_links) = 'array'));
alter table public.note_suggestions add column if not exists before_html text;
alter table public.note_suggestions
  drop constraint if exists note_suggestions_kind_check,
  add constraint note_suggestions_kind_check check (kind in ('replace', 'insert', 'page'));
alter table public.note_suggestions
  drop constraint if exists note_suggestions_check,
  add constraint note_suggestions_check check (kind in ('insert', 'page') or before_text <> '');
alter table public.note_suggestions
  add constraint note_suggestions_before_html_check
    check ((kind = 'page') = (before_html is not null) and char_length(coalesce(before_html, '')) <= 500000);
alter table public.note_suggestions
  add column if not exists sources jsonb
    check (sources is null or (jsonb_typeof(sources) = 'array' and jsonb_array_length(sources) between 1 and 8));
alter table public.note_suggestions enable row level security;
create policy note_suggestions_member on public.note_suggestions for select to authenticated
  using (note_id in (select n.id from public.notes n where public.is_member(n.org_id)));
