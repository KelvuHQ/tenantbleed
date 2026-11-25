-- Coverage labeling cases (specs 03, 13, 15), all about reporting an untested object honestly.

-- Spec 03: a schema the API does not expose, reachable only through a function. The table is filled
-- so the function can be called, but the API never serves it, so it must be reported "not exposed",
-- not as a coverage gap. (config.toml exposes only public + graphql_public.)
create schema hidden_vault;
grant usage on schema hidden_vault to authenticated;
create table hidden_vault.secrets (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  secret text not null
);
grant select, insert on hidden_vault.secrets to authenticated;
alter table hidden_vault.secrets enable row level security;
create policy hv_own on hidden_vault.secrets for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create function public.my_secret_count() returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from hidden_vault.secrets where owner_id = auth.uid()
$$;

-- Spec 15: a unique text column with a constant default. Both tenants would insert '' and the second
-- would collide, leaving its child without a parent. The tag column is filled per tenant, and on a
-- real collision the existing row is adopted; the child must get test data for both tenants.
create table public.label_tags (
  id bigint generated always as identity primary key,
  tag text not null default '' unique,
  name text not null
);
create table public.label_links (
  id uuid primary key default gen_random_uuid(),
  tag_id bigint not null references public.label_tags(id) on delete cascade,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  note text not null
);
alter table public.label_tags enable row level security;
alter table public.label_links enable row level security;
create policy label_tags_read on public.label_tags for select to authenticated using (true);
create policy label_tags_write on public.label_tags for insert to authenticated with check (true);
create policy label_links_own on public.label_links for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());

-- Spec 14: a two-party row (a direct chat) between two people. Built between the two test users it
-- would belong to neither and the table would look "shared"; built between a tenant and a bystander
-- it belongs to the tenant, and the other tenant reading it is a real cross-tenant read (planted).
create table public.direct_chats (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  member_id uuid not null references auth.users(id) on delete cascade,
  body text not null,
  check (owner_id <> member_id)
);
alter table public.direct_chats enable row level security;
-- PLANTED: meant to be "the two people in the chat", written as every signed-in user.
create policy direct_chats_read on public.direct_chats for select to authenticated using (true);
create policy direct_chats_write on public.direct_chats for insert to authenticated with check (owner_id = auth.uid());

-- Spec 02: a user table the app never ties to auth.users with a foreign key (the server writes the
-- row with the auth id as text); a policy compares its key to the caller. Without recognizing it,
-- everything below it is "shared" and never attacked. With it, tenants own their firms and the
-- other tenant attacks their invoices (planted leak); the firm-scoped receipts must stay clean.
create table public.svc_members (id text primary key, email text not null);
create table public.svc_firms (id uuid primary key default gen_random_uuid(), name text not null);
create table public.svc_firm_members (
  member_id text not null references public.svc_members(id) on delete cascade,
  firm_id uuid not null references public.svc_firms(id) on delete cascade,
  primary key (member_id, firm_id)
);
create table public.svc_invoices (id uuid primary key default gen_random_uuid(), firm_id uuid not null references public.svc_firms(id) on delete cascade, total numeric not null);
create table public.svc_receipts (id uuid primary key default gen_random_uuid(), firm_id uuid not null references public.svc_firms(id) on delete cascade, amount numeric not null);
alter table public.svc_members enable row level security;
alter table public.svc_firms enable row level security;
alter table public.svc_firm_members enable row level security;
alter table public.svc_invoices enable row level security;
alter table public.svc_receipts enable row level security;
create policy svc_members_self on public.svc_members for all to authenticated using (id = auth.uid()::text) with check (id = auth.uid()::text);
create policy svc_fm_mine on public.svc_firm_members for all to authenticated using (member_id = auth.uid()::text) with check (member_id = auth.uid()::text);
create policy svc_firms_mine on public.svc_firms for all to authenticated
  using (id in (select firm_id from public.svc_firm_members where member_id = auth.uid()::text))
  with check (id in (select firm_id from public.svc_firm_members where member_id = auth.uid()::text));
-- PLANTED leak: every signed-in user reads every invoice.
create policy svc_invoices_leak on public.svc_invoices for select to authenticated using (auth.uid() is not null);
create policy svc_invoices_write on public.svc_invoices for insert to authenticated with check (firm_id in (select firm_id from public.svc_firm_members where member_id = auth.uid()::text));
-- Clean control: receipts are firm-scoped.
create policy svc_receipts_ok on public.svc_receipts for all to authenticated
  using (firm_id in (select firm_id from public.svc_firm_members where member_id = auth.uid()::text))
  with check (firm_id in (select firm_id from public.svc_firm_members where member_id = auth.uid()::text));

-- Spec 02c: a person column with no foreign key at all, compared to the caller in the table's policy.
create table public.svc_inbox (id uuid primary key default gen_random_uuid(), recipient uuid not null, body text not null);
alter table public.svc_inbox enable row level security;
create policy svc_inbox_own on public.svc_inbox for select to authenticated using (recipient = auth.uid());
-- PLANTED leak: any signed-in user reads any inbox row (the row is owned via its no-FK recipient).
create policy svc_inbox_leak on public.svc_inbox for select to authenticated using (true);

-- Spec 09a: a tenant column with no foreign key, scoped through a membership subquery. Without the
-- inferred link the table has no owner and is judged "shared"; with it the row belongs to the
-- tenant, so the planted open read is a real cross-tenant read. The membership-scoped control stays
-- clean.
create table public.orgs2 (id uuid primary key default gen_random_uuid(), name text not null);
create table public.org_memberships2 (
  org_id uuid not null references public.orgs2(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  primary key (org_id, user_id)
);
create table public.org_events (id uuid primary key default gen_random_uuid(), org_id uuid not null, detail text not null);
create table public.org_reports (id uuid primary key default gen_random_uuid(), org_id uuid not null, body text not null);
alter table public.orgs2 enable row level security;
alter table public.org_memberships2 enable row level security;
alter table public.org_events enable row level security;
alter table public.org_reports enable row level security;
create policy orgs2_member on public.orgs2 for all to authenticated using (id in (select m.org_id from public.org_memberships2 m where m.user_id = auth.uid())) with check (id in (select m.org_id from public.org_memberships2 m where m.user_id = auth.uid()));
create policy om2_self on public.org_memberships2 for all to authenticated using (user_id = auth.uid()) with check (user_id = auth.uid());
-- org_events: scoped by membership, PLUS a planted open read.
create policy events_member on public.org_events for insert to authenticated with check (org_id in (select m.org_id from public.org_memberships2 m where m.user_id = auth.uid()));
create policy events_leak on public.org_events for select to authenticated using (true);
-- Clean control: membership-scoped only.
create policy reports_member on public.org_reports for all to authenticated
  using (org_id in (select m.org_id from public.org_memberships2 m where m.user_id = auth.uid()))
  with check (org_id in (select m.org_id from public.org_memberships2 m where m.user_id = auth.uid()));

-- Spec 18b: shared tables (no link from their rows to a user) that are open to everyone or every
-- signed-in user. Today they are only counted as "shared by design"; now they get a report line.
create table public.shared_contacts (id uuid primary key default gen_random_uuid(), name text not null, phone text, email text);
create table public.shared_leads (id uuid primary key default gen_random_uuid(), company text not null, contact_email text, contact_phone text);
create table public.shared_regions (id uuid primary key default gen_random_uuid(), code text not null, label text not null);
alter table public.shared_contacts enable row level security;
alter table public.shared_leads enable row level security;
alter table public.shared_regions enable row level security;
-- contacts: every signed-in user can read and change it -> shared-open-write (medium).
create policy contacts_read on public.shared_contacts for select to authenticated using (true);
create policy contacts_write on public.shared_contacts for update to authenticated using (true) with check (true);
-- leads: a visitor can read it, and it holds contact details -> shared-anon-read (high).
create policy leads_anon on public.shared_leads for select to anon using (true);
-- regions: a public catalog, read-only, no personal columns -> no new line (control).
create policy regions_read on public.shared_regions for select to authenticated using (true);

-- A shared table any visitor can write -> shared-open-write (high).
create table public.shared_guestbook (id uuid primary key default gen_random_uuid(), author_email text, message text not null);
alter table public.shared_guestbook enable row level security;
create policy guestbook_anon_write on public.shared_guestbook for insert to anon with check (true);
create policy guestbook_read on public.shared_guestbook for select to authenticated using (true);
