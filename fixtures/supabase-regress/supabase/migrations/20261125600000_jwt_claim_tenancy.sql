-- Spec 09b step 1: tenancy carried by a JWT claim, not a foreign key.
-- The policy scopes rows by an org id read from the token ((auth.jwt() ->> 'org_id')::uuid = org_id).
-- There is no person foreign key and no auth.uid() comparison, so attribution finds no owner and the
-- table used to be filed as "shared" (a false all-clear). tenantbleed must instead classify it as
-- tenant-scoped through a claim it does not mint: not attacked, but not shared and not a silent gap.
-- (Minting the claim to actually attack it is step 2, kept separate because it is the risky part.)

create table public.tenant_records (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null,
  body text not null
);
alter table public.tenant_records enable row level security;
-- The org id comes from the JWT. In a real app it must be set from app_metadata (server-controlled).
create policy tenant_records_by_claim on public.tenant_records for all to authenticated
  using ((auth.jwt() ->> 'org_id')::uuid = org_id)
  with check ((auth.jwt() ->> 'org_id')::uuid = org_id);
grant select, insert, update, delete on public.tenant_records to authenticated;
