-- Table order: tables that point at each other through optional links (an offer belongs to a
-- gig or a draft; a gig remembers the offer it came from; a draft remembers the gig it became), copied
-- from a field-test app, names changed. The offer's check rule needs one of its parents set, so the
-- parents must be built first even though the gig links back to the offer. Built the other way round,
-- the offer row could only be written with its rule paused, and every function that updates it then
-- fails on that rule. An offer on a draft is refused by the app's own trigger (the draft must be
-- approved), so the row is retried with its optional links empty, and the check rule then needs one
-- link filled again from the tenant's own gig (check/parent-link).
-- Read policy on offers open (planted); the recalculation has no caller check.
create table public.studio_gigs (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  title text not null
);

create table public.studio_drafts (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  converted_gig_id uuid references public.studio_gigs(id) on delete set null,
  title text not null
);

create table public.studio_offers (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  gig_id uuid references public.studio_gigs(id) on delete set null,
  draft_id uuid references public.studio_drafts(id) on delete set null,
  total numeric(12,2) not null default 0,
  priced_at timestamptz
);
alter table public.studio_offers add constraint studio_offers_has_gig_or_draft check (gig_id is not null or draft_id is not null);

alter table public.studio_gigs add column origin_offer_id uuid references public.studio_offers(id) on delete set null;

alter table public.studio_gigs enable row level security;
alter table public.studio_drafts enable row level security;
alter table public.studio_offers enable row level security;
create policy studio_gigs_own on public.studio_gigs for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
create policy studio_drafts_own on public.studio_drafts for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));
create policy studio_offers_read on public.studio_offers for select to authenticated using (true);
create policy studio_offers_write on public.studio_offers for insert to authenticated
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.recalc_offer_total(p_offer_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.studio_offers set total = total + 1, priced_at = now() where id = p_offer_id;
end;
$$;

create function public.studio_offer_needs_approved_draft() returns trigger
language plpgsql as $$
begin
  if new.draft_id is not null then
    raise exception 'The draft must be approved before an offer can be made';
  end if;
  return new;
end;
$$;
create trigger studio_offers_draft_rule before insert on public.studio_offers for each row execute function public.studio_offer_needs_approved_draft();
