-- A read a policy opens once a parent is in a normal state (shape from a field-test app, names
-- changed): a booking is readable to everyone while its listing is "live", and the booking carries
-- the guest's id and a note. The world leaves the listing a draft, so the "live" branch never fires
-- and the leak is missed. Setting the victim's listing live must prove the read. The control twin
-- has the same shape with the second policy using (false) and must stay clean.
create type public.stay_state as enum ('draft', 'live');
create table public.stay_listings (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title text not null,
  state public.stay_state not null default 'draft'
);
create table public.stay_bookings (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid not null references public.stay_listings(id) on delete cascade,
  guest_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  guest_email text not null
);
alter table public.stay_listings enable row level security;
alter table public.stay_bookings enable row level security;
create policy stay_listings_own on public.stay_listings for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy stay_listings_live on public.stay_listings for select using (state = 'live');
create policy stay_bookings_own on public.stay_bookings for select to authenticated using (guest_id = auth.uid());
create policy stay_bookings_insert on public.stay_bookings for insert to authenticated with check (guest_id = auth.uid());
-- PLANTED: whole booking rows readable while the listing is live.
create policy stay_bookings_live on public.stay_bookings for select to authenticated
  using (exists (select 1 from public.stay_listings l where l.id = listing_id and l.state = 'live'));

-- Control: the same shape, second policy using (false). Must stay clean.
create table public.hall_listings (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  title text not null,
  state public.stay_state not null default 'draft'
);
create table public.hall_bookings (
  id uuid primary key default gen_random_uuid(),
  listing_id uuid not null references public.hall_listings(id) on delete cascade,
  guest_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  guest_email text not null
);
alter table public.hall_listings enable row level security;
alter table public.hall_bookings enable row level security;
create policy hall_listings_own on public.hall_listings for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy hall_listings_live on public.hall_listings for select using (state = 'live');
create policy hall_bookings_own on public.hall_bookings for select to authenticated using (guest_id = auth.uid());
create policy hall_bookings_insert on public.hall_bookings for insert to authenticated with check (guest_id = auth.uid());
create policy hall_bookings_never on public.hall_bookings for select to authenticated using (false);
