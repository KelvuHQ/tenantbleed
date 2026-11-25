-- args/row-state and owner-control/row-state: writes that only act on rows in a given state (a payout
-- still pending, credits above zero), copied from field-test apps, names changed. Fresh test rows sit
-- in the default state, so the write matched nothing for anyone, the owner included, and the function
-- was left not tested. The scan puts the victim's row in that state inside the rolled-back transaction
-- and calls again. settle_studio_payout and use_studio_credit have no caller check (planted);
-- cancel_studio_payout checks the caller, so it must end as tested, by the owner's call.
create table public.studio_payouts (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  status text not null default 'draft' check (status in ('draft', 'pending', 'paid', 'cancelled')),
  paid_at timestamptz
);
alter table public.studio_payouts enable row level security;
create policy studio_payouts_own on public.studio_payouts for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create table public.studio_credits (
  id uuid primary key default gen_random_uuid(),
  studio_id uuid not null references public.studios(id) on delete cascade,
  credits integer not null default 0
);
alter table public.studio_credits enable row level security;
create policy studio_credits_own on public.studio_credits for all to authenticated
  using (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()))
  with check (exists (select 1 from public.studios s where s.id = studio_id and s.created_by = auth.uid()));

create function public.settle_studio_payout(p_payout_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.studio_payouts set status = 'paid', paid_at = now()
  where id = p_payout_id and status = 'pending' and paid_at is null;
end;
$$;

create function public.use_studio_credit(p_studio_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.studio_credits set credits = credits - 1 where studio_id = p_studio_id and credits > 0;
end;
$$;

create function public.cancel_studio_payout(p_payout_id uuid) returns void
language plpgsql security definer set search_path = '' as $$
begin
  update public.studio_payouts p set status = 'cancelled'
  where p.id = p_payout_id and p.status = 'pending'
    and exists (select 1 from public.studios s where s.id = p.studio_id and s.created_by = auth.uid());
end;
$$;
