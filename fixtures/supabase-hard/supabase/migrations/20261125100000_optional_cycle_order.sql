-- A circle of optional links over several tables (shape from field-test apps, names changed): a board
-- has an optional cover file, a file an optional card, a card an optional column; cards and columns
-- need their board. Following every link put cards before the board they need, so cards and
-- columns got no test data. Both must be filled; the read policy on cards is open (planted).
create table public.deck_boards (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  cover_file_id uuid
);
create table public.deck_files (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users(id) on delete cascade,
  name text not null,
  card_id uuid
);
create table public.deck_cards (
  id uuid primary key default gen_random_uuid(),
  board_id uuid not null references public.deck_boards(id) on delete cascade,
  body text not null,
  column_id uuid
);
create table public.deck_columns (
  id uuid primary key default gen_random_uuid(),
  board_id uuid not null references public.deck_boards(id) on delete cascade,
  label text not null
);
alter table public.deck_boards add foreign key (cover_file_id) references public.deck_files(id) on delete set null;
alter table public.deck_files add foreign key (card_id) references public.deck_cards(id) on delete set null;
alter table public.deck_cards add foreign key (column_id) references public.deck_columns(id) on delete set null;

alter table public.deck_boards enable row level security;
alter table public.deck_files enable row level security;
alter table public.deck_cards enable row level security;
alter table public.deck_columns enable row level security;
create policy deck_boards_own on public.deck_boards for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy deck_files_own on public.deck_files for all to authenticated using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy deck_columns_own on public.deck_columns for all to authenticated
  using (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()))
  with check (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()));
create policy deck_cards_read on public.deck_cards for select to authenticated using (true);
create policy deck_cards_write on public.deck_cards for insert to authenticated
  with check (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()));

-- A parent that only a later table's trigger creates: a board's stats row carries a signature of the
-- board id that only the app computes, and is made when a tag is added; a stats log needs the stats
-- row. The stats and the log come before the tag in build order; both must still be filled.
create table public.deck_stats (
  board_id uuid primary key references public.deck_boards(id) on delete cascade,
  signature text not null check (signature = encode(extensions.digest(board_id::text, 'sha256'), 'hex')),
  tags integer not null default 0
);
create function public.deck_tags_count() returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.deck_stats (board_id, signature, tags)
  values (new.board_id, encode(extensions.digest(new.board_id::text, 'sha256'), 'hex'), 1)
  on conflict (board_id) do update set tags = public.deck_stats.tags + 1;
  return new;
end;
$$;
create table public.deck_stat_logs (
  id uuid primary key default gen_random_uuid(),
  board_id uuid not null references public.deck_stats(board_id) on delete cascade,
  note text not null
);
create table public.deck_tags (
  id uuid primary key default gen_random_uuid(),
  board_id uuid not null references public.deck_boards(id) on delete cascade,
  label text not null
);
alter table public.deck_tags enable row level security;
create policy deck_tags_own on public.deck_tags for all to authenticated
  using (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()))
  with check (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()));
create trigger deck_tags_count after insert on public.deck_tags for each row execute function public.deck_tags_count();

alter table public.deck_stats enable row level security;
alter table public.deck_stat_logs enable row level security;
create policy deck_stats_own on public.deck_stats for select to authenticated
  using (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()));
create policy deck_stat_logs_own on public.deck_stat_logs for select to authenticated
  using (exists (select 1 from public.deck_boards b where b.id = board_id and b.owner_id = auth.uid()));
