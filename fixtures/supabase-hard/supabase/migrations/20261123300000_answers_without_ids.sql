-- owner-control/victim-removal: functions that take no id, so no call can be aimed at a victim and
-- the blank-id compare has nothing to blank (copied from field-test apps, names changed).
-- A total over every studio's sessions (planted): its answer changes when the victim's rows are
-- gone, so it tells any caller something about them.
create function public.all_studio_session_total() returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from public.studio_sessions
$$;
-- Control: the caller's own studios only. The same answer with or without the victim's rows: tested.
create function public.my_studio_total() returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from public.studios where created_by = auth.uid()
$$;
