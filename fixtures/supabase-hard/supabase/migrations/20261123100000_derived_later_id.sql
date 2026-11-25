-- args/blank-id-compare on a later id: a count about any job, no caller check (planted). The argument
-- name says nothing about which table it takes, so the first ids tried (a studio, a session) count 0,
-- the same as an id that exists nowhere; only the victim's job id gives their real count.
create function public.job_result_count(p_ref uuid) returns integer
language sql stable security definer set search_path = '' as $$
  select count(*)::integer from public.studio_job_results where job_id = p_ref
$$;
