-- static/definer-exec-arg: helpers that run SQL text the caller sends, as their owner (copied from
-- field-test apps, names changed). Callable through the API, so anyone runs any statement and every
-- policy is skipped. Planted: the text itself, and the text glued into a statement.
create function public.run_admin_sql(sql_query text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  execute sql_query;
  return jsonb_build_object('success', true);
exception when others then
  return jsonb_build_object('success', false, 'error', sqlerrm);
end;
$$;
create function public.count_where(p_table text, p_filter text) returns bigint
language plpgsql security definer set search_path = '' as $$
declare n bigint;
begin
  execute format('select count(*) from public.%I', p_table) || ' where ' || p_filter into n;
  return n;
end;
$$;
-- Control: the table name is quoted (%I) and the value is bound (USING): nothing the caller sends runs as SQL.
create function public.count_rows_in(p_table text, p_studio uuid) returns bigint
language plpgsql security definer set search_path = '' as $$
declare n bigint;
begin
  execute format('select count(*) from public.%I where studio_id = $1', p_table) into n using p_studio;
  return n;
end;
$$;
