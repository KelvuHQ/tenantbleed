-- static/definer-security-ddl: test helpers that switch a table's row level security off, or drop a
-- policy, for any caller (copied from a field-test app, names changed). The table name is quoted, so
-- no SQL comes from the caller, but the statement itself removes the isolation.
create function public.toggle_rls_for_tests(table_name text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  execute format('alter table public.%I disable row level security', table_name);
  return jsonb_build_object('success', true);
end;
$$;
create function public.reset_policy_for_tests(table_name text, policy_name text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  execute format('drop policy if exists %I on public.%I', policy_name, table_name);
end;
$$;
-- Control: the same switch behind an admin check on the caller.
create table public.platform_operators (user_id uuid primary key references auth.users(id));
alter table public.platform_operators enable row level security;
create function public.operator_toggle_rls(table_name text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.platform_operators where user_id = auth.uid()) then
    raise exception 'operators only';
  end if;
  execute format('alter table public.%I disable row level security', table_name);
end;
$$;
