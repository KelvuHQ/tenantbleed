-- Functions whose risk is outside the database, copied from field-test apps (names changed). The
-- scan cannot follow an HTTP request or tell a secret from data, so a schema check states the risk;
-- the warnings are flagged, never left untested. The key below is a fake built for this fixture
-- (role service_role, no valid signature), and the URL is a dead local port: nothing leaves the machine.
create extension if not exists http with schema extensions;

-- static/definer-http (critical with a service role key): anyone can make the database delete any
-- stored file, as the service role.
create function public.remove_stored_file(bucket text, object text, out status int, out content text)
language plpgsql security definer set search_path = ''
as $$
declare
  project_url text := 'http://127.0.0.1:9';
  service_role_key text := 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ0ZW5hbnRwcm9vZi1maXh0dXJlIiwicm9sZSI6InNlcnZpY2Vfcm9sZSJ9.fixture-signature-not-a-key';
  url text := project_url || '/storage/v1/object/' || bucket || '/' || object;
begin
  select into status, content result.status::int, result.content::text
  from extensions.http((
    'DELETE', url,
    array[extensions.http_header('authorization', 'Bearer ' || service_role_key)],
    null, null
  )::extensions.http_request) as result;
end;
$$;

-- static/definer-vault: hands a vault secret to any caller.
create function public.app_base_url() returns text
language plpgsql security definer set search_path = ''
as $$
declare
  secret_value text;
begin
  select decrypted_secret into secret_value from vault.decrypted_secrets where name = 'app_base_url';
  return secret_value;
end;
$$;

-- world/cron-paused: a job that runs every minute, as field-test apps schedule calls to their hosted
-- Edge Functions. The scan pauses the app's scheduled jobs while it runs and turns them back on after,
-- so a job can neither change the test data mid-scan nor send requests on a customer's machine.
create extension if not exists pg_cron;
select cron.schedule('tp-fixture-every-minute', '* * * * *', $$ update public.api_stats set updated_at = now() $$);
