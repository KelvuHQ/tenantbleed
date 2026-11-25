-- Second batch of planted bugs: functions that write, and Storage buckets.
-- Every planted bug is tagged with "PLANTED". Everything else is meant to be correct.

-- ---------------------------------------------------------------- functions that write
-- PLANTED: security definer, renames any document by id, never checks the caller.
create function public.rename_document(d uuid, new_title text) returns void
language sql security definer volatile set search_path = ''
as $$
  update public.documents set title = new_title where id = d
$$;

-- Correct: same shape, but refuses documents of orgs the caller is not a member of.
create function public.archive_document(d uuid) returns void
language plpgsql security definer volatile set search_path = ''
as $$
begin
  if not exists (
    select 1 from public.documents x where x.id = d and public.is_member(x.org_id)
  ) then
    raise exception 'not allowed';
  end if;
  update public.documents set body = coalesce(body, '') || ' [archived]' where id = d;
end
$$;
revoke execute on function public.archive_document(uuid) from anon;

-- ---------------------------------------------------------------- storage
-- Convention used by both private buckets: files live under "<user id>/...".
insert into storage.buckets (id, name, public) values
  ('attachments', 'attachments', false),
  ('receipts', 'receipts', false),
  ('avatars', 'avatars', true);

-- receipts (correct): every operation is limited to the caller's own folder.
create policy receipts_select on storage.objects for select to authenticated
  using (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);
create policy receipts_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);
create policy receipts_update on storage.objects for update to authenticated
  using (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);
create policy receipts_delete on storage.objects for delete to authenticated
  using (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);

-- PLANTED: attachments checks the folder on upload, but read and delete only check the bucket,
-- so any signed-in user can download and delete everyone's attachments.
create policy attachments_select on storage.objects for select to authenticated
  using (bucket_id = 'attachments');
create policy attachments_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'attachments' and (storage.foldername(name))[1] = auth.uid()::text);
create policy attachments_delete on storage.objects for delete to authenticated
  using (bucket_id = 'attachments');

-- avatars (public by design): anyone can view, users write only their own folder.
create policy avatars_insert on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);
create policy avatars_update on storage.objects for update to authenticated
  using (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

-- ---------------------------------------------------------------- graphql
-- Off by default on new Supabase projects. Turned on here so the GraphQL probe has something to
-- test: /graphql/v1 applies the same RLS as the REST API, so the same leaks must show up there.
create extension if not exists pg_graphql;
