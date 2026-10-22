-- ============================================================
-- Branchly update_4: سجل النشاط (Audit log) — للأدمن فقط
-- شغّله مرة واحدة في Supabase SQL Editor (آمن لإعادة التشغيل)
-- ============================================================
create table if not exists public.audit_log (
  id         bigserial primary key,
  at         timestamptz not null default now(),
  actor      uuid,
  actor_name text default '',
  tbl        text not null,
  op         text not null,
  row_id     text,
  summary    text default '',
  old_data   jsonb,
  new_data   jsonb
);
create index if not exists audit_at_idx on public.audit_log (at desc);
alter table public.audit_log enable row level security;
drop policy if exists audit_read on public.audit_log;
create policy audit_read on public.audit_log for select to authenticated using (public.is_admin());
revoke all on public.audit_log from anon, authenticated;
grant select on public.audit_log to authenticated;

create or replace function public.audit_trg()
returns trigger language plpgsql security definer set search_path = public as $$
declare o jsonb; n jsonb; sm text := ''; an text := '';
begin
  if tg_op in ('UPDATE','DELETE') then o := to_jsonb(old); end if;
  if tg_op in ('INSERT','UPDATE') then n := to_jsonb(new); end if;
  if tg_op = 'UPDATE' and o = n then return null; end if;
  sm := case tg_table_name
    when 'reports'         then coalesce(n->>'type', o->>'type', '') || ' · ' || coalesce(n->>'report_date', o->>'report_date', '')
    when 'tasks'           then coalesce(n->>'title', o->>'title', '')
    when 'profiles'        then coalesce(n->>'username', o->>'username', '')
    when 'positions'       then coalesce(n->>'label', o->>'label', '')
    when 'groups'          then coalesce(n->>'name', o->>'name', '')
    when 'checklist_items' then coalesce(n->>'title', o->>'title', '')
    when 'branch_invites'  then 'دعوة'
    when 'settings'        then 'إعدادات المنصة'
    else '' end;
  if tg_table_name = 'settings' then o := null; n := null; end if;
  select name into an from public.profiles where id = auth.uid();
  insert into public.audit_log (actor, actor_name, tbl, op, row_id, summary, old_data, new_data)
  values (auth.uid(), coalesce(an, ''), tg_table_name, tg_op,
          coalesce((case when n is not null then n->>'id' end), (case when o is not null then o->>'id' end)),
          left(sm, 200), o, n);
  return null;
end $$;
revoke execute on function public.audit_trg() from public, anon, authenticated;

do $$
declare t text;
begin
  foreach t in array array['reports','tasks','profiles','positions','groups','checklist_items','branch_invites','settings'] loop
    if to_regclass('public.' || t) is not null then
      execute format('drop trigger if exists audit_%1$s on public.%1$s', t);
      execute format('create trigger audit_%1$s after insert or update or delete on public.%1$s for each row execute function public.audit_trg()', t);
    end if;
  end loop;
end $$;

-- حذف السجلات الأقدم من عدد أيام (للأدمن)
create or replace function public.purge_audit(p_days int default 180)
returns int language plpgsql security definer set search_path = public as $$
declare n int;
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  delete from public.audit_log where at < now() - make_interval(days => greatest(p_days, 7));
  get diagnostics n = row_count;
  return n;
end $$;
revoke execute on function public.purge_audit(int) from public, anon;
grant  execute on function public.purge_audit(int) to authenticated;
