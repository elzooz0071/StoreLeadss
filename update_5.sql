-- ============================================================
-- Branchly update_5: مسح البيانات (للأدمن فقط) — نهائي ولا يمكن التراجع عنه
-- شغّله مرة واحدة في Supabase SQL Editor (آمن لإعادة التشغيل)
-- يعمل من زر «إدارة البيانات» داخل التطبيق، ويمكن تشغيله مباشرة أيضاً:
--   select public.admin_wipe_data('all', 'مسح');   -- كل شيء ما عدا حساب الأدمن
--   select public.admin_wipe_data('ops', 'مسح');   -- البيانات التشغيلية فقط
-- ملاحظة: ملفات المرفقات في Storage لا تُحذف من SQL (Supabase يمنع ذلك)؛ زر التطبيق يحذفها عبر الـ API.
-- ============================================================
create or replace function public.admin_wipe_data(p_scope text, p_confirm text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  n jsonb := '{}'::jsonb; c int; me uuid := auth.uid(); an text;
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  if p_confirm is distinct from 'مسح' then raise exception 'confirmation text mismatch'; end if;
  if p_scope not in ('ops', 'all') then raise exception 'bad scope'; end if;
  select name into an from public.profiles where id = me;

  -- البيانات التشغيلية
  if to_regclass('public.task_status')     is not null then delete from public.task_status;     get diagnostics c = row_count; n := n || jsonb_build_object('task_status', c); end if;
  delete from public.tasks;                get diagnostics c = row_count; n := n || jsonb_build_object('tasks', c);
  delete from public.reports;              get diagnostics c = row_count; n := n || jsonb_build_object('reports', c);
  delete from public.check_runs;           get diagnostics c = row_count; n := n || jsonb_build_object('check_runs', c);
  delete from public.inventory_items;      get diagnostics c = row_count; n := n || jsonb_build_object('inventory_items', c);
  delete from public.inventory_meta;       get diagnostics c = row_count; n := n || jsonb_build_object('inventory_meta', c);
  delete from public.notifications;        get diagnostics c = row_count; n := n || jsonb_build_object('notifications', c);

  -- كل شيء ما عدا حسابات الأدمن
  if p_scope = 'all' then
    delete from public.branch_invites;     get diagnostics c = row_count; n := n || jsonb_build_object('branch_invites', c);
    delete from public.checklist_items;    get diagnostics c = row_count; n := n || jsonb_build_object('checklist_items', c);
    if to_regclass('public.groups') is not null then
      update public.profiles set group_id = null where group_id is not null;
      delete from public.groups;           get diagnostics c = row_count; n := n || jsonb_build_object('groups', c);
    end if;
    delete from public.positions where not builtin;
    get diagnostics c = row_count; n := n || jsonb_build_object('positions', c);
    delete from auth.users where id in (select id from public.profiles where role <> 'admin');
    get diagnostics c = row_count; n := n || jsonb_build_object('users', c);
  end if;

  -- تنظيف سجل النشاط (التريجرات سجّلت عمليات الحذف نفسها) ثم تسجيل عملية المسح
  if to_regclass('public.audit_log') is not null then
    delete from public.audit_log;
    insert into public.audit_log (actor, actor_name, tbl, op, row_id, summary, new_data)
    values (me, coalesce(an, ''), 'system', 'WIPE', null, 'مسح بيانات (' || p_scope || ')', n);
  end if;
  return n;
end $$;
revoke execute on function public.admin_wipe_data(text, text) from public, anon;
grant  execute on function public.admin_wipe_data(text, text) to authenticated;
