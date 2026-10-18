-- =====================================================================
-- Branchly — تحديث 2: تخصيص القوائم + الجودة + تقفيل الكاشير + إكسل + السوبر ماركت
-- شغّله مرة واحدة في Supabase > SQL Editor (آمن لو اتشغّل أكتر من مرة)
-- =====================================================================

-- 1) عمود التخصيصات
alter table public.settings add column if not exists custom jsonb not null default '{}';

-- 2) تعديل بنود فحص الجودة (لمن يملك m_quality_edit أو m_settings)
create or replace function public.set_quality_items(items jsonb)
returns void language plpgsql security definer set search_path = public as $$
begin
  if not (public.has_perm('m_quality_edit') or public.has_perm('m_settings')) then
    raise exception 'غير مصرح';
  end if;
  if jsonb_typeof(items) <> 'array' or jsonb_array_length(items) < 1 or jsonb_array_length(items) > 60 then
    raise exception 'قائمة بنود غير صالحة';
  end if;
  update public.settings set custom = jsonb_set(coalesce(custom,'{}'::jsonb), '{qItems}', items, true) where id = 1;
end $$;
revoke all on function public.set_quality_items(jsonb) from public, anon;
grant execute on function public.set_quality_items(jsonb) to authenticated;

-- 3) سياسات التقارير: الصلاحية حسب نوع التقرير
drop policy if exists r_sel on public.reports;
drop policy if exists r_ins on public.reports;
create policy r_sel on public.reports for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_dash','m_reports','m_exec','m_quality']) and public.visible_branch(branch_id)));
create policy r_ins on public.reports for insert to authenticated with check (
  branch_id = auth.uid() and status = 'new'
  and (case type
        when 'inventory' then public.has_perm('b_inventory')
        when 'qinspect'  then public.has_perm('b_quality')
        when 'cash_am'   then public.has_perm('b_cashier')
        when 'cash_pm'   then public.has_perm('b_cashier')
        else public.has_perm('b_submit') end));

-- 4) رؤية حسابات الفروع لمن يملك صلاحية الجودة
drop policy if exists p_sel on public.profiles;
create policy p_sel on public.profiles for select to authenticated using (
  public.is_admin() or id = auth.uid()
  or (role = 'branch' and public.visible_branch(id)
      and public.has_any(array['m_dash','m_reports','m_exec','m_checklist','m_tasks','m_branches','m_quality']))
);

-- 5) الصلاحيات الجديدة للوظائف الحالية (القيم الموجودة لا تتغير)
update public.positions set perms = '{"m_quality":true,"m_quality_edit":true}'::jsonb || perms where key = 'ops_manager';
update public.positions set perms = '{"m_quality":true,"m_quality_edit":false}'::jsonb || perms where key = 'area_manager';
update public.positions set perms = '{"b_cashier":true,"b_quality":true,"b_excel":true}'::jsonb || perms where key = 'branch_manager';
update public.positions set perms = '{"m_quality":false,"m_quality_edit":false}'::jsonb || perms where scope <> 'own' and not (perms ? 'm_quality');
update public.positions set perms = '{"b_cashier":false,"b_quality":false,"b_excel":false}'::jsonb || perms where scope = 'own' and not (perms ? 'b_cashier');
