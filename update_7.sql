-- ============================================================
-- Branchly update_7: سجل الأخطاء + دعم كاشير الأوفلاين
-- شغّله مرة واحدة في Supabase SQL Editor (آمن لإعادة التشغيل). يحتاج update_6 قبله.
-- ============================================================
create table if not exists public.app_errors (
  id        bigserial primary key,
  at        timestamptz not null default now(),
  user_id   uuid,
  username  text default '',
  msg       text not null,
  src       text default '',
  stack     text default '',
  ua        text default '',
  ver       text default ''
);
create index if not exists apperr_at_idx on public.app_errors (at desc);
alter table public.app_errors enable row level security;
drop policy if exists apperr_ins on public.app_errors;
drop policy if exists apperr_sel on public.app_errors;
drop policy if exists apperr_del on public.app_errors;
create policy apperr_ins on public.app_errors for insert to authenticated with check (user_id = auth.uid() and length(msg) < 2000);
create policy apperr_sel on public.app_errors for select to authenticated using (public.is_admin());
create policy apperr_del on public.app_errors for delete to authenticated using (public.is_admin());
revoke all on public.app_errors from anon;
revoke update on public.app_errors from authenticated;
grant usage, select on sequence public.app_errors_id_seq to authenticated;

-- حذف النسخة القديمة من pos_sell ثم إنشاء الجديدة (تقبل معرّف الفاتورة والوقت لإعادة الإرسال الآمن)
drop function if exists public.pos_sell(jsonb, numeric, text, numeric);
-- ---------- بيع (الأسعار من الداتابيز + خصم المخزون) ----------
create or replace function public.pos_sell(p_items jsonb, p_discount numeric default 0, p_method text default 'cash', p_paid numeric default null, p_id uuid default null, p_at timestamptz default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  me uuid := auth.uid(); sh public.pos_shifts; it jsonb; pr public.pos_products; q numeric;
  lines jsonb := '[]'::jsonb; ex public.pos_sales; sub numeric := 0; disc numeric; tot numeric; pd numeric; chg numeric := 0; s public.pos_sales;
begin
  if me is null or not public.has_perm('b_pos') then raise exception 'not allowed'; end if;
  if p_method not in ('cash','card','other') then raise exception 'bad method'; end if;
  -- إعادة إرسال نفس الفاتورة (من طابور الأوفلاين) لا تتكرر
  if p_id is not null then
    select * into ex from public.pos_sales where id = p_id;
    if found then
      if ex.branch_id <> me then raise exception 'not allowed'; end if;
      return to_jsonb(ex);
    end if;
  end if;
  select * into sh from public.pos_shifts where branch_id = me and closed_at is null;
  if not found then raise exception 'no open shift'; end if;
  if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) = 0 then raise exception 'empty cart'; end if;
  for it in select * from jsonb_array_elements(p_items) loop
    q := (it->>'qty')::numeric;
    if q is null or q <= 0 or q > 9999 then raise exception 'bad qty'; end if;
    select * into pr from public.pos_products where id = (it->>'id')::uuid and branch_id = me and active;
    if not found then raise exception 'product not found'; end if;
    sub := sub + pr.price * q;
    lines := lines || jsonb_build_object('id', pr.id, 'name', pr.name, 'price', pr.price, 'qty', q, 'inv', pr.inv_item_id, 'invq', pr.inv_qty);
    if pr.inv_item_id is not null and pr.inv_qty > 0 then
      update public.inventory_items set qty = greatest(qty - pr.inv_qty * q, 0) where id = pr.inv_item_id and branch_id = me;
    end if;
  end loop;
  disc := least(greatest(coalesce(p_discount, 0), 0), sub);
  tot := sub - disc;
  if p_method = 'cash' then
    pd := coalesce(p_paid, tot);
    if pd < tot then raise exception 'paid less than total'; end if;
    chg := pd - tot;
  else pd := tot; end if;
  insert into public.pos_sales (id, branch_id, shift_id, cashier, subtotal, discount, total, method, paid, change_due, items, created_at)
  values (coalesce(p_id, gen_random_uuid()), me, sh.id, sh.cashier, sub, disc, tot, p_method, pd, chg, lines, least(coalesce(p_at, now()), now())) returning * into s;
  return to_jsonb(s);
end $$;

revoke execute on function public.pos_sell(jsonb,numeric,text,numeric,uuid,timestamptz) from public, anon;
grant  execute on function public.pos_sell(jsonb,numeric,text,numeric,uuid,timestamptz) to authenticated;

-- تحديث «مسح البيانات» ليشمل سجل الأخطاء
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
  if to_regclass('public.app_errors') is not null then delete from public.app_errors; end if;
  if to_regclass('public.pos_sales') is not null then
    delete from public.pos_sales;          get diagnostics c = row_count; n := n || jsonb_build_object('pos_sales', c);
    delete from public.pos_shifts;         get diagnostics c = row_count; n := n || jsonb_build_object('pos_shifts', c);
  end if;

  -- كل شيء ما عدا حسابات الأدمن
  if p_scope = 'all' then
    if to_regclass('public.pos_products') is not null then delete from public.pos_products; get diagnostics c = row_count; n := n || jsonb_build_object('pos_products', c); end if;
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
