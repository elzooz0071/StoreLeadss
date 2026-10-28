-- ============================================================
-- Branchly update_6: نظام الكاشير (POS) داخل التطبيق
-- شغّله مرة واحدة في Supabase SQL Editor (آمن لإعادة التشغيل)
-- يضيف: أصناف البيع، الورديات، الفواتير، وخصم المخزون التلقائي.
-- كل عمليات البيع والإلغاء وإقفال الوردية تتم داخل الداتابيز (الأسعار تُحسب هناك لا من المتصفح).
-- ============================================================
create table if not exists public.pos_products (
  id          uuid primary key default gen_random_uuid(),
  branch_id   uuid not null references public.profiles(id) on delete cascade,
  name        text not null,
  price       numeric(12,2) not null check (price >= 0),
  category    text not null default '',
  barcode     text not null default '',
  inv_item_id uuid references public.inventory_items(id) on delete set null,
  inv_qty     numeric not null default 1 check (inv_qty >= 0),
  active      boolean not null default true,
  sort        int not null default 0
);
create index if not exists posp_branch_idx on public.pos_products (branch_id);
create unique index if not exists posp_barcode_uq on public.pos_products (branch_id, barcode) where barcode <> '';

create table if not exists public.pos_shifts (
  id            uuid primary key default gen_random_uuid(),
  branch_id     uuid not null references public.profiles(id) on delete cascade,
  cashier       text not null,
  opened_at     timestamptz not null default now(),
  opening_cash  numeric(12,2) not null default 0 check (opening_cash >= 0),
  closed_at     timestamptz,
  counted_cash  numeric(12,2),
  expected_cash numeric(12,2),
  note          text default ''
);
create index if not exists poss_branch_idx on public.pos_shifts (branch_id, opened_at desc);
create unique index if not exists poss_one_open on public.pos_shifts (branch_id) where closed_at is null;

create table if not exists public.pos_sales (
  id         uuid primary key default gen_random_uuid(),
  no         bigint generated always as identity,
  branch_id  uuid not null references public.profiles(id) on delete cascade,
  shift_id   uuid not null references public.pos_shifts(id) on delete cascade,
  cashier    text not null,
  subtotal   numeric(12,2) not null,
  discount   numeric(12,2) not null default 0,
  total      numeric(12,2) not null,
  method     text not null check (method in ('cash','card','other')),
  paid       numeric(12,2) not null,
  change_due numeric(12,2) not null default 0,
  items      jsonb not null,
  voided     boolean not null default false,
  voided_at  timestamptz,
  created_at timestamptz not null default now()
);
create index if not exists poss_sales_shift_idx  on public.pos_sales (shift_id);
create index if not exists poss_sales_branch_idx on public.pos_sales (branch_id, created_at desc);

alter table public.pos_products enable row level security;
alter table public.pos_shifts   enable row level security;
alter table public.pos_sales    enable row level security;

drop policy if exists posp_sel on public.pos_products;
drop policy if exists posp_own on public.pos_products;
create policy posp_sel on public.pos_products for select to authenticated using (
  branch_id = auth.uid() or (public.has_any(array['m_dash','m_exec']) and public.visible_branch(branch_id)));
create policy posp_own on public.pos_products for all to authenticated
  using (branch_id = auth.uid() and public.has_perm('b_pos')) with check (branch_id = auth.uid() and public.has_perm('b_pos'));

drop policy if exists poss_sel on public.pos_shifts;
create policy poss_sel on public.pos_shifts for select to authenticated using (
  branch_id = auth.uid() or (public.has_any(array['m_dash','m_exec']) and public.visible_branch(branch_id)));
drop policy if exists posl_sel on public.pos_sales;
create policy posl_sel on public.pos_sales for select to authenticated using (
  branch_id = auth.uid() or (public.has_any(array['m_dash','m_exec']) and public.visible_branch(branch_id)));

-- الورديات والفواتير للقراءة فقط من التطبيق؛ الكتابة عبر الدوال أدناه
revoke insert, update, delete on public.pos_shifts, public.pos_sales from anon, authenticated;
revoke all on public.pos_products, public.pos_shifts, public.pos_sales from anon;

-- صلاحية الكاشير لمدير الفرع الافتراضي (باقي الوظائف تُمنح من شاشة الوظائف والصلاحيات)
update public.positions set perms = coalesce(perms, '{}'::jsonb) || '{"b_pos": true}'::jsonb where key = 'branch_manager';

-- ---------- فتح وردية ----------
create or replace function public.pos_open_shift(p_cashier text, p_opening numeric default 0)
returns uuid language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); sid uuid;
begin
  if me is null or not public.has_perm('b_pos') or not exists (select 1 from public.profiles where id = me and role = 'branch' and active) then raise exception 'not allowed'; end if;
  if coalesce(trim(p_cashier), '') = '' then raise exception 'cashier name required'; end if;
  if coalesce(p_opening, 0) < 0 then raise exception 'bad opening cash'; end if;
  if exists (select 1 from public.pos_shifts where branch_id = me and closed_at is null) then raise exception 'shift already open'; end if;
  insert into public.pos_shifts (branch_id, cashier, opening_cash) values (me, trim(p_cashier), coalesce(p_opening, 0)) returning id into sid;
  return sid;
end $$;

-- ---------- بيع (الأسعار من الداتابيز + خصم المخزون) ----------
create or replace function public.pos_sell(p_items jsonb, p_discount numeric default 0, p_method text default 'cash', p_paid numeric default null)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  me uuid := auth.uid(); sh public.pos_shifts; it jsonb; pr public.pos_products; q numeric;
  lines jsonb := '[]'::jsonb; sub numeric := 0; disc numeric; tot numeric; pd numeric; chg numeric := 0; s public.pos_sales;
begin
  if me is null or not public.has_perm('b_pos') then raise exception 'not allowed'; end if;
  if p_method not in ('cash','card','other') then raise exception 'bad method'; end if;
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
  insert into public.pos_sales (branch_id, shift_id, cashier, subtotal, discount, total, method, paid, change_due, items)
  values (me, sh.id, sh.cashier, sub, disc, tot, p_method, pd, chg, lines) returning * into s;
  return to_jsonb(s);
end $$;

-- ---------- إلغاء فاتورة (يرجّع المخزون) ----------
create or replace function public.pos_void(p_sale uuid)
returns void language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); s public.pos_sales; l jsonb;
begin
  if me is null or not public.has_perm('b_pos') then raise exception 'not allowed'; end if;
  select * into s from public.pos_sales where id = p_sale and branch_id = me for update;
  if not found then raise exception 'sale not found'; end if;
  if s.voided then raise exception 'already voided'; end if;
  if not exists (select 1 from public.pos_shifts where id = s.shift_id and closed_at is null) then raise exception 'shift closed'; end if;
  for l in select * from jsonb_array_elements(s.items) loop
    if l->>'inv' is not null and (l->>'invq')::numeric > 0 then
      update public.inventory_items set qty = qty + (l->>'invq')::numeric * (l->>'qty')::numeric where id = (l->>'inv')::uuid and branch_id = me;
    end if;
  end loop;
  update public.pos_sales set voided = true, voided_at = now() where id = s.id;
end $$;

-- ---------- إقفال الوردية ----------
create or replace function public.pos_close_shift(p_counted numeric, p_note text default '')
returns jsonb language plpgsql security definer set search_path = public as $$
declare me uuid := auth.uid(); sh public.pos_shifts; cash numeric; exp numeric; cnt int; tot numeric; v int;
begin
  if me is null or not public.has_perm('b_pos') then raise exception 'not allowed'; end if;
  if p_counted is null or p_counted < 0 then raise exception 'bad counted cash'; end if;
  select * into sh from public.pos_shifts where branch_id = me and closed_at is null for update;
  if not found then raise exception 'no open shift'; end if;
  select coalesce(sum(total) filter (where method = 'cash'), 0), count(*), coalesce(sum(total), 0)
    into cash, cnt, tot from public.pos_sales where shift_id = sh.id and not voided;
  select count(*) into v from public.pos_sales where shift_id = sh.id and voided;
  exp := sh.opening_cash + cash;
  update public.pos_shifts set closed_at = now(), counted_cash = p_counted, expected_cash = exp, note = coalesce(p_note, '') where id = sh.id;
  return jsonb_build_object('shift', sh.id, 'cashier', sh.cashier, 'opened_at', sh.opened_at, 'opening', sh.opening_cash,
    'cash_sales', cash, 'sales_count', cnt, 'sales_total', tot, 'voided', v, 'expected', exp, 'counted', p_counted, 'diff', p_counted - exp);
end $$;

revoke execute on function public.pos_open_shift(text,numeric), public.pos_sell(jsonb,numeric,text,numeric), public.pos_void(uuid), public.pos_close_shift(numeric,text) from public, anon;
grant  execute on function public.pos_open_shift(text,numeric), public.pos_sell(jsonb,numeric,text,numeric), public.pos_void(uuid), public.pos_close_shift(numeric,text) to authenticated;

-- سجل النشاط للأصناف والورديات
do $$
declare t text;
begin
  if to_regclass('public.audit_log') is not null then
    foreach t in array array['pos_products','pos_shifts'] loop
      execute format('drop trigger if exists audit_%1$s on public.%1$s', t);
      execute format('create trigger audit_%1$s after insert or update or delete on public.%1$s for each row execute function public.audit_trg()', t);
    end loop;
  end if;
end $$;

-- تحديث «مسح البيانات» ليشمل بيانات الكاشير
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
