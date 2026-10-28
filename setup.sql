-- =====================================================================
--  منصة إدارة العمليات التشغيلية للمطاعم — إعداد قاعدة البيانات (Supabase)
--  شغّل هذا الملف كاملاً مرة واحدة في: SQL Editor > New query > Run
--  (يمكن إعادة تشغيله بأمان، لن يمسح بياناتك)
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------------------------------------------------------------------
-- 1) الجداول
-- ---------------------------------------------------------------------
create table if not exists public.profiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  username      text unique not null,
  role          text not null default 'branch' check (role in ('admin','branch','staff')),
  name          text not null,
  manager       text default '',
  email_contact text default '',
  active        boolean not null default true,
  created_at    timestamptz default now()
);

-- الوظائف (Positions): كل وظيفة لها صلاحيات يحددها الأدمن، ونطاق رؤية للفروع:
--   all      = كل الفروع | assigned = فروع يحددها الأدمن للموظف | own = فرعه فقط
create table if not exists public.positions (
  key     text primary key,
  label   text not null,
  scope   text not null default 'assigned' check (scope in ('all','assigned','own')),
  perms   jsonb not null default '{}',
  builtin boolean not null default false,
  sort    int not null default 0
);

-- ترقية جدول profiles (آمنة عند إعادة التشغيل)
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('admin','branch','staff'));
alter table public.profiles add column if not exists position   text;
alter table public.profiles add column if not exists branch_ids uuid[] not null default '{}';
do $$ begin
  if not exists (select 1 from pg_constraint where conname = 'profiles_position_fk') then
    alter table public.profiles add constraint profiles_position_fk
      foreign key (position) references public.positions(key) on update cascade on delete restrict;
  end if;
end $$;

create table if not exists public.settings (
  id       int primary key default 1 check (id = 1),
  company  text not null default 'مجموعة المطاعم',
  currency text not null default 'ج.م',
  concept  text not null default 'fast',
  targets  jsonb not null default '{"waste":3,"labor":25,"quality":90}',
  custom   jsonb not null default '{}'
);

create table if not exists public.checklist_items (
  id         uuid primary key default gen_random_uuid(),
  shift      text not null check (shift in ('open','service','close')),
  title      text not null,
  descr      text default '',
  sort       int default 0,
  created_at timestamptz default now()
);

create table if not exists public.check_runs (
  branch_id uuid not null references public.profiles(id) on delete cascade,
  run_date  date not null,
  item_id   uuid not null references public.checklist_items(id) on delete cascade,
  done_at   text,
  primary key (branch_id, run_date, item_id)
);

create table if not exists public.tasks (
  id         uuid primary key default gen_random_uuid(),
  title      text not null,
  descr      text default '',
  priority   text not null default 'mid' check (priority in ('high','mid','low')),
  due        date,
  targets    uuid[] not null,
  archived   boolean not null default false,
  created_by uuid,
  created_at timestamptz default now()
);

create table if not exists public.task_status (
  task_id   uuid not null references public.tasks(id) on delete cascade,
  branch_id uuid not null references public.profiles(id) on delete cascade,
  done_at   timestamptz default now(),
  primary key (task_id, branch_id)
);

create table if not exists public.reports (
  id          uuid primary key default gen_random_uuid(),
  branch_id   uuid not null references public.profiles(id) on delete cascade,
  type        text not null,
  report_date date not null,
  data        jsonb not null default '{}',
  notes       text default '',
  att_name    text,
  att_path    text,
  status      text not null default 'new' check (status in ('new','reviewed','returned')),
  review      text default '',
  reviewed_at timestamptz,
  created_at  timestamptz default now()
);
create index if not exists reports_date_idx   on public.reports (report_date);
create index if not exists reports_branch_idx on public.reports (branch_id);

create table if not exists public.inventory_items (
  id        uuid primary key default gen_random_uuid(),
  branch_id uuid not null references public.profiles(id) on delete cascade,
  name      text not null,
  unit      text default '',
  qty       numeric not null default 0,
  min_qty   numeric not null default 0,
  sort      int default 0
);
create index if not exists inv_branch_idx on public.inventory_items (branch_id);

create table if not exists public.inventory_meta (
  branch_id  uuid primary key references public.profiles(id) on delete cascade,
  updated_at timestamptz default now()
);

create table if not exists public.notifications (
  id         uuid primary key default gen_random_uuid(),
  to_user    uuid references public.profiles(id) on delete cascade,
  to_admin   boolean not null default false,
  text       text not null,
  read       boolean not null default false,
  created_at timestamptz default now()
);
create index if not exists notif_user_idx on public.notifications (to_user);

-- ---------------------------------------------------------------------
-- 2) دوال مساعدة
-- ---------------------------------------------------------------------
create or replace function public.is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles
                 where id = auth.uid() and role = 'admin' and active);
$$;

-- حماية الحسابات:
--   * لا يمكن إيقاف أو تغيير آخر أدمن نشط
--   * غير الأدمن لا يغيّر دوراً ولا وظيفة ولا فروعاً مسندة أبداً
--   * وغير الأدمن لا يعدّل اسم دخول أي حساب، ولا اسمه/حالته هو شخصياً
--     (يعدّل فقط اسم المسؤول والبريد؛ ومن يملك صلاحية إدارة الفروع يعدّل اسم/حالة الفروع)
create or replace function public.protect_profile()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if old.role = 'admin' and (new.role <> 'admin' or not new.active)
     and not exists (select 1 from public.profiles where role = 'admin' and active and id <> old.id) then
    raise exception 'لا يمكن إيقاف أو تغيير آخر أدمن';
  end if;
  if not public.is_admin() then
    new.role       := old.role;
    new.position   := old.position;
    new.branch_ids := old.branch_ids;
    new.username   := old.username;
    if old.id = auth.uid() then
      new.active := old.active;
      new.name   := old.name;
    end if;
  end if;
  return new;
end $$;
drop trigger if exists trg_protect_profile on public.profiles;
create trigger trg_protect_profile before update on public.profiles
  for each row execute function public.protect_profile();

-- حذف الدوال القديمة (لو كانت موجودة من التشغيل السابق)
drop function if exists public.admin_create_branch(text,text,text);
drop function if exists public._create_user(text,text,text,text);
drop function if exists public.admin_sync_users();

-- عضو نشط (له ملف في profiles)
create or replace function public.is_member()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and active);
$$;

-- ---- دوال الصلاحيات (تُستخدم داخل سياسات RLS) ----
-- هل للمستخدم الحالي هذه الصلاحية؟ (الأدمن لديه كل الصلاحيات دائماً)
create or replace function public.has_perm(p text)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or coalesce(po.perms ->> p, '') = 'true'
    from public.profiles pr
    left join public.positions po
      on po.key = coalesce(pr.position, case when pr.role = 'branch' then 'branch_manager' end)
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- هل لديه أي صلاحية من القائمة؟
create or replace function public.has_any(p text[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin'
        or exists (select 1 from unnest(p) k where coalesce(po.perms ->> k, '') = 'true')
    from public.profiles pr
    left join public.positions po
      on po.key = coalesce(pr.position, case when pr.role = 'branch' then 'branch_manager' end)
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- هل يرى كل الفروع؟ (أدمن، أو موظف وظيفته بنطاق "all")
create or replace function public.is_all_scope()
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or (pr.role = 'staff' and po.scope = 'all')
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- هل يستطيع رؤية بيانات هذا الفرع؟ (فرعه، أو كل الفروع، أو فروع أُسندت إليه)
create or replace function public.visible_branch(b uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or b = pr.id
        or (pr.role = 'staff' and (po.scope = 'all' or b = any (pr.branch_ids)))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- هل يتقاطع هذا الصف مع فروعه المسموحة؟ (لقراءة التكليفات)
create or replace function public.visible_any(t uuid[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or (pr.role = 'staff' and (po.scope = 'all' or t && pr.branch_ids))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- هل كل الفروع المستهدفة ضمن نطاقه؟ (لإصدار التكليفات)
create or replace function public.can_target(t uuid[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or (pr.role = 'staff' and (po.scope = 'all' or t <@ pr.branch_ids))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- دعوات الحسابات: المسؤول يسجل الاسم من الموقع، ثم يُنشأ الحساب فيُربط تلقائياً
create table if not exists public.branch_invites (
  username   text primary key,
  name       text not null,
  created_at timestamptz default now()
);
alter table public.branch_invites add column if not exists role       text   not null default 'branch';
alter table public.branch_invites add column if not exists position   text;
alter table public.branch_invites add column if not exists branch_ids uuid[] not null default '{}';
alter table public.branch_invites enable row level security;
drop policy if exists bi_all on public.branch_invites;
create policy bi_all on public.branch_invites for all to authenticated
  using (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope()))
  with check (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope()
              and role = 'branch' and coalesce(position, 'branch_manager') = 'branch_manager'));

-- عند إنشاء أي مستخدم جديد في Supabase: يُربط تلقائياً بجدول profiles
--   * لو له دعوة فرع  => فرع
--   * لو لا يوجد مدير بعد => يصبح هو المدير
--   * غير ذلك => لا يُمنح أي صلاحية
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_user text := split_part(lower(coalesce(new.email,'')), '@', 1);
  v_inv  public.branch_invites;
begin
  begin
    select * into v_inv from public.branch_invites where username = v_user;
    if found and lower(new.email) = v_user || '@rms-portal.com' then
      insert into public.profiles (id, username, role, name, position, branch_ids)
      values (new.id, v_user, v_inv.role, v_inv.name,
              coalesce(v_inv.position, case when v_inv.role = 'branch' then 'branch_manager' end),
              coalesce(v_inv.branch_ids, '{}')) on conflict do nothing;
      delete from public.branch_invites where username = v_user;
    elsif not exists (select 1 from public.profiles where role = 'admin') then
      insert into public.profiles (id, username, role, name)
      values (new.id, regexp_replace(v_user, '[^a-z0-9_]', '', 'g'), 'admin', 'الأدمن') on conflict do nothing;
    end if;
  exception when others then
    raise warning 'handle_new_user failed: %', sqlerrm;
  end;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ربط أي مستخدمين موجودين في Supabase ولا يملكون profile (يُستدعى تلقائياً بنهاية هذا الملف)
--   أول مستخدم (أو المسمى admin) يصبح المدير إن لم يوجد مدير، والباقي فروع
create or replace function public._sync_users()
returns int language plpgsql security definer set search_path = public, auth as $$
declare u record; v_base text; v_name text; v_i int; v_role text;
begin
  for u in
    select au.id, lower(au.email) as email from auth.users au
    where au.email is not null and not exists (select 1 from public.profiles p where p.id = au.id)
    order by (split_part(lower(au.email),'@',1) = 'admin') desc, au.created_at
  loop
    v_base := regexp_replace(split_part(u.email,'@',1), '[^a-z0-9_]', '', 'g');
    if v_base = '' then v_base := 'user'; end if;
    v_name := v_base; v_i := 0;
    while exists (select 1 from public.profiles where username = v_name) loop
      v_i := v_i + 1; v_name := v_base || v_i;
    end loop;
    v_role := case when exists (select 1 from public.profiles where role = 'admin') then 'branch' else 'admin' end;
    insert into public.profiles (id, username, role, name, position)
    values (u.id, v_name, v_role, case when v_role = 'admin' then 'الأدمن' else 'فرع ' || v_name end,
            case when v_role = 'branch' then 'branch_manager' end);
  end loop;
  return (select count(*) from public.profiles)::int;
end $$;
revoke execute on function public._sync_users() from public, anon, authenticated;

-- دعوة فرع جديد (الأدمن، أو موظف يملك صلاحية إدارة الفروع ويرى كل الفروع)
create or replace function public.admin_invite_branch(p_username text, p_name text)
returns void language plpgsql security definer set search_path = public, auth as $$
begin
  if not (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope())) then
    raise exception 'غير مصرح';
  end if;
  if p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'اسم الدخول: 3-20 حرفاً إنجليزياً صغيراً أو أرقاماً'; end if;
  if exists (select 1 from public.profiles where username = p_username)
     or exists (select 1 from auth.users where lower(email) = p_username || '@rms-portal.com') then
    raise exception 'اسم الدخول مستخدم مسبقاً';
  end if;
  insert into public.branch_invites (username, name, role, position, branch_ids)
  values (p_username, p_name, 'branch', 'branch_manager', '{}')
  on conflict (username) do update
    set name = excluded.name, role = 'branch', position = 'branch_manager', branch_ids = '{}';
end $$;

-- دعوة موظف إداري (مدير تشغيل / مدير منطقة / أي وظيفة) — للأدمن فقط
create or replace function public.admin_invite_staff(p_username text, p_name text, p_position text, p_branch_ids uuid[])
returns void language plpgsql security definer set search_path = public, auth as $$
declare v_scope text;
begin
  if not public.is_admin() then raise exception 'غير مصرح'; end if;
  if p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'اسم الدخول: 3-20 حرفاً إنجليزياً صغيراً أو أرقاماً'; end if;
  select scope into v_scope from public.positions where key = p_position;
  if v_scope is null then raise exception 'الوظيفة غير موجودة'; end if;
  if v_scope = 'own' then raise exception 'هذه الوظيفة خاصة بحسابات الفروع'; end if;
  if exists (select 1 from public.profiles where username = p_username)
     or exists (select 1 from auth.users where lower(email) = p_username || '@rms-portal.com') then
    raise exception 'اسم الدخول مستخدم مسبقاً';
  end if;
  insert into public.branch_invites (username, name, role, position, branch_ids)
  values (p_username, p_name, 'staff', p_position, coalesce(p_branch_ids, '{}'))
  on conflict (username) do update
    set name = excluded.name, role = 'staff', position = excluded.position, branch_ids = excluded.branch_ids;
end $$;

-- تغيير كلمة مرور: الأدمن لأي حساب، ومن يملك إدارة الفروع لحسابات الفروع داخل نطاقه فقط
create or replace function public.admin_set_password(p_user uuid, p_password text)
returns void language plpgsql security definer set search_path = public, extensions, auth as $$
begin
  if not (public.is_admin() or (
        public.has_perm('m_branches') and public.visible_branch(p_user)
        and exists (select 1 from public.profiles where id = p_user and role = 'branch'))) then
    raise exception 'غير مصرح';
  end if;
  if length(coalesce(p_password,'')) < 6 then raise exception 'كلمة المرور قصيرة'; end if;
  update auth.users set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')),
                        updated_at = now()
  where id = p_user;
end $$;

-- طلب استعادة كلمة المرور (متاح قبل تسجيل الدخول)
create or replace function public.request_password_reset(p_email text)
returns void language plpgsql security definer set search_path = public as $$
declare v_name text; v_text text;
begin
  select name into v_name from public.profiles
   where role <> 'admin' and lower(email_contact) = lower(trim(p_email)) limit 1;
  if v_name is not null then
    v_text := 'طلب استعادة كلمة المرور من ' || v_name;
    if not exists (select 1 from public.notifications
                   where to_admin and text = v_text and created_at > now() - interval '1 hour') then
      insert into public.notifications (to_admin, text) values (true, v_text);
    end if;
  end if;
end $$;

revoke execute on function public.admin_invite_branch(text,text) from public, anon;
revoke execute on function public.admin_invite_staff(text,text,text,uuid[]) from public, anon;
revoke execute on function public.admin_set_password(uuid,text)  from public, anon;
grant  execute on function public.admin_invite_branch(text,text) to authenticated;
grant  execute on function public.admin_invite_staff(text,text,text,uuid[]) to authenticated;
grant  execute on function public.admin_set_password(uuid,text)  to authenticated;
grant  execute on function public.is_member()                    to authenticated;
-- دوال الصلاحيات: للمستخدمين المسجلين فقط
revoke execute on function public.has_perm(text)         from public, anon;
revoke execute on function public.has_any(text[])        from public, anon;
revoke execute on function public.is_all_scope()         from public, anon;
revoke execute on function public.visible_branch(uuid)   from public, anon;
revoke execute on function public.visible_any(uuid[])    from public, anon;
revoke execute on function public.can_target(uuid[])     from public, anon;
grant  execute on function public.has_perm(text)         to authenticated;
grant  execute on function public.has_any(text[])        to authenticated;
grant  execute on function public.is_all_scope()         to authenticated;
grant  execute on function public.visible_branch(uuid)   to authenticated;
grant  execute on function public.visible_any(uuid[])    to authenticated;
grant  execute on function public.can_target(uuid[])     to authenticated;

-- تقليل ما يمكن استدعاؤه من الخارج: دوال الـ trigger لا تحتاج صلاحية تنفيذ للمستخدمين،
-- ودوال التحقق (is_admin / is_member) تحتاجها المستخدمين المسجلين فقط
revoke execute on function public.is_admin()        from public, anon;
revoke execute on function public.is_member()       from public, anon;
revoke execute on function public.handle_new_user() from public, anon, authenticated;
revoke execute on function public.protect_profile() from public, anon, authenticated;
grant  execute on function public.request_password_reset(text)        to anon, authenticated;
grant  execute on function public.is_admin()                          to authenticated;

-- ---------------------------------------------------------------------
-- 3) الصلاحيات (RLS)
-- ---------------------------------------------------------------------
alter table public.profiles         enable row level security;
alter table public.settings         enable row level security;
alter table public.checklist_items  enable row level security;
alter table public.check_runs       enable row level security;
alter table public.tasks            enable row level security;
alter table public.task_status      enable row level security;
alter table public.reports          enable row level security;
alter table public.inventory_items  enable row level security;
alter table public.inventory_meta   enable row level security;
alter table public.notifications    enable row level security;

alter table public.positions        enable row level security;

-- positions: الكل (المسجلون) يقرأ، والأدمن فقط يعدّل
drop policy if exists po_sel on public.positions;
drop policy if exists po_ins on public.positions;
drop policy if exists po_upd on public.positions;
drop policy if exists po_del on public.positions;
create policy po_sel on public.positions for select to authenticated using (public.is_member());
create policy po_ins on public.positions for insert to authenticated with check (public.is_admin() and not builtin);
create policy po_upd on public.positions for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy po_del on public.positions for delete to authenticated using (public.is_admin() and not builtin);

-- profiles
drop policy if exists p_sel on public.profiles;
drop policy if exists p_upd on public.profiles;
create policy p_sel on public.profiles for select to authenticated using (
  public.is_admin() or id = auth.uid()
  or (role = 'branch' and public.visible_branch(id)
      and public.has_any(array['m_dash','m_reports','m_exec','m_checklist','m_tasks','m_branches']))
);
create policy p_upd on public.profiles for update to authenticated
  using (public.is_admin() or id = auth.uid()
         or (role = 'branch' and public.has_perm('m_branches') and public.visible_branch(id)))
  with check (public.is_admin() or id = auth.uid()
         or (role = 'branch' and public.has_perm('m_branches') and public.visible_branch(id)));

-- settings
drop policy if exists s_sel on public.settings;
drop policy if exists s_upd on public.settings;
create policy s_sel on public.settings for select to authenticated using (public.is_member());
create policy s_upd on public.settings for update to authenticated using (public.has_perm('m_settings')) with check (public.has_perm('m_settings'));

-- checklist_items
drop policy if exists c_sel on public.checklist_items;
drop policy if exists c_all on public.checklist_items;
create policy c_sel on public.checklist_items for select to authenticated using (public.is_member());
create policy c_all on public.checklist_items for all to authenticated using (public.has_perm('m_checklist_edit')) with check (public.has_perm('m_checklist_edit'));

-- check_runs
drop policy if exists cr_sel on public.check_runs;
drop policy if exists cr_ins on public.check_runs;
drop policy if exists cr_del on public.check_runs;
drop policy if exists cr_upd on public.check_runs;
create policy cr_sel on public.check_runs for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_dash','m_checklist','m_exec']) and public.visible_branch(branch_id)));
create policy cr_ins on public.check_runs for insert to authenticated with check (branch_id = auth.uid() and public.has_perm('b_check'));
create policy cr_del on public.check_runs for delete to authenticated using (branch_id = auth.uid() and public.has_perm('b_check'));
create policy cr_upd on public.check_runs for update to authenticated using (branch_id = auth.uid() and public.has_perm('b_check')) with check (branch_id = auth.uid() and public.has_perm('b_check'));

-- tasks
drop policy if exists t_sel on public.tasks;
drop policy if exists t_all on public.tasks;
create policy t_sel on public.tasks for select to authenticated using (
  auth.uid() = any (targets)
  or (public.has_any(array['m_tasks','m_dash','m_exec']) and public.visible_any(targets)));
create policy t_all on public.tasks for all to authenticated
  using (public.has_perm('m_tasks') and public.visible_any(targets))
  with check (public.has_perm('m_tasks') and public.can_target(targets));

-- task_status
drop policy if exists ts_sel on public.task_status;
drop policy if exists ts_ins on public.task_status;
drop policy if exists ts_upd on public.task_status;
create policy ts_sel on public.task_status for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_tasks','m_dash','m_exec']) and public.visible_branch(branch_id)));
create policy ts_ins on public.task_status for insert to authenticated with check (
  branch_id = auth.uid() and public.has_perm('b_tasks')
  and exists (select 1 from public.tasks t where t.id = task_id and auth.uid() = any (t.targets))
);
create policy ts_upd on public.task_status for update to authenticated using (branch_id = auth.uid() and public.has_perm('b_tasks')) with check (branch_id = auth.uid() and public.has_perm('b_tasks'));

-- reports
drop policy if exists r_sel on public.reports;
drop policy if exists r_ins on public.reports;
drop policy if exists r_upd on public.reports;
create policy r_sel on public.reports for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_dash','m_reports','m_exec']) and public.visible_branch(branch_id)));
create policy r_ins on public.reports for insert to authenticated with check (
  branch_id = auth.uid() and status = 'new'
  and (case when type = 'inventory' then public.has_perm('b_inventory') else public.has_perm('b_submit') end));
create policy r_upd on public.reports for update to authenticated
  using (public.has_perm('m_review') and public.visible_branch(branch_id))
  with check (public.has_perm('m_review') and public.visible_branch(branch_id));

-- inventory
drop policy if exists i_sel on public.inventory_items;
drop policy if exists i_own on public.inventory_items;
create policy i_sel on public.inventory_items for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_dash','m_exec']) and public.visible_branch(branch_id)));
create policy i_own on public.inventory_items for all to authenticated using (branch_id = auth.uid() and public.has_perm('b_inventory')) with check (branch_id = auth.uid() and public.has_perm('b_inventory'));

drop policy if exists im_sel on public.inventory_meta;
drop policy if exists im_own on public.inventory_meta;
create policy im_sel on public.inventory_meta for select to authenticated using (
  branch_id = auth.uid()
  or (public.has_any(array['m_dash','m_exec']) and public.visible_branch(branch_id)));
create policy im_own on public.inventory_meta for all to authenticated using (branch_id = auth.uid() and public.has_perm('b_inventory')) with check (branch_id = auth.uid() and public.has_perm('b_inventory'));

-- notifications (إشعارات الإدارة يراها الأدمن ومن يملك صلاحية التقارير)
drop policy if exists n_sel on public.notifications;
drop policy if exists n_ins on public.notifications;
drop policy if exists n_upd on public.notifications;
create policy n_sel on public.notifications for select to authenticated using (to_user = auth.uid() or (to_admin and public.has_any(array['m_reports','m_review'])));
create policy n_ins on public.notifications for insert to authenticated with check (public.is_member() and (to_admin or to_user is not null));
create policy n_upd on public.notifications for update to authenticated using (to_user = auth.uid() or (to_admin and public.has_any(array['m_reports','m_review'])));

-- ---------------------------------------------------------------------
-- 4) تخزين المرفقات (خاص — الفرع يرى مرفقاته فقط، والمدير يرى الكل)
-- ---------------------------------------------------------------------
insert into storage.buckets (id, name, public) values ('attachments', 'attachments', false)
on conflict (id) do nothing;

drop policy if exists att_ins on storage.objects;
drop policy if exists att_sel on storage.objects;
create policy att_ins on storage.objects for insert to authenticated
  with check (bucket_id = 'attachments' and (storage.foldername(name))[1] = auth.uid()::text);
create policy att_sel on storage.objects for select to authenticated
  using (bucket_id = 'attachments' and (
    (storage.foldername(name))[1] = auth.uid()::text
    or (public.has_any(array['m_reports','m_review'])
        and (storage.foldername(name))[1] ~ '^[0-9a-fA-F-]{36}$'
        and public.visible_branch(((storage.foldername(name))[1])::uuid))));

-- ---------------------------------------------------------------------
-- 5) البيانات الأولية
-- ---------------------------------------------------------------------
-- الوظائف الافتراضية (يمكن للأدمن تعديل صلاحياتها وإضافة وظائف أخرى من التطبيق)
insert into public.positions (key, label, scope, perms, builtin, sort) values
 ('ops_manager',    'مدير تشغيل', 'all',
  '{"m_dash":true,"m_reports":true,"m_review":true,"m_exec":true,"m_export":true,"m_tasks":true,"m_checklist":true,"m_checklist_edit":true,"m_branches":false,"m_settings":false}', false, 1),
 ('area_manager',   'مدير منطقة', 'assigned',
  '{"m_dash":true,"m_reports":true,"m_review":true,"m_exec":true,"m_export":true,"m_tasks":true,"m_checklist":true,"m_checklist_edit":false,"m_branches":false,"m_settings":false}', false, 2),
 ('branch_manager', 'مدير فرع',   'own',
  '{"b_dash":true,"b_submit":true,"b_inventory":true,"b_check":true,"b_tasks":true}', true, 3)
on conflict (key) do nothing;

-- كل حسابات الفروع الموجودة تأخذ وظيفة «مدير فرع»، وتسمية الأدمن
update public.profiles set position = 'branch_manager' where role = 'branch' and position is null;
update public.profiles set name = 'الأدمن' where role = 'admin' and name = 'مدير المنطقة';

insert into public.settings (id) values (1) on conflict (id) do nothing;

insert into public.checklist_items (shift, title, descr, sort)
select v.shift, v.title, v.descr, v.ord
from (values
  ('open','تشغيل وفحص القلايات والشوايات','التأكد من درجات الحرارة القياسية لمعدات التشغيل',1),
  ('open','فحص حرارة الثلاجات والفريزرات','تسجيل القراءات والتأكد من سلامة الحساسات',2),
  ('open','جاهزية الفريق والزي الرسمي','الالتزام بمعايير المظهر والنظافة الشخصية',3),
  ('open','جرد المخبوزات والمكونات الرئيسية','تسجيل الكميات المتاحة لبدء الوردية',4),
  ('open','فتح الكاشير وفحص نظام الطلبات','',5),
  ('service','متابعة زمن تجهيز الطلبات','الالتزام بالزمن المستهدف للخدمة',6),
  ('service','فحص جودة الزيت وتبديله عند الحاجة','',7),
  ('service','مراجعة نظافة الصالة ودورات المياه','',8),
  ('close','تنظيف وتعقيم المعدات','',9),
  ('close','مطابقة الكاشير وتسليم الإيراد','',10),
  ('close','تأمين المخزن وإغلاق الأجهزة','',11)
) as v(shift, title, descr, ord)
where not exists (select 1 from public.checklist_items);

-- ربط المستخدمين الموجودين (لو أنشأت مستخدماً من Authentication > Users قبل تشغيل الملف)
select public._sync_users() as عدد_الحسابات_المربوطة;

-- نتيجة التحقق: يجب أن ترى إيميلك ودوره admin
select u.email, p.username, p.role, p.position, p.active, (u.email_confirmed_at is not null) as confirmed
from auth.users u left join public.profiles p on p.id = u.id
order by u.created_at;

-- ---------------------------------------------------------------------
-- 6) تحديث 2 (تخصيص + جودة + كاشير)
-- ---------------------------------------------------------------------
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
update public.positions set perms = '{"b_cashier":true,"b_pos":true,"b_quality":true,"b_excel":true}'::jsonb || perms where key = 'branch_manager';
update public.positions set perms = '{"m_quality":false,"m_quality_edit":false}'::jsonb || perms where scope <> 'own' and not (perms ? 'm_quality');
update public.positions set perms = '{"b_cashier":false,"b_quality":false,"b_excel":false}'::jsonb || perms where scope = 'own' and not (perms ? 'b_cashier');
-- =====================================================================
-- Branchly — تحديث 3: المجموعات المقفولة (فروع وموظفون لا يراهم إلا أعضاء نفس المجموعة)
-- شغّله مرة واحدة في Supabase > SQL Editor (آمن لو اتشغّل أكتر من مرة)
-- القاعدة: الأدمن يرى الكل. غير ذلك: مدير بنطاق "كل الفروع" يرى فقط فروع مجموعته،
--          و"بدون مجموعة" = المجموعة الرئيسية (لا ترى المجموعات المقفولة).
-- =====================================================================
create table if not exists public.groups (
  id         uuid primary key default gen_random_uuid(),
  name       text not null unique,
  sort       int  not null default 0,
  created_at timestamptz default now()
);
alter table public.groups enable row level security;

alter table public.profiles        add column if not exists group_id uuid references public.groups(id) on delete restrict;
alter table public.branch_invites  add column if not exists group_id uuid references public.groups(id) on delete set null;
alter table public.notifications   add column if not exists from_user uuid default auth.uid();

create or replace function public.my_group()
returns uuid language sql stable security definer set search_path = public as $$
  select group_id from public.profiles where id = auth.uid() and active;
$$;
revoke execute on function public.my_group() from public, anon;
grant  execute on function public.my_group() to authenticated;

drop policy if exists g_sel on public.groups;
drop policy if exists g_ins on public.groups;
drop policy if exists g_upd on public.groups;
drop policy if exists g_del on public.groups;
create policy g_sel on public.groups for select to authenticated using (public.is_admin() or id = public.my_group());
create policy g_ins on public.groups for insert to authenticated with check (public.is_admin());
create policy g_upd on public.groups for update to authenticated using (public.is_admin()) with check (public.is_admin());
create policy g_del on public.groups for delete to authenticated using (public.is_admin());

-- نطاق الرؤية الجديد (يراعي المجموعة)
create or replace function public.visible_branch(b uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin' or b = pr.id
        or (pr.role = 'staff' and (b = any (pr.branch_ids)
            or (po.scope = 'all' and exists (select 1 from public.profiles x
                  where x.id = b and x.group_id is not distinct from pr.group_id))))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

create or replace function public.visible_any(t uuid[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin'
        or (pr.role = 'staff' and (t && pr.branch_ids
            or (po.scope = 'all' and exists (select 1 from public.profiles x
                  where x.id = any (t) and x.group_id is not distinct from pr.group_id))))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

create or replace function public.can_target(t uuid[])
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((
    select pr.role = 'admin'
        or (pr.role = 'staff' and (t <@ pr.branch_ids
            or (po.scope = 'all' and not exists (select 1 from public.profiles x
                  where x.id = any (t) and x.group_id is distinct from pr.group_id))))
    from public.profiles pr left join public.positions po on po.key = pr.position
    where pr.id = auth.uid() and pr.active
  ), false);
$$;

-- منع غير الأدمن من تغيير المجموعة
create or replace function public.protect_profile()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then return new; end if;
  if old.role = 'admin' and (new.role <> 'admin' or not new.active)
     and not exists (select 1 from public.profiles where role = 'admin' and active and id <> old.id) then
    raise exception 'لا يمكن إيقاف أو تغيير آخر أدمن';
  end if;
  if not public.is_admin() then
    new.role       := old.role;
    new.position   := old.position;
    new.branch_ids := old.branch_ids;
    new.username   := old.username;
    new.group_id   := old.group_id;
    if old.id = auth.uid() then
      new.active := old.active;
      new.name   := old.name;
    end if;
  end if;
  return new;
end $$;

-- ربط الحساب الجديد بمجموعته من الدعوة
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_user text := split_part(lower(coalesce(new.email,'')), '@', 1);
  v_inv  public.branch_invites;
begin
  begin
    select * into v_inv from public.branch_invites where username = v_user;
    if found and lower(new.email) = v_user || '@rms-portal.com' then
      insert into public.profiles (id, username, role, name, position, branch_ids, group_id)
      values (new.id, v_user, v_inv.role, v_inv.name,
              coalesce(v_inv.position, case when v_inv.role = 'branch' then 'branch_manager' end),
              coalesce(v_inv.branch_ids, '{}'), v_inv.group_id) on conflict do nothing;
      delete from public.branch_invites where username = v_user;
    elsif not exists (select 1 from public.profiles where role = 'admin') then
      insert into public.profiles (id, username, role, name)
      values (new.id, regexp_replace(v_user, '[^a-z0-9_]', '', 'g'), 'admin', 'الأدمن') on conflict do nothing;
    end if;
  exception when others then
    raise warning 'handle_new_user failed: %', sqlerrm;
  end;
  return new;
end $$;

-- الدعوات: الأدمن يحدد المجموعة، ومن غيره تُفرض مجموعته هو
drop function if exists public.admin_invite_branch(text, text);
drop function if exists public.admin_invite_staff(text, text, text, uuid[]);

create or replace function public.admin_invite_branch(p_username text, p_name text, p_group uuid default null)
returns void language plpgsql security definer set search_path = public, auth as $$
declare v_group uuid;
begin
  if not (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope())) then
    raise exception 'غير مصرح';
  end if;
  if p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'اسم الدخول: 3-20 حرفاً إنجليزياً صغيراً أو أرقاماً'; end if;
  if exists (select 1 from public.profiles where username = p_username)
     or exists (select 1 from auth.users where lower(email) = p_username || '@rms-portal.com') then
    raise exception 'اسم الدخول مستخدم مسبقاً';
  end if;
  v_group := case when public.is_admin() then p_group else public.my_group() end;
  insert into public.branch_invites (username, name, role, position, branch_ids, group_id)
  values (p_username, p_name, 'branch', 'branch_manager', '{}', v_group)
  on conflict (username) do update
    set name = excluded.name, role = 'branch', position = 'branch_manager', branch_ids = '{}', group_id = excluded.group_id;
end $$;

create or replace function public.admin_invite_staff(p_username text, p_name text, p_position text, p_branch_ids uuid[], p_group uuid default null)
returns void language plpgsql security definer set search_path = public, auth as $$
declare v_scope text;
begin
  if not public.is_admin() then raise exception 'غير مصرح'; end if;
  if p_username !~ '^[a-z0-9_]{3,20}$' then raise exception 'اسم الدخول: 3-20 حرفاً إنجليزياً صغيراً أو أرقاماً'; end if;
  select scope into v_scope from public.positions where key = p_position;
  if v_scope is null then raise exception 'الوظيفة غير موجودة'; end if;
  if v_scope = 'own' then raise exception 'هذه الوظيفة خاصة بحسابات الفروع'; end if;
  if exists (select 1 from public.profiles where username = p_username)
     or exists (select 1 from auth.users where lower(email) = p_username || '@rms-portal.com') then
    raise exception 'اسم الدخول مستخدم مسبقاً';
  end if;
  insert into public.branch_invites (username, name, role, position, branch_ids, group_id)
  values (p_username, p_name, 'staff', p_position, coalesce(p_branch_ids, '{}'), p_group)
  on conflict (username) do update
    set name = excluded.name, role = 'staff', position = excluded.position,
        branch_ids = excluded.branch_ids, group_id = excluded.group_id;
end $$;

revoke execute on function public.admin_invite_branch(text,text,uuid) from public, anon;
revoke execute on function public.admin_invite_staff(text,text,text,uuid[],uuid) from public, anon;
grant  execute on function public.admin_invite_branch(text,text,uuid) to authenticated;
grant  execute on function public.admin_invite_staff(text,text,text,uuid[],uuid) to authenticated;

-- سياسة الدعوات: غير الأدمن لا يدعو إلا داخل مجموعته
drop policy if exists bi_all on public.branch_invites;
create policy bi_all on public.branch_invites for all to authenticated
  using (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope()
         and group_id is not distinct from public.my_group()))
  with check (public.is_admin() or (public.has_perm('m_branches') and public.is_all_scope()
              and role = 'branch' and coalesce(position, 'branch_manager') = 'branch_manager'
              and group_id is not distinct from public.my_group()));

-- الإشعارات: لا يرى إشعارات فرع خارج نطاقه
drop policy if exists n_sel on public.notifications;
drop policy if exists n_upd on public.notifications;
create policy n_sel on public.notifications for select to authenticated using (
  to_user = auth.uid()
  or (to_admin and public.has_any(array['m_reports','m_review'])
      and (from_user is null or public.visible_branch(from_user))));
create policy n_upd on public.notifications for update to authenticated using (
  to_user = auth.uid()
  or (to_admin and public.has_any(array['m_reports','m_review'])
      and (from_user is null or public.visible_branch(from_user))));

-- طلب استعادة كلمة المرور يحمل صاحب الطلب (لتُحجب عن المجموعات الأخرى)
create or replace function public.request_password_reset(p_email text)
returns void language plpgsql security definer set search_path = public as $$
declare v_name text; v_id uuid; v_text text;
begin
  select id, name into v_id, v_name from public.profiles
   where role <> 'admin' and lower(email_contact) = lower(trim(p_email)) limit 1;
  if v_name is not null then
    v_text := 'طلب استعادة كلمة المرور من ' || v_name;
    if not exists (select 1 from public.notifications
                   where to_admin and text = v_text and created_at > now() - interval '1 hour') then
      insert into public.notifications (to_admin, text, from_user) values (true, v_text, v_id);
    end if;
  end if;
end $$;
