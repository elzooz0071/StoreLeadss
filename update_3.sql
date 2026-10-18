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
