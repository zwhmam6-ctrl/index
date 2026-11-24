-- LYVORA migration 001 — Phase 1/2: profiles, settings, follows, blocks, admin roles, audit logs, storage
-- Run in Supabase → SQL Editor (or `supabase db push`).

create extension if not exists citext;

-- ───────────── helpers ─────────────
create or replace function public.set_updated_at() returns trigger
language plpgsql as $$ begin new.updated_at = now(); return new; end $$;

-- ───────────── admin roles (created first: used by policies) ─────────────
create table public.admin_roles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('super_admin','moderator')),
  granted_by uuid references auth.users(id),
  created_at timestamptz not null default now()
);
alter table public.admin_roles enable row level security;
-- No insert/update/delete policies: clients can NEVER grant roles. Grant via SQL editor only.

create or replace function public.is_admin() returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.admin_roles where user_id = auth.uid());
$$;

create policy "admins read roles" on public.admin_roles for select using (public.is_admin());

-- ───────────── profiles ─────────────
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username citext not null unique
    check (username ~ '^[a-zA-Z0-9_]{3,20}$'),
  display_name text not null check (char_length(display_name) between 1 and 50),
  avatar_url text,
  cover_url text,
  bio text check (char_length(bio) <= 300),
  location text check (char_length(location) <= 60),
  website text check (char_length(website) <= 120),
  is_private boolean not null default false,
  status text not null default 'active' check (status in ('active','suspended','banned')),
  last_seen_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index profiles_created_idx on public.profiles (created_at desc);
create trigger profiles_updated before update on public.profiles
  for each row execute function public.set_updated_at();
alter table public.profiles enable row level security;

create policy "profiles readable" on public.profiles for select using (true);
create policy "own profile update" on public.profiles for update
  using (auth.uid() = id) with check (auth.uid() = id);
-- No insert policy (created by trigger) and no delete policy (use delete_my_account()).

-- users may not change their own moderation status
create or replace function public.protect_profile_status() returns trigger
language plpgsql as $$
begin
  if new.status is distinct from old.status and not public.is_admin() then
    raise exception 'status can only be changed by an administrator';
  end if;
  return new;
end $$;
create trigger profiles_protect_status before update on public.profiles
  for each row execute function public.protect_profile_status();

-- ───────────── user settings ─────────────
create table public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  language text not null default 'ar' check (language in ('ar','en')),
  theme text not null default 'dark' check (theme in ('dark','light')),
  show_online_status boolean not null default true,
  notify_follows boolean not null default true,
  notify_likes boolean not null default true,
  notify_comments boolean not null default true,
  notify_messages boolean not null default true,
  notify_mentions boolean not null default true,
  updated_at timestamptz not null default now()
);
create trigger settings_updated before update on public.user_settings
  for each row execute function public.set_updated_at();
alter table public.user_settings enable row level security;
create policy "own settings read" on public.user_settings for select using (auth.uid() = user_id);
create policy "own settings update" on public.user_settings for update
  using (auth.uid() = user_id) with check (auth.uid() = user_id);

-- ───────────── profile + settings creation on signup ─────────────
create or replace function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
declare
  uname text;
  dname text;
begin
  uname := lower(coalesce(new.raw_user_meta_data->>'username', ''));
  if uname !~ '^[a-z0-9_]{3,20}$' or exists (select 1 from public.profiles where username = uname) then
    -- e.g. Google sign-in: derive a safe unique username
    uname := 'user_' || substr(replace(new.id::text, '-', ''), 1, 10);
  end if;
  dname := left(coalesce(nullif(new.raw_user_meta_data->>'display_name', ''),
                         nullif(new.raw_user_meta_data->>'full_name', ''),
                         split_part(coalesce(new.email, uname), '@', 1)), 50);
  insert into public.profiles (id, username, display_name, avatar_url)
  values (new.id, uname, dname, new.raw_user_meta_data->>'avatar_url');
  insert into public.user_settings (user_id) values (new.id);
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- username availability check usable before signup (anon)
create or replace function public.username_available(p_username text) returns boolean
language sql stable security definer set search_path = public as $$
  select not exists (select 1 from public.profiles where username = lower(p_username));
$$;
grant execute on function public.username_available(text) to anon, authenticated;

-- ───────────── follows ─────────────
create table public.follows (
  follower_id uuid not null references public.profiles(id) on delete cascade,
  following_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'accepted' check (status in ('pending','accepted')),
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),          -- prevents duplicate follows
  check (follower_id <> following_id)
);
create index follows_following_idx on public.follows (following_id, status);
alter table public.follows enable row level security;

create policy "follows readable" on public.follows for select using (true);
create policy "follow as self" on public.follows for insert
  with check (auth.uid() = follower_id);
create policy "unfollow as self or remove follower" on public.follows for delete
  using (auth.uid() = follower_id or auth.uid() = following_id);
create policy "accept requests" on public.follows for update
  using (auth.uid() = following_id) with check (auth.uid() = following_id);

-- server decides pending vs accepted, never the client
create or replace function public.follows_set_status() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if (select is_private from public.profiles where id = new.following_id) then
    new.status := 'pending';
  else
    new.status := 'accepted';
  end if;
  if exists (select 1 from public.blocks
             where (blocker_id = new.following_id and blocked_id = new.follower_id)
                or (blocker_id = new.follower_id and blocked_id = new.following_id)) then
    raise exception 'blocked';
  end if;
  return new;
end $$;

-- ───────────── blocks ─────────────
create table public.blocks (
  blocker_id uuid not null references public.profiles(id) on delete cascade,
  blocked_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
alter table public.blocks enable row level security;
create policy "own blocks read" on public.blocks for select using (auth.uid() = blocker_id);
create policy "block as self" on public.blocks for insert with check (auth.uid() = blocker_id);
create policy "unblock as self" on public.blocks for delete using (auth.uid() = blocker_id);

create trigger follows_status_trg before insert on public.follows
  for each row execute function public.follows_set_status();

-- ───────────── audit logs ─────────────
create table public.audit_logs (
  id bigint generated always as identity primary key,
  actor_id uuid references auth.users(id) on delete set null,
  action text not null,
  target_type text,
  target_id text,
  details jsonb,
  created_at timestamptz not null default now()
);
create index audit_logs_created_idx on public.audit_logs (created_at desc);
alter table public.audit_logs enable row level security;
create policy "admins read audit" on public.audit_logs for select using (public.is_admin());
-- inserts happen only from security-definer functions

-- ───────────── account deletion ─────────────
create or replace function public.delete_my_account() returns void
language plpgsql security definer set search_path = public, auth as $$
begin
  if auth.uid() is null then raise exception 'not authenticated'; end if;
  insert into public.audit_logs (actor_id, action, target_type, target_id)
    values (auth.uid(), 'account_deleted', 'user', auth.uid()::text);
  delete from auth.users where id = auth.uid();   -- cascades to profile, settings, follows, blocks
end $$;
revoke all on function public.delete_my_account() from public, anon;
grant execute on function public.delete_my_account() to authenticated;

-- ───────────── storage ─────────────
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
  ('avatars', 'avatars', true, 2097152, array['image/jpeg','image/png','image/webp']),
  ('covers',  'covers',  true, 5242880, array['image/jpeg','image/png','image/webp'])
on conflict (id) do nothing;

-- files live under "<user_id>/<filename>"; users can write only inside their own folder
create policy "public read avatars/covers" on storage.objects for select
  using (bucket_id in ('avatars','covers'));
create policy "upload own folder" on storage.objects for insert to authenticated
  with check (bucket_id in ('avatars','covers') and (storage.foldername(name))[1] = auth.uid()::text);
create policy "update own folder" on storage.objects for update to authenticated
  using (bucket_id in ('avatars','covers') and (storage.foldername(name))[1] = auth.uid()::text);
create policy "delete own folder" on storage.objects for delete to authenticated
  using (bucket_id in ('avatars','covers') and (storage.foldername(name))[1] = auth.uid()::text);
