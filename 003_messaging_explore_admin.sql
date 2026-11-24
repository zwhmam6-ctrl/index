-- LYVORA migration 003 — messaging, explore RPCs, admin RPCs, stories tables, suspended-user guard

-- suspended / banned users cannot write
create or replace function public.require_active() returns trigger language plpgsql security definer set search_path = public as $$
declare uid uuid := coalesce(to_jsonb(new)->>'author_id', to_jsonb(new)->>'sender_id')::uuid;
begin
  if (select status from profiles where id = uid) <> 'active' then raise exception 'account suspended'; end if;
  return new;
end $$;
create trigger posts_active before insert on public.posts for each row execute function public.require_active();
create trigger comments_active before insert on public.comments for each row execute function public.require_active();

-- ───────── messaging ─────────
create table public.conversations (id uuid primary key default gen_random_uuid(), created_at timestamptz not null default now());
create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index cm_user_idx on public.conversation_members (user_id);
create table public.messages (
  id bigint generated always as identity primary key,
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 2000),
  created_at timestamptz not null default now()
);
create index messages_conv_idx on public.messages (conversation_id, created_at desc);

create or replace function public.is_member(p_conv uuid) returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from conversation_members where conversation_id = p_conv and user_id = auth.uid());
$$;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;
create policy "conv member read" on public.conversations for select using (public.is_member(id));
create policy "members read" on public.conversation_members for select using (public.is_member(conversation_id));
create policy "messages read" on public.messages for select using (public.is_member(conversation_id));
create policy "messages send" on public.messages for insert with check (
  auth.uid() = sender_id and public.is_member(conversation_id)
  and not exists (select 1 from conversation_members m join blocks b
      on (b.blocker_id = m.user_id and b.blocked_id = auth.uid()) or (b.blocker_id = auth.uid() and b.blocked_id = m.user_id)
      where m.conversation_id = messages.conversation_id and m.user_id <> auth.uid()));
-- no client inserts into conversations/members: use start_conversation()

create or replace function public.start_conversation(p_other uuid) returns uuid
language plpgsql security definer set search_path = public as $$
declare cid uuid;
begin
  if auth.uid() is null or p_other = auth.uid() then raise exception 'invalid'; end if;
  if exists (select 1 from blocks where (blocker_id = p_other and blocked_id = auth.uid()) or (blocker_id = auth.uid() and blocked_id = p_other)) then raise exception 'blocked'; end if;
  select a.conversation_id into cid from conversation_members a join conversation_members b on a.conversation_id = b.conversation_id
    where a.user_id = auth.uid() and b.user_id = p_other limit 1;
  if cid is null then
    insert into conversations default values returning id into cid;
    insert into conversation_members (conversation_id, user_id) values (cid, auth.uid()), (cid, p_other);
  end if;
  return cid;
end $$;
grant execute on function public.start_conversation(uuid) to authenticated;

create or replace function public.mark_read(p_conv uuid) returns void language sql security definer set search_path = public as $$
  update conversation_members set last_read_at = now() where conversation_id = p_conv and user_id = auth.uid();
$$;
grant execute on function public.mark_read(uuid) to authenticated;

create or replace function public.trg_notify_message() returns trigger language plpgsql security definer set search_path = public as $$
declare r uuid;
begin
  for r in select user_id from conversation_members where conversation_id = new.conversation_id and user_id <> new.sender_id loop
    perform notify(r, new.sender_id, 'message', null);
  end loop; return new;
end $$;
create trigger messages_active before insert on public.messages for each row execute function public.require_active();
create trigger notify_message after insert on public.messages for each row execute function public.trg_notify_message();
alter publication supabase_realtime add table public.messages;

-- ───────── explore (security invoker: RLS still applies) ─────────
create or replace function public.trending_hashtags() returns table (tag text, uses bigint)
language sql stable as $$
  select h.tag::text, count(*) from post_hashtags ph join hashtags h on h.id = ph.hashtag_id join posts p on p.id = ph.post_id
  where p.created_at > now() - interval '7 days' group by h.tag order by count(*) desc limit 10;
$$;
create or replace function public.popular_accounts() returns table (id uuid, username text, display_name text, avatar_url text, followers bigint)
language sql stable as $$
  select p.id, p.username::text, p.display_name, p.avatar_url, count(f.follower_id)
  from profiles p left join follows f on f.following_id = p.id and f.status = 'accepted'
  where p.status = 'active' and p.id <> auth.uid()
    and not exists (select 1 from follows me where me.follower_id = auth.uid() and me.following_id = p.id)
    and not exists (select 1 from blocks b where (b.blocker_id = auth.uid() and b.blocked_id = p.id) or (b.blocker_id = p.id and b.blocked_id = auth.uid()))
  group by p.id order by count(f.follower_id) desc, p.created_at desc limit 8;
$$;
create or replace function public.trending_posts() returns setof uuid language sql stable as $$
  select p.id from posts p left join likes l on l.post_id = p.id and l.created_at > now() - interval '7 days'
  where p.created_at > now() - interval '7 days' group by p.id having count(l.user_id) > 0 order by count(l.user_id) desc limit 10;
$$;

-- ───────── admin ─────────
create or replace function public.admin_stats() returns json language plpgsql stable security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  return json_build_object(
    'users', (select count(*) from profiles), 'posts', (select count(*) from posts), 'comments', (select count(*) from comments),
    'open_reports', (select count(*) from reports where status = 'open'),
    'active_users', (select count(distinct a) from (select author_id a from posts where created_at > now() - interval '7 days'
                      union select author_id from comments where created_at > now() - interval '7 days'
                      union select sender_id from messages where created_at > now() - interval '7 days') x));
end $$;
create or replace function public.admin_set_status(p_user uuid, p_status text) returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  if p_status not in ('active','suspended','banned') then raise exception 'invalid status'; end if;
  if exists (select 1 from admin_roles where user_id = p_user) then raise exception 'cannot moderate an admin'; end if;
  update profiles set status = p_status where id = p_user;
  insert into audit_logs (actor_id, action, target_type, target_id, details) values (auth.uid(), 'set_status', 'user', p_user::text, json_build_object('status', p_status)::jsonb);
end $$;
create or replace function public.admin_review_report(p_id bigint, p_status text, p_delete boolean default false) returns void language plpgsql security definer set search_path = public as $$
declare r reports;
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  select * into r from reports where id = p_id;
  if p_delete then
    if r.target_type = 'post' then delete from posts where id = r.target_id::uuid;
    elsif r.target_type = 'comment' then delete from comments where id = r.target_id::uuid; end if;
  end if;
  update reports set status = p_status where id = p_id;
  insert into audit_logs (actor_id, action, target_type, target_id, details) values (auth.uid(), 'review_report', 'report', p_id::text, json_build_object('status', p_status, 'deleted', p_delete)::jsonb);
end $$;
create or replace function public.admin_delete_hashtag(p_id bigint) returns void language plpgsql security definer set search_path = public as $$
begin
  if not is_admin() then raise exception 'forbidden'; end if;
  delete from hashtags where id = p_id;
  insert into audit_logs (actor_id, action, target_type, target_id) values (auth.uid(), 'delete_hashtag', 'hashtag', p_id::text);
end $$;
revoke all on function public.admin_stats(), public.admin_set_status(uuid,text), public.admin_review_report(bigint,text,boolean), public.admin_delete_hashtag(bigint) from public, anon;
grant execute on function public.admin_stats(), public.admin_set_status(uuid,text), public.admin_review_report(bigint,text,boolean), public.admin_delete_hashtag(bigint) to authenticated;
grant execute on function public.trending_hashtags(), public.popular_accounts(), public.trending_posts() to authenticated;

-- ───────── stories (tables + RLS; UI not built yet) ─────────
create table public.stories (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  media_url text not null, kind text not null check (kind in ('image','video')),
  created_at timestamptz not null default now(), expires_at timestamptz not null default now() + interval '24 hours'
);
create index stories_active_idx on public.stories (user_id, expires_at);
create table public.story_views (
  story_id uuid not null references public.stories(id) on delete cascade,
  viewer_id uuid not null references public.profiles(id) on delete cascade,
  viewed_at timestamptz not null default now(), primary key (story_id, viewer_id)
);
alter table public.stories enable row level security;
alter table public.story_views enable row level security;
create policy "stories visible" on public.stories for select using (expires_at > now() and public.can_view_author(user_id));
create policy "story own insert" on public.stories for insert with check (auth.uid() = user_id);
create policy "story own delete" on public.stories for delete using (auth.uid() = user_id or public.is_admin());
create policy "view as self" on public.story_views for insert with check (auth.uid() = viewer_id);
create policy "owner or viewer reads views" on public.story_views for select
  using (viewer_id = auth.uid() or exists (select 1 from stories s where s.id = story_id and s.user_id = auth.uid()));
