-- LYVORA migration 002 — posts, media, likes, comments, bookmarks, hashtags, reports, notifications
create or replace function public.can_view_author(p_author uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select auth.uid() = p_author
  or (
    not exists (select 1 from blocks b where (b.blocker_id = p_author and b.blocked_id = auth.uid())
                                         or (b.blocker_id = auth.uid() and b.blocked_id = p_author))
    and ( not (select is_private from profiles where id = p_author)
          or exists (select 1 from follows f where f.follower_id = auth.uid() and f.following_id = p_author and f.status = 'accepted') )
  );
$$;

create table public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text not null default '' check (char_length(body) <= 1000),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index posts_created_idx on public.posts (created_at desc);
create index posts_author_idx on public.posts (author_id, created_at desc);
create trigger posts_updated before update on public.posts for each row execute function public.set_updated_at();
alter table public.posts enable row level security;
create policy "posts visible" on public.posts for select using (public.can_view_author(author_id));
create policy "posts insert own" on public.posts for insert with check (auth.uid() = author_id);
create policy "posts update own" on public.posts for update using (auth.uid() = author_id) with check (auth.uid() = author_id);
create policy "posts delete own or admin" on public.posts for delete using (auth.uid() = author_id or public.is_admin());

-- rate limit: 20 posts/hour, 30 comments/hour per user
create or replace function public.rate_limit_posts() returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from posts where author_id = new.author_id and created_at > now() - interval '1 hour') >= 20 then
    raise exception 'rate limit: too many posts';
  end if;
  return new;
end $$;
create trigger posts_rate before insert on public.posts for each row execute function public.rate_limit_posts();

create table public.post_media (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  url text not null,
  storage_path text not null,
  kind text not null check (kind in ('image','video')),
  position smallint not null default 0
);
create index post_media_post_idx on public.post_media (post_id);
alter table public.post_media enable row level security;
create policy "media visible" on public.post_media for select
  using (exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "media insert own" on public.post_media for insert
  with check (exists (select 1 from posts p where p.id = post_id and p.author_id = auth.uid()));
create policy "media delete own" on public.post_media for delete
  using (exists (select 1 from posts p where p.id = post_id and p.author_id = auth.uid()));

create table public.likes (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)          -- no duplicate likes
);
alter table public.likes enable row level security;
create policy "likes visible" on public.likes for select
  using (exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "like as self" on public.likes for insert
  with check (auth.uid() = user_id and exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "unlike as self" on public.likes for delete using (auth.uid() = user_id);

create table public.comments (
  id uuid primary key default gen_random_uuid(),
  post_id uuid not null references public.posts(id) on delete cascade,
  author_id uuid not null references public.profiles(id) on delete cascade,
  parent_id uuid references public.comments(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 500),
  created_at timestamptz not null default now()
);
create index comments_post_idx on public.comments (post_id, created_at);
alter table public.comments enable row level security;
create policy "comments visible" on public.comments for select
  using (exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "comment as self" on public.comments for insert
  with check (auth.uid() = author_id and exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "comment delete own/admin" on public.comments for delete using (auth.uid() = author_id or public.is_admin());

create table public.comment_likes (
  comment_id uuid not null references public.comments(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  primary key (comment_id, user_id)
);
alter table public.comment_likes enable row level security;
create policy "clikes read" on public.comment_likes for select using (true);
create policy "clike self" on public.comment_likes for insert with check (auth.uid() = user_id);
create policy "cunlike self" on public.comment_likes for delete using (auth.uid() = user_id);

create table public.bookmarks (
  post_id uuid not null references public.posts(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id)
);
alter table public.bookmarks enable row level security;
create policy "own bookmarks" on public.bookmarks for select using (auth.uid() = user_id);
create policy "bookmark self" on public.bookmarks for insert with check (auth.uid() = user_id);
create policy "unbookmark self" on public.bookmarks for delete using (auth.uid() = user_id);

-- hashtags
create table public.hashtags (id bigint generated always as identity primary key, tag citext not null unique);
create table public.post_hashtags (
  post_id uuid not null references public.posts(id) on delete cascade,
  hashtag_id bigint not null references public.hashtags(id) on delete cascade,
  primary key (post_id, hashtag_id)
);
create index post_hashtags_tag_idx on public.post_hashtags (hashtag_id);
alter table public.hashtags enable row level security;
alter table public.post_hashtags enable row level security;
create policy "hashtags read" on public.hashtags for select using (true);
create policy "post_hashtags read" on public.post_hashtags for select
  using (exists (select 1 from posts p where p.id = post_id and public.can_view_author(p.author_id)));
create policy "admins manage hashtags" on public.hashtags for delete using (public.is_admin());

create or replace function public.extract_hashtags() returns trigger language plpgsql security definer set search_path = public as $$
declare m text[]; hid bigint;
begin
  delete from post_hashtags where post_id = new.id;
  for m in select regexp_matches(new.body, '#([[:alnum:]_\u0600-\u06FF]{2,50})', 'g') loop
    insert into hashtags (tag) values (m[1]) on conflict (tag) do nothing;
    select id into hid from hashtags where tag = m[1];
    insert into post_hashtags values (new.id, hid) on conflict do nothing;
  end loop;
  return new;
end $$;
create trigger posts_hashtags after insert or update of body on public.posts for each row execute function public.extract_hashtags();

-- reports
create table public.reports (
  id bigint generated always as identity primary key,
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  target_type text not null check (target_type in ('post','comment','user')),
  target_id text not null,
  reason text not null check (char_length(reason) between 3 and 300),
  status text not null default 'open' check (status in ('open','reviewed','dismissed')),
  created_at timestamptz not null default now(),
  unique (reporter_id, target_type, target_id)
);
alter table public.reports enable row level security;
create policy "report as self" on public.reports for insert with check (auth.uid() = reporter_id);
create policy "own reports read" on public.reports for select using (auth.uid() = reporter_id or public.is_admin());
create policy "admins update reports" on public.reports for update using (public.is_admin());

-- notifications
create table public.notifications (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  actor_id uuid not null references public.profiles(id) on delete cascade,
  type text not null check (type in ('follow','like','comment','reply','message','mention')),
  post_id uuid references public.posts(id) on delete cascade,
  read boolean not null default false,
  created_at timestamptz not null default now()
);
create index notifications_user_idx on public.notifications (user_id, created_at desc);
alter table public.notifications enable row level security;
create policy "own notifications read" on public.notifications for select using (auth.uid() = user_id);
create policy "own notifications mark read" on public.notifications for update using (auth.uid() = user_id) with check (auth.uid() = user_id);
create policy "own notifications delete" on public.notifications for delete using (auth.uid() = user_id);
-- inserts only via triggers below
alter publication supabase_realtime add table public.notifications;

create or replace function public.notify(p_user uuid, p_actor uuid, p_type text, p_post uuid) returns void
language plpgsql security definer set search_path = public as $$
declare ok boolean;
begin
  if p_user = p_actor then return; end if;
  select case p_type when 'follow' then notify_follows when 'like' then notify_likes
                     when 'comment' then notify_comments when 'reply' then notify_comments
                     when 'mention' then notify_mentions else notify_messages end
    into ok from user_settings where user_id = p_user;
  if coalesce(ok, true) then insert into notifications (user_id, actor_id, type, post_id) values (p_user, p_actor, p_type, p_post); end if;
end $$;
revoke all on function public.notify(uuid, uuid, text, uuid) from public, anon, authenticated;

create or replace function public.trg_notify_follow() returns trigger language plpgsql security definer set search_path = public as $$
begin perform notify(new.following_id, new.follower_id, 'follow', null); return new; end $$;
create trigger notify_follow after insert on public.follows for each row execute function public.trg_notify_follow();

create or replace function public.trg_notify_like() returns trigger language plpgsql security definer set search_path = public as $$
begin perform notify((select author_id from posts where id = new.post_id), new.user_id, 'like', new.post_id); return new; end $$;
create trigger notify_like after insert on public.likes for each row execute function public.trg_notify_like();

create or replace function public.trg_notify_comment() returns trigger language plpgsql security definer set search_path = public as $$
declare owner uuid; parent_author uuid;
begin
  select author_id into owner from posts where id = new.post_id;
  if new.parent_id is not null then
    select author_id into parent_author from comments where id = new.parent_id;
    perform notify(parent_author, new.author_id, 'reply', new.post_id);
  end if;
  perform notify(owner, new.author_id, 'comment', new.post_id);
  return new;
end $$;
create trigger notify_comment after insert on public.comments for each row execute function public.trg_notify_comment();

-- post media storage (public read; write only inside own folder)
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types) values
  ('post-media', 'post-media', true, 52428800, array['image/jpeg','image/png','image/webp','video/mp4','video/webm'])
on conflict (id) do nothing;
create policy "post-media read" on storage.objects for select using (bucket_id = 'post-media');
create policy "post-media upload own" on storage.objects for insert to authenticated
  with check (bucket_id = 'post-media' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "post-media delete own" on storage.objects for delete to authenticated
  using (bucket_id = 'post-media' and (storage.foldername(name))[1] = auth.uid()::text);
