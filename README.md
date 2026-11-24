# LYVORA — Connect Libya. Share Your World.

Libyan social platform: React + TypeScript + Tailwind + Supabase (Postgres, Auth, Storage, Realtime).

## Status
| Phase | State |
|---|---|
| 1. Setup + design system | Done |
| 2. Auth + profiles | Done (needs your Supabase project to run) |
| 3. Feed + posts (edit-less), pagination, empty/error/loading states | Done |
| 4. Image/video upload (4 images or 1 video, type+size checks, files removed with post) | Done |
| 5. Likes, comments + replies, bookmarks, share link, report, follow | Done |
| 6. Notifications (realtime, mark-all-read, per-type preferences in DB) | Done. Private messaging not started |
| 6b. Private messaging: 1:1, realtime, unread counts, read receipts (text only), blocked-user restriction | Done |
| 7. Search (users, posts, #hashtags) + Explore (trending posts/hashtags, suggested accounts, real data only) | Done |
| 9. Admin: stats, reports, suspend/ban, delete content, hashtags, audit log (all enforced server-side) | Done |
| 14–16. Settings, legal pages (templates: have them reviewed), AR/EN | Done |
| 8. Stories + short videos | Database tables + RLS only, no UI yet |
| Not built | Image messages, online status display, light theme, Google/email edge cases untested, automated tests |

## Setup
1. Create a project at supabase.com.
2. SQL Editor → run, in order, `supabase/migrations/001_core_auth_profiles.sql` then `002_posts_social.sql`.
3. Authentication → URL Configuration: Site URL = your site (http://localhost:5173 for dev); add `/home` and `/reset-password` to Redirect URLs.
4. Authentication → Providers → Email: keep "Confirm email" ON.
5. Google login: Providers → Google → add Client ID/Secret from Google Cloud Console (OAuth client, redirect = the callback URL Supabase shows).
6. `cp .env.example .env` and fill in the project URL and **anon** key (Project Settings → API). Never use the service_role key here.
7. `npm install && npm run dev`

## Make yourself admin (only possible via SQL, never from the app)
```sql
insert into public.admin_roles (user_id, role)
select id, 'super_admin' from auth.users where email = 'you@example.com';
```

## Test checklist (Phase 2)
- Register → confirm email → land on /home → profile exists at /u/<username>.
- Taken username shows "Username is taken" before submit.
- Forgot password → email link → /reset-password → new password works.
- Edit profile: avatar (≤2MB) and cover (≤5MB) upload; a .gif or oversized file is rejected.
- Private toggle: a new follow on a private account shows "Requested".
- Delete account removes the profile and auth user.
- Arabic ↔ English switch flips direction and persists after reload.

## Deploy (Vercel)
Import the GitHub repo, framework Vite, add the two env vars, deploy. `vercel.json` handles SPA routing.
