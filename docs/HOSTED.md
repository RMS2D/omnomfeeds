# Hosted mode design notes

This document scopes the multi-tenant hosted variant of oM noM. It is the
working spec for the `feat/hosted` branch. Self-host single-binary stays the
canonical distribution; hosted adds account-aware deployment of the same
code via a `HOSTED_MODE=true` env flag.

## Two distributions, one codebase

| Mode | Trigger | Storage | Users | Auth |
| --- | --- | --- | --- | --- |
| Self-host (current) | default | SQLite local | single, implicit | none |
| Hosted | `HOSTED_MODE=true` | SQLite (WAL) on the same droplet | many | Google OAuth + magic link via email, session cookie |

**On the SQLite decision (revised from Postgres).** Workload doesn't justify
Postgres complexity at the scales we're targeting. SQLite in WAL mode handles
~60 writes/sec sustained, which corresponds to ~10k+ active users at our
write profile. Litestream replicates the file to R2 for off-box backup. If
we ever cross that ceiling, migration to Postgres is a known recipe; doing
it now on hypotheticals just burns days for zero benefit.

The fetch loop, scoring engine, MITRE / NVD / EPSS enrichers, web UI, and
every keybind work identically in both modes. The differences are confined to:

- `internal/config`: hosted mode reads OAuth + Resend + Stripe + session
  secrets from env vars instead of loading a single `config.json`.
- `internal/storage`: same SQLite store; hosted-mode tables co-exist with
  the self-host article cache.
- `internal/auth`: new package. Two login methods, both producing a row
  in `users`:
    - **Google OAuth** for one-click sign-in
    - **Magic link** via Resend for users who don't want a Google account
      (ProtonMail, FastMail, self-hosted, work email).
  Sessions are server-side rows in `user_sessions`; the cookie carries
  the unhashed token, the DB holds SHA-256.
- `internal/server`: new endpoints under `/api/me/*` for per-user data
  (settings, bookmarks, read state, alert rules, stack profile).
- `web/index.html`: minor diffs that surface login/account state when
  hosted mode is active. The worm UI itself is unchanged.

## Free vs Pro

### Free hosted (login required)

Sign in with Google or by entering your email and clicking a magic link.
Across devices, your account holds:

- Watched accounts (Bluesky), enabled sources, all settings
- Bookmarks, read state, filters, source pickers, search history
- Worm preferences (spicy mode, divider position, sources)
- 30-day article history
- BYOK API key entry for the AI digest (free tier requires you to supply your own key)

### Pro ($5/mo, cancel anytime)

Everything in Free, plus:

**Convenience**
- Managed AI brief: daily intel digest tuned to user focus, no BYOK setup
- Email digest: daily/weekly summary delivered via Resend

**Operational**
- KEV webhook alerts: Slack / Discord / generic webhook fired within minutes
  of a new CISA KEV entry
- Saved keyword alerts: user-defined keywords / CVE patterns trigger same
  webhook + email path
- Stack-aware prioritization: per-user scoring overlay based on declared
  tech tags + optional dependency manifests
- Dependency advisory matcher: pinned-version CVE alerts when a manifest
  is uploaded
- Daily blast-radius brief: morning AI summary of what specifically affects
  the user's stack

**Power**
- REST API: token-issued endpoints for query + bookmark + alerts CRUD
- Custom private feeds: add private RSS URLs that fetch under the user's
  account
- 6 months article history retention (vs 30 days free)
- Threat actor follow: subscribe to curated APT / ransomware names, get
  per-actor feed page + trending detection
- Full-corpus search vs free's account-history search

## Schema

Tables added on top of the existing self-host schema. Self-host continues to
use the same `articles`, `cve_details`, `epss` tables; hosted adds the
user-scoped tables below. The SQL shown here is Postgres-style for
readability; the SQLite implementation in `internal/storage/storage.go`
substitutes TEXT for UUID, BLOB for BYTEA, DATETIME for TIMESTAMPTZ, and
TEXT for JSONB.

```sql
-- Users. id_provider="google"|"email", id_external = google sub or email.
CREATE TABLE users (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  id_provider     TEXT NOT NULL,
  id_external     TEXT NOT NULL,
  email           TEXT NOT NULL,
  display_name    TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  pro_until       TIMESTAMPTZ,
  UNIQUE (id_provider, id_external),
  UNIQUE (email)
);

-- One-time magic-link tokens for email-based login. TTL 15min, single use.
CREATE TABLE magic_link_tokens (
  token_hash      BYTEA PRIMARY KEY,
  email           TEXT NOT NULL,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  expires_at      TIMESTAMPTZ NOT NULL,
  used_at         TIMESTAMPTZ,
  user_agent      TEXT,
  ip_hash         BYTEA
);

CREATE TABLE user_sessions (
  token_hash      BYTEA PRIMARY KEY,
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  user_agent      TEXT,
  expires_at      TIMESTAMPTZ NOT NULL
);

-- Free-form per-user settings: theme prefs, divider width, scanline toggle,
-- spicy mode, watched Bluesky accounts, declared focus area, anything we'd
-- otherwise put in localStorage.
CREATE TABLE user_settings (
  user_id         UUID PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  settings        JSONB NOT NULL DEFAULT '{}',
  updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Per-user article state. (user_id, article_id) unique.
CREATE TABLE user_read_state (
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id      TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  read_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, article_id)
);

CREATE TABLE user_bookmarks (
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  article_id      TEXT NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
  bookmarked_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  note            TEXT,
  PRIMARY KEY (user_id, article_id)
);

-- Pro feature: stack profile. Tags + parsed dep manifest entries.
CREATE TABLE user_stack_tags (
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  tag             TEXT NOT NULL,
  PRIMARY KEY (user_id, tag)
);

CREATE TABLE user_dep_packages (
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ecosystem       TEXT NOT NULL,          -- "go", "npm", "pypi", "cargo", "rubygems"
  name            TEXT NOT NULL,
  version_pin     TEXT NOT NULL,
  uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, ecosystem, name)
);

-- Pro feature: saved keyword alerts.
CREATE TABLE user_alert_rules (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  kind            TEXT NOT NULL,          -- "kev", "keyword", "cve_pattern", "actor", "dep_match"
  pattern         TEXT NOT NULL,          -- the keyword / CVE / regex / actor name
  channel         TEXT NOT NULL,          -- "email", "slack_webhook", "discord_webhook", "generic_webhook"
  channel_target  TEXT,                   -- webhook URL or null for email-to-account
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_fired_at   TIMESTAMPTZ
);

-- Pro feature: subscribed threat actors.
CREATE TABLE user_actor_follows (
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  actor_slug      TEXT NOT NULL,          -- curated list, e.g. "volt-typhoon", "lockbit"
  followed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (user_id, actor_slug)
);

-- Pro feature: user-added private RSS sources, fetched by the same loop
-- but only their articles surface to that user.
CREATE TABLE user_custom_sources (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  url             TEXT NOT NULL,
  enabled         BOOLEAN NOT NULL DEFAULT TRUE,
  last_fetch_at   TIMESTAMPTZ,
  last_error      TEXT,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Pro feature: API tokens for power users.
CREATE TABLE user_api_tokens (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name            TEXT NOT NULL,
  token_hash      BYTEA NOT NULL UNIQUE,
  scopes          TEXT[],
  created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_used_at    TIMESTAMPTZ,
  revoked_at      TIMESTAMPTZ
);

CREATE INDEX ON user_read_state (user_id, read_at DESC);
CREATE INDEX ON user_bookmarks (user_id, bookmarked_at DESC);
CREATE INDEX ON user_alert_rules (user_id, enabled);
CREATE INDEX ON user_custom_sources (user_id, enabled);
```

Articles themselves stay global. Each user gets their own overlay of read,
bookmark, settings, and alert state on top of the shared fetched corpus.

## Implementation phases

1. Storage layer: add Postgres support behind the existing storage interface.
   Hosted mode uses `pgstore`; self-host stays on `sqlitestore`. Both
   implement `storage.Store`.
2. Auth: `internal/auth` package. Google OAuth callback at `/auth/callback`.
   Session cookies via `Secure; HttpOnly; SameSite=Lax`. Optional CSRF for
   state-changing endpoints.
3. Per-user settings + read/bookmark state. Client-side sends `Authorization`
   or relies on session cookie; server resolves user via middleware.
4. Stripe entitlement check. `pro_until > NOW()` gates Pro endpoints. Webhook
   handler updates `pro_until` from `checkout.session.completed`,
   `invoice.paid`, `customer.subscription.deleted` events.
5. **Managed AI brief**: cron daily 06:00 UTC. For each Pro user, build the
   prompt with their focus tag and their last-24h top-scored articles. Call
   Anthropic with server-side key. Store result in `user_ai_briefs`. Email
   delivery via Resend. **Ship Pro at this point.**
6. KEV webhook + saved keyword alerts. Hook into the fetch loop: after
   each scored article is upserted, evaluate it against every active alert
   rule; fire webhooks asynchronously.
7. Stack-aware prioritization + dep matcher. Per-user scoring overlay
   applied at query time against `user_stack_tags` + `user_dep_packages`.
   Adds boost to articles whose tags/CPE/keywords overlap with the user's
   stack.
8. Threat actor follow + actor feed pages.
9. Daily blast-radius brief: composes from items 5+6+7 into one paragraph.
10. Email digest, full-corpus search, custom feeds, 6mo history.

## Hosting

- Single droplet on DigitalOcean (`ubuntu-s-1vcpu-1gb-nyc1` with a reserved
  IP). Caddy reverse-proxies to the Go binary on `localhost:8080`.
- Postgres co-located on the box for v1. Move to a managed db only if
  resource pressure shows up.
- Stripe customer portal handles cancellations + invoice access; we never
  build a billing UI ourselves.
- Resend for transactional email.
- Backups: nightly `pg_dump` to local `/var/backups/omnomfeeds/` plus
  weekly upload to R2 (or DO Spaces) for off-box. Retain 30 days.

## Privacy + ToS

- No analytics, no telemetry, no tracking pixels in the email digest.
- Article reading state is per-user, not shared. Aggregate / anonymized
  "trending" data is explicitly opt-out, default off.
- One-click "Delete my account" wipes user row + cascades all per-user
  data. No tombstone, no soft delete.
- Termly-generated privacy policy + ToS at `/privacy` and `/terms`,
  shown on signup.

## Open questions

- Postgres on the same droplet vs managed: stay co-located until traffic
  forces the issue. Backups can ship to R2 either way.
- Bluesky watched-account fetches: currently one source instance for all
  users. In hosted mode, each Pro user can add their own watched accounts.
  Option A: pool all users' watched accounts in one fetch loop, dedup
  results per-user. Option B: per-user fetcher (cost: more API calls to
  Bluesky). A is the right call.
- Email rate limits: Resend free tier covers ~3k emails/mo. Past that,
  ~$20/mo for 50k. Defer until we have signups.
- Free tier abuse: anonymous signups + immediate Pro signup might attract
  fraud. Stripe Radar handles most of it; if it becomes a problem, add
  email verification or a credit-card-required step for Pro.
