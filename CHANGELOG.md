# Changelog

All notable changes get a line here. Format roughly follows
[Keep a Changelog](https://keepachangelog.com/). Versioning is
[SemVer](https://semver.org/).

## [Unreleased]

## [1.0.0]

First public release. Self-host single binary + hosted instance at
omnomfeeds.com running the same code.

### Reader surfaces
- Web reader at `localhost:8080`: two-pane vim-keybind interface with
  9 modals (settings, MITRE coverage, stats, intel brief, IOC decoder,
  source viz, help, command palette, curated Bluesky picker).
- Bubbletea TUI (`./secfeed tui`) at full self-host parity with the
  web reader: 12+ keybinds, async NVD/EPSS lookups, score explainer,
  ATT&CK Navigator export, bookmarks.

### Sources
- 55+ RSS feeds across major security publications, vendor PSIRT
  blogs, government advisories, and academic security blogs.
- Bluesky firehose search + 107-entry curated researcher watchlist.
- Mastodon instances + hashtag aggregation.
- GitHub Security Advisories + PoC discovery.
- Reddit (`/r/netsec`, `/r/AskNetsec`, etc.).
- MalwareBazaar IOC feed (BYOK).
- MSRC Security Update Guide + Mandiant Threat Intel.

### Enrichment
- NVD CVE detail (CVSS v3, CWE, descriptions, publication dates).
- EPSS exploit-probability scores via daily refresh.
- CISA KEV awareness with red-pulse styling.
- AlienVault OTX pulse counts.
- MITRE ATT&CK technique extraction + Navigator v4.5 layer export.

### Scoring + dedup
- Keyword-category scoring with MITRE ATT&CK mapping; categories
  exposed via `/api/scoring` for transparency.
- URL normalisation + title-hash dedup across sources.
- Optional LLM semantic dedup (hosted, BYOK).

### Public surfaces
- Server-rendered `/cve/<id>` landing pages with KEV chip, EPSS,
  vendor PSIRT timeline, researcher consensus heatmap, dynamic
  sitemap.
- `/trending` top-50 CVE leaderboard.
- `/pre-kev` watchlist (CVEs heating up before CISA adds them to KEV).
- `/api` public REST docs.

### Hosted-mode features
- Google OAuth + magic-link (Resend) auth.
- Stripe billing for the Pro tier.
- Webhook alerts (Slack / Discord / generic) with SSRF guard.
- Email digests (daily / weekly).
- LLM-powered Patch Tuesday brief generator.
- Inline triage one-liners for high-score articles (BYOK).
- ATT&CK Navigator export over a user's bookmarked set.

### Hardening
- Cookies: HttpOnly + Secure + SameSite=Lax.
- CSP + Cache-Control on `/app`.
- SSRF guard on outbound webhooks (dial-time IP check + redirect
  re-validation, closes rebinding window).
- `io.LimitReader` on every feed and enrichment HTTP body.
- Per-IP + per-email magic-link rate limiting.
- Slowloris-safe `ReadHeaderTimeout`.
- Cosign-keyless signing on release artefacts via GitHub OIDC.
- systemd unit with `ProtectSystem=strict`, `SystemCallFilter`, empty
  `CapabilityBoundingSet`.

[Unreleased]: https://github.com/RMS2D/omnomfeeds/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/RMS2D/omnomfeeds/releases/tag/v1.0.0
