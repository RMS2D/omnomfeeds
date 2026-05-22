# oM noM Security Feeds

A self-hosted security news reader. Pulls 55+ RSS feeds, Reddit, Bluesky, Mastodon, GitHub Security Advisories, and MalwareBazaar; deduplicates across them; scores articles by keyword relevance to your threat model; cross-references every CVE-ID against NVD, EPSS, CISA KEV, and AlienVault OTX inline.

**Two surfaces, same data, one binary:**

- **`./secfeed`** - HTTP daemon + web reader at `localhost:8080`. Two-pane vim-keybind interface in the browser.
- **`./secfeed tui`** - Bubbletea terminal reader. Same keybinds, same features, no browser. For when you live in tmux.

Single Go binary. Embedded UI. SQLite on disk. No telemetry. MIT-licensed.

```
> j/k:nav  o:open  b:★  /:search  s:src  t:type  1-9:score  u:unread  d:dupes  r:refresh  c:CVE  D:IOC  T:mitre  S:stats  v:viz  I:brief  W:gone  L:trending  P:patch  E:export  e:explain  ?:help
```

## Why this exists

Every morning, staying current on security meant 30-60 minutes of fragmented browsing - Twitter for breaking news, r/netsec, BleepingComputer, NVD for new CVEs, CISA KEV for newly-exploited stuff, vendor PSIRT blogs for whatever ships next. The signal-to-noise was terrible and the cross-referencing was manual ("is this CVE in KEV? did anyone serious post about it? what's the EPSS?"). This is the tool that consolidates that morning - one corpus, scored, KEV-flagged, threat-actor-tagged, with a vim-style reader for triaging fast.

Two surfaces because security teams live in different places. Web reader for sharing URLs with the team; TUI for the operator who's already in tmux and doesn't want one more browser tab.

Built solo. The hosted version at [omnomfeeds.com](https://omnomfeeds.com) runs this same binary if you want to try the web reader before installing, but the OSS path is fully usable and is what this README is about.

---

## What it does

### Reader

- Two-pane vim-style interface (`j`/`k` nav, `o` open, `b` bookmark, `/` search)
- Per-source, per-type, per-score filtering with one-keystroke toggles
- Cross-source deduplication (URL normalisation + title cosine similarity)
- Bookmark + read-state, force-refresh, source-health view
- Command palette (`:` or `Ctrl-K`) for fuzzy-search across every action
- IOC decoder (`D`): paste a hash / CVE / IPv4 / URL / domain → pivot links to VirusTotal, MalwareBazaar, AbuseIPDB, GreyNoise, Shodan, NVD, etc.

### CVE enrichment

- Click any CVE-ID for an inline popover with **CVSS v3 score + severity**, **EPSS percentile**, **CWE**, **CISA KEV status** (red pulse if actively exploited; amber "pre-KEV" if heating up across curated sources before CISA adds it), **AlienVault OTX pulse count**
- Per-CVE timeline: orders events as `first mention → vendor advisory → first PoC → latest activity`
- Per-CVE shareable page at `/cve/<id>` showing all of the above plus every article from the corpus that mentioned it
- KEV catalog refreshed every 24h; EPSS scores reloaded daily; NVD details cached locally per CVE

### Threat actor + malware family chips

- 30 curated threat actors (APT41, Lazarus, Scattered Spider, LockBit, Cl0p, Volt Typhoon, ...) and 30 malware families (Cobalt Strike, Mimikatz, RedLine, Sliver, BumbleBee, ...) detected via curated alias lists
- Click any chip to filter the corpus to articles mentioning that actor or family
- Per-actor + per-malware shareable pages with all referencing articles

### Public CVE leaderboards

- `/trending` - top CVEs by mention count across the corpus, last 7d
- `/pre-kev` - CVEs being talked about by 3+ curated sources but NOT yet in CISA KEV (early-warning list)
- `/live` - real-time stream of newly-ingested articles (SSE)

These work without an account; share them with your team.

### MITRE ATT&CK Navigator export

- Articles are auto-tagged with referenced ATT&CK technique IDs
- Export a Navigator v4.5 layer JSON for "everything tagged initial-access" or "everything I bookmarked this week"
- Drops straight into [attack-navigator.mitre.org](https://mitre-attack.github.io/attack-navigator/) → `Open Existing Layer`

### Webhook routing

- Route CISA KEV pops, breaking-news matches, or custom score-threshold matches to Discord, Slack, Teams, or generic JSON endpoints
- SSRF-guarded poster: rejects RFC1918, link-local, loopback, and DNS-rebinding payloads at dial time

### AI features (BYOK)

- One-sentence triage line under each article ("what does the post actually say, separate from the headline"). Runs on a 5-min worker against high-score articles, ~$0.0005/article through Claude Haiku
- Per-article + per-CVE deep-dive explainers on demand
- Daily AI digest (`I` keybind) of the last 24h's highest-signal items
- "While you were gone" brief (`W` keybind) summarising what's accumulated since your last visit
- AI is fully opt-in. Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` to enable; leave unset for a pure-keyword install

### Patch Tuesday brief

- Auto-generated vendor-bucketed brief on the second Tuesday of each month
- Configure which vendors you care about (Microsoft, Adobe, Oracle, SAP, Cisco, ...)

### Daily digest email

- Email summary of the last 24h's high-score items at a time you pick
- Per-article direct links, unsubscribe in every email
- Needs `RESEND_API_KEY` + a verified sending domain

### JSON REST API

- Full reader is available headlessly: `/api/articles`, `/api/cve/<id>`, `/api/actors/<slug>`, `/api/malware/<slug>`, `/api/attack/export`, `/api/sources`, `/api/stats`, `/api/trending`, `/api/pre-kev`
- `/feed.xml` exposes the corpus as RSS for piping into your existing reader
- Bearer-token auth (per-user tokens, SHA-256-at-rest)
- Full docs at `/api` on a running instance

---

## Install

### One-liner (recommended)

**Linux / macOS:**

```
curl -fsSL https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.sh | sh
```

**Windows (PowerShell):**

```
irm https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.ps1 | iex
```

The installers detect OS + arch, fetch the latest release, and drop the binary on your PATH (`/usr/local/bin` or `~/.local/bin` on unix, `%LOCALAPPDATA%\secfeed` on Windows).

Pin a specific version with `SECFEED_VERSION=v0.2.0` before piping; override install dir with `SECFEED_INSTALL=~/.bin`.

### Pre-built binaries (manual)

Grab the archive for your platform from [Releases](https://github.com/RMS2D/omnomfeeds/releases), extract, run.

### From source

```
go install github.com/RMS2D/omnomfeeds@latest
```

Drops `secfeed` (or `secfeed.exe`) into `$GOPATH/bin`.

### Build from a checkout

```
git clone https://github.com/RMS2D/omnomfeeds
cd omnomfeeds
go build -o secfeed .
./secfeed
```

---

## First run

```
./secfeed
```

On first launch, the binary writes a default config to your OS user config directory:

| OS      | Path                                                |
|---------|-----------------------------------------------------|
| Linux   | `~/.config/secfeed/config.json`                     |
| macOS   | `~/Library/Application Support/secfeed/config.json` |
| Windows | `%APPDATA%\secfeed\config.json`                     |

The SQLite database lives alongside the config (`secfeed.db`).

Open `http://localhost:8080` in a browser. Press `?` for the keybind cheatsheet.

---

## Configuration

Three layers, later overrides earlier:

1. **Default config** (embedded in the binary, written on first run)
2. **`config.json`** (live-editable; press `c` in the app for the GUI panel)
3. **Environment variables** (override secrets at process start)

### Environment variables

| Var | Purpose |
|---|---|
| `SECFEED_CONFIG` | Path to an alternate config file |
| `BLUESKY_APP_PASSWORD` | Bluesky app password (free, generate at bsky.app) |
| `MALWAREBAZAAR_API_KEY` | abuse.ch MalwareBazaar key (free) |
| `GITHUB_TOKEN` | GitHub PAT for GHSA + LOLBAS scraping (60 req/hr unauthed → 5000 authed) |
| `ANTHROPIC_API_KEY` | Enable AI triage, explainers, daily brief (Claude Haiku) |
| `OPENAI_API_KEY` | Alternate AI provider; takes precedence if both are set |
| `RESEND_API_KEY` | Enable daily digest email + magic-link login. Needs a verified sending domain |
| `HOSTED_MODE` | `true` to flip multi-tenancy on (auth, billing, per-user state). Off by default |

You can also pass a config path as the first CLI arg: `./secfeed /path/to/config.json`.

---

## Sources shipped by default

**RSS / Atom (55 feeds):**

- **Vulnerability + CISA:** CISA Alerts, CISA KEV, Exploit-DB, SANS ISC, Full Disclosure, oss-security
- **Vendor PSIRTs:** Microsoft Security, MSRC Update Guide, Cisco Talos, Palo Alto Unit 42, Palo Alto PSIRT, Fortinet PSIRT, AWS Security Bulletins, Google Security Blog, GitHub Security Lab, Sophos Security Advisories
- **Research blogs:** Project Zero, Securelist (Kaspersky), ESET WeLiveSecurity, Rapid7 Blog, SentinelOne Blog, CrowdStrike Blog, Elastic Security, Recorded Future, Mandiant Threat Intel, Wiz Research
- **Offensive / red team:** SpecterOps, MDSec, Outflank, TrustedSec, Black Hills InfoSec, Bishop Fox, Praetorian
- **DFIR / blue team:** The DFIR Report, NVISO Security, Volatility Labs, Volexity, Microsoft Threat Intel
- **News + commentary:** BleepingComputer, The Hacker News, Krebs on Security, SecurityWeek, Dark Reading, The Register, CyberScoop, Risky Business, The Record, Schneier on Security
- **LOLBins / LOLDrivers:** LOLBAS Commits, LOLDrivers Commits
- **Distros + browser:** Debian DSA, Ubuntu Security Notices, Chrome Releases, Mozilla Security
- **Academia:** arXiv cs.CR

Full list lives in `config.default.json`. PRs welcome for missing feeds.

**Reddit (10 subs):** r/netsec, r/cybersecurity, r/malware, r/ReverseEngineering, r/blueteamsec, r/redteamsec, r/AskNetsec, r/computerforensics, r/crypto, r/Pentesting

**Mastodon:** infosec.exchange + ioc.exchange (configurable)

**GitHub Security Advisories:** all CRITICAL + HIGH severity, plus PoC repo scrapers for known LOLBAS / LOLDriver tracker repos

**MalwareBazaar:** new-sample feed (needs a free abuse.ch API key)

**Bluesky:** off by default. Enable in `config.json` with an app password + a list of search terms + watched handles. A starter handle list lives at [examples/researcher-handles.json](examples/researcher-handles.json) (100+ infosec researchers); copy any subset into `config.json` → `bluesky.watched_accounts`.

---

## Scoring

Articles are scored 0-100 based on keyword relevance to:

- AWL / EDR / AMSI / ETW bypass, BYOVD, execution-control evasion
- Zero-days, active exploitation, RCE
- Process injection, DLL sideloading, LOLBins, C2 frameworks
- Supply-chain compromise, bootkits, rootkits, firmware implants
- Threat actor activity (APT groups, ransomware crews)
- Detection engineering, DFIR, IOC pivots

Any CVE referenced in CISA KEV auto-scores 100 and gets a red KEV pulse. The KEV catalog is refreshed every 24h. A "pre-KEV mention" chip fires when a CVE is heating up across 3+ curated sources before CISA adds it - useful early-warning signal.

Tune categories or weights by editing keyword lists in `internal/scoring/scoring.go` or via the **Filtering** tab in the config modal (`c`).

---

## Surfaces

Two ways to use the reader. Same SQLite, same scoring, same data.

### Web reader (`./secfeed`)

The default. Starts an HTTP daemon on `localhost:8080` that fetches feeds, scores them, fires webhooks, and serves the two-pane reader UI in your browser. Press `?` in the app for the live keybind cheatsheet.

Public surfaces the daemon also serves:
- **`/trending`** - top CVEs by mention count, last 7 days
- **`/pre-kev`** - CVEs being talked about across 3+ curated sources but not yet in CISA KEV (early-warning list)
- **`/cve/<id>`** - per-CVE deep-dive page (CVSS / EPSS / KEV / OTX + every article that mentioned it)
- **`/live`** - SSE stream of newly-ingested articles
- **`/feed.xml`** - the corpus as RSS, for piping into your existing reader

### Terminal reader (`./secfeed tui`)

A [Bubbletea](https://github.com/charmbracelet/bubbletea) TUI hitting the same SQLite. Two-pane interface, vim-keybinds, mouse-free workflow. Designed for the operator who already lives in tmux.

```
┌─[ ●●● FEED ]─────────────────────────────┬─[ READER ]──────────────────────────┐
│  46 ★ [BleepingComputer] CVE-2026-...    │  [CVE Alerts] CVE-2026-34216 -      │
│ ▌47 ● [TheHackerWire] CVE-2026-2587 ...  │  CtrlPanel: Authenticated RCE       │
│  43   [Blockchain Report] Grafana's ...  │                                     │
│  35   [eu-forums.bsky.social] Ekrem ...  │  ◆ Bluesky  ·  2d ago  ·  score 42  │
│  ...                                     │                                     │
│                                          │  rce  T1190  cisa kev  exploit      │
│                                          │                                     │
│                                          │  ◆ AI triage: Authenticated RCE     │
│                                          │  in CtrlPanel admin UI - patch ...  │
│                                          │                                     │
│                                          │  url: https://github.com/.../...    │
└──────────────────────────────────────────┴─────────────────────────────────────┘
filters: score≥10                          j/k nav   o open   /search   ? help
```

The daemon (`./secfeed`) handles fetching. Run it in the background, then open either or both readers. They share the SQLite via WAL so concurrent reads + occasional writes (mark-read, bookmark) are clean.

```
# Terminal 1: daemon
./secfeed

# Terminal 2 (or any time later): TUI on the same data
./secfeed tui
```

The TUI is a self-host-only surface. It opens the local SQLite directly; there's no auth, no remote API to hit. To use the AI features (`I` brief, `W` "while you were gone" brief), set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY` in the environment before launching.

## Keybinds

Both surfaces share the same keybinds. Anything you learn in the web reader works in the TUI and vice versa.

```
Navigation
  j / k         next / prev item
  g / G         top / bottom
  ctrl-d/u      half-page down / up
  space         toggle preview pane (web only)

Reading
  o / Enter     open in browser (marks read)
  m             toggle read on selected
  M             mark all visible read
  b             toggle bookmark (★) on selected
  B             filter to bookmarked only / clear

Filters
  1..9          min score (10..90)
  0             clear score
  /             incremental search (ESC clears)
  s             source picker (j/k, Enter, ESC)
  t             cycle source-type filter
  u             toggle unread-only
  d             toggle show-dupes
  U             undo last filter change (web only)

Tools
  r             force refresh
  :  /  ^K      command palette (web only - fuzzy-search any action)
  c             CVE deep-dive popover (CVSS / EPSS / KEV / consensus / timeline)
  D             IOC decoder (paste hash / CVE / IP / URL / domain)
  T             MITRE ATT&CK coverage modal
  S             Feast Stats (per-source + per-tag bar charts)
  v             Feeding Tubes (source distribution chart)
  I             AI intel brief :: last 24h (needs ANTHROPIC_API_KEY)
  W             while you were gone brief :: last 4h
  L             leaderboards :: /trending + /pre-kev
  P             Patch Tuesday brief reader
  e             score explainer (which keywords fired?)
  E             export MITRE ATT&CK Navigator layer JSON
  ?             keybind cheatsheet
  q / ctrl-c    quit TUI
```

Some web-only operations (`U` undo filter, `space` preview toggle, `:` command palette, config panel) don't have TUI equivalents in v1 - the TUI defers config editing to your `$EDITOR` on `config.json` rather than embedding a multi-tab form in the terminal.

---

## Self-hosting at scale

Self-host runs comfortably on a 1-vCPU 1 GB droplet:

- Resident memory: ~120-180 MB after warm-up (with all default feeds)
- Disk: SQLite + WAL, ~50 MB/month of article growth on default feeds; older articles auto-archive to a compressed cold tier
- Network: ~30 MB/day of RSS fetches at default poll intervals (3 min for fast feeds, 10 min for normal)

For multi-user self-host (rare but supported), set `HOSTED_MODE=true` and bring `ANTHROPIC_API_KEY`, `RESEND_API_KEY`, plus Google OAuth or Resend-magic-link creds. Same code path as the hosted version.

A `/healthz` endpoint reports `{status, version, uptime_s, hosted_mode}` for uptime monitoring.

---

## Privacy

**Self-host:**

- All data stays local. The SQLite DB is yours; nothing leaves the machine without an explicit pivot click.
- All source-API calls go direct from your machine to the source (`abuse.ch`, `bsky.app`, `nvd.nist.gov`, etc.). No proxy through us.
- No telemetry. No update pings. No analytics.
- API keys you set via the config panel are written to `config.json` on your disk. Env-var keys never touch disk.

---

## Don't want to run anything?

[`omnomfeeds.com`](https://omnomfeeds.com) is the same binary with `HOSTED_MODE=true`. The free tier is the full reader, CVE enrichment, actor/malware chips, public leaderboards, ATT&CK export, IOC decoder, MITRE coverage view. A $10/mo Pro tier adds the cross-device-sync, email digest, webhook alerts, AI features, and REST API tokens that are normally BYOK on self-host.

The Pro wall is operational (someone has to pay the hosting + Anthropic + Resend bills), not feature-based. Everything is the same MIT-licensed Go binary on this repo - if you self-host with your own BYOK keys, you get all of it.

Hosted privacy policy at [omnomfeeds.com/privacy](https://omnomfeeds.com/privacy).

---

## Tier comparison

| | Self-host | Hosted free | Hosted Pro |
|---|---|---|---|
| All 55+ RSS / Reddit / Bluesky / Mastodon sources | ✅ | ✅ | ✅ |
| **Web reader** (browser, `localhost:8080`) | ✅ | ✅ | ✅ |
| **Bubbletea TUI** (`./secfeed tui`) | ✅ | - | - |
| CVE enrichment (NVD + EPSS + KEV + OTX) | ✅ | ✅ | ✅ |
| Threat actor + malware family chips | ✅ | ✅ | ✅ |
| Public leaderboards (`/trending`, `/pre-kev`, `/cve/<id>`) | ✅ | ✅ | ✅ |
| MITRE ATT&CK Navigator export | ✅ | ✅ | ✅ |
| IOC decoder, MITRE coverage view, Feast Stats | ✅ | ✅ | ✅ |
| Two-pane reader, vim keybinds, command palette | ✅ | ✅ | ✅ |
| Bookmarks + read state | ✅ (local) | ✅ (local) | ✅ (synced across devices) |
| Per-user custom RSS sources | ✅ | - | ✅ |
| Webhook routing (Slack / Discord / Teams / generic) | ✅ | - | ✅ |
| AI triage, daily brief, "while you were gone" | ✅ (BYOK) | - | ✅ (managed) |
| Daily digest email | ✅ (BYOK Resend) | - | ✅ |
| REST API access | ✅ (open) | ✅ (open, no auth needed for read) | ✅ (per-user tokens) |
| AI personalization (re-rank by interest blurb) | ✅ (BYOK) | - | ✅ |
| Price | Free | Free | $10/mo (founder pricing, locked in for life) |
| Your data | Stays on your box | We hold it (see privacy) | We hold it (see privacy) |

Self-host is the recommended path if you have a box. The hosted product exists because not everyone wants to run a daemon, and the AI features require a paid Anthropic key which is awkward to BYOK if you don't already use Claude.

---

## License

[MIT](LICENSE). oM noM Security Feeds contributors.
