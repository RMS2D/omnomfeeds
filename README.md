# oM noM Security Feeds

A security-research news terminal. Pulls from RSS, Reddit, Bluesky, Mastodon, GitHub Security Advisories, and MalwareBazaar, deduplicates, scores by relevance across the cybersecurity surface (vulnerability research, threat intel, cloud / web / endpoint / mobile, identity, supply chain), enriches each CVE with NVD + EPSS + CISA KEV + OTX data inline, extracts threat actor and malware family mentions, and renders the result as a keyboard-driven two-pane reader in your browser.

Single Go binary. Embedded UI. SQLite on disk. No telemetry.

```
> j/k:nav  o:open  m:read  b:★  /:search  s:src  t:type  1-9:score  u:unread  d:dupes  r:refresh  : :cmd  D:decode  v:viz  c:config  ?:help
```

## Two ways to run it

| Mode | Who it's for | Cost |
|---|---|---|
| **Self-host** (this repo) | One person on their box. Single user, full control. | Free, MIT-licensed |
| **Hosted** ([omnomfeeds.com](https://omnomfeeds.com)) | People who don't want to run anything. Same code, multi-user. | Free tier; $10/mo Pro |

The hosted version runs identical code with `HOSTED_MODE=true` flipping multi-tenancy on. Pro gates only apply when hosted; in self-host every endpoint is open because you ARE the operator.

---

## Features

### Reader

- Two-pane keyboard-driven interface (vim bindings)
- Per-source, per-type, per-score filtering
- Bookmark + read-state tracking
- Cross-source deduplication (URL normalisation + title cosine similarity)
- Force-refresh, source-health view, IOC decoder paste-box

### CVE enrichment

- Click any CVE-ID for a popover with **CVSS**, **EPSS percentile**, **CWE**, **CISA KEV status** (with "actively exploited" + "pre-KEV mention" chips), and **AlienVault OTX pulse count**
- Per-CVE timeline: orders events as `first mention → vendor advisory → first PoC → latest activity`
- KEV catalog refreshed every 24h; EPSS scores reloaded daily

### Threat actor + malware family chips

- 30 curated threat actors (APT41, Lazarus, Scattered Spider, LockBit, Cl0p, ...) and 30 malware families (Cobalt Strike, Mimikatz, RedLine, Sliver, ...) detected via curated alias lists
- Click any chip to filter the feed to articles mentioning that actor or family

### MITRE ATT&CK Navigator export

- Articles are auto-tagged with referenced techniques
- Export a Navigator v4.5 layer JSON for "everything I read this week" or "everything I bookmarked tagged initial-access"
- Drops straight into the public Navigator UI

### Webhook routing (Pro / self-host with config)

- Route KEV pop alerts, breaking news, or custom score-threshold matches to Discord, Slack, Teams, or generic JSON endpoints
- SSRF-guarded poster (rejects RFC1918 + link-local + loopback)

### AI triage (self-host: BYOK)

- One-sentence Claude Haiku summary under each article row ("what does the post actually say, separate from the headline")
- Runs on a 5-minute worker, ~$0.0005/article, opt-out
- Per-article and per-CVE deep-dive explainers
- Daily AI digest of the highest-signal items

### Patch Tuesday brief

- Auto-generated vendor-bucketed brief on the second Tuesday of each month
- Toggle which vendors you care about (Microsoft, Adobe, Oracle, SAP, ...)

### Daily digest email (self-host: BYOK)

- Email summary of high-score items in the last 24h, delivered at the user's preferred time
- Per-article direct links, unsubscribe in the email

### JSON REST API

- `/api/articles`, `/api/cve/<id>`, `/api/actors/<slug>`, `/api/malware/<slug>`, `/api/attack/export`, `/api/sources`, `/api/stats`
- Self-host: open. Hosted: per-user API tokens (Pro)

---

## Install

### One-liner installers (recommended)

**Linux / macOS:**

```
curl -fsSL https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.sh | sh
```

**Windows (PowerShell):**

```
irm https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.ps1 | iex
```

The installers detect your OS + architecture, fetch the latest release, and drop the binary on your PATH (`/usr/local/bin` or `~/.local/bin` on unix, `%LOCALAPPDATA%\secfeed` on Windows).

Pin a specific version with `SECFEED_VERSION=v0.2.0` or override the install dir with `SECFEED_INSTALL=~/.bin` before piping.

### Pre-built binaries (manual)

Download the archive for your platform from the [Releases](https://github.com/RMS2D/omnomfeeds/releases) page, extract, run.

### From source

```
go install github.com/RMS2D/omnomfeeds@latest
```

This drops `secfeed` (or `secfeed.exe`) into `$GOPATH/bin`.

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

On first launch, oM noM Security Feeds writes a default config to your OS user config directory:

| OS      | Path                                                |
|---------|-----------------------------------------------------|
| Linux   | `~/.config/secfeed/config.json`                     |
| macOS   | `~/Library/Application Support/secfeed/config.json` |
| Windows | `%APPDATA%\secfeed\config.json`                     |

The SQLite database lives alongside the config (`secfeed.db`).

Open `http://localhost:8080` in a browser. Press `?` for the keybind help.

---

## Configuration

Three layers, later overrides earlier:

1. **The default config** (embedded in the binary, written on first run)
2. **Your `config.json`** (live-editable; press `c` in the app for the GUI panel)
3. **Environment variables** (override secrets at process start)

### Environment variables

| Var | Purpose |
|---|---|
| `SECFEED_CONFIG` | Path to an alternate config file |
| `BLUESKY_APP_PASSWORD` | Bluesky app password (free, generate at bsky.app) |
| `MALWAREBAZAAR_API_KEY` | abuse.ch MalwareBazaar key (free) |
| `GITHUB_TOKEN` | GitHub PAT for GHSA + LOLBAS scrape (60 req/hr unauthed -> 5000 req/hr authed) |
| `ANTHROPIC_API_KEY` | Enable AI triage, per-article explainer, AI digest (Claude Haiku). BYOK for self-host. |
| `OPENAI_API_KEY` | Alternate AI provider; takes precedence if both are set |
| `RESEND_API_KEY` | Enable daily digest email + magic-link login. Needs a verified sending domain. |
| `HOSTED_MODE` | `true` to flip multi-tenancy on (auth, billing, per-user state). Off by default. |

You can also pass a config path as the first CLI arg: `./secfeed /path/to/config.json`.

---

## Sources shipped by default

**RSS / Atom (53 feeds):**

- **Vulnerability + CISA:** CISA Alerts, CISA KEV, Exploit-DB, SANS ISC, Full Disclosure, oss-security
- **Vendor PSIRTs:** Microsoft Security, Cisco Talos, Palo Alto Unit 42, Palo Alto PSIRT, Fortinet PSIRT, AWS Security Bulletins, Google Security Blog, Adobe PSIRT, GitLab Security, GitHub Security Lab
- **Research blogs:** Project Zero, Securelist (Kaspersky), ESET WeLiveSecurity, Rapid7 Blog, SentinelOne Blog, CrowdStrike Blog, Elastic Security, Recorded Future, Mandiant (M-Trends), JFrog Security Research
- **Offensive / red team:** SpecterOps, MDSec, Outflank, TrustedSec, Black Hills InfoSec, Bishop Fox, Praetorian
- **DFIR / blue team:** The DFIR Report, NVISO Security, Volatility Labs, MalwareTech
- **News + commentary:** BleepingComputer, The Hacker News, Krebs on Security, SecurityWeek, Dark Reading, The Register Security, CyberScoop
- **LOLBins / LOLDrivers:** LOLBAS Commits, LOLDrivers Commits
- **Distros:** Debian Security, Ubuntu Security Notices, Red Hat Security Advisories

(Full list lives in `config.default.json`. PR welcome for missing feeds.)

**Reddit (10 subs):** r/netsec, r/cybersecurity, r/malware, r/ReverseEngineering, r/blueteamsec, r/AskNetsec, r/threatintel, r/Pentesting, r/sysadmin, r/Bitwarden

**Mastodon:** infosec.exchange + ioc.exchange (configurable)

**GitHub Security Advisories:** all CRITICAL + HIGH severity, plus a PoC repo scraper for known LOLBAS / LOLDriver tracker repos

**MalwareBazaar:** new-sample feed (requires a free abuse.ch API key)

**Bluesky:** off by default. Enable in `config.json` with an app password and a list of search terms + watched handles. A starter handle list lives at [examples/researcher-handles.json](examples/researcher-handles.json) (70+ infosec researchers); copy any subset into `config.json` → `bluesky.watched_accounts`.

---

## Scoring

Articles are scored 0-100 based on keyword relevance to:

- AWL / EDR / AMSI / ETW bypass, BYOVD, execution-control evasion
- Zero-days, active exploitation, RCE
- Process injection, DLL sideloading, LOLBins, C2 frameworks
- Supply-chain compromise, bootkits, rootkits, firmware implants
- Threat actor activity (APT groups, ransomware crews)
- Detection engineering, DFIR, IOC pivots

Any CVE referenced in CISA KEV auto-scores 100 and gets a red KEV pulse on the chip. The KEV catalog is refreshed every 24h. A "pre-KEV mention" chip fires when a CVE is heating up across multiple curated sources before CISA adds it.

Tune the categories or weights by editing the keyword lists in `internal/scoring/scoring.go`.

---

## Keybinds

```
Navigation
  j / k         next / prev item
  g / G         top / bottom
  ctrl-d/u      half-page down / up
  space         toggle preview pane

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
  U             undo last filter change

Tools
  r             force refresh
  :  /  ^K      command palette (fuzzy-search any action)
  D             IOC decoder (paste hash / CVE / IP / URL / domain)
  v             sources distribution visualization
  c             open config panel
  ?             keybind help
```

---

## Self-hosting at scale

Self-host runs comfortably on a `t3.small` / 1-vCPU 1 GB droplet:

- Resident memory: ~120-180 MB after warm-up
- Disk: SQLite + WAL, ~50 MB/month of article growth on default feeds
- Network: ~30 MB/day of RSS fetches at default poll intervals

For a multi-user self-host (rare but supported), set `HOSTED_MODE=true` and bring `ANTHROPIC_API_KEY`, `RESEND_API_KEY`, and Google OAuth or Resend-magic-link creds. Same code path as the hosted version.

A `/healthz` endpoint reports `{status, version, uptime_s, hosted_mode}` for uptime monitoring.

---

## Hosted version

[`omnomfeeds.com`](https://omnomfeeds.com) runs this codebase with `HOSTED_MODE=true`. Free tier is the full reader + CVE enrichment + actor/malware chips + ATT&CK export. Pro tier ($10/mo) adds:

- Daily digest email at a time you choose
- Webhook routing for KEV / breaking-news / custom alerts
- Per-user custom RSS sources
- AI personalization (re-sorts the feed by relevance to a profile blurb)
- Bookmarks + read state synced across devices
- REST API tokens

Same code as this repo. The Pro wall is operational (hosted infrastructure + my time running it), not feature-based - if you self-host with BYOK API keys, you get everything.

---

## Privacy

**Self-host:**

- All data stays local. The SQLite DB is yours; nothing leaves the machine without an explicit pivot click.
- All source-API calls go direct from your machine to the source (`abuse.ch`, `bsky.app`, `nvd.nist.gov`, etc.). No proxy through us.
- No telemetry. No update pings. No analytics.
- API keys you set via the config panel are written to `config.json` on your disk. Env-var keys never touch disk.

**Hosted (omnomfeeds.com):**

- We store: email (for login), opaque session ID, your bookmarks / read marks / alert rules, billing identifiers from Stripe.
- We log: feature-usage counts via an internal analytics layer (no IPs, no UAs, no fingerprints; opaque session token only). Used to decide which features to keep building.
- We do not sell or share user data.
- Full policy at [omnomfeeds.com/privacy](https://omnomfeeds.com/privacy).

---

## License

[MIT](LICENSE). oM noM Security Feeds contributors.
