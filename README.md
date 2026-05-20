# oM noM Security Feeds

A security-research news terminal. Pulls from RSS, Reddit, Bluesky, Mastodon, GitHub Security Advisories, and MalwareBazaar, deduplicates, scores by relevance across the full cybersecurity surface (vulnerability research, threat intel, cloud / web / endpoint / mobile, identity, supply chain), and renders the result as a keyboard-driven two-pane reader in your browser.

Single binary. Runs entirely on your machine. No telemetry. No proxy. All API calls go direct.

```
> j/k:nav  o:open  m:read  b:★  /:search  s:src  t:type  1-9:score  u:unread  d:dupes  r:refresh  : :cmd  D:decode  v:viz  c:config  ?:help
```

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

Open `http://localhost:8080` in a browser.

## Configuration

You have three ways to configure oM noM Security Feeds; later layers override earlier ones:

1. **The default config** (embedded in the binary, written on first run).
2. **Your `config.json`** (live-editable).
3. **Environment variables** (override secrets at process start):
   - `BLUESKY_APP_PASSWORD`
   - `MALWAREBAZAAR_API_KEY`
   - `GITHUB_TOKEN`
   - `SECFEED_CONFIG` (path to an alternate config file)

You can also pass a config path as the first CLI arg: `./secfeed /path/to/config.json`.

In the running app, press `c` for the in-app config panel (API keys, source health, behavior toggles).

## Sources shipped by default

**RSS / Atom (28 feeds):**
CISA Alerts, Exploit-DB, SANS ISC, Full Disclosure, oss-security, LOLBAS Commits, LOLDrivers Commits, BleepingComputer, The Hacker News, Krebs on Security, SecurityWeek, Dark Reading, Rapid7 Blog, SentinelOne Blog, Microsoft Security, Project Zero, Elastic Security, Unit42 (Palo Alto), Talos Intelligence, CrowdStrike Blog, Recorded Future, SpecterOps, MDSec, Outflank, TrustedSec, The DFIR Report, Black Hills InfoSec, NVISO Security.

**Reddit:** r/netsec, r/cybersecurity, r/malware, r/ReverseEngineering, r/blueteamsec.

**Mastodon:** infosec.exchange (configurable).

**GitHub Security Advisories:** all CRITICAL + HIGH severity, plus a PoC repo scraper for known LOLBAS / LOLDriver tracker repos.

**MalwareBazaar:** new sample feed (requires a free abuse.ch API key).

**Bluesky:** off by default. Enable in `config.json` with an app password and a list of search terms + watched handles. A starter handle list lives at [examples/researcher-handles.json](examples/researcher-handles.json) (70+ infosec researchers); copy any subset into `config.json` -> `bluesky.watched_accounts`.

## Scoring

Articles are scored 0-100 based on keyword relevance to:

- AWL / EDR / AMSI / ETW bypass, BYOVD, execution-control evasion
- Zero-days, active exploitation, RCE
- Process injection, DLL sideloading, LOLBins, C2 frameworks
- Supply-chain compromise, bootkits, rootkits, firmware implants
- Threat actor activity (APT groups, ransomware crews)
- Detection engineering, DFIR, IOC pivots

Any CVE referenced in CISA KEV auto-scores 100 and gets a red KEV pulse on the chip. The KEV catalog is refreshed every 24h.

Tune the categories or weights by editing the keyword lists in `internal/scoring/scoring.go`.

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

## Privacy

- All data stays local. The SQLite DB is yours; nothing leaves the machine without an explicit pivot click.
- All source-API calls go direct from your machine to the source (`abuse.ch`, `bsky.app`, `nvd.nist.gov`, etc.). No proxy through us.
- No telemetry. No update pings. No analytics.
- API keys you set via the config panel are written to `config.json` on your disk. Env-var keys never touch disk.

## License

[MIT](LICENSE). oM noM Security Feeds contributors.
