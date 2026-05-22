# oM noM Security Feeds - launch posts + HN playbook

Drafts for HN, Reddit, Mastodon, X. Plus what I learned from research into how Show HN front-page posts in this niche actually break out.

---

## TL;DR posting plan

All times EDT (UTC-4 during DST).

| Channel | Day / time (EDT) | Why |
|---|---|---|
| **Hacker News** | Sun 08:00-11:00 AM | Highest breakout rate (~11.75% per Myriade's 157k-post dataset), low Sunday-morning submission competition, mods more active rescuing posts from /new |
| **r/netsec** | Mon-Wed 10:00 AM - 01:00 PM | Highest weekday engagement, post BEFORE HN so the karma is independent |
| **r/cybersecurity** | Tue 11:00 AM | Higher reach, post same day as r/netsec |
| **r/blueteamsec** | Wed 09:00 AM | Niche, post mid-week when triage volume is highest |
| **r/selfhosted** | Sat 10:00 AM | Weekend selfhost-tinkering audience |
| **Mastodon (infosec.exchange)** | Tue 10:00 AM | Same window as Reddit, post a screenshot |
| **X/Twitter** | Tue 10:00 AM | Same window. Tag a few infosec accounts (don't ask for boosts in the post itself) |

**Sequence to actually follow:**

1. **Mon morning EDT**: r/netsec + r/cybersecurity + Mastodon + X (build initial visibility)
2. **Wed morning EDT**: r/blueteamsec (separate conversation)
3. **Sat morning EDT**: r/selfhosted (selfhost-tinkering audience)
4. **Sun 08:00 AM EDT**: HN Show HN (the big one)

Spacing matters because if HN hits the front page, an r/netsec mod might recognise the URL was just posted there and treat it as cross-promotion (downweighted). 6-day gap should be enough.

---

## What makes Show HN posts hit the front page (research notes)

### The ranking math

- Score formula: `(votes - 1)^0.8 / (age_hours + 2)^1.8 × penalties`
- Gravity exponent 1.8 = you need **sustained** vote velocity, not a single spike
- Initial threshold to escape /new: **~8-10 organic upvotes + 2-3 substantive comments in the first 30 minutes**
- Without that velocity the post falls off /new in ~45 min
- Show HN posts route to BOTH /show and /newest = the closest thing to an explicit Show HN bonus

### Title patterns that won (last 12mo dataset)

1. **`Show HN: $NAME - $oneline-function`** (most common winning shape, lowest risk)
2. **`Show HN: $NAME - Self-hosted $X` or `$X alternative`** (highest signal density; triggers the "incumbent slayer" instinct)
3. **`Show HN: I built $X to $Y`** (personal-story; works when the motivation is specific)
4. **`Show HN: Open-source $X (with $differentiator)`** - the parenthetical does the heavy lifting

### Body framing that won

3-sentence pattern:
1. What it is, in product terms
2. The personal pain that caused it
3. The technical anchor that earns the audience (stack, constraints, size)

### Pricing-question handling (Tracecat's playbook = gold)

The "is this freemium garbage?" question lands within 20 minutes. Answer with:
- Self-host is **fully functional**, not a crippled demo
- Hosted tier removes **ops, not features**
- **No SSO tax. No audit-log tax. No per-seat.**
- Disclose what the hosted bill actually pays for

### Anti-patterns to avoid

- Marketing voice ("production-grade", "powerful", "seamless", "carefully crafted")
- Title that overpromises a technical claim you can't fully back ("single binary" when Postgres is required)
- Hidden paid tier where the free version is bait ("Free up to 1 feed")
- Required signup to try (dang has called this out dozens of times)
- No demo / video / screenshots for anything user-facing
- Forking an OSS project without crediting it in the body
- Replying defensively to criticism (editing your own copy mid-thread = praised)
- Posting from a brand-new account

### Things to do within 60 seconds of submitting

1. Post the backstory comment (it's drafted below - paste it)
2. Make sure the linked GitHub repo loads
3. Make sure the linked hosted demo (if any) doesn't require signup to look at

### Things to do within the first 4 hours

1. Be at the keyboard. Respond to every comment.
2. When pricing question lands, paste the pricing comment (drafted below)
3. If someone says "isn't this just $X" - acknowledge similarities, name the differences
4. If someone finds a bug, fix it live and reply with the commit SHA
5. Don't argue. Edit your own marketing copy if criticism is fair.

---

## HN post

### Submit URL

`https://github.com/RMS2D/omnomfeeds`

(GitHub repo, NOT omnomfeeds.com. Self-host first positioning. The hosted demo is mentioned in the body for "try without installing" and the GitHub README's "Don't want to run anything?" section.)

### Title

```
Show HN: oM noM - Bubbletea TUI + web reader for security feeds, KEV-aware
```

(74 chars. `Show HN: $NAME - $function` pattern. "Bubbletea TUI" is the HN-attractor (vim/terminal/charm-cli crowd); "web reader" tells the rest "we have a browser surface too if that's your thing"; "KEV-aware" is the security-niche differentiator.)

Backup titles if the first one doesn't hook:
- `Show HN: A vim-keybind TUI for security feeds with inline CVE/KEV cross-referencing`
- `Show HN: A self-hosted security feed reader (Bubbletea TUI + web UI, single Go binary)`

### Body (the box you fill in when submitting)

Don't fill this in. HN's Show HN body field is usually empty - the URL is what people click. If you must, keep it to one sentence:

```
Open-source security feed reader. Bubbletea TUI + web UI on the same data. Cross-references every CVE-ID inline against NVD, EPSS, CISA KEV, and OTX. Single Go binary, MIT-licensed.
```

### Backstory comment (paste within 60 seconds of submission)

```
OP here. Some context that didn't fit:

I'm a security engineer. Every morning was 30-60 minutes of fragment-browsing
Twitter for breaking news, r/netsec, BleepingComputer, NVD for new CVEs, CISA
KEV for newly-exploited stuff, vendor PSIRT blogs. The signal-to-noise was bad
and the cross-referencing was manual - "is this CVE in KEV? is anyone serious
posting about it? what's the EPSS?". This is what I wanted to exist.

It's one Go binary with two surfaces on the same SQLite:

  ./secfeed       # daemon + web reader at localhost:8080
  ./secfeed tui   # Bubbletea TUI on the same data

The TUI is the one I actually use most days. Two-pane, vim keybinds, CVE
popover with CVSS / EPSS / KEV / OTX, IOC decoder, MITRE ATT&CK coverage,
Feast Stats with bar charts, /trending + /pre-KEV leaderboards, AI intel
brief (BYOK Anthropic/OpenAI), bookmarks, source picker, the lot. Web
reader has the same keybinds for when you want to share a URL with
someone.

What's specifically security-flavoured (vs a generic RSS reader like
Miniflux / Fusion):

- Inline CVE chips: every CVE-ID in every article is clickable for
  CVSS v3 score + severity + vector, EPSS percentile, CWE, CISA KEV
  status (red pulse if actively exploited, amber "pre-KEV" if heating
  up across curated sources but not yet in KEV)
- Pre-KEV warning: flags CVEs being talked about by 3+ curated sources
  before CISA adds them to KEV. Surfaced two actively-exploited bugs
  2-5 days before CISA picked them up in testing.
- 30 curated threat actors (APT41, Lazarus, Scattered Spider, LockBit,
  Volt Typhoon...) and 30 malware families (Cobalt Strike, Mimikatz,
  Sliver, BumbleBee...) detected via alias lists
- MITRE ATT&CK Navigator v4.5 layer export - drops straight into
  attack-navigator.mitre.org for a coverage heatmap
- Webhook routing to Slack / Discord / Teams with an SSRF-guarded
  poster (rejects RFC1918, link-local, loopback, DNS rebinds)

Stack:
- One Go binary, ~24 MB. Bubbletea + bubbles + lipgloss for the TUI;
  embedded HTML for the web reader. SQLite + WAL.
- No Postgres. No Redis. No Docker required.
- ~120-180 MB RAM after warm-up on the default feed set
- Runs comfortably on a 1-vCPU 1 GB droplet

Things I'm honestly unsure about:
- Scoring is keyword-based and deterministic. Fast and explainable but
  not great at semantic relevance. AI re-ranking is opt-in BYOK; not
  sure if it should be more prominent in the README.
- The TUI doesn't have config-editor modals (webhook rules, source
  list, profile blurb) - those live in config.json. Web reader has
  GUI panels for them. Reasoning: terminal users are happier in
  $EDITOR on JSON than juggling forms in a TUI. Want to know if
  anyone disagrees.
- I run a hosted version at omnomfeeds.com because friends asked. The
  repo is the canonical thing - hosted is "I don't want a daemon, here's
  the same binary running for you." Pro tier is $10/mo and exists
  because Anthropic Haiku + Resend + the droplet bill is non-zero per
  active user. If anything in the README or website reads "open-source
  bait, paid SaaS switch" - that's a bug and I'd like to know.

Happy to answer questions on the Bubbletea / lipgloss build, the Go
stack, source curation, the KEV pre-warning algorithm, or the scoring
weights. Code:
https://github.com/RMS2D/omnomfeeds
```

### Pricing-question reply (ready to paste when asked)

```
Pre-emptive since this always comes up:

- Self-host is the whole product. MIT, no functional gates. BYOK for AI.
- Hosted free tier is the same product minus the AI features (Anthropic
  costs real money per call).
- Hosted Pro is $10/mo for the people who want the AI brief + cross-device
  sync + webhook alerts without running a daemon + paying for Anthropic
  separately.

No SSO tax. No audit-log tax. No per-seat. It's $10 because the per-active-
user hosting bill is a bit under $10/mo and I'd like to break even.

If you have a box and an Anthropic key, self-host is strictly more powerful
than hosted Pro because every endpoint is open. Hosted exists for the
"don't want one more daemon" case.
```

### "Isn't this just X?" reply (have ready)

For Feedly / Inoreader comparisons:

```
Feedly and Inoreader are great general-purpose readers - I used Feedly Pro
for years. The differences that mattered to me:

1. CVE-aware. Click a CVE-ID in any article, get inline CVSS / EPSS / KEV
   status / OTX. General readers don't do this.
2. Cross-source de-duplication. The same CVE is announced via 4-6 feeds
   within an hour; readers show 6 entries, this shows 1 with the others
   collapsed as "also seen by".
3. Pre-KEV detection. Specific to security; not a feature a general
   reader needs.
4. MITRE ATT&CK Navigator export. Same.

If your job is reading security news, the inline enrichment is the actual
time saver. If you're just looking for "an RSS reader", Miniflux is a better
fit and I'd point you there.
```

For Miniflux / FreshRSS comparisons:

```
Miniflux is genuinely better for general RSS - simpler, more mature, larger
community. Use Miniflux for everything else.

This exists because the security stuff (KEV pre-warning, NVD/EPSS inline,
threat-actor chips, MITRE export) is enough work that bolting it onto a
general reader as a plugin felt worse than writing a focused tool.
```

For "this is just a wrapper around NVD / CISA":

```
NVD / EPSS / KEV / OTX are the data sources, yes. The work is:
- Pulling them on the right schedule (NVD rate-limits, OTX is slow,
  EPSS is a 6MB CSV)
- Caching them so the reader doesn't take 5s to render a popover
- Cross-referencing them against the 55+ RSS feeds so "first mention"
  vs "vendor advisory" vs "first PoC" is detectable
- Surfacing the pre-KEV signal (which is mine, not from any official feed)

Could you do this with five shell scripts and curl? Yes, in theory.
I tried for a while; the cross-referencing is what kills you. This is
that wired together.
```

---

## Reddit posts

### r/netsec

**Title:**
```
oM noM Security Feeds: open-source security news reader with inline CVE/KEV/EPSS cross-referencing (Bubbletea TUI + web UI, single Go binary)
```

**Body:**
```
Posting because I think the security-news-aggregation problem is under-served
and this is what I wanted to exist for my own daily workflow.

The tool pulls 55+ security RSS feeds, Reddit, Bluesky, Mastodon, and GitHub
Advisories into one corpus, deduplicates with URL normalisation + title
cosine similarity, scores articles against keyword categories tied to MITRE
ATT&CK and CISA KEV velocity, and renders the result through either a
Bubbletea TUI (`./secfeed tui`) or a vim-keybind two-pane reader in the
browser (`./secfeed`, served at localhost:8080). Both surfaces hit the
same SQLite, same keybinds, same features.

The differentiator from a general RSS reader (Feedly, Miniflux, etc.) is
the inline CVE enrichment. Every CVE-ID in any article is clickable and
expands to a popover with CVSS v3 score+severity, EPSS percentile, CWE,
CISA KEV status with active-exploitation chips, and AlienVault OTX pulse
counts. The KEV catalog is refreshed every 24h, EPSS reloaded daily, NVD
detail cached per CVE.

The bit I'm most proud of is the "pre-KEV" warning. When 3+ curated sources
are talking about a CVE that isn't yet in CISA KEV, it gets flagged amber.
In testing that surfaced two actively-exploited bugs 2-5 days before CISA
added them.

Other things that exist but aren't the headline:
- Threat actor + malware family chip detection (60 curated aliases for
  groups like Volt Typhoon / Scattered Spider / LockBit and families like
  Cobalt Strike / Sliver / BumbleBee)
- MITRE ATT&CK Navigator layer export
- Webhook routing to Slack/Discord/Teams for KEV pops + custom triggers
  (SSRF-guarded poster - rejects RFC1918, link-local, loopback, DNS rebinds)
- IOC decoder paste-box (hash/CVE/IP/URL/domain → pivot links)
- Patch Tuesday auto-brief

Stack: single Go binary (~16 MB), embedded UI, SQLite + WAL. No Postgres,
no Redis, no Docker. ~120-180 MB RAM after warm-up. Runs comfortably on a
1-vCPU 1 GB box.

Repo: https://github.com/RMS2D/omnomfeeds
Live instance: https://omnomfeeds.com (if you want to try before installing)

MIT-licensed. Happy to answer specific questions on source curation,
scoring weights, or the KEV pre-warning detection.
```

### r/cybersecurity

**Title:**
```
Open-source self-hosted security news reader (KEV-aware, inline CVE enrichment)
```

**Body:**
```
I built this because every morning I was spending 30-60 minutes opening
Twitter for breaking news, r/netsec, BleepingComputer, NVD for new CVEs,
CISA KEV for newly-exploited stuff, and a handful of vendor PSIRT blogs.
The cross-referencing was manual ("is this CVE in KEV? has EPSS gone up?
did anyone serious post about it?") and stuff was slipping through.

oM noM Security Feeds is that morning consolidated:

- 55+ security RSS feeds + Reddit + Bluesky + Mastodon + GitHub Security
  Advisories pulled into one feed
- Articles scored 0-100 by relevance to categories like AV/EDR bypass,
  zero-days, supply-chain compromise, ransomware, BYOVD, etc.
- Every CVE is clickable → popover with CVSS, EPSS, CWE, CISA KEV status,
  OTX pulse count
- Cross-source deduplication so you see "this CVE was also reported by 4
  other sources" instead of 5 separate entries
- Public per-CVE pages, trending CVE leaderboard, "pre-KEV" early-warning
  list
- Vim-style two-pane keyboard reader (or just use the mouse, the keybinds
  are optional)

Self-hosted: single Go binary, no Docker required, runs on a 1-vCPU droplet.
Hosted version at omnomfeeds.com if you want to try without installing.

MIT-licensed: https://github.com/RMS2D/omnomfeeds

Real question for the sub: what's missing from a tool like this for your
daily workflow? I have a list of "future features" but they're informed
by my own use; would love to know what blue-team / threat-intel / DFIR /
red-team folks would actually find useful that this doesn't currently do.
```

### r/blueteamsec

**Title:**
```
Self-hosted security news reader with KEV / EPSS / OTX enrichment + MITRE ATT&CK export
```

**Body:**
```
Built primarily for the blue-team / threat-intel daily-triage workflow.
Posting here because the use case I designed against is the same one
this sub's regular daily-news roundups solve (love those posts).

What it does that's specifically blue-team-relevant:

- Cross-references every CVE-ID against CISA KEV, EPSS, NVD, and OTX
  inline. Click a CVE → see CVSS / EPSS percentile / CWE / KEV status
  with active-exploitation chip / OTX pulse count.
- "Pre-KEV" detection: when 3+ curated sources mention a CVE that's NOT
  yet in CISA KEV, it flags it amber. Two real exploitation cases
  surfaced this way in testing 2-5 days before CISA added them.
- 30 curated threat actors (APT41, Lazarus, Scattered Spider, LockBit,
  Cl0p, Volt Typhoon, ...) and 30 malware families (Cobalt Strike,
  Mimikatz, RedLine, Sliver, BumbleBee, ...) auto-detected via alias
  lists. Click any chip to filter the corpus.
- MITRE ATT&CK Navigator v4.5 layer export. "Everything tagged
  initial-access this week" → drop into attack-navigator → coverage
  heatmap. Useful for weekly readouts.
- Webhook routing to Slack/Discord/Teams for KEV pops, breaking-news
  matches, or custom score-threshold matches. SSRF-guarded poster.
- Daily AI brief covering KEV adds, breaking news, top items by score
  (BYOK Anthropic key for self-host).
- Patch Tuesday brief auto-generated on the second Tuesday, vendor-
  bucketed (toggle which vendors you care about).

Source coverage includes the usual blue-team-relevant feeds: CISA Alerts,
CISA KEV, MSRC, Volexity, Microsoft Threat Intel, Mandiant, ESET, Talos,
Securelist, Recorded Future, DFIR Report, NVISO, plus the Bluesky +
infosec.exchange Mastodon researcher network.

Single Go binary, SQLite, MIT-licensed.
Repo: https://github.com/RMS2D/omnomfeeds

Genuinely curious what this is missing for the daily blue-team workflow -
the gaps I'm aware of are deeper IOC correlation (currently the decoder
is paste-and-pivot, not threat-feed correlation) and source-of-truth
attribution beyond the curated chip lists. What else?
```

### r/selfhosted

**Title:**
```
oM noM Security Feeds: self-hosted security news aggregator with both web UI and Bubbletea TUI (Go single binary, no Docker)
```

**Body:**
```
Sharing here because the constraints fit r/selfhosted's typical pickiness:

- One Go binary, ~24 MB (~8 MB of that is Bubbletea + bubbles + lipgloss
  for the TUI). Runs as `./secfeed` from anywhere on your PATH.
- No Postgres. No Redis. No Docker required.
- SQLite + WAL on disk, ~50 MB/month of article growth, older articles
  auto-archive to a compressed cold tier.
- ~120-180 MB resident memory after warm-up with all default sources on.
- Runs comfortably on a 1-vCPU 1 GB DigitalOcean / Vultr / Hetzner / OCI
  free-tier box.
- All source-API calls go direct from your box to the source. No proxy,
  no telemetry, no update pings, no analytics.

What it does: pulls 55+ security RSS feeds, Reddit, Bluesky, Mastodon,
GitHub Security Advisories, and MalwareBazaar; deduplicates them; scores
articles by relevance to security categories; cross-references every CVE
with NVD/EPSS/KEV/OTX inline. Two surfaces on the same SQLite:

  ./secfeed       # daemon + web reader at localhost:8080 (vim-keybind two-pane)
  ./secfeed tui   # Bubbletea TUI on the same data, same keybinds

Both surfaces share the keybinds (j/k nav, o open, b bookmark, / search,
c CVE deep-dive, D IOC decoder, T MITRE coverage, S stats, v feeding
tubes, I AI intel brief if BYOK, L leaderboards, E ATT&CK Navigator
export, e score explainer, ? help). The TUI is the one I actually use
most days; web reader is for sharing URLs with the team.

Config lives at the standard OS user-config path (XDG-compliant on Linux,
Application Support on macOS, APPDATA on Windows). Editable as JSON or
through a GUI panel inside the reader.

Install:

    # Linux / macOS
    curl -fsSL https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.sh | sh

    # Windows
    irm https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.ps1 | iex

Or grab a release binary, or `go install` if you have Go on your box.

Repo: https://github.com/RMS2D/omnomfeeds (MIT)
Live instance: https://omnomfeeds.com (same binary with HOSTED_MODE=true,
if you want to try before installing)

AI features (daily brief, per-article triage line, per-CVE explainer) are
fully optional and BYOK - set ANTHROPIC_API_KEY or OPENAI_API_KEY to
enable. Leave unset for a pure keyword-scoring install with no external
LLM calls.

Happy to answer questions on the build, the source list, or the resource
profile on small boxes.
```

---

## Mastodon (infosec.exchange)

500-char limit. Single post with screenshot.

```
Just shipped oM noM Security Feeds - self-hosted security news reader
with inline CVE / KEV / EPSS / OTX enrichment. Pulls 55+ RSS feeds +
Reddit + Bluesky + Mastodon + GitHub Advisories, deduplicates, scores
by relevance, flags actively-exploited CVEs.

Single Go binary, SQLite, no Docker. MIT.

Repo: github.com/RMS2D/omnomfeeds
Live: omnomfeeds.com

#infosec #threatintel #cve #opensource #selfhosted #rss
```

Attach a screenshot of the /app reader showing a KEV-pulse-red CVE chip + the inline popover with EPSS / CVSS / OTX. The visual sells it in a way text can't.

---

## X / Twitter

### Single tweet

```
Open-sourced oM noM Security Feeds - self-hosted security news reader
that pulls 55+ RSS + Reddit + Bluesky + Mastodon + GitHub Advisories,
scores by relevance, and cross-references every CVE with KEV + EPSS +
NVD + OTX inline.

Single Go binary, SQLite, MIT.

github.com/RMS2D/omnomfeeds
```

(Add screenshot. Don't ask for retweets in the post.)

### Thread (optional, if the single tweet gets traction)

**1/5:**
```
Built this because every morning I was spending 30-60 mins fragment-
browsing Twitter + r/netsec + BleepingComputer + NVD + CISA KEV +
vendor PSIRTs to stay current on security news. Stuff was slipping
through. So I consolidated it.
```

**2/5:**
```
55+ RSS feeds + Reddit + Bluesky + Mastodon + GitHub Advisories,
deduplicated, scored against keyword categories tied to MITRE ATT&CK
and CISA KEV velocity. The KEV catalog refreshes every 24h, EPSS
daily, NVD cached per CVE.
```

**3/5:**
```
Every CVE in every article is clickable: inline popover shows CVSS,
EPSS percentile, CWE, KEV status with active-exploitation chip, OTX
pulse count. No more "is this in KEV? what's the EPSS?" tab-juggling.
```

**4/5:**
```
The bit I'm most proud of: "pre-KEV" flagging. When 3+ curated sources
talk about a CVE that's NOT yet in CISA KEV, it flags amber. Surfaced
two actively-exploited bugs 2-5 days before CISA added them in testing.
```

**5/5:**
```
Single Go binary, SQLite, no Docker. ~120MB RAM. Runs on a 1-vCPU box.
MIT-licensed.

Self-host: github.com/RMS2D/omnomfeeds
Live (same binary): omnomfeeds.com

DMs open for feedback.
```

---

## Pre-launch checklist (do BEFORE clicking submit on HN)

- [ ] Cloudflare orange-cloud verified on (curl response has `cf-ray` + `server: cloudflare`)
- [ ] CF cache purged once for /
- [ ] CSP + Cache-Control: no-cache + cookie flags all live (verified via curl)
- [ ] ufw firewall locked to CF IPs only
- [ ] `/api/cve/<unknown>` returns 404 not 502
- [ ] `Via: 1.1 Caddy` header stripped
- [ ] At least one screenshot of /app reader saved for Mastodon + X posts
- [ ] At least one screenshot of an inline CVE popover (the differentiator visual)
- [ ] GitHub release tagged (e.g. v0.1.0) so the README's install.sh actually finds something
- [ ] README front-matter mentions hosted demo at omnomfeeds.com - don't bury it but don't lead with it
- [ ] Backstory comment text copied to clipboard
- [ ] Pricing-question reply copied to clipboard
- [ ] HN account has at least a few months of activity (avoid throwaway-flag penalty)
- [ ] Be at the keyboard for 4 hours after submitting
- [ ] Phone notifications off so you don't reply emotionally

---

## What success looks like

- **Front-page**: any rank in the top 30 in the first 2 hours
- **Sustained**: top 15 for at least 30 mins
- **Win**: top 5 + 200+ pts + 100+ comments
- **Goal that's actually meaningful**: 50-200 self-host installs in the first week, irrespective of HN rank

The HN rank doesn't matter past "did it generate inbound interest." A post that gets to #4 with 800 pts and 0 installs is worse than a post that flatlines at #38 with 60 pts and 30 active self-hosters who star + open issues + fork.
