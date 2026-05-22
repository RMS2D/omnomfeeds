# Launch checklist - manual steps before posting

Things the code can't do for you. Work top-to-bottom; nothing depends
on anything below it unless flagged.

---

## GitHub repo settings

Open `https://github.com/RMS2D/omnomfeeds/settings` and walk through:

- [ ] **General -> Features**
  - [ ] **Discussions: OFF** (turn on later when you have bandwidth)
  - [ ] **Wiki: OFF** (issues + README are enough)
  - [ ] **Projects: OFF** (issues are enough)
  - [ ] **Issues: ON**
  - [ ] **Sponsorships: ON** if you want them; otherwise off

- [ ] **General -> Pull Requests**
  - [ ] **Allow squash merging: ON** (only this one)
  - [ ] **Allow merge commits: OFF**
  - [ ] **Allow rebase merging: OFF**
  - [ ] **Automatically delete head branches: ON**

- [ ] **Code security and analysis** (left sidebar)
  - [ ] **Dependency graph: ON** (auto-on for public repos)
  - [ ] **Dependabot alerts: ON**
  - [ ] **Dependabot security updates: ON**
  - [ ] **Secret scanning: ON**
  - [ ] **Push protection: ON** (blocks accidental key pushes at push time)
  - [ ] **Private vulnerability reporting: ON** (gives you a GitHub-native disclosure channel alongside SECURITY.md)

- [ ] **Branches -> Branch protection rules** (add for `main`)
  - [ ] **Require a pull request before merging: ON**
  - [ ] **Require status checks to pass: ON** (select the `ci` workflow's jobs)
  - [ ] **Require linear history: ON**
  - [ ] **Do not allow bypassing the above settings: ON** (yes, even for you)

- [ ] **Actions -> General**
  - [ ] **Allow GitHub Actions to create and approve pull requests: ON**
    (needed for Dependabot auto-PRs)

---

## Repo home page

- [ ] **About** (gear icon, top-right of repo home)
  - [ ] Description: "Self-hosted security news reader. RSS + social + GHSA, scored, KEV-aware, vim keybinds. Single Go binary, embedded UI, SQLite, no telemetry."
  - [ ] Website: `https://omnomfeeds.com`
  - [ ] Topics: `security`, `cve`, `kev`, `rss`, `go`, `bubbletea`, `self-hosted`, `tui`, `mitre-attack`, `threat-intel`
  - [ ] **Include in the home page**: Releases (ON), Packages (off), Deployments (off)

- [ ] **Pin the v1.0.0 release** on the repo home (click the release in the right sidebar after tagging, "Set as the latest release" stays checked).

---

## Tag and ship v1.0.0

- [ ] `git pull --tags origin main`
- [ ] `git tag -a v1.0.0 -m "v1.0.0 - first public release"`
- [ ] `git push origin v1.0.0`
- [ ] Watch the `release` workflow run on the Actions tab; confirm it produces:
  - [ ] Per-OS archives (`omnomfeeds_1.0.0_linux_x86_64.tar.gz`, etc.)
  - [ ] `checksums.txt`
  - [ ] `checksums.txt.sig` + `checksums.txt.pem` (cosign artefacts)
- [ ] On a clean machine (not the dev box), test the verify snippet from the README end-to-end. If it fails, fix and retag as v1.0.1 BEFORE posting anywhere.
- [ ] Confirm `install.sh` resolves the new release: `curl -fsSL https://raw.githubusercontent.com/RMS2D/omnomfeeds/main/install.sh | sh` on a throwaway directory.

---

## Cloudflare config (hosted instance)

Login at `https://dash.cloudflare.com`, select the omnomfeeds.com zone.

- [ ] **DNS**: confirm the A record for the apex is orange-clouded (proxied).
- [ ] **SSL/TLS -> Overview**: encryption mode = **Full (strict)**.
- [ ] **SSL/TLS -> Edge Certificates**: **Always Use HTTPS: ON**, **Automatic HTTPS Rewrites: ON**, **HSTS: ON** with `max-age=31536000`, include-subdomains, preload (only enable preload after you've verified the site is reachable on HTTPS for at least a week).
- [ ] **Rules -> Cache Rules**:
  - [ ] Rule 1: name "no cache for API + auth + health"
    - When: `(starts_with(http.request.uri.path, "/api/") or starts_with(http.request.uri.path, "/auth/") or http.request.uri.path eq "/healthz")`
    - Then: **Bypass cache**
  - [ ] Rule 2: name "cache static for an hour"
    - When: `(http.request.uri.path matches "\.(css|js|svg|png|webp|woff2?)$")`
    - Then: **Eligible for cache**, edge TTL = 1 hour
- [ ] **Security -> WAF -> Rate limiting**:
  - [ ] Rule: 60 req/min per IP on `/auth/magic/request`, `/auth/google/callback`, `/api/ai/brief`. Block for 10 min on hit.
- [ ] **Security -> Bots**: **Bot Fight Mode: OFF** for the hosted instance (it'd break the public RSS endpoint for legitimate readers). Leave off until you see actual scraping abuse.
- [ ] **Network -> WebSockets**: ON (the SSE endpoint relies on long-lived HTTP, not strictly websockets, but flip on regardless).

---

## Server-side prep (hosted box)

SSH to the box. All paths assume `/opt/omnomfeeds/`.

- [ ] **Install logrotate config**:
  ```
  sudo cp /opt/omnomfeeds/repo/deploy/omnomfeeds.logrotate /etc/logrotate.d/omnomfeeds
  sudo logrotate --debug /etc/logrotate.d/omnomfeeds   # dry-run check
  ```

- [ ] **Reinstall the updated systemd unit** (now hardened):
  ```
  sudo cp /opt/omnomfeeds/repo/deploy/omnomfeeds.service /etc/systemd/system/
  sudo systemctl daemon-reload
  sudo systemctl restart omnomfeeds
  sudo systemctl status omnomfeeds   # confirm active (running)
  ```
  Check that `journalctl -u omnomfeeds -n 50` shows no permission errors caused by the tightened sandbox.

- [ ] **Apply the firewall lockdown**:
  ```
  sudo bash /opt/omnomfeeds/repo/deploy/cf_lockdown.sh
  sudo ufw status verbose | head -30   # confirm CF ranges allowed, default deny inbound
  ```

- [ ] **Confirm `LimitNOFILE` took**:
  ```
  cat /proc/$(pgrep -f /opt/omnomfeeds/bin/omnomfeeds)/limits | grep "open files"
  ```
  Soft + hard should read 65535.

- [ ] **Set OMNOMFEEDS_HOST in your local shell** (since deploy.ps1 now requires it):
  ```
  $env:OMNOMFEEDS_HOST = 'user@your-host'
  ```

- [ ] **Sanity-check the live site**:
  - [ ] `curl -I https://omnomfeeds.com/healthz` returns 200 with `{"status":"ok","uptime_s":...}` (note: no `version` or `hosted_mode` keys now)
  - [ ] `curl -I https://omnomfeeds.com/` returns 200 with `Strict-Transport-Security` and `Content-Security-Policy` headers
  - [ ] `curl -fsSL https://omnomfeeds.com/cve/CVE-2024-3094` returns a rendered page

---

## Day-of posting

- [ ] HN account is at least a few weeks old with non-zero karma. Throwaway-flag will sink the post.
- [ ] At the keyboard for the 4 hours after submission. Phone notifications off.
- [ ] Title and body copy from `docs/launch-posts.md` Show HN section.
- [ ] First 30 minutes: do NOT comment on your own post.
- [ ] After 30 minutes: a single "Author here, happy to answer questions" top-level comment with a one-line backstory.
- [ ] Replies use the pre-loaded templates in `docs/launch-posts.md`, paraphrased.
- [ ] No defensive replies to flamebait. No replies past your local midnight.

---

## Post-launch hygiene

- [ ] Watch issue volume in the first 24h. Triage to: bug / feature / question / WONTFIX, no need to respond in depth on day one.
- [ ] If a real security report comes in via `rob@wiredepth.com` or GitHub's private vulnerability reporting, acknowledge within 4 hours.
- [ ] Don't ship feature commits in the launch window. Bug fixes only. New features can land the week after.
- [ ] Cosign-sign every subsequent release the same way. If you skip a release the install one-liner pulls the unsigned one and the verify snippet stops working for that version.
