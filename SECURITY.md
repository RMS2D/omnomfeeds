# Security Policy

## Reporting a vulnerability

Email **rob@wiredepth.com** with details. PGP key on request.

What to include:
- The version (`omnomfeeds --version` or commit SHA).
- Whether self-host or the hosted `omnomfeeds.com` instance.
- Reproduction steps.
- Impact you observed or expect.

I'll acknowledge within 72 hours and keep you updated through triage,
fix, and disclosure. Embargoes are honoured; coordinated disclosure is
preferred. Credit in the release notes if you want it.

## Scope

In scope:
- The `RMS2D/omnomfeeds` Go binary and embedded web reader.
- The hosted instance at `omnomfeeds.com`.
- The release pipeline (GitHub Actions + goreleaser).

Out of scope:
- Third-party RSS feeds, social platforms, or other sources we read.
- The NVD, EPSS, CISA KEV, and AlienVault OTX APIs we query.
- Anthropic / OpenAI inference (BYOK).
- Anything you'd need to root the host to exploit.

## Hardening notes for self-hosters

- Don't expose the daemon directly. Front it with Caddy or nginx for
  TLS, and put the box behind a firewall that only allows your
  reverse-proxy's IP.
- The `deploy/cf_lockdown.sh` script in this repo locks ufw down to
  Cloudflare IP ranges if you're using their proxy.
- Magic-link sign-in needs a Resend API key and outbound HTTPS; if
  you're not using hosted-mode auth, leave it disabled.
- BYOK API keys (Anthropic, OpenAI, GitHub, MalwareBazaar) live in
  `config.json` or env vars. Keep that file `chmod 600`.

## Versions covered

I patch the latest minor release. If you're on something older, the
fix is "upgrade".
