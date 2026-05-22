# Screenshots and demos referenced by the main README

The main README links these files. Capture them locally before tagging
the v1.0.0 release so they're present in the published archive.

## Required

| File | What | How to capture |
|------|------|----------------|
| `tui.png` | TUI hero shot, list + reader pane, KEV-listed CVE selected, score column visible, source-type colours showing | Run `./secfeed tui`, navigate to a KEV-tagged article, take screenshot at a wide terminal (200+ cols, 50+ rows). PNG, dark theme. |
| `tui-demo.gif` | 20-30s asciinema-cast-to-gif of TUI usage: list nav, search, open a CVE modal, exit | Record with `asciinema rec tui.cast`, convert with [agg](https://github.com/asciinema/agg): `agg --theme=monokai --speed=1.5 tui.cast tui-demo.gif`. Trim to <2 MB. |

## Optional but high-leverage

| File | What |
|------|------|
| `web-reader.png` | The two-pane web reader at typical width, showing a CVE chip with EPSS percentile |
| `cve-modal.png` | The CVE deep-dive modal with KEV pulse banner |
| `mitre-coverage.png` | MITRE ATT&CK technique-mention frequency view (the `T` modal) |

Keep each PNG under 400 KB. WebP is fine if you'd rather, just update
the README references.

These files are committed to the repo so the README renders them on
GitHub without an external host.
