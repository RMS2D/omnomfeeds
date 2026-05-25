# Screenshots referenced by the main README

The main README links these files. Capture them locally before tagging
the v1.0.0 release so they're present in the published archive.

## Required

| File | What | How to capture |
|------|------|----------------|
| `tui.png` | TUI hero shot: list pane on the left, reader pane on the right, a KEV-tagged CVE selected, "ACTIVELY EXPLOITED" red banner visible in the reader pane, mix of source types and score tiers in the list | Run `./secfeed tui` against a populated DB, scroll to a KEV-tagged article (red 100 chip), take screenshot at a wide terminal (~200 cols x 50 rows). PNG, dark theme. Optimise under 400 KB. |

## Optional but high-leverage

| File | What |
|------|------|
| `cve-modal.png` | The CVE deep-dive modal with KEV pulse banner, CVSS, CWE, EPSS percentile visible. Press `c` on the hero shot's selected article to open. |
| `web-reader.png` | The two-pane web reader at typical width, showing a CVE chip with EPSS percentile expanded. |
| `mitre-coverage.png` | MITRE ATT&CK technique-mention frequency view (the `T` modal). |

Keep each PNG under 400 KB. WebP is fine if you'd rather, just update
the README references.

These files are committed to the repo so the README renders them on
GitHub without an external host.
