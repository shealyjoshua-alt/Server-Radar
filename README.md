# Server Radar

A personal macOS menu bar radar for a Windows Server lead. It checks public sources every
hour and sorts what matters into **Act now**, **Keep an eye on** and **Might interest you**.

- Menu bar dot: **red** (unread Act now, with count) · **grey** (a source has failed 3+ times) ·
  **amber** (unread Keep an eye on) · **green** (all clear). Click to open the dashboard;
  right-click for Refresh Now, Mark All Read, Open at Login, Quit.
- macOS notification **only** for newly *actively exploited* issues (CISA KEV or Microsoft
  "Exploitation Detected") affecting Server 2019/2022/2025, VMware, Azure or your agents.
  The first load after install never notifies.
- Read-only, public data only. Nothing is sent anywhere except plain requests to the sources.

## Sources

| Source | What |
|---|---|
| CISA Known Exploited Vulnerabilities | actively exploited CVEs |
| Microsoft Security Update Guide (CVRF API) | monthly CVEs, severity, exploited flag |
| Windows release health (2019 / 2022 / 2025) | known issues and fixes per update |
| Broadcom advisories (VMware + Carbon Black) | VMSAs |
| Splunk advisories (RSS) | Universal Forwarder |
| Nagios disclosures (NCPA) | agent advisories |
| NVD | CrowdStrike, Carbon Black, NSClient++, NCPA, Splunk UF CVEs |
| Azure status (RSS) | incidents; Azure Government recognised by region name |
| Azure Updates (RSS) | features, GA/preview, retirements |

**CrowdStrike gap:** CrowdStrike tech alerts are behind the customer portal; coverage here is
public CVEs, Microsoft notes and community reports.

## Run, build, install

```bash
npm install
npm test            # unit tests
npm start           # run from source
npm run package     # builds dist/Server Radar.app (seconds, uses the local Electron)
cp -R "dist/Server Radar.app" ~/Applications/
```

The installed app turns on Open at Login the first time it runs.

## Files

- State: `~/Library/Application Support/server-radar/radar-state.json` (delete it to start fresh;
  the next load is treated as a first sync and won't notify).
- Settings: `config/radar.config.json` — product keywords, exclusions, interest keywords,
  refresh interval. Changes need a rebuild (`npm run package`) for the installed app.
- `node scripts/smoke.js /tmp/test-state.json` runs one live refresh and prints each source's health.
