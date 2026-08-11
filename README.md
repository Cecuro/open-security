# OpenSec

OpenSec runs security-review agents against a repository, checks their findings, and stores the result in a local SQLite ledger. The CLI and review UI run on your machine; there is no hosted service.

## Agent flow

```text
Repository
  → inventory and threat model
  → parallel discovery agents
  → validation and severity checks
  → duplicate removal and report
  → local review UI and exports
```

Each agent gets a focused part of the review. Later stages check reachability, counter-evidence, and severity before a finding reaches the report.

## Quick start

Requires Node.js 22.19+, Docker Engine 28+, and macOS or Linux. Use WSL2 on Windows.

```sh
git clone https://github.com/Cecuro/open-security.git
cd open-security
npm ci
npm run build
npm link

opensec env
opensec scan /path/to/repository --model provider/model
opensec review
```

Run `opensec --help` for scan limits, cost controls, diff scans, and CI options.

## What you can do

- Review runs and filter findings by run, repository, severity, or state.
- Confirm, suppress, follow up, or comment on a finding.
- Inspect the threat model, evidence, source locations, cost, and coverage.
- Export JSON, CSV, SARIF, or a read-only HTML snapshot.
- Resume interrupted scans and set CI severity thresholds.

![Run overview](docs/screenshots/runs.jpg)

![Finding review](docs/screenshots/findings.jpg)

Review data stays in `~/.opensec/opensec.db`. Exports can contain sensitive code-review data, so inspect them before sharing.
