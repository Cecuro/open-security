# OpenSec

OpenSec is a local security code-review CLI. It scans a repository with coding agents, stores the run in SQLite, and produces findings with evidence and severity.

The bundled reviewer is local-only. OpenSec does not upload runs, host a dashboard, or sync review state.

## Requirements

- Node.js 22.19 or newer
- Docker Engine 28 or newer for the default isolated scan profile

## Install

Until an npm release exists, install from the repository:

```sh
git clone https://github.com/Cecuro/open-security.git
cd open-security
npm ci
npm run build
npm link
```

Once published, the intended npm install is:

```sh
npm install --global opensec
```

## Scan and review

```sh
opensec scan /path/to/repository
opensec review
```

`opensec review [scanId]` opens a browser over a server bound to `127.0.0.1`. Use `--no-open` on a headless machine, `--port <n>` to choose a port, and `--db <path>` to use another ledger. Stop it with Ctrl-C.

The default ledger is `~/.opensec/opensec.db`. Reviews can be written only after a run completes.

Finding states mean:

- Needs review: no final human decision
- Confirmed: include the finding in final exports
- Needs follow-up: more work is required
- Suppressed: valid but intentionally excluded
- Not applicable: not a finding for this target

Comments and state changes stay in the finding history. JSON, CSV, and SARIF exports use the current finding state.

## Sharing and privacy

HTML snapshots are read-only files. They include the repository name, revision, run time, model, cost, coverage, threat model, finding text, repository-relative locations, review comments, and worker labels. They omit the absolute repository path, scan configuration, and internal scan events.

JSON exports contain the full ledger projection for the run. Treat all exports as sensitive review data and inspect them before sharing.

The reviewer has no remote access, user accounts, or team permissions. Do not expose its port through a proxy or network tunnel.

## Development

```sh
npm ci
npm run typecheck
npm test
npm run build
```

Run the full package gate before a release:

```sh
npm run release:check
npm pack --dry-run
```

## Versions and npm releases

The package starts at `0.1.0` and uses semantic versioning. While it remains below `1.0.0`, minor versions may change the CLI or review data contract.

When npm publishing is enabled:

1. Update `CHANGELOG.md`.
2. Run `npm version patch`, `npm version minor`, or `npm version major`. This runs the full release gate before creating the version commit and tag.
3. Run `npm publish --dry-run`, then `npm publish`. Publishing runs the release gate again.
4. Push the commit and tag with `git push --follow-tags`.

`prepack` always runs a clean build, so source-only checkouts cannot publish a package without the CLI and reviewer assets.
