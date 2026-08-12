# Contributing

Open an issue before a large or breaking change. Never commit credentials, scan ledgers, or source from a private codebase.

OpenSec needs Node.js 22.19 or newer. Docker Engine 28 or newer is needed for container-profile integration work.

```sh
npm ci
npm run release:check
```

Add focused tests for behavior changes. Keep changes small, remove unused code, and update public docs when commands or exported types change.

## Database changes

`src/db/schema.sql` defines a new ledger. After `v0.1.0`, each schema change must also add a numbered entry to `src/db/migrations.ts` and a migration test that keeps existing data intact. Never edit or reuse a released schema version.
