# Security scan: vuln-app

| | |
|---|---|
| repository | `/Users/gustavhartz/Projects/open-security/.claude/worktrees/security-tool-implementation-b7e028/test/fixtures/vuln-app` |
| revision | `d641d1ab0ec47184a9dd50733470497d05e86d9f` |
| profile | **static** — nothing was executed |
| model | `azure-openai-responses/gpt-5.6-luna` |
| prompts | `0ce6e0100e50cf89` |
| started | 2026-08-06T14:57:22.574Z |
| tokens | 156,069 in / 20,491 out |
| cost | $0.0392 |

## Coverage

- **2 / 2 files touched** (100%)
- **1.9 KB / 1.9 KB read** (100%) — the number to trust
- 0 files excluded from scope with a recorded reason

> Coverage is derived from the read and grep calls that actually happened, not
> from anything the agents claimed. It is a **laziness detector, not proof of
> review**: a file that was read is not thereby a file that was understood.

Extensions in scope: `.js`.

## Findings

| # | severity | confidence | finding | location |
|---|---|---|---|---|
| c1 | critical (unproven) | 0.3 | Attacker-controlled host is interpolated into a shell command | `server.js:14` |
| c2 | critical (unproven) | 0.3 | Download path is not contained under the uploads directory | `server.js:23` |
| c3 | critical (unproven) | 0.3 | User ID is interpolated into an SQL statement | `db.js:6` |
| c4 | critical (unproven) | 0.3 | User lookup accepts an arbitrary Authorization header and does not enforce record ownership | `server.js:33` |
| c5 | critical (unproven) | 0.3 | Administrative reset is protected by a hardcoded shared credential | `server.js:11` |

### c1 — Attacker-controlled host is interpolated into a shell command

**critical (unproven)** · confidence 0.3 · CWE-78

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:14-18` — `GET /api/ping`

**What an attacker gets**

A remote caller can put shell metacharacters in the host query parameter and execute arbitrary commands with the Node process's privileges, rather than merely pinging a host.

**Evidence**

> server.js:15 assigns req.query.host directly from the request. server.js:16 constructs `ping -c 1 ${host}` and passes it to child_process.exec, which invokes a shell; server.js:14-18 contains no validation, allowlist, or shell-safe argument handling.

**Investigation**

Traced the request path: Express registers GET /api/ping at server.js:15; the query parser supplies req.query.host to the handler at server.js:16; there is no authentication, type/format validation, allowlist, quoting, or argument-array API before server.js:17 interpolates host into `ping -c 1 ${host}`. Node's child_process.exec executes that string through a shell, so an encoded shell metacharacter in the host value (for example, a semicolon followed by another command) becomes shell syntax rather than ping data. The callback only returns the command result at server.js:18-19 and does not undo execution. server.js:50 exports the configured Express app; no listener is present in this fixture, but that is missing runtime wiring rather than an input control, and the route is network-reachable wherever the exported app is mounted.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c2 — Download path is not contained under the uploads directory

**critical (unproven)** · confidence 0.3 · CWE-22

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:23-29` — `GET /api/download`

**What an attacker gets**

A remote caller can use traversal segments in name to make the application read and return arbitrary files readable by the process outside uploads.

**Evidence**

> server.js:24 takes req.query.name directly from the request. server.js:25 joins it to __dirname/uploads, but server.js:26 immediately reads that result and server.js:27-28 sends the contents; there is no canonicalization or post-resolution check that target remains beneath uploads.

**Investigation**

The route is registered at server.js:24 and has no authentication or validation middleware before its handler. An attacker-controlled query value is read directly at line 25. At line 26, path.join(__dirname, "uploads", name) normalizes traversal segments but performs no containment check; for example, a value such as ../server.js resolves to a sibling of uploads, and additional ../ segments can escape the application directory. The resulting path is passed unchanged to fs.readFile at line 27. If the process can read it, the success branch at lines 28-29 sends the file bytes in the HTTP response. The only branch control is an I/O error mapped to 404, not a boundary check. express.json() is unrelated to GET query parameters, and the app has no route-specific control stopping the value.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c3 — User ID is interpolated into an SQL statement

**critical (unproven)** · confidence 0.3 · CWE-89

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `db.js:6-8` — `getUser`
- `server.js:33-35` — `GET /api/users/:id`

**What an attacker gets**

A remote caller can inject SQL through the user id path parameter and alter the lookup, potentially extracting or bypassing the intended user selection.

**Evidence**

> server.js:35 passes req.params.id to db.getUser without validation. db.js:7 inserts id inside a quoted SQL literal in `WHERE id = '${id}'` and db.js:8 executes it with conn.get; no parameter binding is used.

**Investigation**

The HTTP path is complete with no control on the ID: GET /api/users/:id takes req.params.id at server.js:33-35 and passes it directly to db.getUser. The only gate is a presence check for req.headers.authorization; any caller can satisfy it with an arbitrary header, and it does not validate or constrain the ID. db.js:6-8 constructs `SELECT id, email, role FROM users WHERE id = '${id}'` by string interpolation and sends it to sqlite3 Database#get without parameter binding. A URL-encoded ID such as `' OR '1'='1` produces a tautological WHERE clause, so sqlite3 can return the first matching user row rather than the requested ID. The endpoint serializes that row, disclosing another user's id/email/role and bypassing the intended selection. No framework routing or JSON handling control prevents this; stacked statements are unnecessary.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c4 — User lookup accepts an arbitrary Authorization header and does not enforce record ownership

**critical (unproven)** · confidence 0.3 · CWE-862

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:33-38` — `GET /api/users/:id`

**What an attacker gets**

Any remote caller can set any non-empty Authorization header and request another user's id to obtain that user's email and role; the header is neither authenticated nor tied to the requested record.

**Evidence**

> server.js:34 authorizes solely on the presence of req.headers.authorization and never verifies its value or resolves an identity. server.js:35 queries the caller-selected req.params.id, and server.js:37 returns the row directly without an ownership, role, or tenant check.

**Investigation**

Confirmed by static end-to-end trace. The exported Express app mounts GET /api/users/:id at server.js:34 with no authentication middleware. At server.js:35 the only gate is truthiness of req.headers.authorization, so any non-empty value (including a fabricated token) passes; there is no token validation or identity resolution. The attacker-selected req.params.id is passed directly to db.getUser at server.js:36. db.js:7-8 interpolates that id into the user lookup and returns the selected row's id, email, and role. server.js:37-38 serializes that row to the caller. For an existing different user's ID, the caller therefore obtains that user's email and role without an ownership, role, or tenant check. The only blocking control is absence of the header, which the attacker can trivially satisfy.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c5 — Administrative reset is protected by a hardcoded shared credential

**critical (unproven)** · confidence 0.3 · CWE-798

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:11-11` — `ADMIN_TOKEN`
- `server.js:41-46` — `POST /api/admin/reset`
- `db.js:10-12` — `reset`

**What an attacker gets**

Anyone who obtains the source or deployed credential can call the reset endpoint and delete every session; the administrative secret is embedded in source and is the sole gate for the destructive operation.

**Evidence**

> server.js:11 defines ADMIN_TOKEN as a literal secret. server.js:42 grants the operation on equality with the caller-controlled x-admin-token header, and server.js:43 invokes db.reset; db.js:11-12 implements that as `DELETE FROM sessions`, with no named principal, scoped authorization, or additional control.

**Investigation**

The end-to-end path is complete with no control that protects the credential: server.js:12 embeds ADMIN_TOKEN as a literal; the POST /api/admin/reset handler at server.js:42-47 reads the caller-controlled x-admin-token header and grants access solely when it equals that literal at line 43; line 44 calls db.reset(); and db.js:11-12 executes DELETE FROM sessions, removing all sessions. The route has no user authentication, principal/role check, rate limit, or additional authorization. Anyone who obtains the source or the embedded token can make the remote POST and globally invalidate sessions. The equality check only rejects callers without the shared secret; it does not mitigate the hardcoded-credential exposure.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

## Leads that went nowhere

"No findings" from an agent that never looked is indistinguishable from "no
findings" from an agent that looked hard — unless the dead ends are written
down. These are they.

- Reviewed express.json() and all routes: no handler consumes req.body, so the JSON parser is not a reachable input sink for this fixture.
- Reviewed the fixed ./app.db initialization: its path is not derived from request data, so no remote database-path injection was established.
- Reviewed db.reset's lack of a completion callback: it can make the success response race the deletion, but that is a reliability issue and does not add a distinct security-boundary bypass beyond the hardcoded-token reset finding.
- Reviewed error responses and the no-row user case: they do not expose a separate controllable sink or authorization bypass beyond the recorded command, file, SQL, and user-record findings.

---

## How severity was computed

Severity is computed from observable inputs, not chosen by a model. Suppression
is a gate before the matrix, so low impact downgrades but never discards.

| impact | L=high   | L=medium | L=low    |
|--------|----------|----------|----------|
| high   | high     | high     | medium   |
| medium | high     | medium   | low      |
| low    | medium   | low      | low      |
| none   | low      | low      | info     |

Critical is a promotion, not a cell: unauthenticated + network-reachable +
(execution proven | cross-tenant | traced path with no intervening control).

Confidence is bound to method: reproduced PoC 1.0, ASan 0.9, debugger 0.8,
code understanding alone 0.3, counterevidence 0.0.

This scan ran under the **static** profile. Nothing was executed, so no finding
here carries execution proof, and any critical is marked `(unproven)`.

