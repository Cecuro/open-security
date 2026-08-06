# Security scan: vuln-app

| | |
|---|---|
| repository | `/Users/gustavhartz/Projects/open-security/.claude/worktrees/security-tool-implementation-b7e028/test/fixtures/vuln-app` |
| revision | `382ed06b4bda7d3664bd34f935566b75554d6d22` |
| profile | **static** — nothing was executed |
| model | `azure-openai-responses/gpt-5.6-luna` |
| prompts | `70f8685e384e1d3c` |
| started | 2026-08-06T16:48:41.291Z |
| tokens | 214,619 in / 12,461 out |
| cost | $0.0306 |

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
| c2 | critical (unproven) | 0.3 | Download endpoint allows path traversal outside uploads | `server.js:22` |
| c4 | critical (unproven) | 0.3 | User endpoint accepts any Authorization header and lacks object authorization | `server.js:30` |
| c5 | critical (unproven) | 0.3 | Hardcoded administrator token authorizes global session deletion | `server.js:10` |
| c3 | medium | 0.3 | User lookup is vulnerable to SQL injection | `db.js:5` |

### c1 — Attacker-controlled host is interpolated into a shell command

**critical (unproven)** · confidence 0.3 · CWE-78

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:14-16` — `GET /api/ping`

**What an attacker gets**

A remote caller can place shell metacharacters in the host query parameter and cause the server process to execute arbitrary additional commands through exec().

**Evidence**

> server.js:15 assigns req.query.host without validation, and server.js:16 interpolates it into `ping -c 1 ${host}` passed to child_process.exec, which invokes a shell. The route then returns command output or errors to the caller at lines 17-18.

**Investigation**

The path completes without a control: GET /api/ping is registered at server.js:15; server.js:16 copies req.query.host directly, and server.js:17 interpolates it into a command string passed to child_process.exec. exec invokes a shell, so shell metacharacters in host are interpreted as additional commands. The only preceding middleware is express.json() at server.js:9, which does not validate query parameters. The callback at server.js:18-19 returns command output or errors, but does not prevent execution. server.js:50 exports the app and no repository code makes the route unreachable. An unauthenticated remote caller can therefore obtain arbitrary command execution in the server process, subject to the process OS permissions.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c2 — Download endpoint allows path traversal outside uploads

**critical (unproven)** · confidence 0.3 · CWE-22

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:22-26` — `GET /api/download`

**What an attacker gets**

A remote caller can supply traversal segments in name and read arbitrary files accessible to the Node process, including the SQLite database or application source.

**Evidence**

> server.js:23 takes req.query.name directly; line 24 joins it with __dirname/uploads without resolving and checking that the result remains under uploads; line 25 reads the result and line 26 sends its bytes to the requester.

**Investigation**

The actual unauthenticated GET handler takes req.query.name with no type, allowlist, traversal, or containment validation (server.js:24-26), then passes path.join(__dirname, "uploads", name) directly to fs.readFile (server.js:26-27). Node path.join normalizes '..' segments, so names such as ../server.js resolve outside uploads; successful reads are returned with res.send(data) (server.js:27-29). The only shown middleware is express.json(), which does not constrain GET query values, and no auth check exists on this route. There is no upstream caller control in this repository. The route is exported by the app module, and missing deployment/listen wiring is not a control that stops the handler.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c4 — User endpoint accepts any Authorization header and lacks object authorization

**critical (unproven)** · confidence 0.3 · CWE-862

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:30-34` — `GET /api/users/:id`

**What an attacker gets**

A remote caller can send any nonempty Authorization header and request another user's id, receiving that user's email and role without identity, ownership, or role checks.

**Evidence**

> server.js:31 treats header presence alone as authentication. It passes the attacker-selected req.params.id to db.getUser at line 32 and returns the selected row via res.json at line 34; no token validation or comparison between the caller and requested id is present.

**Investigation**

The complete call path is: an HTTP request reaches GET /api/users/:id (server.js:34); the only gate is a truthiness check on req.headers.authorization (server.js:35), so any nonempty attacker-supplied value passes and no token is parsed or validated. The attacker-controlled req.params.id is then passed unchanged to db.getUser (server.js:36). db.getUser interpolates that ID into a query selecting id, email, and role (db.js:7-8), and the returned row is serialized to the caller with res.json (server.js:37-38). There is no session lookup, identity derivation, ownership comparison, role check, or authorization middleware in the reviewed call path. Thus a caller without valid credentials can present an arbitrary nonempty Authorization value and retrieve another user's email and role, assuming that user ID exists. The query's separate SQL interpolation issue is not needed to establish this candidate.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c5 — Hardcoded administrator token authorizes global session deletion

**critical (unproven)** · confidence 0.3 · CWE-798

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:10-11` — `ADMIN_TOKEN`
- `server.js:36-41` — `POST /api/admin/reset`
- `db.js:10-12` — `reset`

**What an attacker gets**

Anyone who obtains the source or otherwise learns the embedded token can invoke the reset endpoint and delete every session; the credential cannot be rotated independently of deployment.

**Evidence**

> server.js:11 embeds the static token in source. Lines 37-38 grant the reset operation solely when the request header exactly matches it, with no identity, expiry, scope, or audit check. db.js:11 executes DELETE FROM sessions, so successful use has global session impact.

**Investigation**

The request path completes without a control: server.js:12 hardcodes ADMIN_TOKEN; server.js:42-43 exposes POST /api/admin/reset and authorizes solely by exact equality of the attacker-supplied x-admin-token header; server.js:44 invokes db.reset(); db.js:11-12 runs DELETE FROM sessions without a WHERE clause. No caller restriction, token expiry/rotation, identity check, or scope check exists in this path. An attacker who learns the embedded token can remotely invalidate every session. Static review only; no execution claimed.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c3 — User lookup is vulnerable to SQL injection

**medium** · confidence 0.3 · CWE-89

**Locations**

- `db.js:5-7` — `getUser`
- `server.js:30-33` — `GET /api/users/:id`

**What an attacker gets**

A caller can inject SQL through the id path parameter and alter the users query, potentially bypassing the lookup predicate or extracting unintended user data.

**Evidence**

> server.js:31 forwards req.params.id directly to db.getUser after only checking whether an Authorization header exists. db.js:6 concatenates id inside a quoted SQL string and executes it with conn.get at line 7; no parameter binding or input validation is used.

**Investigation**

The actual request path completes without a stopping control: Express supplies the URL segment as req.params.id (server.js:29-31), the route only checks for presence of an Authorization header, and passes the value directly to db.getUser. db.js:6-7 interpolates id inside a quoted SQL string and executes it via conn.get. A quote-containing id can change the WHERE expression (for example, an OR predicate), and the returned row is sent to the caller at server.js:32-34. No parameter binding, type check, or escaping exists in this path; the header check does not constrain the id or SQL. Static review only; no execution claimed.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=user` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood medium from vector=remote, auth_required=user
- matrix: impact=medium × likelihood=medium → medium

## Leads that went nowhere

"No findings" from an agent that never looked is indistinguishable from "no
findings" from an agent that looked hard — unless the dead ends are written
down. These are they.

- Reviewed express.json() at server.js:8-9; no route reads req.body, so no body-controlled sink is reachable in this repository.
- Reviewed db.reset() at db.js:10-12 and its caller; it is intentionally destructive but has no additional attacker-controlled SQL input beyond the separate static-token authorization issue.
- Reviewed download error handling at server.js:25-26; it returns a generic 404 and does not add a distinct information disclosure beyond the traversal flaw.

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

