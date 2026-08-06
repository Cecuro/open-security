# Security scan: vuln-app

| | |
|---|---|
| repository | `/Users/gustavhartz/Projects/open-security/.claude/worktrees/security-tool-implementation-b7e028/test/fixtures/vuln-app` |
| revision | `07a76f66281f190e7d9fe06ae5e806457a39afd1` |
| profile | **static** — nothing was executed |
| model | `azure-openai-responses/gpt-5.6-luna` |
| prompts | `0ce6e0100e50cf89` |
| started | 2026-08-06T15:24:46.468Z |
| tokens | 111,293 in / 8,967 out |
| cost | $0.0201 |

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
| c1 | critical (unproven) | 0.3 | Ping endpoint enables shell command injection | `server.js:15` |
| c2 | critical (unproven) | 0.3 | Download endpoint permits path traversal outside uploads | `server.js:23` |
| c4 | critical (unproven) | 0.3 | Administrative reset credential is hardcoded in source | `server.js:10` |
| c5 | critical (unproven) | 0.3 | User endpoint has no real authentication or ownership authorization | `server.js:32` |
| c3 | medium | 0.3 | User lookup is vulnerable to SQL injection | `db.js:6` |

### c1 — Ping endpoint enables shell command injection

**critical (unproven)** · confidence 0.3 · CWE-78

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:15-19` — `GET /api/ping`

**What an attacker gets**

A remote caller can place shell metacharacters in the host query parameter and execute arbitrary commands as the Node.js process.

**Evidence**

> server.js:16 assigns req.query.host directly, and server.js:17 interpolates it into exec(`ping -c 1 ${host}`), which invokes a shell. There is no allowlist or argument-safe subprocess API before execution.

**Investigation**

The actual route has a direct source-to-sink path: an unauthenticated GET to /api/ping supplies req.query.host (server.js:14-16), which is interpolated without validation or quoting into exec(`ping -c 1 ${host}`) (server.js:17). child_process.exec invokes a shell, so shell metacharacters in host can append or chain commands executed with the Node.js process privileges. There is no upstream middleware or route check controlling this value; express.json() does not validate query parameters, and the callback only handles the command result after execution. Static review did not execute a payload.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c2 — Download endpoint permits path traversal outside uploads

**critical (unproven)** · confidence 0.3 · CWE-22

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:23-29` — `GET /api/download`

**What an attacker gets**

A remote caller can use traversal segments in name to read arbitrary files accessible to the application process.

**Evidence**

> server.js:24 takes req.query.name and server.js:25 passes it to path.join(__dirname, "uploads", name). server.js:26-28 reads and returns the resulting path, with no canonicalization and containment check.

**Investigation**

The route directly accepts req.query.name at server.js:24, constructs target with path.join(__dirname, "uploads", name) at line 25, and performs fs.readFile(target) at line 26. No validation, normalization-plus-containment check, or authorization occurs before the read. A request such as GET /api/download?name=../../etc/passwd causes path.join to normalize traversal segments outside the uploads directory (assuming the process can read the target), and the bytes are returned via res.send(data) at line 28; read errors only produce 404. The route has no authentication check, so the path is remotely reachable without credentials.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c4 — Administrative reset credential is hardcoded in source

**critical (unproven)** · confidence 0.3 · CWE-798

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:10-12` — `ADMIN_TOKEN`

**What an attacker gets**

Anyone who obtains the source or a source-bearing artifact can recover the static admin token and invoke the session reset endpoint.

**Evidence**

> server.js:11 defines ADMIN_TOKEN as a literal credential. server.js:40-42 authorizes reset solely by equality with the request x-admin-token header, and db.js:10-12 deletes all sessions.

**Investigation**

The static literal at server.js:12 is the complete credential used by the actual reset handler. An attacker who obtains the source can set the x-admin-token header to that value; server.js:42-45 compares it directly, calls db.reset(), and db.js:11-12 executes DELETE FROM sessions with no further authorization or validation. The route is an HTTP POST and the code does not require any separate user authentication. This completes the source-to-effect path; the practical precondition is obtaining the source or a source-bearing artifact and reaching the deployed Express app.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c5 — User endpoint has no real authentication or ownership authorization

**critical (unproven)** · confidence 0.3 · CWE-287

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:32-36` — `GET /api/users/:id`

**What an attacker gets**

A caller can send any nonempty Authorization header and retrieve any user record, including email and role, because the header is never validated or bound to the requested id.

**Evidence**

> server.js:33 checks only whether req.headers.authorization exists. server.js:34 passes attacker-selected req.params.id to the database, and server.js:36 returns the result without checking an authenticated subject or ownership.

**Investigation**

The actual route is reachable at server.js:34. Its only gate at server.js:35 rejects a missing/falsy Authorization header, but does not parse, verify, or derive a subject from that header; any nonempty attacker-supplied value passes. The route then forwards the attacker-controlled path parameter at server.js:36 to db.getUser. In db.js:7-8, getUser interpolates that value into the SELECT and returns id, email, and role. The callback at server.js:37-38 sends the database row directly as JSON, with no ownership or subject comparison. Thus a caller without credentials can present an arbitrary nonempty Authorization header and request another user's record, crossing the user boundary. The database interpolation is a separate SQL-injection issue, but it does not prevent the direct unauthorized-ID path for ordinary IDs.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c3 — User lookup is vulnerable to SQL injection

**medium** · confidence 0.3 · CWE-89

**Locations**

- `db.js:6-8` — `getUser`

**What an attacker gets**

A remote caller can inject SQL through the user id route parameter and alter the users query, potentially exposing or manipulating query results.

**Evidence**

> server.js:33-34 passes req.params.id to db.getUser. db.js:6-7 inserts id directly into a single-quoted SQL string in conn.get, without parameter binding or validation.

**Investigation**

The actual request path completes without a controlling validation or encoding step: GET /api/users/:id at server.js:31-37 checks only for the presence of an Authorization header, then passes req.params.id unchanged to db.getUser. In db.js:6-8, getUser interpolates that value inside a single-quoted SQL literal and sends it directly to sqlite3.Database#get. A value such as ' OR '1'='1 changes the WHERE predicate and can return a different user's row (subject to the database contents); the route then serializes that row with res.json. The authentication check does not constrain the id or prevent SQL syntax manipulation.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=user` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood medium from vector=remote, auth_required=user
- matrix: impact=medium × likelihood=medium → medium

## Leads that went nowhere

"No findings" from an agent that never looked is indistinguishable from "no
findings" from an agent that looked hard — unless the dead ends are written
down. These are they.

- Reviewed the global express.json parser; visible routes do not consume req.body, so no body-driven sink or deserialization flaw was identified.
- Reviewed the reset handler and database reset routine; aside from the separately reported hardcoded-token authorization weakness, the operation is a fixed DELETE with no attacker-controlled SQL or path input.
- No additional template rendering, outbound HTTP client, archive extraction, dynamic evaluation, environment/configuration read, or server listen path exists in the two accountable files.

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

