# Security scan: vuln-app

| | |
|---|---|
| repository | `/Users/gustavhartz/Projects/open-security/.claude/worktrees/security-tool-implementation-b7e028/test/fixtures/vuln-app` |
| revision | `dcdea2f8e520e883df8ed81f718a68fb53451abc` |
| profile | **static** — nothing was executed |
| model | `azure-openai-responses/gpt-5.6-luna` |
| prompts | `0ce6e0100e50cf89` |
| started | 2026-08-06T16:26:44.455Z |
| tokens | 123,472 in / 9,988 out |
| cost | $0.0224 |

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
| c1 | critical (unproven) | 0.3 | User-controlled host is interpolated into a shell command | `server.js:15` |
| c2 | critical (unproven) | 0.3 | Download route permits path traversal outside uploads | `server.js:23` |
| c4 | critical (unproven) | 0.3 | User-record endpoint has no meaningful authentication or object authorization | `server.js:32` |
| c5 | critical (unproven) | 0.3 | Hardcoded admin token protects destructive session reset | `server.js:10` |
| c6 | critical (unproven) | 0.3 | Ping endpoint allows server-side requests to attacker-selected hosts | `server.js:15` |
| c3 | medium | 0.3 | User ID is concatenated into a SQL query | `db.js:6` |

### c1 — User-controlled host is interpolated into a shell command

**critical (unproven)** · confidence 0.3 · CWE-78

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:15-19` — `GET /api/ping handler`

**What an attacker gets**

A remote caller can place shell metacharacters in the host query parameter and execute arbitrary commands in the Node process context.

**Evidence**

> The handler assigns req.query.host at line 16 and interpolates it into exec(`ping -c 1 ${host}`) at line 17. exec invokes a shell, so input such as a command separator is interpreted by the operating system rather than treated solely as a hostname.

**Investigation**

The actual handler reads req.query.host without validation at server.js:16 and interpolates it into exec(`ping -c 1 ${host}`) at server.js:17. Node's child_process.exec executes the supplied string through a shell, so shell metacharacters from the query value remain active; for example, a host value containing a command separator can append a second command. The callback only handles the command result and provides no input control. server.js exports this Express app, and no upstream caller or validation is present in the reviewed call path.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c2 — Download route permits path traversal outside uploads

**critical (unproven)** · confidence 0.3 · CWE-22

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:23-29` — `GET /api/download handler`

**What an attacker gets**

A remote caller can use traversal segments in name to read arbitrary files accessible to the process, not just files under uploads.

**Evidence**

> Line 25 takes req.query.name and line 26 passes it to path.join(__dirname, "uploads", name). No canonicalized containment check is performed before fs.readFile at line 27, so traversal can escape the intended directory.

**Investigation**

The unauthenticated GET /api/download route assigns req.query.name directly to `name` at server.js:24, then constructs `path.join(__dirname, "uploads", name)` at server.js:25 and passes that path to fs.readFile at server.js:26. Node's path.join normalizes `..` segments; a value such as `../../etc/passwd` therefore escapes the uploads directory (assuming the target file is readable by the process), and the success branch sends the bytes in the HTTP response at server.js:28. There is no validation, canonicalized containment check, or authorization in this call path. The only failure control is fs.readFile's error response, which does not prevent reads of accessible files.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c4 — User-record endpoint has no meaningful authentication or object authorization

**critical (unproven)** · confidence 0.3 · CWE-862

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:32-38` — `GET /api/users/:id handler`

**What an attacker gets**

Any client able to send a nonempty Authorization header can request an arbitrary user ID and receive that user's email and role; the header is neither validated nor tied to the requested subject.

**Evidence**

> The handler only checks header presence at line 33, then passes attacker-selected req.params.id to db.getUser at line 34 and returns the row at lines 35-38. There is no token verification, identity extraction, ownership check, or missing-row authorization handling.

**Investigation**

The route's only gate is a truthiness check on req.headers.authorization (server.js:35), so any nonempty value, including an unvalidated fabricated value, passes. The attacker-selected path parameter is then passed directly to db.getUser (server.js:36). db.getUser interpolates that value into the user lookup (db.js:7-8), and the callback returns the selected row via res.json(row) without checking identity, ownership, or role (server.js:37-39). Thus a caller can request another existing user's id and receive that user's id, email, and role. No caller or middleware in this repository adds authentication or authorization.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c5 — Hardcoded admin token protects destructive session reset

**critical (unproven)** · confidence 0.3 · CWE-798

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:10-12` — `ADMIN_TOKEN declaration`
- `server.js:40-45` — `POST /api/admin/reset handler`

**What an attacker gets**

Anyone who obtains the source or otherwise learns the embedded token can invoke the reset endpoint and delete all sessions, causing broad authentication disruption.

**Evidence**

> The credential is embedded as a source literal at line 11. The route authorizes solely by exact equality of the attacker-supplied x-admin-token header at line 41, then calls db.reset at line 42; db.reset deletes every sessions row (db.js lines 10-12).

**Investigation**

Static end-to-end trace: server.js line 11 defines the administrative credential as a source literal. The POST /api/admin/reset handler at lines 40-45 compares the attacker-controlled x-admin-token header only against that literal; there is no other authorization or rate/role control. A request supplying the learned literal passes the equality check at line 41, invokes db.reset() at line 42, and db.js lines 10-12 execute DELETE FROM sessions, removing every session. This is not self-only and crosses all users' authentication state; learning the source/token is a credential-disclosure prerequisite, not an existing administrative privilege. The route is exposed by the Express app and is network-reachable when the app is served. No control in the actual call path prevents use of the embedded token.

**Severity inputs**

`impact=high` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=high × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, cross-tenant, but nothing was executed

### c6 — Ping endpoint allows server-side requests to attacker-selected hosts

**critical (unproven)** · confidence 0.3 · CWE-918

> `proof_gap: no_execution` — this severity is asserted from code, not demonstrated.

**Locations**

- `server.js:15-19` — `GET /api/ping handler`

**What an attacker gets**

A remote caller can make the application host send ping traffic to arbitrary destinations reachable from its network, enabling internal-network probing or abuse of the server's network position.

**Evidence**

> The route accepts req.query.host at line 16 and invokes ping against that value at line 17 without an allowlist or restriction to public, expected destinations. Even absent shell metacharacters, the endpoint gives callers control over the destination of server-originated network activity.

**Investigation**

The actual route has a direct attacker-input-to-network-effect path with no validation or destination restriction: an HTTP GET to /api/ping supplies req.query.host (server.js:15-16), which is interpolated into the shell command passed to child_process.exec (server.js:17). The ping process therefore originates from the application host and targets the supplied destination; its output is returned to the caller at server.js:18-19. No middleware or caller-side check in this path constrains host. In fact, shell interpolation also creates a separate command-injection risk, but the SSRF/network-probing behavior exists even for a plain hostname or address.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=none` `network_reachable=true` `cross_tenant=false` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood high from vector=remote, auth_required=none
- matrix: impact=medium × likelihood=high → high
- critical (unproven): unauthenticated, network-reachable, traced path with no intervening control, but nothing was executed

### c3 — User ID is concatenated into a SQL query

**medium** · confidence 0.3 · CWE-89

**Locations**

- `db.js:6-8` — `getUser`

**What an attacker gets**

A remote caller can inject SQL through /api/users/:id and alter the users lookup, potentially returning records beyond the requested identifier or changing query behavior.

**Evidence**

> getUser receives the route-controlled id and constructs `SELECT ... WHERE id = '${id}'` through string interpolation at line 7 before passing it to sqlite3 at line 8. No bound parameter or input constraint separates SQL syntax from the identifier.

**Investigation**

The route handler takes req.params.id directly from the remote URL and, after only checking that an Authorization header is present, passes it unchanged to db.getUser (server.js:33-36). getUser interpolates that value inside a quoted SQL string and executes it with sqlite3.Database#get (db.js:6-8). A value such as ' OR 1=1 -- closes the string and changes the WHERE predicate, so the query can return a row other than the requested identifier. There is no parameter binding, identifier validation, or escaping in this call path. The existing authorization check requires only a caller-supplied header and does not constrain the id or SQL syntax.

**Severity inputs**

`impact=medium` `vector=remote` `auth_required=user` `network_reachable=true` `cross_tenant=true` `traced_path_no_control=true` `code_execution_proven=false` `method=code_reading`

- likelihood medium from vector=remote, auth_required=user
- matrix: impact=medium × likelihood=medium → medium

## Leads that went nowhere

"No findings" from an agent that never looked is indistinguishable from "no
findings" from an agent that looked hard — unless the dead ends are written
down. These are they.

- The global express.json parser accepts JSON, but no route reads req.body and Express applies its normal parser limit, so I found no body-driven sink or separate parser exploit.
- The app exports the Express object without a listener or visible proxy, so deployment exposure is unknown rather than a demonstrated repository defect.
- Database reset has no callback/error response, but the observable security issue is the separately recorded hardcoded-token authorization; no additional injection or authorization sink was identified in db.js.

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

