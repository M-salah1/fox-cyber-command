# FOX CYBER COMMAND v2.00 — API / واجهة برمجية

Local only. The server binds `127.0.0.1` by default and never
accepts external connections. No external network calls are made.

## Authentication / المصادقة

Every route requires the header:

```
X-FOXCC-Token: <token>
```

The token is generated once by `create_api_token(base_dir)` and
stored in `.foxcc_api_token` (mode 0600, git-ignored). It is never
in code and never printed in full. Without it: `401 unauthorized`.

```python
from foxcc.core.api import create_api_token, run_api_server
token = create_api_token(".")          # keep it secret
server = run_api_server(".", host="127.0.0.1", port=8765)
server.serve_forever()
```

## REST

| Method | Route | Description |
|---|---|---|
| GET | `/api/v1/status` | Tool, version, status |
| GET | `/api/v1/missions` | Recorded missions |
| GET | `/api/v1/findings?scan_id=<id>` | Findings for a scan (or all) |
| POST | `/api/v1/mission` | Create (record) a mission — scope-guarded |

### POST /api/v1/mission

Request:

```json
{"target": "https://example.com", "kind": "mission"}
```

- Requires an active signed scope covering `target`
  (`ScopeManager.require`); otherwise `403 out_of_scope`.
- Response `201`: `{"mission_id": "M-...", "target": ...,
  "kind": ..., "status": "created", "note": "recorded only — run
  the mission from the console to execute it"}`.
- Creating a mission only **records** it; it does not claim a scan
  ran. Execute missions from the `foxcc >` console.

## JSON-RPC (POST /api/v1/rpc)

JSON-RPC 2.0. Methods:

| Method | Params | Result |
|---|---|---|
| `status` | — | tool/version/status |
| `mission.create` | `{target, kind}` | mission record (scope-guarded; out of scope → error `-32003`) |
| `mission.get` | `{mission_id}` | mission row or error `-32602` |
| `findings.list` | `{scan_id?}` | findings list |

Example:

```json
{"jsonrpc": "2.0", "id": 1, "method": "status", "params": {}}
```

## Errors

| Code | Meaning |
|---|---|
| 401 | Missing/invalid `X-FOXCC-Token` |
| 403 | Out of scope (write routes) |
| 404 | Unknown route |
| -32601 | JSON-RPC method not found |
| -32602 | Invalid params / mission not found |
| -32003 | Out of scope (JSON-RPC) |

## حدود / Limits

- Localhost only; do not change the host to `0.0.0.0` unless you
  understand the exposure — the token is the only protection.
- No scan is executed by the API itself; scans run from the console
  under a signed scope.
