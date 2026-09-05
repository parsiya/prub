# Request-Response Proxy Sample Analysis

The current JSON output produced from these structures is documented in `ai-docs/export-format.md`.

## Sample

* Path: `burp-files/2026-08-03-request-response.burp`.
* Contents: one marked HTTP request and deterministic marked response through Burp Proxy.
* Size: 524,288 bytes.
* SHA-256: `47c1c95a1907d1eb8270daa260aca8e4fe93bca6805fb05d67d9087811e6b6b3`.
* Allocation cursor: 460808.
* Last nonzero byte: 459215.

Stable header fields and root traversal match the earlier samples.

## Proxy Item

Both Proxy HTTP collections resolve to one shared `Zp1u` item at address `415338`.

| `Zdr` field | Value  | Verified meaning                  |
| ----------: | -----: | --------------------------------- |
| 15          | 414842 | Raw request byte record           |
| 16          | null   | Alternate request variant absent  |
| 17          | null   | Alternate request variant absent  |
| 18          | 415102 | Raw response byte record          |
| 19          | null   | Alternate response variant absent |
| 20          | null   | Alternate response variant absent |

This completed HTTP/1.1 Proxy exchange validates field `15` as the active request variant and field `18` as the active response variant.

## Request Record

* Address: 414842.
* Total size: 260.
* Logical length: 252.
* Payload starts at 414850.

```http
POST /__burp_project_request_7f3c9a__ HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: curl/8.21.0
Accept: */*
X-Burp-Project-Marker: REQUEST-7F3C9A
Content-Type: text/plain
Content-Length: 32
Connection: keep-alive

BURP_PROJECT_REQUEST_BODY_7F3C9A
```

## Response Record

* Address: 415102.
* Total size: 236.
* Logical length: 228.
* Payload starts at 415110.

```http
HTTP/1.0 218 Burp-Project-Probe
Server: BaseHTTP/0.6 Python/3.13.14
Date: Mon, 03 Aug 2026 20:07:13 GMT
Content-Type: text/plain
X-Burp-Project-Marker: RESPONSE-4D8E2B
Content-Length: 33

BURP_PROJECT_RESPONSE_BODY_4D8E2B
```

Request and response are separate, adjacent variable byte records. Both are stored directly, uncompressed, and preserve CRLF HTTP framing.

## Parser Consequence

The verified extraction path for a normal Proxy exchange is:

```text
header -> project root field 1 -> Proxy root
Proxy root fields 0/1 -> chunked HTTP collections
logical item -> Zp1u compact object
Zp1u field 15 -> raw request record
Zp1u field 18 -> raw response record
```

Other request and response variants remain inspectable by field ID and must not be assigned semantics without corresponding samples or reader/writer evidence.

## Export Validation

The verified pair exports to the unified JSON format with:

```bash
prub export PROJECT.burp export.json
```

The exported message contains:

* `request_base64`: the exact 252 request bytes encoded as standard base64.
* `response_base64`: the exact 228 response bytes encoded as standard base64.
* A dedicated entry in the top-level `proxy` array.

The exporter deduplicates the shared item across both Proxy collection views. If Target references the same request/response pair, it is also emitted independently in the top-level `target` array.
