# One-Request Proxy Sample Analysis

The current JSON output produced from these structures is documented in `ai-docs/export-format.md`.

## Sample

* Path: `burp-files/2026-08-03-one-request.burp`.
* Contents: one marked HTTP request sent through Burp Proxy; no marked response is stored.
* Size: 524,288 bytes.
* SHA-256: `4fc40009b2f2513f958a0205201babda1fe187a53cdfbf1e1d4bd32a14772886`.
* Byte positions differing from empty baseline: 11,242.

## Header Delta

Stable header fields match the empty baseline: magic, outer version, compatibility value, schema `226`, metadata root `72`, project root `250`, and `Long.MAX_VALUE` physical-file span.

Changed fields:

| Field             | Empty baseline | One-request sample |
| ----------------- | -------------: | -----------------: |
| Random identifier | `0xd3615296`   | `0xc2f1c1f7`       |
| Allocation cursor | 414802         | 418970             |
| Last nonzero byte | 414737         | 418969             |

The request sample allocates 4,168 additional bytes. Its remaining 105,318-byte preallocated tail is outside the allocation cursor.

## Stored Request

All planned request markers occur directly in the file. No `RESPONSE-4D8E2B` or response-body marker occurs.

The raw request byte object is at address `414940`:

* Total size: 282 bytes.
* Logical byte length: 274.
* Payload starts at address `414948`.
* Framing satisfies `282 == 8 + 274`.

Persisted payload:

```http
POST http://127.0.0.1:18080/__burp_project_request_7f3c9a__ HTTP/1.1
Host: 127.0.0.1:18080
User-Agent: curl/8.21.0
Accept: */*
X-Burp-Project-Marker: REQUEST-7F3C9A
Content-Type: text/plain
Content-Length: 32
Connection: keep-alive

BURP_PROJECT_REQUEST_BODY_7F3C9A
```

The absolute-form request target is expected for an HTTP proxy request. Header and body bytes are stored directly and uncompressed.

## Proxy Collections

The stable traversal from the empty baseline still applies:

```text
header project root 250
  -> project-root field 1: Proxy root 1062
  -> Proxy field 0: HTTP collection 1124
  -> Proxy field 1: HTTP collection 1270
```

Both HTTP collections now have logical size `1` and refer to the same `Zp1u` item at address `415222`.

| Collection | Size | Leading offset | Chunk list | Chunk-array record | Logical item slot |
| ---------: | ---: | -------------: | ---------: | -----------------: | ----------------- |
| 1124       | 1    | 0              | 1160       | 415714             | slot 0 -> 415222  |
| 1270       | 1    | 1              | 1306       | 417322             | slot 1 -> 415222  |

Each chunk-array record has total size 1,608, element count 200, and element size 8. The secondary chunk retains the same address in slot 0, but its leading offset is 1, so logical index 0 resolves through slot 1. It still represents one logical item, not two.

The collection hierarchy is:

```text
Zwtw collection
  -> field 2: Zg_i chunk-list object
  -> chunk-list field 1: 10-slot array of chunk addresses
  -> populated chunk address: 200-slot array of item addresses
  -> logical item slot: Zp1u object address
```

## Proxy Item

The shared item at address `415222` is a compact object with type `1`, subtype `0`, and all 31 `Zdr` descriptors.

Relevant `Zdr` address fields:

| Field IDs | Static role                            | Sample value |
| --------- | -------------------------------------- | ------------ |
| 15        | First request-byte variant             | 414940       |
| 16-17     | Other request-byte variants            | null         |
| 18-20     | Response-byte variants                 | null         |
| 21-23     | Request metadata or marker collections | null         |

This validates the static division: request byte variants occupy fields 15-17, and response byte variants occupy fields 18-20. For this request, field 15 owns the raw request and every response field is absent.

## Automated Inspection

The parser now reproduces this traversal without hardcoded sample addresses:

```bash
prub inspect proxy PROJECT.burp
```

It discovers both collection paths from header and descriptor fields, follows bounded forwarding records, honors collection leading offsets, and reports request/response variant addresses and lengths. On this sample both collection paths report item `415222`, field `15` address `414940`, length `274`, and null fields `16..20`.

The full marked Proxy exchange confirmed that a normal completed HTTP/1.1 exchange uses response field `18`. See `ai-docs/request-response-analysis.md`.
