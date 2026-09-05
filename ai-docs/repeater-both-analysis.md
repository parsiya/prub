# Combined Repeater Sample Analysis

The current JSON output produced from these structures is documented in `ai-docs/export-format.md`.

## Sample

* Path: `burp-files/2026-08-030-repeater-both.burp`.
* Filename includes the received `08-030` date typo; it is preserved unchanged.
* Size: 524,288 bytes.
* SHA-256: `3fea7e177f3cccb7f9bfd828463b4ce48e257ec1711b77c48de475a7c7707e86`.
* Allocation cursor: 416648.
* Last nonzero byte: 416647.
* Byte positions differing from empty baseline: 12,291.

Proxy HTTP collections remain empty, confirming this fixture contains Repeater state rather than Proxy history.

## Repeater Root

Project-root field `2` points to Repeater root `Zb_y` at address `1708`. The object has subtype `2`, matching descriptor `Zdq`.

| Field ID | Descriptor meaning                  | Sample value |
| -------: | ----------------------------------- | -----------: |
| 0        | Integer control field               | 2            |
| 1        | Tab collection                      | 1760         |
| 2        | Integer control field               | 2            |
| 4        | Group collection                    | 1870         |
| 5        | Additional Repeater settings object | 1980         |

The direct tab collection has logical size `2` and points to tab objects `99676` and `414784`. The direct group collection has logical size `1` and points to group object `416526`.

## Tabs

Both tabs are HTTP Repeater objects with abstract type ID `0` and descriptor `Zdu`.

| Property                       | `repeater-1`                           | `repeater-2`                           |
| ------------------------------ | -------------------------------------: | -------------------------------------: |
| Tab object                     | 99676                                  | 414784                                 |
| Caption object                 | 99824                                  | 414932                                 |
| Group reference, field 32      | null                                   | 416526                                 |
| Pair collection, field 2       | 100042                                 | 415150                                 |
| Pair count                     | 0                                      | 1                                      |
| Current request bytes, field 4 | null                                   | null                                   |
| Tab UUID object, field 33      | 100316                                 | 415424                                 |
| UUID                           | `5a9ea5ac-b6da-4f4c-a492-9a09d2a8033e` | `a1b297a2-203f-433a-88ae-6e6d964c3a5e` |

Captions use mutable string descriptor `Zvp`: field `0` is character length, field `1` is Java hash, field `2` is chunk width, and field `3` points to a direct collection of UTF-16BE character arrays. Both captions have length `10` and chunk width `32`.

### Unsent Draft Result

No `UNSENT-B6E219` marker or unsent request target occurs in any tested text encoding. Tab `repeater-1` has an empty pair collection and null current-request field `4`. Therefore the unsent editor draft was not persisted in this sample; only the renamed tab metadata was stored.

This is an observed sample result, not a claim that every Burp version or every unsent editor state behaves identically.

## Tab Group

Group object `416526` uses descriptor `Zzk`.

| Field ID | Meaning             | Sample value    |
| -------: | ------------------- | --------------- |
| 0        | Name string         | `GROUP-D7A4C2`  |
| 1        | Color enum ID       | `7` = `GROUP_0` |
| 2        | Expanded flag       | true            |
| 3        | Integer/index field | 1               |
| 4        | UUID object         | 416622          |

Group UUID: `fcd376d6-d5c5-4a64-a0b6-94d3f0e0dbfc`.

The user observed Burp automatically assign purple. Static enum `Zxpb` maps persisted ID `7` to `GROUP_0`; therefore this build's `GROUP_0` UI palette is the observed purple group color.

Membership is a direct tab-to-group object reference. `repeater-2` field `32` equals group address `416526`; `repeater-1` field `32` is null. No separate membership table is needed for these tabs.

## Completed Pair

Tab `repeater-2` contains one `Zx4g` pair at address `415828`, using descriptor `Zdg`.

| Field ID | Meaning                            | Sample value |
| -------: | ---------------------------------- | -----------: |
| 0        | HTTP service metadata              | 415708       |
| 1        | Higher-level HTTP message metadata | 416196       |
| 2        | Raw request byte record            | 415984       |
| 3        | Raw response byte record           | 416292       |

The writer `Zppn.ZU` and mapped readers `Zmda.ZWB`/`Zmd3.ZWf` confirm fields `2` and `3`.

### Request

* Record address: 415984.
* Total size: 211.
* Logical length: 203.
* Marker: `SENT-C4A731`.

### Response

* Record address: 416292.
* Total size: 234.
* Logical length: 226.
* Status: 219.
* Marker: `RESPONSE-D9F208`.

Both payloads are direct, separate, uncompressed byte records preserving HTTP CRLF framing.

## Automated Inspection and Export

Inspect:

```bash
prub inspect repeater PROJECT.burp
```

Export:

```bash
prub export PROJECT.burp export.json
```

The unified JSON contains one message for the completed pair:

* `request_base64`: the exact 203 request bytes encoded as standard base64.
* `response_base64`: the exact 226 response bytes encoded as standard base64.
* A dedicated entry in the top-level `repeater` array containing tab caption, tab UUID, group details, and pair index.

No message is exported for `repeater-1` because it has no persisted pair or current-request byte record.
