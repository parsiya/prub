# Empty Project Sample Analysis

The current JSON output and exported project-level fields are documented in `ai-docs/export-format.md`.

## Sample

* Path: `burp-files/2026-08-03-empty-project.burp`.
* Contents: fresh project created with default options and no manually added traffic.
* Size: 524,288 bytes.
* SHA-256: `3401ab0b70fa66ab8b7af0f7b6eda557f4d16526566a9d0134947322d83c9dfc`.
* Burp version: expected 2026.7.1 from current research input; confirm independently if the sample was created by another build.

## Validated Header

All multi-byte fields below are big-endian.

| Offset | Size | Value            | Meaning                                     | Evidence                           |
| -----: | ---: | ---------------: | ------------------------------------------- | ---------------------------------- |
| 0      | 4    | `0x66858280`     | File magic                                  | Static reader and sample           |
| 4      | 4    | `1`              | Outer format version                        | Static reader and sample           |
| 8      | 4    | `0x80527974`     | Signed compatibility value `-2142078604`    | Static reader and sample           |
| 12     | 2    | `226`            | Schema floor or stored schema               | Static writer and sample           |
| 14     | 2    | `226`            | Current schema revision                     | Static reader/writer and sample    |
| 16     | 4    | `0xd3615296`     | Per-project random identifier               | Static writer and sample           |
| 40     | 8    | `72`             | Metadata root address                       | Static writer and sample           |
| 48     | 8    | `Long.MAX_VALUE` | Address span assigned to each physical file | Static open/create path and sample |
| 56     | 8    | `414802`         | Next-allocation cursor                      | Static allocator and sample        |
| 64     | 8    | `250`            | Top-level project root address              | Static writer and sample           |

The file is preallocated to 524,288 bytes. Every byte from allocation cursor `414802` through end of file is zero. The last nonzero byte is at offset `414737`. Therefore file size is capacity, not used-data length; parser bounds and scans should use the allocation cursor when interpreting allocated objects.

## Metadata Root

The object at address `72` parses as a compact object with one descriptor:

* Flags: `0`.
* Type: `0`.
* Subtype: `0`.
* Field `0`: relative offset `7`, address `88`.

The object at address `88` is a `Zgsd` recycling pool. Its field `1` points to a chunked collection at address `104` containing reusable `Zuei` string chunks. The collection is empty in this sample.

Static method `Zsa1.ZQ(collection, store)` removes the last free chunk or allocates one when the pool is empty. The inverse overload clears a chunk's length and next pointer before returning it to the collection. `Zx0k` uses these chunks to store strings in segments of at most 100 characters.

All four current real samples have zero free chunks in this pool. Header offset `40` therefore anchors a persisted object-recycling pool, not a checksum block or transaction journal.

## Project Root

The object at address `250` has subtype `7`, matching `Zys.ZB()`. Its 16 descriptors exactly match the `Zys` project-root schema. Every field is an 8-byte stored-object address.

| Field ID | Relative offset | Static descriptor type | Sample target | Target compact shape |
| -------: | --------------: | ---------------------- | ------------: | -------------------- |
| 0        | 52              | String object (`Zshs`) | 96810         | subtype 0, 2 fields  |
| 1        | 60              | `Zkx`                  | 1062          | subtype 0, 6 fields  |
| 2        | 68              | `Zb_y`                 | 1708          | subtype 2, 5 fields  |
| 3        | 76              | `Zg70`                 | 2112          | subtype 2, 5 fields  |
| 4        | 84              | `Zckj`                 | 51418         | subtype 1, 6 fields  |
| 5        | 92              | Collection of `Zp42`   | 79258         | subtype 0, 2 fields  |
| 6        | 100             | String object (`Zshs`) | 96950         | subtype 0, 2 fields  |
| 7        | 108             | `Zen0`                 | 430           | subtype 0, 9 fields  |
| 8        | 116             | `Zi8r`                 | 79368         | subtype 0, 1 field   |
| 9        | 124             | Collection of `Zuxa`   | 79384         | subtype 0, 4 fields  |
| 10       | 132             | `Zbfd`                 | 36838         | subtype 0, 5 fields  |
| 11       | 140             | `Zgbs`                 | 37008         | subtype 0, 2 fields  |
| 12       | 148             | `Zeia`                 | 19498         | subtype 0, 2 fields  |
| 13       | 156             | `Zg6d`                 | 50824         | subtype 1, 4 fields  |
| 15       | 164             | String object (`Zshs`) | 96880         | subtype 0, 2 fields  |
| 16       | 172             | `Zho5`                 | 79530         | subtype 0, 4 fields  |

Class names remain obfuscated. The descriptor types and addresses are verified; product-level subsystem names are not yet assigned.

## Proxy Storage Root

Project-root field `1` points to address `1062`. Static descriptors identify this object as `Zkx`, and its mapped implementation `Zmdc` exposes two `Zp1u` collections and two `Zxrm` collections. `Zp1u` is the persistent Proxy HTTP item model already mapped through descriptor `Zdr`.

The object at `1062` exactly matches descriptor `Zdn`:

| Field ID | Relative offset | Static meaning              | Sample value |
| -------: | --------------: | --------------------------- | -----------: |
| 0        | 22              | Primary `Zp1u` collection   | 1124         |
| 1        | 30              | Secondary `Zp1u` collection | 1270         |
| 2        | 38              | Primary `Zxrm` collection   | 1416         |
| 3        | 46              | Secondary `Zxrm` collection | 1562         |
| 4        | 54              | `Zp1u` sequence counter     | 0            |
| 5        | 58              | `Zxrm` sequence counter     | 0            |

All four collection objects use descriptor `Zwtw`. Mapped implementation `Zmea.size()` reads field `0`, proving the empty baseline has zero entries:

| Collection address | Element type | Size field 0 | Chunk size field 1 | Chunk-list address field 2 | Field 3 |
| -----------------: | ------------ | -----------: | -----------------: | -------------------------: | ------: |
| 1124               | `Zp1u`       | 0            | 200                | 1160                       | 0       |
| 1270               | `Zp1u`       | 0            | 200                | 1306                       | 0       |
| 1416               | `Zxrm`       | 0            | 200                | 1452                       | 0       |
| 1562               | `Zxrm`       | 0            | 200                | 1598                       | 0       |

Each chunk-list object has logical size `0` and points to a variable address-array record with capacity `10`:

| Chunk list | Address-array record | Record total size | Element count | Element size | Values             |
| ---------: | -------------------: | ----------------: | ------------: | -----------: | ------------------ |
| 1160       | 1182                 | 88                | 10            | 8            | Ten null addresses |
| 1306       | 1328                 | 88                | 10            | 8            | Ten null addresses |
| 1452       | 1474                 | 88                | 10            | 8            | Ten null addresses |
| 1598       | 1620                 | 88                | 10            | 8            | Ten null addresses |

Static class `Zme_` reads each backing payload through a `LongBuffer`; each element is a big-endian 64-bit object address and zero resolves to null. This proves the variable-record header is generic: logical length counts elements, while payload size is `logical_length * element_size`. Raw-byte records are the element-size-1 specialization.

Verified traversal for Proxy comparison is therefore:

```text
header offset 64 -> project root 250
project root field 1 -> Proxy root 1062
Proxy root field 0 -> primary HTTP collection 1124
Proxy root field 1 -> secondary HTTP collection 1270
```

The request-only Proxy fixture confirms the next two layers: a chunk-list address slot points to a 200-slot chunk array, and the chunk array's logical item slot points to the `Zp1u` object. See `ai-docs/one-request-analysis.md`.

## Storage Correction

Normal project creation passes `Long.MAX_VALUE` as the physical-file address span, and this value appears at header offset 48. The other relevant constants are mapping-window controls:

* Initial mapped region: 32 KiB.
* Growth mapped region: up to 128 MiB.
* Maximum mapped window: 1 GiB.

The 1 GiB value does not mean normal projects split into another physical file at 1 GiB. Additional physical files are supported by generic storage code only when the configured per-file address span is exceeded; that span is effectively unreachable for the observed normal project path.

## Confidence Boundary

Header values, compact object layouts, addresses, and zero-filled tail measurements are validated against this sample. Higher-level meanings of obfuscated child types and collection traversal remain static-analysis hypotheses until mapped through readers and compared with marked samples.
