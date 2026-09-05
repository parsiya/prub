# Burp Project Format Specification
This document consolidates the format structures verified for Burp Suite `2026.7.1`, outer storage version `1`, and project schema `226`. It describes enough of the proprietary format to explain `prub`; it is not a complete Burp project-file specification.

## Evidence and Scope
Findings use two kinds of evidence:

* Static evidence from matching reader and writer paths in decompiled Burp classes.
* Sample evidence from four controlled project files: an empty project, a Proxy request without a response, a completed Proxy exchange, and a completed Repeater exchange with grouping.

Vineflower output was the primary static source, JADX was the fallback, and `javap -p -c` was used for decisive methods that decompiled poorly. Vineflower recovered 20,502 Java files and 99.81 percent of input top-level class names; all 39 top-level classes it missed were present in the JADX output. Obfuscated names such as `Zp1u` and `Zdr` are retained where no verified product-level name exists.

Claims are limited to the traced schema-226 paths. Unknown fields and object types must remain generic until reader/writer symmetry or a discriminating sample establishes their semantics.

## Outer Header
The file begins with a 72-byte big-endian header. Allocated objects begin at offset `72` and observed allocations are aligned to even offsets.

| Offset | Size | Meaning                                             |
| -----: | ---: | --------------------------------------------------- |
| 0      | 4    | Magic `0x66858280`.                                 |
| 4      | 4    | Signed outer storage version, currently `1`.        |
| 8      | 4    | Signed compatibility value, currently `0x80527974`. |
| 12     | 2    | Unsigned schema floor or stored schema.             |
| 14     | 2    | Unsigned current schema revision.                   |
| 16     | 4    | Per-project random identifier.                      |
| 40     | 8    | Metadata-root address.                              |
| 48     | 8    | Physical-file address span.                         |
| 56     | 8    | Next-allocation cursor.                             |
| 64     | 8    | Project-root address.                               |

The controlled files use schema `226`, metadata root `72`, project root `250`, and `Long.MAX_VALUE` as the physical-file address span. Their physical files are preallocated beyond the allocation cursor, so file length is capacity rather than used-data length.

`prub` validates that the allocation cursor fits inside the mapped file. Individual object reads are currently bounded by mapped file size, not by the allocation cursor; stricter per-record cursor enforcement remains an untrusted-file hardening item.

## Addresses and Nulls
Persisted object references are signed, big-endian 64-bit values. Positive values are byte addresses in the logical project storage space. Address `0` represents an absent object and is exposed as `null` or `None`; negative addresses are invalid in mapped paths.

Normal project creation uses `Long.MAX_VALUE` as the address span for each physical file. The separate 1 GiB constant controls the maximum memory-mapped window and is not a normal file-split boundary. Generic multi-file support exists in the storage layer, but no normal creation path with a realistically bounded span has been verified.

## Variable Records
Independently addressed byte records use this big-endian framing:

```text
offset +0  int32 total_size
offset +4  int32 logical_length
offset +8  byte payload[logical_length]
```

For nonempty byte records, `total_size = 8 + logical_length`. A zero-length record reserves one padding byte, so it stores `total_size = 9` and `logical_length = 0` while exposing an empty payload.

The same framing supports fixed-width arrays. In those records, logical length counts elements and payload size is `logical_length * element_size`. Verified address arrays use 8-byte elements.

The controlled Proxy and Repeater messages are direct, uncompressed byte records preserving complete HTTP start lines, headers, CRLF delimiters, and bodies. Static byte-object readers and writers do not add text encoding. A dedicated fixture containing every byte from `00` through `ff` has not yet been validated.

## Compact Objects
Current persistent objects are self-describing:

```text
offset +0  uint8 flags
offset +1  uint8 type
offset +2  uint8 subtype_or_schema
offset +3  uint8 descriptor_count
offset +4  descriptor[descriptor_count]
```

Each three-byte descriptor contains:

```text
uint8 field_id
int16  relative_offset
```

The relative offset is read as a signed, big-endian 16-bit value by the mapped implementation. Field IDs are searched in the descriptor table, so their byte positions are not fixed globally. `prub` also requires field IDs to be unique and below `128`, field offsets to follow the descriptor table in increasing order, and referenced bytes to fit inside mapped data.

If flag bit `0` is set, the record is a forwarding record instead of a normal compact object. Its replacement address is the big-endian 64-bit value at offset `+1`. `prub` follows forwarding records with cycle detection and a default maximum depth of `16`.

## Collections and Strings
Verified `Zwtw` chunked collections contain:

* Field `0`: logical size.
* Field `1`: chunk size.
* Field `2`: address of a chunk-list object.
* Field `3`: leading physical-slot offset.

The Proxy collections use 200-slot chunks. A chunk-list points to an address array of chunk addresses, and each populated chunk is another address array containing object addresses. Logical lookup adds the collection's leading offset before selecting a chunk and slot.

Direct `Zg_i` collections use a logical size and one backing address array without this extra chunk layer.

Verified immutable and mutable strings store UTF-16BE character arrays. Mutable Repeater captions use chunked character storage. Header offset `40` leads to a recycling pool for reusable `Zuei` string chunks; the pool is empty in all four controlled samples.

## Project Roots
The schema-226 project root is a compact object at header offset `64`. Mapped fields used by `prub` are:

* Field `0`: Burp installation ID string.
* Field `1`: Proxy root `Zkx`.
* Field `2`: Repeater root `Zb_y`.
* Field `3`: shared Target and Scanner indexes `Zg70`.
* Field `6`: project display name.
* Field `7`: Scanner Dashboard state `Zen0`.
* Field `11`: separate Target auxiliary keyed state `Zgbs`.
* Field `15`: random per-project identifier string.

Other root fields are structurally inspectable but do not have verified product-level meanings in this specification.

## HTTP Message Mappings
The following mappings are supported and sample-validated.

### Proxy
Project-root field `1` points to Proxy root `Zkx`. Its fields `0` and `1` are two chunked collections that may reference the same `Zp1u` history item. `prub` deduplicates an item address across those two collection views.

`Zp1u` uses descriptor `Zdr`. For a normal completed HTTP exchange:

* Field `15`: complete raw request byte-record address.
* Field `18`: complete raw response byte-record address.

Fields `16-17` are alternate request-byte slots, fields `19-20` are alternate response-byte slots, and fields `21-23` are parsed request structures paired with request fields `15-17`. Their producer-specific meanings are not yet named and are not exported as normal messages.

### Repeater
Project-root field `2` points to the Repeater root. Its verified collections contain tabs and groups. A completed `Zx4g` message pair using descriptor `Zdg` stores:

* Field `2`: complete raw request byte-record address.
* Field `3`: complete raw response byte-record address.

Tab field `32` directly references its group and field `33` references its UUID. The controlled unsent tab had no pair, a null current-request field `4`, and no request marker in the project file. This is one sample observation, not a guarantee for every unsent state or Burp version.

### Target Site Map
Project-root field `3` points to `Zg70`, which owns service, path, request, and identity indexes shared by Target and Scanner. Site Map hierarchy nodes of the mapped message-bearing types use field `33` to reference `Zfkk` message metadata. Descriptor `Zkp` stores:

* Field `0`: complete raw request byte-record address.
* Field `1`: complete raw response byte-record address.

The completed sample reuses the exact Proxy request and response byte objects in its Target Site Map node. Proxy and Target remain separate export sections because they represent separate Burp contexts.

## Unsupported Persisted Data
Scanner Dashboard root field `7` is nonempty even in the baseline. Every checked sample has two default task or template records with type IDs `4` and `5`, plus one default `Zwre` configuration/profile object. These baseline objects must not be mistaken for user-created scans.

Scanner/audit item `Zsuv` uses descriptor `Zj9`, with request field `1` and response field `2`, rather than Site Map descriptor `Zkp`. Task ownership and subtype-specific collections remain unmapped, so `prub` does not enumerate or export Scanner records.

Logger HTTP history is outside project-file extraction scope. Its item interface does not implement the persisted-object contract, Logger is absent from mapped project-root save/load paths, and its history uses explicit in-memory limits.

WebSocket messages, extension-owned project data, and unknown compact-object semantics are not supported.

## Durability and Integrity
Normal projects use periodic-and-on-close durability. The traced path forces every mapped physical region with `MappedByteBuffer.force()` every 10 seconds and performs one final force during close before releasing locks, channels, and files.

No compression, encryption, Java serialization, or database layer was found in the outer open/create and mapped-storage path. No checksum or transaction journal was found in mapped outer storage, flush, collection, Proxy, or Repeater paths, and the normal force path writes no separate commit marker. These are scoped negative findings, not proof that every subtype or extension-owned payload lacks its own integrity or encoding mechanism.

## Compatibility Boundary
`prub` behavior is documented and validated only for Burp Suite `2026.7.1`, outer storage version `1`, and schema `226`. The parser rejects unsupported outer storage and compatibility values, but it does not currently reject a project solely because its schema differs from `226`. Successful parsing of another schema does not establish compatibility.

The current JSON output has no explicit export-format version field. Its exact shape is documented in the [JSON export format](export-format.md); adding a version field before treating that shape as a long-term stable interchange contract remains a release decision.

Controlled `.burp` samples, Burp binaries, and decompiled sources are intentionally excluded from the public repository. Individual sample-analysis documents record hashes, addresses, and marker-based evidence so findings remain auditable without redistributing proprietary material or sensitive project files.
