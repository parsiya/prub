# Target and Site Map Analysis

The current JSON output produced from these structures is documented in the [JSON export format](export-format.md).

## Ownership

Project-root field `3` points to `Zg70` at address `2112`. Static descriptor `Zk6` identifies five persisted indexes:

* Field `0`: HTTP service to host node.
* Field `1`: HTTP request metadata to path node.
* Field `2`: HTTP request metadata to leaf node.
* Field `3`: identity index of all `Zml1` hierarchy nodes.
* Field `4`: auxiliary list index.

Montoya Site Map insertion converts request and response bytes to temporary `Zri3` and `Zgfl` values, then `Zr9z`/`Zms_` creates persistent `Zml1` hierarchy nodes through these indexes.

Project-root field `11` (`Zgbs`) is separate Target auxiliary state: maps from target strings to extensible `Zcg7` nodes. It is not the primary Site Map HTTP item index.

## Identity Index

The `Zpt2<Zml1>` identity index is at address `15096`.

| Sample                   | Entry count |
| ------------------------ | ----------: |
| Empty baseline           | 0           |
| Completed Proxy exchange | 4           |

Descriptor `Zcw4` stores load factor, resize threshold, entry count, chunked bucket collection, and hash-version metadata. The completed sample has 32 buckets, with three nonempty bucket objects and four total `Zss7` tuples. Each tuple is 24 bytes:

```text
int64 hash
int64 key_object_address
int64 associated_value
```

Decoded completed-sample keys:

| Key address | Node type | Role level                 | Associated value |
| ----------: | --------: | -------------------------- | ---------------: |
| 435784      | 1         | Host/root node             | 78               |
| 436380      | 3         | Path/leaf hierarchy node   | 3                |
| 437252      | 4         | Parameterized/message leaf | 3                |
| 452376      | 3         | Path/leaf hierarchy node   | 77               |

## HTTP Message Fields

Type-3 and type-4 hierarchy nodes use field `33` to reference `Zfkk` message metadata. Descriptor `Zkp` defines:

* Field `0`: raw request byte record.
* Field `1`: raw response byte record.

In the completed Proxy exchange, node `437252` points to message object `437600`:

| Field        | Record address | Logical length |
| -----------: | -------------: | -------------: |
| Request `0`  | 414842         | 252            |
| Response `1` | 415102         | 228            |

The other hierarchy nodes contain no raw message pair. Request and response records are the same records referenced by the Proxy item, demonstrating shared object reuse between Proxy history and Target Site Map.

## Scanner Distinction

Scanner/audit item model `Zsuv` uses descriptor `Zj9`, not `Zkp`:

* Request field `1`.
* Response field `2`.

These audit items may reference the same HTTP records but must not be treated as Site Map rows. Scanner task layouts remain subtype-specific.

## Automated Inspection and Export

Inspect:

```bash
prub inspect target PROJECT.burp
```

Export:

```bash
prub export PROJECT.burp export.json
```

The unified JSON contains:

* `request_base64`: the exact 252 request bytes encoded as standard base64.
* `response_base64`: the exact 228 response bytes encoded as standard base64.
* A dedicated entry in the top-level `target` array.

Both decoded marker headers match the completed Proxy fixture. Because Proxy and Target are separate top-level arrays, the pair appears once in each applicable section.
