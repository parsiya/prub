# Burp Classes and Methods Index
This index maps the obfuscated Burp Suite `2026.7.1` classes and methods that were important to the schema-226 project-file analysis. Names are retained exactly as decompiled because no stable product-level names are available.

The tables distinguish verified behavior from unresolved boundaries. A field mapping is listed only when matching static reader/writer paths or controlled project samples support it.

## Project Lifecycle and Storage

| Class  | Important methods                                                                                    | Role and relationships                                                                                                                                                     |
| ------ | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Zwic` | `Zo(String)`, `ZO(String)`                                                                           | Existing-project and new-project lifecycle entry points. They call `Zcv6.ZX` and `Zcv6.Zq`, respectively.                                                                  |
| `Zcv6` | `Zq(...)`, `ZX(...)`, `Zn(...)`, `Zc(...)`, `Zm(...)`, `ZB(byte[])`, `Zr(...)`, `ZG(...)`, `close()` | Persistent-object store coordinator. Opens or creates storage, allocates compact objects and variable records, resolves descriptors, and delegates physical I/O to `Zp6u`. |
| `Zp6u` | `ZU(...)`, `Zz(...)`, `ZP(...)`, `ZH(int)`, `Zt(long,int)`, `ZT(int)`, `ZL()`, `close()`             | Physical memory-mapped store. Creates or opens files, allocates aligned addresses, derives segment filenames, forces mappings, and closes locks and channels.              |
| `Zino` | `Zy(...)`, `Zi()`, `Zn()`                                                                            | One physical mapped-file segment. Wraps `RandomAccessFile`, `FileChannel`, and mapped regions for `Zp6u`.                                                                  |
| `Zq8`  | Storage-opening implementation                                                                       | Participates in normal project opening and header validation. Exact method-level naming is not needed by `prub`.                                                           |
| `Zuve` | Storage helper                                                                                       | Participates in outer storage construction. Its narrower product role remains unresolved.                                                                                  |
| `Zikg` | `PERIODIC_AND_ON_CLOSE`                                                                              | Durability policy that schedules `Zp6u.ZL()` every 10 seconds and forces once more during close.                                                                           |
| `Zi_y` | Header constants                                                                                     | Supplies magic, storage version, compatibility value, and schema values to storage creation and validation.                                                                |

## Persistent Object Framework

| Class     | Important methods or fields                        | Role and relationships                                                                                        |
| --------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------- |
| `Zm6s`    | `Zlz()` and stored address accessors               | Base class for mapped persistent objects; retains the owning `Zcv6` store and object address.                 |
| `Ze48<T>` | `Zy()`, `Zg()`, `Zt(byte)`, `ZY()`, `ZB()`, `ZC()` | Descriptor protocol used by compact-object readers and writers.                                               |
| `Zbb<T>`  | `Zt(byte)` in subclasses                           | Base descriptor implementation. Connects field descriptors, object factories, type IDs, and subtype dispatch. |
| `Ze8h`    | `ZK()`, `Zb()`                                     | Field-descriptor protocol exposing a field ID and encoded width.                                              |
| `Zshv<T>` | Constructor field ID                               | Stored-object address field descriptor, including raw-byte references.                                        |
| `Zshx<T>` | Constructor field ID                               | Typed structured-object field descriptor.                                                                     |
| `Zshs`    | Constructor field ID                               | Persistent string field descriptor.                                                                           |
| `Zshz`    | Constructor field ID                               | Persistent integer field descriptor.                                                                          |
| `Zsht`    | Constructor field ID                               | Persistent long field descriptor.                                                                             |
| `Zshg`    | Constructor field ID                               | Persistent enum or integer-like field descriptor.                                                             |
| `Zs29`    | Constructor field ID                               | Persistent boolean-like field descriptor.                                                                     |

## Raw Bytes and Variable Records

| Class  | Important methods                  | Role and relationships                                                                            |
| ------ | ---------------------------------- | ------------------------------------------------------------------------------------------------- |
| `Zx9j` | `Zrd()`, `Zh(byte[])`              | Raw-byte object interface used for HTTP requests and responses.                                   |
| `Zmem` | `Zrd()`, `Zh(byte[])`              | Mapped `Zx9j` implementation. Reads and writes payload bytes through a mapped `ByteBuffer` slice. |
| `Zcv6` | `ZB(byte[])`, `Zr(...)`, `ZG(...)` | Creates and reads variable records with an 8-byte size/length prefix.                             |
| `Zme_` | Long-buffer element access         | Reads variable arrays of big-endian 64-bit object addresses.                                      |

## Collections and Strings

| Class     | Important methods or fields           | Role and relationships                                                                              |
| --------- | ------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Zwtw<T>` | Fields `0`-`3`                        | Chunked collection descriptor: logical size, chunk size, chunk-list address, and leading offset.    |
| `Zmea<T>` | `size()` and indexed access           | Mapped chunked-collection implementation used by Proxy collections.                                 |
| `Zg_i<T>` | Logical size and backing-array fields | Direct collection without the extra chunk-list layer.                                               |
| `Zgsd`    | Field `1`                             | Metadata-root recycling pool containing reusable `Zuei` string chunks.                              |
| `Zsa1`    | `ZQ(...)` overloads                   | Removes or allocates a free string chunk and clears a returned chunk before recycling it.           |
| `Zuei`    | Length and next-chunk fields          | Reusable string chunk used by segmented strings.                                                    |
| `Zx0k`    | String-segment operations             | Stores strings in `Zuei` segments of at most 100 characters.                                        |
| `Zvp`     | Fields `0`-`3`                        | Mutable string descriptor: character length, Java hash, chunk width, and UTF-16BE chunk collection. |

## Project Root and Identity Metadata

| Class  | Important methods or fields                             | Role and relationships                                                                                                                                                          |
| ------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Zys`  | `ZB()`; fields `0`, `1`, `2`, `3`, `6`, `7`, `11`, `15` | Schema-226 project-root descriptor. Connects installation ID, Proxy, Repeater, Target/Scanner indexes, project name, Scanner Dashboard, Target auxiliary state, and project ID. |
| `Zgaz` | `Zl(...)`                                               | Reads, validates, or generates Burp's 20-character installation ID.                                                                                                             |
| `Zpg6` | `ZT(...)`, `Zx(...)`                                    | Reads and writes the `burp.suite.installationId` Java preference used by `Zgaz`.                                                                                                |
| `Zckj` | Root field `4`                                          | Verified root object shape; product-level meaning unresolved.                                                                                                                   |
| `Zp42` | Root field `5` collection element                       | Root collection element with unresolved product-level meaning; also appears as Repeater pair metadata field `0`.                                                                |
| `Zi8r` | Root field `8`                                          | Verified root object shape; product-level meaning unresolved.                                                                                                                   |
| `Zuxa` | Root field `9` collection element                       | Verified collection shape; product-level meaning unresolved.                                                                                                                    |
| `Zbfd` | Root field `10`                                         | Verified root object shape; product-level meaning unresolved.                                                                                                                   |
| `Zeia` | Root field `12`                                         | Verified root object shape; product-level meaning unresolved.                                                                                                                   |
| `Zg6d` | Root field `13`                                         | Verified root object shape; product-level meaning unresolved.                                                                                                                   |
| `Zho5` | Root field `16`                                         | Verified root object shape; product-level meaning unresolved.                                                                                                                   |

## Proxy History

| Class          | Important methods or fields     | Role and relationships                                                                                                                                                                        |
| -------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Zkx`          | Fields `0`-`5`                  | Proxy storage root containing two `Zp1u` collections, two `Zxrm` collections, and their sequence counters.                                                                                    |
| `Zdn`          | Six field descriptors           | Descriptor for `Zkx`. Establishes the Proxy root's collection and counter layout.                                                                                                             |
| `Zmdc`         | Collection accessors            | Mapped `Zkx` implementation. Exposes the four collections described by `Zdn`.                                                                                                                 |
| `Zp1u`         | HTTP item accessors             | Persistent Proxy HTTP item interface. Raw request and response references are defined by `Zdr`.                                                                                               |
| `Zmdu`, `Zmdv` | Mapped field readers            | Concrete mapped implementations of `Zp1u`.                                                                                                                                                    |
| `Zdr`          | Fields `15`-`23`                | Proxy item descriptor. Fields `15`-`17` are request byte variants, `18`-`20` response byte variants, and `21`-`23` paired parsed-request structures. Normal exports use fields `15` and `18`. |
| `Zxrm`         | Proxy secondary collection item | Stored in the other two `Zkx` collections. Exact product semantics remain unresolved.                                                                                                         |

## Repeater

| Class  | Important methods or fields      | Role and relationships                                                                              |
| ------ | -------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Zb_y` | Root collections                 | Repeater root containing tabs, groups, and related state.                                           |
| `Zdq`  | Root field descriptors           | Descriptor for the schema-226 Repeater root.                                                        |
| `Zr0g` | Tab accessors; fields `32`, `33` | Repeater tab model. Field `32` references its group and field `33` its UUID.                        |
| `Zdu`  | Tab field descriptors            | Repeater tab descriptor used by the controlled tabs.                                                |
| `Zx4g` | Pair accessors                   | Persistent Repeater request/response pair interface.                                                |
| `Zdg`  | Fields `2`, `3`                  | Repeater pair descriptor. Field `2` is the raw request and field `3` the raw response.              |
| `Zppn` | `ZU(...)`                        | Pair writer confirming request and response field assignments.                                      |
| `Zmda` | `ZWB()`                          | Mapped pair reader confirming the request field.                                                    |
| `Zmd3` | `ZWf()`                          | Concrete mapped pair reader confirming the response field.                                          |
| `Zzk`  | Group field descriptors          | Repeater group descriptor for name, UUID, expanded state, and color.                                |
| `Zxpb` | Persisted color IDs              | Repeater group color enum. ID `7` mapped to `GROUP_0`, observed as purple in the controlled sample. |

## Target Site Map

| Class          | Important methods or fields                          | Role and relationships                                                                                                                     |
| -------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `Zg70`         | Fields `0`-`4`                                       | Shared Target/Scanner indexes: service-to-host, request-to-path, request-to-leaf, identity-indexed hierarchy nodes, and an auxiliary list. |
| `Zk6`          | Five field descriptors                               | Descriptor establishing the `Zg70` index layout.                                                                                           |
| `Zpt2<K>`      | Hash lookup and iteration methods                    | Persistent identity hash index used for `Zml1` Site Map hierarchy nodes.                                                                   |
| `Zcw4`         | Load factor, threshold, count, buckets, hash version | Descriptor for the identity index.                                                                                                         |
| `Zss7`         | Three 64-bit tuple values                            | Stored hash-index tuple: hash, key-object address, and associated value.                                                                   |
| `Zml1`         | Node type and field `33`                             | Persistent Site Map hierarchy node. Message-bearing type-3 and type-4 nodes reference `Zfkk` through field `33`.                           |
| `Zfkk`         | Message metadata fields                              | Site Map message object described by `Zkp`.                                                                                                |
| `Zkp`          | Fields `0`, `1`                                      | Site Map message descriptor. Field `0` is the raw request and field `1` the raw response.                                                  |
| `Zri3`, `Zgfl` | Temporary request/response values                    | Intermediate values used by Montoya Site Map insertion before persistence.                                                                 |
| `Zr9z`, `Zms_` | Site Map construction methods                        | Convert temporary HTTP values into persistent `Zml1` hierarchy nodes and indexes.                                                          |
| `Zgbs`         | Two map fields                                       | Separate Target auxiliary keyed state at project-root field `11`; not the primary Site Map HTTP index.                                     |
| `Zcg7`         | Extensible keyed node                                | Value type stored under Target auxiliary keys in `Zgbs`.                                                                                   |

## Scanner and Logger Boundaries

| Class  | Important methods or fields           | Role and relationships                                                                                                                             |
| ------ | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Zen0` | Nine root fields                      | Scanner Dashboard state at project-root field `7`. Contains baseline task/template and profile records even in an empty project.                   |
| `Zgao` | Configuration accessors               | Configuration source used to seed Scanner profile/resource state.                                                                                  |
| `Zwre` | Profile fields                        | Scanner profile or resource settings seeded from `Zgao`; not a raw finding collection.                                                             |
| `Zsuv` | Request field `1`, response field `2` | Scanner/audit item model. Kept distinct from Site Map message objects.                                                                             |
| `Zj9`  | Fields `1`, `2`                       | Descriptor for `Zsuv` request and response references. Task ownership and subtype collections remain unresolved.                                   |
| `Zboe` | Logger item interface                 | Boundary finding: does not implement the persistent-object contract. Logger history is session-ephemeral and absent from project-root persistence. |

## Critical Relationships

```text
Open existing project
  Zwic.Zo -> Zcv6.ZX -> Zp6u.Zz -> mapped header and segments

Create project
  Zwic.ZO -> Zcv6.Zq -> Zp6u.ZU -> initialized header and roots

Proxy message
  Zys field 1 -> Zkx/Zdn -> Zwtw<Zp1u> -> Zp1u/Zdr
  -> fields 15 and 18 -> Zx9j/Zmem -> raw request and response bytes

Repeater message
  Zys field 2 -> Zb_y/Zdq -> Zr0g/Zdu -> Zx4g/Zdg
  -> fields 2 and 3 -> Zx9j/Zmem -> raw request and response bytes

Target Site Map message
  Zys field 3 -> Zg70/Zk6 -> Zpt2<Zml1> -> Zml1 field 33
  -> Zfkk/Zkp -> fields 0 and 1 -> Zx9j/Zmem -> raw bytes

Periodic durability
  Zikg.PERIODIC_AND_ON_CLOSE -> Zp6u.ZL -> MappedByteBuffer.force
```

## Confidence Boundary

Scanner task subtypes, WebSocket persistence, extension-owned data, and unresolved project-root objects require additional reader/writer tracing or discriminating samples before receiving stronger names.
