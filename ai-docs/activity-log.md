# Activity Log

## 2026-07-23

* Defined target: reverse engineer Burp Suite project-file format.
* Chose Java-aware decompilation over Ghidra for primary JAR analysis.
* Kept Ghidra as fallback for native code or ambiguous decompilation.
* Created `ai-docs/burp-project-format-research-plan.md`.
* Reduced workflow to JAR extraction, whole-JAR decompilation, source search, and controlled project comparison.
* Confirmed WSL2 Linux environment.
* Confirmed OpenJDK 21.0.7 with `java`, `javac`, `jar`, `javap`, and `jdeps`.
* Confirmed existing tools: `unzip` 6.00, ripgrep 13.0.0, GNU `strings` 2.40, and `sha256sum`.
* Identified missing tools: JADX and `xxd`.
* Confirmed Debian repository provides `xxd`; package installation required interactive sudo authentication.
* Selected official JADX 1.5.6 cross-platform CLI/GUI release.
* Installed JADX 1.5.6 in WSL user environment.
* Installed `xxd` in WSL Debian.
* Verified `jadx --version`: 1.5.6.
* Verified `xxd -v`: 2022-01-14 release.
* Located `burpsuite_desktop_v2026.7.1.jar` in workspace root.
* Created `artifacts/extracted`, `artifacts/decompiled`, and `artifacts/searches`.
* Recorded JAR checksum in `artifacts/jar.sha256`.
* Verified SHA-256: `21aaf2b965e0932ca2a4d94c189c472a519c7f5bc71e01fb9b700db359bafb27`.
* Started JADX decompilation with `--deobf`; process reached 89% and failed with `java.lang.OutOfMemoryError: Java heap space` while saving output.
* Confirmed JADX 1.5.6 has no resume or skip-existing option.
* Confirmed WSL allocation: 15 GiB RAM and 4 GiB swap.
* Confirmed JADX launcher accepts JVM settings through `JADX_OPTS`.
* Revised retry to use a 12 GiB heap, four processing threads, and no first-pass deobfuscation.
* Burp JAR has not been executed.

## 2026-07-24

* JADX retry reached 99% and remained active.
* Observed repeated warnings for unknown `Record` and `PermittedSubclasses` Java class attributes.
* Classified warnings as nonfatal metadata loss: record declarations and sealed-class relationships may be reconstructed imperfectly, while method bytecode remains available.
* Decided to let JADX finish and use `javap`, CFR, or Vineflower only for affected classes when exact type metadata matters.
* Checked apparent 99% stall after 36 minutes: JADX remained active at approximately 396% CPU with 103,499 output files and 1.6 GiB written.
* Confirmed output files were still being created within minutes of inspection.
* Confirmed effective JADX heap limit was 18 GiB, with approximately 17.2 GiB in use.
* Left the active process untouched because CPU and output activity showed continued progress.
* Rechecked after 59 minutes: output remained unchanged for 28 minutes while old-generation heap reached 99.98%.
* Measured approximately 49 minutes spent in full garbage collection, confirming GC thrashing rather than useful progress.
* Stopped the stalled process with `SIGTERM`; force termination was not required.
* Extracted the JAR into `artifacts/extracted`.
* Counted 55,120 total classes and 20,609 classes under the `burp` package.
* Chose a focused Burp-only decompilation to exclude bundled dependencies.
* Built `artifacts/burp-classes.jar`: 20,609 classes and 46 MiB.
* Ran focused JADX with a 16 GiB heap, four threads, and resource decoding disabled.
* Focused run reached 97%, reported 11 loading errors, and was interrupted.
* Preserved 19,030 generated Java source files under `artifacts/decompiled-burp/sources` totaling 234 MiB.
* Accepted focused output as sufficient for persistence API and string searches; missing classes will be decompiled individually if needed.
* Compared 20,491 top-level input classes against generated Java filenames.
* Identified 1,461 top-level classes with no generated source file, for 92.87% filename coverage.
* Identified 5,341 generated files with explicit JADX failure or omitted-method markers; 13,689 generated files had neither marker.
* Classified failures: 5,278 `JadxOverflowException`, 163 `JadxRuntimeException`, 11 dependency-scan failures, and one type-inference failure.
* Saved detailed lists and summary under `artifacts/searches`.
* Ran Vineflower against `artifacts/burp-classes.jar`.
* Vineflower generated 20,502 Java files totaling 280 MiB.
* Measured 99.81% top-level coverage: 39 of 20,491 top-level classes had no Vineflower source file.
* Confirmed 68 additional unmatched entries were nested classes represented in parent source files.
* Vineflower recovered all 1,461 top-level classes missing from JADX.
* Identified 2,927 Vineflower files with explicit failure markers and 4,543 failed-method markers.
* Confirmed all 39 Vineflower top-level misses exist in JADX output; 15 are clean there.
* Selected Vineflower as primary source tree and JADX as fallback.
* Created `ai-docs/next-session-prompt.md` with verified state, artifact paths, working rules, and the next investigation task.
* Located project-file lifecycle entry points in `Zwic`: `Zo(String)` opens an existing project through `Zcv6.ZX`, and `ZO(String)` creates one through `Zcv6.Zq`.
* Identified the outer storage implementation in `Zp6u`, `Zino`, `Zuve`, and `Zq8`.
* Confirmed the outer format is a custom big-endian memory-mapped binary store, not Java serialization or a database.
* Confirmed project open maps and validates a 72-byte header before mapping object data.
* Decoded header offset 0 as magic `0x66858280` (`1720025728`).
* Confirmed header offset 4 is an outer format version. Current value is `1`; files with a greater value are rejected.
* Decoded header offset 8 as format discriminator or compatibility value `0x80527974` (`-2142078604` signed). Greater signed values are rejected.
* Confirmed short schema fields at offsets 12 and 14. Both are initialized to `226` in this build; project age checks read offset 14 and treat values below `100` as old.
* Confirmed header offset 16 stores a random 32-bit identifier initialized with `SecureRandom` when absent.
* Confirmed header offset 40 stores the address of an internal metadata root object.
* Confirmed header offset 48 stores the per-segment address span supplied at creation.
* Confirmed header offset 56 stores the next-allocation cursor, initialized to `72` and advanced after each allocation.
* Confirmed header offset 64 stores the address of the top-level project root object.
* Confirmed allocations begin at offset 72 and are aligned to even offsets.
* Confirmed project storage uses an initial 32 KiB mapping, grows mappings up to 128 MiB, and uses a maximum 1 GiB mapping window.
* Confirmed generic storage can derive additional physical filenames through `Zp6u.ZT(int)`, but normal project creation configures `Long.MAX_VALUE` as the per-file address span.
* Identified variable-size record framing in `Zcv6.Zr` and `Zcv6.ZG`: big-endian 32-bit total size, big-endian 32-bit logical length, then payload bytes at record offset `+8`.
* Confirmed variable-record loading rejects a total size that does not equal encoded payload size plus 8 bytes.
* Identified persistent raw-byte objects in `Zmem`. `Zmem.Zrd()` reads bytes directly from a mapped `ByteBuffer`, and `Zh(byte[])` writes bytes directly into that mapped slice.
* Confirmed raw-byte object creation through `Zcv6.ZB(byte[])` uses the variable-size framing above, with logical length equal to byte-array length.
* Confirmed HTTP request and response model values use the same `Zx9j` byte abstraction and expose raw bytes through `Zrd()`; exact owning project-model field descriptors remain to be mapped.
* Found no checksum, digest, cipher, compression, database, or journal operation in the outer project open/create and mapped-storage path.
* Confirmed durability flushing calls `MappedByteBuffer.force()` for mapped regions. Internal indexes or integrity mechanisms outside the outer path remain unresolved.
* Saved 1,769 broad project persistence matches to `artifacts/searches/project.txt`.
* Saved 307 serialization and binary-I/O matches to `artifacts/searches/serialization.txt`.
* Saved 162 compression, integrity, crypto, database, and protobuf matches to `artifacts/searches/storage.txt`.
* Recorded current constraint: no real project samples are currently available.
* Removed controlled project generation as a blocker for static analysis and parser development.
* Added four deferred sample-based format-validation fixtures to the research plan: empty baseline, request-only probe, request-and-response probe, and binary payload probe.
* Assigned exact filenames and distinctive request, response, and binary markers for future reproducible comparison.
* Reordered pending work around static HTTP descriptor mapping, segment-name decoding, index and integrity analysis, and a defensive read-only parser with synthetic tests.
* Confirmed current persistent object records are self-describing: byte 0 is a flags byte, byte 1 is the object type, byte 2 is subtype or schema revision, and byte 3 is the descriptor count.
* Confirmed the descriptor table begins at object offset 4 and contains `descriptor_count` entries of one unsigned field ID plus one big-endian 16-bit relative data offset.
* Confirmed field readers scan this descriptor table by field ID, so schema field positions need not be hardcoded by a parser.
* Identified `Zp1u` as a persistent Proxy HTTP history model, with mapped implementation `Zmdu`/`Zmdv` and descriptor class `Zdr`.
* Confirmed `Zdr` field IDs 15, 16, and 17 are 8-byte `Zx9j` addresses paired with parsed request structures at field IDs 21, 22, and 23 for three request variants.
* Confirmed `Zdr` field IDs 18, 19, and 20 are 8-byte `Zx9j` addresses for three complete response variants.
* Confirmed absent persistent object fields resolve to address zero and therefore Java `null`.
* Classified this HTTP mapping as verified from descriptor, writer, reader, and UI call-path symmetry but not yet validated against a project sample.
* Confirmed zero-length variable objects reserve one payload padding byte: stored total size is `9`, logical length is `0`, and exposed payload remains empty.
* Confirmed compact object field lookup reads descriptor offsets as signed big-endian 16-bit values and returns zero when a field ID is absent.
* Confirmed compact object flag bit 0 marks a forwarding record whose replacement object address is the big-endian 64-bit value at offset 1.
* Added `tools/burp_project_parser.py`, a standard-library read-only parser for the verified 72-byte header, variable raw-byte records, compact object descriptor tables, forwarding records, and 64-bit object-address fields.
* Added synthetic parser tests under `tests/test_burp_project_parser.py` covering byte order, version and bounds validation, zero-length record padding, malformed records, descriptor bounds, duplicate fields, forwarding, and null addresses.
* Ran 17 focused synthetic tests successfully with `python3 -m unittest discover -s tests -v`.
* Clarified scope: future project samples are only for validating file-format hypotheses; license enforcement, activation, entitlement checks, modification, and bypass are excluded.
* Received empty default-options project sample at `burp-files/2026-08-03-empty-project.burp`.
* Recorded sample size 524,288 bytes and SHA-256 `3401ab0b70fa66ab8b7af0f7b6eda557f4d16526566a9d0134947322d83c9dfc`.
* Validated all predicted outer header constants against the real sample: magic `0x66858280`, outer version `1`, compatibility `0x80527974`, and both schema shorts `226`.
* Parsed real header addresses and cursor: metadata root `72`, project root `250`, segment span `Long.MAX_VALUE`, and allocation cursor `414802`.
* Parsed the metadata root and project root as compact descriptor objects; the project root exposes 16 descriptor-backed fields.
* Confirmed the existing 17 synthetic parser tests still pass after real-sample inspection.
* Prioritized quick follow-up samples: second empty control, unsent Repeater request, and one deterministic Proxy request/response exchange. Deferred binary payload probe until textual traversal works.
* Added `tools/project_probe_server.py` to return the exact marked HTTP `218` response needed for the Proxy exchange fixture.
* Validated the probe endpoint directly: response marker `RESPONSE-4D8E2B` and exactly 33 body bytes `BURP_PROJECT_RESPONSE_BODY_4D8E2B`.
* Measured the empty sample's preallocated tail: 109,486 bytes from allocation cursor to EOF, all zero; last nonzero byte is at offset 414,737.
* Confirmed the project root at address 250 has subtype 7, matching descriptor `Zys`, and all 16 `Zys` fields contain nonzero 8-byte object addresses.
* Correlated every real project-root field ID with its static `Zys` descriptor type and target compact-object shape.
* Corrected storage interpretation: 1 GiB is the maximum mapping-window size, not the normal physical-file split threshold; observed normal projects use `Long.MAX_VALUE` as physical-file address span.
* Added `ai-docs/empty-project-analysis.md` as the canonical evidence record for the baseline sample.
* Identified project-root field 1 as the Proxy storage root `Zkx` at sample address 1062.
* Mapped `Zkx` descriptor `Zdn`: fields 0 and 1 are `Zp1u` HTTP collections, fields 2 and 3 are `Zxrm` collections, and fields 4 and 5 are sequence counters.
* Located empty-sample `Zp1u` collections at addresses 1124 and 1270; both have logical size zero and chunk size 200.
* Established the validated traversal `header -> project root -> field 1 Proxy root -> fields 0/1 HTTP collections` for comparison with the marked Proxy fixture.
* Mapped `Zwtw` collection internals: field 0 is logical size, field 1 is chunk size, field 2 points to a chunk list, and field 3 tracks a leading offset.
* Confirmed `Zme_` variable chunks store big-endian 64-bit object addresses and use generic variable framing where logical length counts elements.
* Parsed four empty-sample backing records at addresses 1182, 1328, 1474, and 1620; each is 88 bytes with ten null address slots.
* Extended `tools/burp_project_parser.py` with generic fixed-element variable arrays and address-array parsing.
* Expanded the focused parser suite to 21 passing tests and validated all four real empty Proxy address arrays.
* Received request-only Proxy sample `burp-files/2026-08-03-one-request.burp`, size 524,288 bytes, SHA-256 `4fc40009b2f2513f958a0205201babda1fe187a53cdfbf1e1d4bd32a14772886`.
* Confirmed all request markers occur directly in the sample and no planned response marker is present.
* Measured allocation cursor growth from 414802 to 418970, adding 4,168 allocated bytes over the empty baseline.
* Corrected Proxy collection hierarchy: chunk-list slots point to 200-slot chunk arrays, whose logical item slots point to `Zp1u` objects.
* Located populated chunk arrays at 415714 and 417322; both collections resolve to the same `Zp1u` item at address 415222.
* Located raw request record at address 414940 with total size 282 and logical length 274; persisted HTTP bytes are direct and uncompressed.
* Confirmed `Zdr` field 15 points to the request record while fields 16-23 are null, including all response variants 18-20.
* Added `ai-docs/one-request-analysis.md` with complete request-only sample evidence.
* Added bounded forwarding resolution and verified `Zwtw` chunked-collection traversal to the parser.
* Added `--proxy-items` to discover both Proxy collections, logical item addresses, and `Zdr` byte variants 15-20.
* Expanded the focused suite to 24 passing tests, including forwarding cycles and leading-offset handling.
* Validated `--proxy-items` against both real samples: zero baseline items and one shared request-only item with field-15 length 274.
* Received completed Proxy exchange sample `burp-files/2026-08-03-request-response.burp`, SHA-256 `47c1c95a1907d1eb8270daa260aca8e4fe93bca6805fb05d67d9087811e6b6b3`.
* Confirmed both request and response markers occur directly in the completed sample.
* Located shared `Zp1u` item at address 415338, raw request at field 15/address 414842, and raw response at field 18/address 415102.
* Parsed direct request framing: total size 260, logical length 252.
* Parsed direct response framing: total size 236, logical length 228.
* Confirmed request and response are separate adjacent variable records, uncompressed, with preserved CRLF HTTP bytes.
* Added `ai-docs/request-response-analysis.md` with completed-exchange evidence.
* Added `--export-proxy DIRECTORY` to export verified request field 15 and response field 18 while deduplicating shared item addresses across collection views.
* Exported the completed sample to `artifacts/proxy-extract-request-response`: one 252-byte request, one 228-byte response, and a JSON manifest.
* Verified both exported marker headers and exact output lengths.
* Defined combined Repeater fixture `2026-08-03-repeater-both.burp` to avoid separate request-only and completed-exchange projects.
* Recorded in-progress Repeater state: ungrouped unsent tab `repeater-1`; completed tab `repeater-2` as sole member of group `GROUP-D7A4C2`; group color purple, automatically assigned by Burp.
* Received `burp-files/2026-08-030-repeater-both.burp`, SHA-256 `3fea7e177f3cccb7f9bfd828463b4ce48e257ec1711b77c48de475a7c7707e86`.
* Identified project-root field 2 as Repeater root `Zb_y` at address 1708; tab collection field 1 contains two tabs and group collection field 4 contains one group.
* Decoded mutable UTF-16BE captions `repeater-1` and `repeater-2`.
* Confirmed `repeater-1` has no group, no pairs, null current-request field, and no unsent marker anywhere in the sample.
* Confirmed `repeater-2` directly references group object 416526 and contains one pair at address 415828.
* Decoded group `GROUP-D7A4C2`, UUID `fcd376d6-d5c5-4a64-a0b6-94d3f0e0dbfc`, expanded flag true, and persisted color ID 7 (`GROUP_0`), observed by the user as purple.
* Located Repeater pair request field 2 at address 415984, total size 211, logical length 203.
* Located Repeater pair response field 3 at address 416292, total size 234, logical length 226, with status 219 marker.
* Added direct collection, immutable/mutable UTF-16 string, UUID, Repeater inspection, and Repeater export support to the parser.
* Expanded the parser suite to 27 passing synthetic tests.
* Exported one Repeater pair to `artifacts/repeater-extract-both` and verified request/response markers and lengths.
* Added `ai-docs/repeater-both-analysis.md` as the canonical Repeater fixture record.
* Changed parser CLI inspection/export to use one read-only memory map instead of copying complete project files into Python memory.
* Revalidated memory-mapped Proxy and Repeater traversal against real samples; all 27 tests remain passing.
* Classified project-root field 7 (`Zen0`) as Scanner Dashboard state from task/resource-pool factories and Dashboard/scan-management call sites; it is not Logger history storage.
* Confirmed project-root field 11 (`Zgbs`) is Target persistence state containing maps of target keys to extensible `Zcg7` nodes; exact site-map HTTP item semantics remain unresolved.
* Confirmed Logger HTTP history is ephemeral: item interface `Zboe` does not extend the persisted-object contract, Logger is absent from project-root save/load, and Logger uses explicit memory-limit warnings.
* Removed Logger fixture and extraction work from the project-file parser plan.
* Stopped Scanner byte-field mapping at the verified boundary because persisted Scanner tasks have many subtype-specific descriptors; no universal request/response field assignment is yet justified.
* Corrected project-root field 3 semantics: `Zg70` owns shared Target/Scanner indexes, not Intruder state.
* Traced Montoya Site Map insertion: raw request/response become `Zri3`/`Zgfl`, then `Zr9z`/`Zms_` create persistent `Zml1` hierarchy nodes backed by `Zg70` maps.
* Identified `Zg70` fields as service-to-host, request-to-path, request-to-leaf, identity-indexed `Zml1`, and auxiliary list indexes.
* Identified Site Map leaf message descriptor `Zkp`: request byte field 0 and response byte field 1.
* Identified `Zsuv`/`Zj9` as Scanner/audit item state with request field 1 and response field 2; these are not Site Map rows.
* Found a second request record and shared response reference in the completed Proxy sample, consistent with automatic Target/Scanner indexing, but deferred generic Site Map export until index traversal is mapped without reverse-reference heuristics.
* Mapped `Zpt2<Zml1>` identity index at address 15096: empty baseline count 0, completed exchange count 4, 32 sparse buckets, and 24-byte hash/key/value tuples.
* Enumerated four completed-sample Target hierarchy keys: one type-1 host/root node, two type-3 path/leaf nodes, and one type-4 parameterized/message leaf.
* Located Site Map leaf `437252`, message object `437600`, request field 0/address 414842, and response field 1/address 415102.
* Confirmed Proxy and Site Map reuse the same request/response byte objects.
* Added sparse identity-index parser support, `--target-items`, and `--export-target DIRECTORY`.
* Exported one Target/Site Map pair to `artifacts/target-extract-request-response` and verified marker headers and exact lengths.
* Expanded the parser suite to 29 passing synthetic tests.
* Added `ai-docs/target-sitemap-analysis.md` and removed the need for an additional normal Target fixture.
* Added root `README.md` documenting Windows PowerShell and Linux usage for header inspection, Proxy extraction, Repeater extraction, Target Site Map extraction, raw-record inspection, tests, safety, and format limitations.
* Validated the documented Proxy export command against `2026-08-03-request-response.burp`: one 252-byte request, one 228-byte response, and manifest.
* Validated the documented raw-record example at `0x6547a` and reran all 29 parser tests successfully.
* Established Scanner Dashboard baseline across empty and completed samples: two task/template records with type IDs 4 and 5, plus one default `Zwre` profile object.
* Corrected `Zwre` semantics: the collection is seeded from `Zgao` configuration and represents Scanner profile/resource settings, not raw findings or HTTP message storage.
* Determined future Scanner fixture comparisons must inspect task subtype/content deltas because a fresh project does not start with an empty task collection.
* Resolved header metadata root: address 72 points through address 88 to a chunked collection at 104 used as a reusable `Zuei` string-chunk pool.
* Verified `Zsa1` removes a free string chunk or allocates one, and clears length/next fields before returning a chunk to the pool.
* Confirmed all four current real samples have zero entries in the string-chunk recycling pool.
* Scoped integrity conclusion: no checksum or journal operation appears in mapped outer storage, flush, collection, Proxy, or Repeater paths; this is not yet a universal claim for every subtype.
* Mapped normal project durability: `Zikg.PERIODIC_AND_ON_CLOSE` runs `Zp6u.ZL()` every 10 seconds, cancels and shuts down on close, then performs one final force.
* Confirmed `Zp6u.ZL()` snapshots mapped physical regions and calls `MappedByteBuffer.force()` on each; no commit marker, journal rotation, or metadata rewrite occurs immediately before force.
* Confirmed close then releases file locks and closes channels/files through `Zino.Zn()`.

## 2026-09-04

* Removed the stale claim that Logger persistence remained unresolved; current evidence classifies Logger HTTP history as session-ephemeral and absent from project-root persistence.
* Corrected completed Proxy fixture references to reuse the request-only Project D markers rather than the unrelated empty or Repeater fixtures.
* Replaced the completed first-goal text with current priorities: real-sample regression tests, generic descriptor inspection, Scanner subtype mapping, and a discriminating combined Scanner fixture.
* Updated the fresh-session prompt to treat the parser as an existing schema-226 implementation rather than future work.
* Added publication preparation requirements for a versioned specification, machine-readable field registry, JSON Schemas, fixture metadata, compatibility boundaries, and release-package provenance review.
* Chose to separate reusable parser and export-library code from CLI argument parsing before expanding format support.
* Required canonical exports to preserve raw payload bytes as unwrapped RFC 4648 base64 with decoded byte length and SHA-256 verification; canonical export must not decode payload bytes as text.
* Moved CLI argument parsing, memory-map orchestration, and JSON presentation into `tools/burp_project_cli.py`; retained `tools/burp_project_parser.py` as the compatible command path.
* Added the context-managed `BurpProject` library API for read-only header, record, Proxy, Repeater, Target, and export access.
* Added a real empty-project library lifecycle test; all 30 tests pass.
* Decoded project-root field 6 as the project display name and field 15 as a random per-project 20-character identifier.
* Resolved project-root field 0 as Burp's installation ID: `Zgaz` reads Java user preferences key `burp.suite.installationId`, validates `^[a-z0-9]{20}$`, generates and stores a replacement when absent or invalid, and copies it into projects.
* Confirmed the installation ID is randomly generated and passed separately from license data; it is not derived from the license owner or key, but it may permit cross-file correlation.
* Found no creator name, OS username, email address, original project path, hostname, license key, activation response, or entitlement record in verified root fields or readable strings of the controlled samples.
* Confirmed Burp's save-copy UI can retain Dashboard and Collaborator IDs depending on selected options.
* Added `--project-metadata` and `BurpProject.inspect_project_metadata()` plus a real-sample metadata test; all 31 tests pass.
* Simplified release decisions: one JSON export document, a single `format_version` field, base64 payloads without redundant decoded-length or SHA-256 fields, and no installation ID in normal exports.
* Chose `prub/` as the public repository root and `prub` as the distribution, import package, and CLI name; package source lives under `src/prub/`.
* Decided not to publish controlled `.burp` fixtures and not to include Burp binaries, decompiled sources, Ghidra data, virtual environments, or generated research artifacts.
* Deferred real-project testing strategy, hostile-file limits, and compatibility behavior for separate discussion in `ai-docs/release-plan.md`.
