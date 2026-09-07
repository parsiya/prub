# ai-docs
These AI-assisted reverse-engineering notes record the evidence and confidence boundaries behind `prub`.

## Research History

* [Activity log](activity-log.md) records the reverse-engineering and implementation chronology.
* [Burp classes and methods](burp-classes.md) indexes the obfuscated symbols, important methods, and relationships used in the analysis.

## Specifications

* [Burp project format](format-specification.md) consolidates verified binary framing, object layouts, HTTP mappings, storage behavior, and compatibility limits.
* [JSON export format](export-format.md) defines the public export document.

## Sample Evidence

* [Empty project](empty-project-analysis.md) maps the header, roots, allocation boundary, and baseline collections.
* [Proxy request only](one-request-analysis.md) maps collection traversal, request field `15`, and null response fields.
* [Proxy request and response](request-response-analysis.md) validates normal request field `15` and response field `18`.
* [Repeater and group](repeater-both-analysis.md) maps tabs, groups, UUIDs, and completed message pairs.
* [Target Site Map](target-sitemap-analysis.md) maps hierarchy indexes and Site Map request/response fields.
* [Project portability](project-portability-analysis.md) records persisted identity metadata and privacy limits.

Controlled `.burp` fixtures, Burp binaries, decompiled sources, and generated research artifacts are intentionally not distributed in this repository. Sample-specific conclusions are not generalized beyond their stated evidence.
