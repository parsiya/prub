# prub
(A)I reverse engineered Burp Suite project format and created a tool to export
Proxy history, Repeater messages, and Target Site Map traffic from projects.

More discussion: https://parsiya.net/blog/burp-project-reverse/.

Burp's extension API has access to the Proxy History so export these have not
been a problem. However, I've always wanted to export Repeater file. This also
allows you to export data from project files without opening them in Burp.

This project is unofficial. Burp Suite is a product of PortSwigger Ltd. This
project is not affiliated with or endorsed by PortSwigger.

* Model: GPT-5.6-Sol - High reasoning effort - 1M context window.
* Rough cost: ~160 USD (fewer than 16,000 GitHub Copilot AI credits).
* Harness: GitHub Copilot CLI and GitHub Copilot Chat in VS Code.

## Supported Format
Current support was derived from static analysis of Burp Suite `2026.7.1` and
controlled project files using schema `226` and outer storage version `1`.

Supported data:

* Project metadata.
* Proxy HTTP history, extensions can already do this but you need to open the file in Burp.
* Repeater tabs, groups, requests, and responses.
* Target Site Map requests and responses.

Scanner records, WebSocket messages, extension-owned data, and project writing
are not supported. Only schema `226` is documented and sample-validated.

## Reverse-Engineered Format Notes
The evidence and current format mapping are published under `ai-docs/`:

* [ai-docs/activity-log.md](ai-docs/activity-log.md) records the reverse-engineering and implementation chronology.
* [ai-docs/burp-classes.md](ai-docs/burp-classes.md) indexes the important obfuscated classes, methods, and relationships.
* [ai-docs/format-specification.md](ai-docs/format-specification.md) consolidates verified binary structures, field mappings, and compatibility limits.
* [ai-docs/export-format.md](ai-docs/export-format.md) defines every field in the JSON export.
* [ai-docs/empty-project-analysis.md](ai-docs/empty-project-analysis.md) describes the header, roots, and baseline object graph.
* [ai-docs/one-request-analysis.md](ai-docs/one-request-analysis.md) and [ai-docs/request-response-analysis.md](ai-docs/request-response-analysis.md) map Proxy records.
* [ai-docs/repeater-both-analysis.md](ai-docs/repeater-both-analysis.md) maps Repeater tabs, groups, and message pairs.
* [ai-docs/target-sitemap-analysis.md](ai-docs/target-sitemap-analysis.md) maps Target Site Map hierarchy and messages.
* [ai-docs/project-portability-analysis.md](ai-docs/project-portability-analysis.md) documents persisted identifiers and privacy findings.

## Install

```bash
python -m pip install .
```

Python 3.10 through 3.13 is supported. The package has no runtime dependencies.

## Export

Export all supported HTTP messages to one JSON file:

```bash
prub export project.burp export.json
```

This is the main command most users need. Output fields and examples are
documented in [ai-docs/export-format.md](ai-docs/export-format.md).

## Python Library
The tool can also be used as a Python library.

```python
from prub import BurpProject, build_export

with BurpProject("project.burp") as project:
  print(project.inspect_project_metadata())
  document = build_export(project)
```

`BurpProject` closes the read-only memory map when its context exits. Inspection
methods return Python dictionaries. Raw records expose payloads as `bytes`.

## JSON Export
The exporter writes one JSON object. Complete field documentation is in
[ai-docs/export-format.md](ai-docs/export-format.md).

Top-level fields:

* `burp_schema`: input Burp schema number.
* `project_name`: persisted project display name.
* `proxy`: Proxy HTTP history messages.
* `repeater`: Repeater request/response pairs.
* `target`: Target Site Map messages.

Every entry contains:

* `id`: ID local to its section, such as `proxy-000001`.
* `request_base64`: exact request bytes, or `null`.
* `response_base64`: exact response bytes, or `null`.

Repeater entries additionally contain tab caption and UUID, optional group name,
UUID, and color ID, plus the pair index within the tab.

Burp's internal Target hierarchy node types are explained in
[ai-docs/target-sitemap-analysis.md](ai-docs/target-sitemap-analysis.md#identity-index).
They are implementation details and are not exported.

Example containing one entry from each supported tool:

```json
{
  "burp_schema": 226,
  "project_name": "example",
  "proxy": [
    {
      "id": "proxy-000001",
      "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
      "response_base64": null
    }
  ],
  "repeater": [
    {
      "id": "repeater-000001",
      "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
      "response_base64": null,
      "tab": {
        "caption": "repeater-2",
        "uuid": "a1b297a2-203f-433a-88ae-6e6d964c3a5e"
      },
      "group": null,
      "pair_index": 1
    }
  ],
  "target": [
    {
      "id": "target-000001",
      "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
      "response_base64": null
    }
  ]
}
```

Request and response values use standard RFC 4648 base64, preserving arbitrary
binary bytes. The same pair may appear in both `proxy` and `target`, making each
tool section independently readable. Installation ID and internal storage
addresses are not included.

## Advanced Inspection
These commands expose Burp storage details for reverse engineering,
troubleshooting, and parser development. They are not needed for normal exports.

Inspect persisted project metadata:

```bash
prub metadata project.burp
```

```json
{
  "header_random_identifier": 305419896,
  "installation_id": "exampleinstall000001",
  "project_identifier": "exampleproject000001",
  "project_name": "example",
  "schema_current": 226,
  "schema_floor": 226
}
```

Inspect internal collections, field variants, hierarchy nodes, record addresses,
and lengths for one supported Burp tool:

```bash
prub inspect proxy project.burp
prub inspect repeater project.burp
prub inspect target project.burp
```

Read one raw byte record at a known internal address:

```bash
prub record project.burp 0x6547a
```

```json
{
  "logical_length": 18,
  "offset": 414842,
  "payload_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
  "total_size": 26
}
```

`record` is useful only when an address is already known from inspection or
format research. It does not search the project file.

## Safety
The parser validates known headers, record lengths, object descriptors,
forwarding depth, collection dimensions, nonnegative addresses, and read bounds
within the mapped file. It never modifies the input project. It is not yet
claimed to be hardened against arbitrary malicious files; individual object
reads are not currently bounded by the allocation cursor.

Treat project files and exports as sensitive. They may contain credentials,
cookies, authorization headers, private URLs, and response bodies. The optional
`installation_id` metadata can also correlate projects created under the same
Burp user profile; it is excluded from normal exports.
