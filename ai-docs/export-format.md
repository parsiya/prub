# JSON Export Format

`prub export PROJECT.burp export.json` writes one JSON object containing all supported HTTP messages from Proxy, Repeater, and Target Site Map.

## Top-Level Object

* `burp_schema`: Burp project schema number read from the input file.
* `project_name`: persisted Burp project display name, or `null` if absent.
* `proxy`: Proxy HTTP history messages.
* `repeater`: Repeater request/response pairs.
* `target`: Target Site Map messages.

The normal export intentionally excludes the Burp installation ID, per-project identifier, header random identifier, source path, and internal storage addresses.

## Common Message Fields

Every Proxy, Repeater, and Target entry contains:

* `id`: sequential identifier local to its section, such as `proxy-000001`.
* `request_base64`: complete request bytes encoded with standard RFC 4648 base64, or `null`.
* `response_base64`: complete response bytes encoded with standard RFC 4648 base64, or `null`.

Proxy and Target can contain the same HTTP pair because Burp stores those as separate tool views. Entries are deduplicated within each section, not across sections.

## Proxy Entry

Proxy entries contain only the common message fields:

```json
{
  "id": "proxy-000001",
  "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
  "response_base64": null
}
```

## Repeater Entry

Repeater entries also contain:

* `tab.caption`: persisted Repeater tab caption, or `null`.
* `tab.uuid`: persisted tab UUID, or `null`.
* `group`: group metadata, or `null` for an ungrouped tab.
* `group.name`: persisted group name, or `null`.
* `group.uuid`: persisted group UUID, or `null`.
* `group.color_id`: persisted numeric group color ID, or `null`.
* `pair_index`: one-based position of the request/response pair within the tab.

```json
{
  "id": "repeater-000001",
  "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
  "response_base64": null,
  "tab": {
    "caption": "repeater-2",
    "uuid": "a1b297a2-203f-433a-88ae-6e6d964c3a5e"
  },
  "group": {
    "name": "GROUP-D7A4C2",
    "uuid": "fcd376d6-d5c5-4a64-a0b6-94d3f0e0dbfc",
    "color_id": 7
  },
  "pair_index": 1
}
```

## Target Entry

Target entries contain only the common message fields:

```json
{
  "id": "target-000001",
  "request_base64": "R0VUIC8gSFRUUC8xLjENCg0K",
  "response_base64": null
}
```

Burp internally assigns hierarchy node types to Target objects. Those numeric implementation details are documented in `ai-docs/target-sitemap-analysis.md#identity-index` and are intentionally not included in the JSON export.

## Complete Example

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

Base64 values decode to the original byte-for-byte HTTP messages, including binary bodies and CRLF framing.
