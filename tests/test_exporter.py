import base64
import struct
import unittest

from prub import ProjectHeader, build_export


def add_record(data: bytearray, offset: int, payload: bytes) -> None:
    struct.pack_into(">ii", data, offset, len(payload) + 8, len(payload))
    data[offset + 8 : offset + 8 + len(payload)] = payload


class FakeProject:
    def __init__(self) -> None:
        self.data = bytearray(256)
        add_record(self.data, 16, b"request-\x00-\xff")
        add_record(self.data, 64, b"response-\x80")
        add_record(self.data, 112, b"repeater-request")
        self.header = ProjectHeader(
            magic=0,
            outer_version=1,
            compatibility=0,
            schema_floor=226,
            schema_current=226,
            random_identifier=0,
            metadata_root=0,
            segment_span=0,
            allocation_cursor=0,
            project_root=0,
        )

    def inspect_project_metadata(self) -> dict[str, object]:
        return {
            "project_name": "example",
            "installation_id": "must-not-export",
            "project_identifier": "must-not-export",
        }

    def inspect_proxy_items(self) -> dict[str, object]:
        item = {
            "address": 200,
            "byte_variants": {
                "15": {"address": 16},
                "18": {"address": 64},
            },
        }
        return {"collections": [{"items": [item]}, {"items": [item]}]}

    def inspect_repeater_items(self) -> dict[str, object]:
        return {
            "groups": [
                {
                    "address": 210,
                    "name": "group",
                    "uuid": "group-uuid",
                    "color_id": 7,
                }
            ],
            "tabs": [
                {
                    "caption": "tab",
                    "uuid": "tab-uuid",
                    "group_address": 210,
                    "pairs": [
                        {
                            "request": {"address": 112},
                            "response": {"address": None},
                        }
                    ],
                }
            ],
        }

    def inspect_target_items(self) -> dict[str, object]:
        return {
            "nodes": [
                {
                    "type_id": 4,
                    "request": {"address": 16},
                    "response": {"address": 64},
                }
            ]
        }


class ExportTests(unittest.TestCase):
    def test_separates_tools_and_preserves_binary_payloads(self) -> None:
        document = build_export(FakeProject())

        self.assertEqual(document["burp_schema"], 226)
        self.assertEqual(document["project_name"], "example")
        self.assertNotIn("format_version", document)
        self.assertNotIn("installation_id", document)
        self.assertNotIn("project_identifier", document)
        self.assertEqual(len(document["proxy"]), 1)
        self.assertEqual(len(document["repeater"]), 1)
        self.assertEqual(len(document["target"]), 1)

        proxy = document["proxy"][0]
        self.assertEqual(proxy["id"], "proxy-000001")
        self.assertEqual(
            base64.b64decode(proxy["request_base64"]),
            b"request-\x00-\xff",
        )
        self.assertEqual(
            base64.b64decode(proxy["response_base64"]),
            b"response-\x80",
        )

        repeater = document["repeater"][0]
        self.assertEqual(repeater["id"], "repeater-000001")
        self.assertEqual(
            base64.b64decode(repeater["request_base64"]),
            b"repeater-request",
        )
        self.assertIsNone(repeater["response_base64"])
        self.assertEqual(repeater["tab"]["caption"], "tab")
        self.assertEqual(repeater["group"]["name"], "group")
        self.assertEqual(repeater["pair_index"], 1)

        target = document["target"][0]
        self.assertEqual(target["id"], "target-000001")
        self.assertNotIn("node_type", target)
        self.assertEqual(
            base64.b64decode(target["request_base64"]),
            b"request-\x00-\xff",
        )


if __name__ == "__main__":
    unittest.main()