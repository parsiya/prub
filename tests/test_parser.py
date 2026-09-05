import struct
import unittest

from prub.parser import (
    HEADER_SIZE,
    MAGIC,
    MAX_COMPATIBILITY,
    ProjectFormatError,
    UnsupportedProjectVersionError,
    inspect_proxy_items,
    parse_address_array_record,
    parse_compact_object,
    parse_header,
    parse_variable_array_record,
    parse_variable_record,
    read_chunked_collection_addresses,
    read_chunked_collection_slots,
    read_direct_collection_addresses,
    read_immutable_string,
    read_identity_index_entries,
    read_mutable_string,
    read_object_address,
    read_utf16_array_string,
    resolve_compact_object,
)


def make_header(**overrides: int) -> bytes:
    values = {
        "magic": MAGIC,
        "outer_version": 1,
        "compatibility": MAX_COMPATIBILITY,
        "schema_floor": 226,
        "schema_current": 226,
        "random_identifier": 0xA1B2C3D4,
        "metadata_root": 80,
        "segment_span": 1 << 30,
        "allocation_cursor": 128,
        "project_root": 96,
    }
    values.update(overrides)

    header = bytearray(128)
    struct.pack_into(
        ">IiiHHI",
        header,
        0,
        values["magic"],
        values["outer_version"],
        values["compatibility"],
        values["schema_floor"],
        values["schema_current"],
        values["random_identifier"],
    )
    struct.pack_into(
        ">qqqq",
        header,
        40,
        values["metadata_root"],
        values["segment_span"],
        values["allocation_cursor"],
        values["project_root"],
    )
    return bytes(header)


class HeaderTests(unittest.TestCase):
    def test_parses_verified_big_endian_fields(self) -> None:
        header = parse_header(make_header())

        self.assertEqual(header.magic, MAGIC)
        self.assertEqual(header.outer_version, 1)
        self.assertEqual(header.compatibility, MAX_COMPATIBILITY)
        self.assertEqual(header.schema_floor, 226)
        self.assertEqual(header.schema_current, 226)
        self.assertEqual(header.random_identifier, 0xA1B2C3D4)
        self.assertEqual(header.metadata_root, 80)
        self.assertEqual(header.segment_span, 1 << 30)
        self.assertEqual(header.allocation_cursor, 128)
        self.assertEqual(header.project_root, 96)

    def test_rejects_short_header(self) -> None:
        with self.assertRaises(ProjectFormatError):
            parse_header(bytes(HEADER_SIZE - 1))

    def test_rejects_wrong_magic(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "invalid project magic"):
            parse_header(make_header(magic=0x12345678))

    def test_rejects_newer_outer_version(self) -> None:
        with self.assertRaises(UnsupportedProjectVersionError):
            parse_header(make_header(outer_version=2))

    def test_rejects_newer_compatibility_value(self) -> None:
        with self.assertRaises(UnsupportedProjectVersionError):
            parse_header(make_header(compatibility=MAX_COMPATIBILITY + 1))

    def test_rejects_cursor_before_header(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "precedes object data"):
            parse_header(make_header(allocation_cursor=HEADER_SIZE - 1))

    def test_rejects_cursor_beyond_available_data(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "exceeds available data"):
            parse_header(make_header(allocation_cursor=129))


class VariableRecordTests(unittest.TestCase):
    def test_parses_raw_payload(self) -> None:
        payload = b"BURP_PROJECT_REQUEST_BODY_7F3C9A"
        record = struct.pack(">ii", len(payload) + 8, len(payload)) + payload

        parsed = parse_variable_record(b"prefix" + record, 6)

        self.assertEqual(parsed.total_size, len(payload) + 8)
        self.assertEqual(parsed.logical_length, len(payload))
        self.assertEqual(parsed.payload, payload)

    def test_parses_zero_length_record_with_padding_byte(self) -> None:
        parsed = parse_variable_record(struct.pack(">iiB", 9, 0, 0), 0)

        self.assertEqual(parsed.total_size, 9)
        self.assertEqual(parsed.logical_length, 0)
        self.assertEqual(parsed.payload, b"")

    def test_rejects_unpadded_zero_length_record(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "expected 9"):
            parse_variable_record(struct.pack(">ii", 8, 0), 0)

    def test_rejects_mismatched_total_size(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "does not match"):
            parse_variable_record(struct.pack(">ii4s", 13, 4, b"test"), 0)

    def test_rejects_truncated_payload(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "exceeds available data"):
            parse_variable_record(struct.pack(">ii3s", 12, 4, b"abc"), 0)


class VariableArrayRecordTests(unittest.TestCase):
    def test_parses_ten_address_slots_matching_proxy_chunk_capacity(self) -> None:
        record = struct.pack(">ii10q", 88, 10, *([0] * 10))

        parsed = parse_variable_array_record(record, 0, 8)

        self.assertEqual(parsed.total_size, 88)
        self.assertEqual(parsed.element_count, 10)
        self.assertEqual(parsed.element_size, 8)
        self.assertEqual(parse_address_array_record(record, 0), (None,) * 10)

    def test_parses_nonzero_address_slots(self) -> None:
        record = struct.pack(">ii3q", 32, 3, 120, 0, 240)

        self.assertEqual(parse_address_array_record(record, 0), (120, None, 240))

    def test_rejects_mismatched_element_size(self) -> None:
        record = struct.pack(">ii10q", 88, 10, *([0] * 10))
        with self.assertRaisesRegex(ProjectFormatError, "does not match"):
            parse_variable_array_record(record, 0, 4)

    def test_rejects_negative_address(self) -> None:
        record = struct.pack(">ii1q", 16, 1, -1)
        with self.assertRaisesRegex(ProjectFormatError, "negative address"):
            parse_address_array_record(record, 0)


class CompactObjectTests(unittest.TestCase):
    def test_parses_descriptor_table_and_address_fields(self) -> None:
        data = bytearray(64)
        data[8:18] = bytes([0, 42, 3, 2, 15, 0, 10, 18, 0, 18])
        struct.pack_into(">q", data, 18, 120)
        struct.pack_into(">q", data, 26, 0)

        object_record = parse_compact_object(data, 8)

        self.assertEqual(object_record.type_id, 42)
        self.assertEqual(object_record.subtype, 3)
        self.assertEqual(
            [(field.field_id, field.relative_offset) for field in object_record.fields],
            [(15, 10), (18, 18)],
        )
        self.assertEqual(read_object_address(data, object_record, 15), 120)
        self.assertIsNone(read_object_address(data, object_record, 18))
        self.assertIsNone(read_object_address(data, object_record, 20))

    def test_parses_forwarding_record(self) -> None:
        data = bytearray(24)
        data[4] = 1
        struct.pack_into(">q", data, 5, 128)

        object_record = parse_compact_object(data, 4)

        self.assertEqual(object_record.forwarding_address, 128)
        self.assertIsNone(object_record.type_id)
        with self.assertRaisesRegex(ProjectFormatError, "forwarding record"):
            read_object_address(data, object_record, 15)

    def test_rejects_truncated_descriptor_table(self) -> None:
        with self.assertRaisesRegex(ProjectFormatError, "descriptor table"):
            parse_compact_object(bytes([0, 1, 0, 2, 15, 0, 10]), 0)

    def test_rejects_descriptor_overlapping_table(self) -> None:
        data = bytes([0, 1, 0, 1, 15, 0, 6, 0])
        with self.assertRaisesRegex(ProjectFormatError, "overlaps"):
            parse_compact_object(data, 0)

    def test_rejects_duplicate_field_ids(self) -> None:
        data = bytes([0, 1, 0, 2, 15, 0, 10, 15, 0, 11, 0, 0])
        with self.assertRaisesRegex(ProjectFormatError, "duplicate field ID"):
            parse_compact_object(data, 0)

    def test_follows_forwarding_record(self) -> None:
        data = bytearray(32)
        data[4] = 1
        struct.pack_into(">q", data, 5, 16)
        data[16:20] = bytes([0, 7, 3, 0])

        object_record = resolve_compact_object(data, 4)

        self.assertEqual(object_record.offset, 16)
        self.assertEqual(object_record.type_id, 7)
        self.assertEqual(object_record.subtype, 3)

    def test_rejects_forwarding_cycle(self) -> None:
        data = bytearray(32)
        data[4] = 1
        data[16] = 1
        struct.pack_into(">q", data, 5, 16)
        struct.pack_into(">q", data, 17, 4)

        with self.assertRaisesRegex(ProjectFormatError, "forwarding cycle"):
            resolve_compact_object(data, 4)


class ChunkedCollectionTests(unittest.TestCase):
    def test_uses_leading_offset_and_ignores_stale_slot(self) -> None:
        data = bytearray(512)

        collection = 16
        data[collection : collection + 16] = bytes(
            [0, 0, 0, 4, 0, 0, 16, 1, 0, 20, 2, 0, 24, 3, 0, 32]
        )
        struct.pack_into(">iiqi", data, collection + 16, 1, 4, 80, 1)

        chunk_list = 80
        data[chunk_list : chunk_list + 10] = bytes(
            [0, 0, 0, 2, 0, 0, 10, 1, 0, 14]
        )
        struct.pack_into(">iq", data, chunk_list + 10, 1, 104)

        struct.pack_into(">ii10q", data, 104, 88, 10, 200, *([0] * 9))
        struct.pack_into(">ii4q", data, 200, 40, 4, 111, 333, 0, 0)

        self.assertEqual(read_chunked_collection_addresses(data, collection), (333,))

    def test_nullable_slots_support_sparse_hash_buckets(self) -> None:
        data = bytearray(512)

        collection = 16
        data[collection : collection + 16] = bytes(
            [0, 0, 0, 4, 0, 0, 16, 1, 0, 20, 2, 0, 24, 3, 0, 32]
        )
        struct.pack_into(">iiqi", data, collection + 16, 2, 4, 80, 0)

        chunk_list = 80
        data[chunk_list : chunk_list + 10] = bytes(
            [0, 0, 0, 2, 0, 0, 10, 1, 0, 14]
        )
        struct.pack_into(">iq", data, chunk_list + 10, 1, 104)

        struct.pack_into(">ii10q", data, 104, 88, 10, 200, *([0] * 9))
        struct.pack_into(">ii4q", data, 200, 40, 4, 111, 0, 0, 0)

        self.assertEqual(
            read_chunked_collection_slots(data, collection),
            (111, None),
        )
        with self.assertRaisesRegex(ProjectFormatError, "logical item 1"):
            read_chunked_collection_addresses(data, collection)


class DirectCollectionAndStringTests(unittest.TestCase):
    def test_reads_direct_collection_addresses(self) -> None:
        data = bytearray(256)
        collection = 16
        data[collection : collection + 10] = bytes(
            [0, 0, 0, 2, 0, 0, 10, 1, 0, 14]
        )
        struct.pack_into(">iq", data, collection + 10, 2, 64)
        struct.pack_into(">ii3q", data, 64, 32, 3, 120, 160, 0)

        self.assertEqual(read_direct_collection_addresses(data, collection), (120, 160))

    def test_reads_utf16_array_and_immutable_string(self) -> None:
        data = bytearray(160)
        string_object = 16
        data[string_object : string_object + 10] = bytes(
            [0, 0, 0, 2, 0, 0, 10, 1, 0, 18]
        )
        struct.pack_into(">qi", data, string_object + 10, 64, 0)
        text = "GROUP-D7A4C2"
        encoded = text.encode("utf-16-be")
        struct.pack_into(">ii", data, 64, len(encoded) + 8, len(text))
        data[72 : 72 + len(encoded)] = encoded

        self.assertEqual(read_utf16_array_string(data, 64), text)
        self.assertEqual(read_immutable_string(data, string_object), text)

    def test_reads_chunked_mutable_string(self) -> None:
        data = bytearray(272)
        string_object = 16
        data[string_object : string_object + 16] = bytes(
            [0, 0, 0, 4, 0, 0, 16, 1, 0, 20, 2, 0, 24, 3, 0, 28]
        )
        struct.pack_into(">iiiq", data, string_object + 16, 5, 0, 4, 64)

        data[64:74] = bytes([0, 0, 0, 2, 0, 0, 10, 1, 0, 14])
        struct.pack_into(">iq", data, 74, 2, 96)
        struct.pack_into(">ii10q", data, 96, 88, 10, 200, 220, *([0] * 8))

        for address, text in ((200, "hell"), (220, "o   ")):
            encoded = text.encode("utf-16-be")
            struct.pack_into(">ii", data, address, 16, 4)
            data[address + 8 : address + 16] = encoded

        self.assertEqual(read_mutable_string(data, string_object), "hello")


class IdentityIndexTests(unittest.TestCase):
    def test_decodes_sparse_bucket_tuple(self) -> None:
        data = bytearray(800)

        index = 16
        data[index : index + 19] = bytes(
            [0, 0, 0, 5, 0, 0, 19, 2, 0, 23, 1, 0, 27, 3, 0, 31, 4, 0, 39]
        )
        struct.pack_into(">fiiqh", data, index + 19, 0.75, 1, 24, 64, 2)

        collection = 64
        data[collection : collection + 16] = bytes(
            [0, 0, 0, 4, 0, 0, 16, 1, 0, 20, 2, 0, 24, 3, 0, 32]
        )
        struct.pack_into(">iiqi", data, collection + 16, 32, 32, 128, 0)

        chunk_list = 128
        data[chunk_list : chunk_list + 10] = bytes(
            [0, 0, 0, 2, 0, 0, 10, 1, 0, 14]
        )
        struct.pack_into(">iq", data, chunk_list + 10, 1, 160)
        struct.pack_into(">ii10q", data, 160, 88, 10, 256, *([0] * 9))

        bucket_slots = [0] * 32
        bucket_slots[5] = 600
        struct.pack_into(">ii32q", data, 256, 264, 32, *bucket_slots)

        data[600:610] = bytes([0, 0, 0, 2, 0, 0, 10, 1, 0, 14])
        struct.pack_into(">iq", data, 610, 1, 640)
        struct.pack_into(">ii6q", data, 640, 56, 2, 12345, 720, 9, 0, 0, 0)
        data[720:724] = bytes([0, 4, 0, 0])

        self.assertEqual(
            read_identity_index_entries(data, index),
            (
                {
                    "bucket": 5,
                    "hash": 12345,
                    "key_address": 720,
                    "value": 9,
                },
            ),
        )


if __name__ == "__main__":
    unittest.main()