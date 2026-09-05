#!/usr/bin/env python3
"""Reusable read-only parser for verified Burp project structures."""

from __future__ import annotations

import mmap
import os
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Final


HEADER_SIZE: Final = 72
MAGIC: Final = 0x66858280
MAX_OUTER_VERSION: Final = 1
MAX_COMPATIBILITY: Final = -2142078604


class ProjectFormatError(ValueError):
    """Raised when bytes violate a verified project-format invariant."""


class UnsupportedProjectVersionError(ProjectFormatError):
    """Raised when a project requires a newer storage implementation."""


@dataclass(frozen=True)
class ProjectHeader:
    magic: int
    outer_version: int
    compatibility: int
    schema_floor: int
    schema_current: int
    random_identifier: int
    metadata_root: int
    segment_span: int
    allocation_cursor: int
    project_root: int


@dataclass(frozen=True)
class VariableRecord:
    offset: int
    total_size: int
    logical_length: int
    payload: bytes


@dataclass(frozen=True)
class VariableArrayRecord:
    offset: int
    total_size: int
    element_count: int
    element_size: int
    payload: bytes


@dataclass(frozen=True)
class ObjectField:
    field_id: int
    relative_offset: int


@dataclass(frozen=True)
class CompactObject:
    offset: int
    flags: int
    type_id: int | None
    subtype: int | None
    fields: tuple[ObjectField, ...]
    forwarding_address: int | None = None

    def field(self, field_id: int) -> ObjectField | None:
        return next((field for field in self.fields if field.field_id == field_id), None)


def parse_header(
    data: bytes | bytearray | memoryview,
    *,
    available_size: int | None = None,
) -> ProjectHeader:
    """Parse and validate the 72-byte outer header.

    ``available_size`` is the total addressable size across known project
    segments. It defaults to the supplied buffer length.
    """

    view = memoryview(data)
    if len(view) < HEADER_SIZE:
        raise ProjectFormatError(
            f"project header requires {HEADER_SIZE} bytes; got {len(view)}"
        )

    magic, outer_version, compatibility = struct.unpack_from(">Iii", view, 0)
    schema_floor, schema_current = struct.unpack_from(">HH", view, 12)
    random_identifier = struct.unpack_from(">I", view, 16)[0]
    metadata_root, segment_span, allocation_cursor, project_root = (
        struct.unpack_from(">qqqq", view, 40)
    )

    if magic != MAGIC:
        raise ProjectFormatError(f"invalid project magic: 0x{magic:08x}")
    if outer_version < 0 or outer_version > MAX_OUTER_VERSION:
        raise UnsupportedProjectVersionError(
            f"unsupported outer version: {outer_version}"
        )
    if compatibility > MAX_COMPATIBILITY:
        raise UnsupportedProjectVersionError(
            f"unsupported compatibility value: {compatibility}"
        )
    if segment_span <= 0:
        raise ProjectFormatError(f"invalid segment span: {segment_span}")
    if allocation_cursor < HEADER_SIZE:
        raise ProjectFormatError(
            f"allocation cursor {allocation_cursor} precedes object data"
        )
    if metadata_root < 0 or project_root < 0:
        raise ProjectFormatError("root addresses must not be negative")

    if available_size is None:
        available_size = len(view)
    if available_size < HEADER_SIZE:
        raise ProjectFormatError(
            f"available project data is smaller than the header: {available_size}"
        )
    if allocation_cursor > available_size:
        raise ProjectFormatError(
            f"allocation cursor {allocation_cursor} exceeds available data "
            f"{available_size}"
        )

    return ProjectHeader(
        magic=magic,
        outer_version=outer_version,
        compatibility=compatibility,
        schema_floor=schema_floor,
        schema_current=schema_current,
        random_identifier=random_identifier,
        metadata_root=metadata_root,
        segment_span=segment_span,
        allocation_cursor=allocation_cursor,
        project_root=project_root,
    )


def parse_variable_record(
    data: bytes | bytearray | memoryview,
    offset: int,
) -> VariableRecord:
    """Parse an independently addressed variable-size raw-byte record."""

    view = memoryview(data)
    if offset < 0:
        raise ProjectFormatError(f"record offset must not be negative: {offset}")
    if offset + 8 > len(view):
        raise ProjectFormatError(f"record header at {offset} exceeds available data")

    total_size, logical_length = struct.unpack_from(">ii", view, offset)
    if logical_length < 0:
        raise ProjectFormatError(f"negative logical length: {logical_length}")

    stored_payload_size = max(logical_length, 1)
    expected_total_size = 8 + stored_payload_size
    if total_size != expected_total_size:
        raise ProjectFormatError(
            f"record total size {total_size} does not match expected "
            f"{expected_total_size}"
        )

    record_end = offset + total_size
    if record_end > len(view):
        raise ProjectFormatError(
            f"record ending at {record_end} exceeds available data {len(view)}"
        )

    payload_start = offset + 8
    payload = bytes(view[payload_start : payload_start + logical_length])
    return VariableRecord(
        offset=offset,
        total_size=total_size,
        logical_length=logical_length,
        payload=payload,
    )


def parse_variable_array_record(
    data: bytes | bytearray | memoryview,
    offset: int,
    element_size: int,
) -> VariableArrayRecord:
    """Parse variable framing whose logical length counts fixed-size elements."""

    if element_size <= 0:
        raise ProjectFormatError(f"element size must be positive: {element_size}")

    view = memoryview(data)
    if offset < 0:
        raise ProjectFormatError(f"record offset must not be negative: {offset}")
    if offset + 8 > len(view):
        raise ProjectFormatError(f"record header at {offset} exceeds available data")

    total_size, element_count = struct.unpack_from(">ii", view, offset)
    if element_count < 0:
        raise ProjectFormatError(f"negative element count: {element_count}")

    payload_size = element_count * element_size
    stored_payload_size = max(payload_size, 1)
    expected_total_size = 8 + stored_payload_size
    if total_size != expected_total_size:
        raise ProjectFormatError(
            f"array total size {total_size} does not match expected "
            f"{expected_total_size}"
        )

    record_end = offset + total_size
    if record_end > len(view):
        raise ProjectFormatError(
            f"array ending at {record_end} exceeds available data {len(view)}"
        )

    payload_start = offset + 8
    payload = bytes(view[payload_start : payload_start + payload_size])
    return VariableArrayRecord(
        offset=offset,
        total_size=total_size,
        element_count=element_count,
        element_size=element_size,
        payload=payload,
    )


def parse_address_array_record(
    data: bytes | bytearray | memoryview,
    offset: int,
) -> tuple[int | None, ...]:
    """Parse a variable array of big-endian 64-bit object addresses."""

    record = parse_variable_array_record(data, offset, 8)
    addresses = struct.unpack(f">{record.element_count}q", record.payload)
    if any(address < 0 for address in addresses):
        raise ProjectFormatError("address array contains a negative address")
    return tuple(None if address == 0 else address for address in addresses)


def parse_compact_object(
    data: bytes | bytearray | memoryview,
    offset: int,
) -> CompactObject:
    """Parse the descriptor table used by outer-format version 1 objects."""

    view = memoryview(data)
    if offset < 0:
        raise ProjectFormatError(f"object offset must not be negative: {offset}")
    if offset + 4 > len(view):
        raise ProjectFormatError(f"object header at {offset} exceeds available data")

    flags = view[offset]
    if flags & 1:
        if offset + 9 > len(view):
            raise ProjectFormatError(
                f"forwarding record at {offset} exceeds available data"
            )
        forwarding_address = struct.unpack_from(">q", view, offset + 1)[0]
        if forwarding_address <= 0:
            raise ProjectFormatError(
                f"invalid forwarding address: {forwarding_address}"
            )
        return CompactObject(
            offset=offset,
            flags=flags,
            type_id=None,
            subtype=None,
            fields=(),
            forwarding_address=forwarding_address,
        )

    type_id = view[offset + 1]
    subtype = view[offset + 2]
    descriptor_count = view[offset + 3]
    descriptor_table_size = 4 + descriptor_count * 3
    table_end = offset + descriptor_table_size
    if table_end > len(view):
        raise ProjectFormatError(
            f"descriptor table ending at {table_end} exceeds available data "
            f"{len(view)}"
        )

    fields: list[ObjectField] = []
    seen_field_ids: set[int] = set()
    previous_offset = descriptor_table_size - 1
    for index in range(descriptor_count):
        entry_offset = offset + 4 + index * 3
        field_id = view[entry_offset]
        relative_offset = struct.unpack_from(">h", view, entry_offset + 1)[0]
        if field_id >= 128:
            raise ProjectFormatError(f"invalid field ID: {field_id}")
        if field_id in seen_field_ids:
            raise ProjectFormatError(f"duplicate field ID: {field_id}")
        if relative_offset < descriptor_table_size:
            raise ProjectFormatError(
                f"field {field_id} offset {relative_offset} overlaps descriptor table"
            )
        if relative_offset <= previous_offset:
            raise ProjectFormatError(
                f"field {field_id} offset {relative_offset} is not increasing"
            )
        if offset + relative_offset >= len(view):
            raise ProjectFormatError(
                f"field {field_id} address {offset + relative_offset} exceeds "
                f"available data {len(view)}"
            )

        fields.append(ObjectField(field_id, relative_offset))
        seen_field_ids.add(field_id)
        previous_offset = relative_offset

    return CompactObject(
        offset=offset,
        flags=flags,
        type_id=type_id,
        subtype=subtype,
        fields=tuple(fields),
    )


def read_object_address(
    data: bytes | bytearray | memoryview,
    object_record: CompactObject,
    field_id: int,
) -> int | None:
    """Read a descriptor-backed 64-bit object address; zero means absent."""

    if object_record.forwarding_address is not None:
        raise ProjectFormatError("cannot read fields from a forwarding record")

    field = object_record.field(field_id)
    if field is None:
        return None

    field_offset = object_record.offset + field.relative_offset
    view = memoryview(data)
    if field_offset + 8 > len(view):
        raise ProjectFormatError(
            f"address field {field_id} at {field_offset} exceeds available data"
        )
    address = struct.unpack_from(">q", view, field_offset)[0]
    if address < 0:
        raise ProjectFormatError(f"negative object address in field {field_id}: {address}")
    return None if address == 0 else address


def resolve_compact_object(
    data: bytes | bytearray | memoryview,
    address: int,
    *,
    max_depth: int = 16,
) -> CompactObject:
    """Follow bounded forwarding records and return the current object."""

    if max_depth < 0:
        raise ProjectFormatError(f"forwarding depth must not be negative: {max_depth}")

    visited: set[int] = set()
    current_address = address
    for _ in range(max_depth + 1):
        if current_address in visited:
            raise ProjectFormatError(f"forwarding cycle at address {current_address}")
        visited.add(current_address)

        object_record = parse_compact_object(data, current_address)
        if object_record.forwarding_address is None:
            return object_record
        current_address = object_record.forwarding_address

    raise ProjectFormatError(f"forwarding depth exceeds limit {max_depth}")


def read_int32_field(
    data: bytes | bytearray | memoryview,
    object_record: CompactObject,
    field_id: int,
) -> int | None:
    """Read a descriptor-backed signed 32-bit field."""

    if object_record.forwarding_address is not None:
        raise ProjectFormatError("cannot read fields from a forwarding record")

    field = object_record.field(field_id)
    if field is None:
        return None

    field_offset = object_record.offset + field.relative_offset
    view = memoryview(data)
    if field_offset + 4 > len(view):
        raise ProjectFormatError(
            f"int32 field {field_id} at {field_offset} exceeds available data"
        )
    return struct.unpack_from(">i", view, field_offset)[0]


def read_chunked_collection_slots(
    data: bytes | bytearray | memoryview,
    collection_address: int,
) -> tuple[int | None, ...]:
    """Read logical address slots from the verified Zwtw/Zmea layout."""

    collection = resolve_compact_object(data, collection_address)
    size = read_int32_field(data, collection, 0)
    chunk_size = read_int32_field(data, collection, 1)
    chunk_list_address = read_object_address(data, collection, 2)
    leading_offset = read_int32_field(data, collection, 3)

    if None in (size, chunk_size, chunk_list_address, leading_offset):
        raise ProjectFormatError("chunked collection is missing a required field")
    if size < 0:
        raise ProjectFormatError(f"negative collection size: {size}")
    if chunk_size <= 0:
        raise ProjectFormatError(f"invalid collection chunk size: {chunk_size}")
    if leading_offset < 0:
        raise ProjectFormatError(f"negative collection leading offset: {leading_offset}")

    chunk_list = resolve_compact_object(data, chunk_list_address)
    chunk_count = read_int32_field(data, chunk_list, 0)
    chunk_array_address = read_object_address(data, chunk_list, 1)
    if chunk_count is None or chunk_array_address is None:
        raise ProjectFormatError("chunk list is missing a required field")
    if chunk_count < 0:
        raise ProjectFormatError(f"negative chunk count: {chunk_count}")

    chunk_addresses = parse_address_array_record(data, chunk_array_address)
    if chunk_count > len(chunk_addresses):
        raise ProjectFormatError(
            f"chunk count {chunk_count} exceeds address capacity "
            f"{len(chunk_addresses)}"
        )

    item_addresses: list[int | None] = []
    chunk_cache: dict[int, tuple[int | None, ...]] = {}
    for logical_index in range(size):
        physical_index = leading_offset + logical_index
        chunk_index, slot_index = divmod(physical_index, chunk_size)
        if chunk_index >= chunk_count:
            raise ProjectFormatError(
                f"logical item {logical_index} requires missing chunk {chunk_index}"
            )

        chunk_address = chunk_addresses[chunk_index]
        if chunk_address is None:
            raise ProjectFormatError(f"chunk {chunk_index} has a null address")
        slots = chunk_cache.setdefault(
            chunk_address,
            parse_address_array_record(data, chunk_address),
        )
        if len(slots) != chunk_size:
            raise ProjectFormatError(
                f"chunk {chunk_index} has {len(slots)} slots; expected {chunk_size}"
            )

        item_address = slots[slot_index]
        item_addresses.append(item_address)

    return tuple(item_addresses)


def read_chunked_collection_addresses(
    data: bytes | bytearray | memoryview,
    collection_address: int,
) -> tuple[int, ...]:
    """Read nonnull logical addresses from the verified Zwtw/Zmea layout."""

    slots = read_chunked_collection_slots(data, collection_address)
    for logical_index, address in enumerate(slots):
        if address is None:
            raise ProjectFormatError(
                f"logical item {logical_index} resolves to a null address"
            )
    return tuple(address for address in slots if address is not None)


def read_direct_collection_addresses(
    data: bytes | bytearray | memoryview,
    collection_address: int,
) -> tuple[int, ...]:
    """Read logical addresses from the verified Zg_i/Zmex collection layout."""

    collection = resolve_compact_object(data, collection_address)
    size = read_int32_field(data, collection, 0)
    backing_address = read_object_address(data, collection, 1)
    if size is None or backing_address is None:
        raise ProjectFormatError("direct collection is missing a required field")
    if size < 0:
        raise ProjectFormatError(f"negative direct collection size: {size}")

    addresses = parse_address_array_record(data, backing_address)
    if size > len(addresses):
        raise ProjectFormatError(
            f"direct collection size {size} exceeds address capacity {len(addresses)}"
        )
    logical_addresses = addresses[:size]
    if any(address is None for address in logical_addresses):
        raise ProjectFormatError("direct collection contains a null logical address")
    return tuple(address for address in logical_addresses if address is not None)


def read_uint8_field(
    data: bytes | bytearray | memoryview,
    object_record: CompactObject,
    field_id: int,
) -> int | None:
    """Read a descriptor-backed unsigned byte field."""

    if object_record.forwarding_address is not None:
        raise ProjectFormatError("cannot read fields from a forwarding record")
    field = object_record.field(field_id)
    if field is None:
        return None
    return memoryview(data)[object_record.offset + field.relative_offset]


def read_uuid_object(
    data: bytes | bytearray | memoryview,
    address: int | None,
) -> str | None:
    """Read the two-long UUID object used by Repeater tabs and groups."""

    if address is None:
        return None
    object_record = resolve_compact_object(data, address)
    values: list[int] = []
    view = memoryview(data)
    for field_id in (0, 1):
        field = object_record.field(field_id)
        if field is None:
            raise ProjectFormatError("UUID object is missing a required field")
        field_offset = object_record.offset + field.relative_offset
        if field_offset + 8 > len(view):
            raise ProjectFormatError("UUID field exceeds available data")
        values.append(struct.unpack_from(">Q", view, field_offset)[0])
    return str(uuid.UUID(int=(values[0] << 64) | values[1]))


def read_utf16_array_string(
    data: bytes | bytearray | memoryview,
    record_address: int,
) -> str:
    """Decode a verified big-endian UTF-16 character-array record."""

    record = parse_variable_array_record(data, record_address, 2)
    return record.payload.decode("utf-16-be")


def read_immutable_string(
    data: bytes | bytearray | memoryview,
    string_address: int | None,
) -> str | None:
    """Read a Zv1/Zmju immutable string object."""

    if string_address is None:
        return None
    string_object = resolve_compact_object(data, string_address)
    chars_address = read_object_address(data, string_object, 0)
    if chars_address is None:
        return None
    return read_utf16_array_string(data, chars_address)


def read_mutable_string(
    data: bytes | bytearray | memoryview,
    string_address: int | None,
) -> str | None:
    """Read a Zvp/Zmjj chunked mutable string object."""

    if string_address is None:
        return None
    string_object = resolve_compact_object(data, string_address)
    length = read_int32_field(data, string_object, 0)
    chunk_width = read_int32_field(data, string_object, 2)
    chunks_address = read_object_address(data, string_object, 3)
    if length is None or chunk_width is None or chunks_address is None:
        raise ProjectFormatError("mutable string is missing a required field")
    if length < 0 or chunk_width <= 0:
        raise ProjectFormatError("mutable string has invalid dimensions")

    chunk_addresses = read_direct_collection_addresses(data, chunks_address)
    text = "".join(read_utf16_array_string(data, address) for address in chunk_addresses)
    if len(text) < length:
        raise ProjectFormatError(
            f"mutable string contains {len(text)} characters; expected {length}"
        )
    return text[:length]


def inspect_proxy_items(
    data: bytes | bytearray | memoryview,
) -> dict[str, object]:
    """Inspect verified Proxy roots and request/response byte variants."""

    header = parse_header(data)
    project_root = resolve_compact_object(data, header.project_root)
    proxy_root_address = read_object_address(data, project_root, 1)
    if proxy_root_address is None:
        raise ProjectFormatError("project root has no Proxy root address")
    proxy_root = resolve_compact_object(data, proxy_root_address)

    collections: list[dict[str, object]] = []
    for field_id in (0, 1):
        collection_address = read_object_address(data, proxy_root, field_id)
        if collection_address is None:
            raise ProjectFormatError(
                f"Proxy root has no HTTP collection in field {field_id}"
            )
        item_addresses = read_chunked_collection_addresses(data, collection_address)
        items: list[dict[str, object]] = []
        for item_address in item_addresses:
            item = resolve_compact_object(data, item_address)
            variants: dict[str, object] = {}
            for variant_field_id in range(15, 21):
                variant_address = read_object_address(data, item, variant_field_id)
                variant: dict[str, object] = {"address": variant_address}
                if variant_address is not None:
                    record = parse_variable_record(data, variant_address)
                    variant["length"] = record.logical_length
                variants[str(variant_field_id)] = variant
            items.append(
                {
                    "address": item_address,
                    "type_id": item.type_id,
                    "subtype": item.subtype,
                    "byte_variants": variants,
                }
            )
        collections.append(
            {
                "field_id": field_id,
                "address": collection_address,
                "items": items,
            }
        )

    return {"root_address": proxy_root_address, "collections": collections}


def inspect_project_metadata(
    data: bytes | bytearray | memoryview,
) -> dict[str, object]:
    """Inspect verified header and project-root identity metadata."""

    header = parse_header(data)
    project_root = resolve_compact_object(data, header.project_root)

    def read_root_string(field_id: int) -> str | None:
        return read_immutable_string(
            data,
            read_object_address(data, project_root, field_id),
        )

    return {
        "schema_floor": header.schema_floor,
        "schema_current": header.schema_current,
        "header_random_identifier": header.random_identifier,
        "installation_id": read_root_string(0),
        "project_name": read_root_string(6),
        "project_identifier": read_root_string(15),
    }


def inspect_repeater_items(
    data: bytes | bytearray | memoryview,
) -> dict[str, object]:
    """Inspect verified Repeater tabs, groups, and HTTP pair byte records."""

    header = parse_header(data)
    project_root = resolve_compact_object(data, header.project_root)
    repeater_root_address = read_object_address(data, project_root, 2)
    if repeater_root_address is None:
        raise ProjectFormatError("project root has no Repeater root address")
    repeater_root = resolve_compact_object(data, repeater_root_address)

    tab_collection_address = read_object_address(data, repeater_root, 1)
    group_collection_address = read_object_address(data, repeater_root, 4)
    if tab_collection_address is None or group_collection_address is None:
        raise ProjectFormatError("Repeater root is missing a required collection")

    group_addresses = read_direct_collection_addresses(data, group_collection_address)
    groups: list[dict[str, object]] = []
    for group_address in group_addresses:
        group = resolve_compact_object(data, group_address)
        color_id = read_uint8_field(data, group, 1)
        expanded = read_uint8_field(data, group, 2)
        groups.append(
            {
                "address": group_address,
                "name": read_immutable_string(
                    data,
                    read_object_address(data, group, 0),
                ),
                "color_id": color_id,
                "color_enum": "GROUP_0" if color_id == 7 else None,
                "expanded": None if expanded is None else bool(expanded),
                "index": read_int32_field(data, group, 3),
                "uuid": read_uuid_object(
                    data,
                    read_object_address(data, group, 4),
                ),
            }
        )

    tab_addresses = read_direct_collection_addresses(data, tab_collection_address)
    tabs: list[dict[str, object]] = []
    for tab_address in tab_addresses:
        tab = resolve_compact_object(data, tab_address)
        pair_collection_address = read_object_address(data, tab, 2)
        pair_addresses = (
            ()
            if pair_collection_address is None
            else read_direct_collection_addresses(data, pair_collection_address)
        )
        pairs: list[dict[str, object]] = []
        for pair_address in pair_addresses:
            pair = resolve_compact_object(data, pair_address)
            pair_data: dict[str, object] = {"address": pair_address}
            for label, field_id in (("request", 2), ("response", 3)):
                record_address = read_object_address(data, pair, field_id)
                value: dict[str, object] = {"address": record_address}
                if record_address is not None:
                    record = parse_variable_record(data, record_address)
                    value["length"] = record.logical_length
                pair_data[label] = value
            pairs.append(pair_data)

        tabs.append(
            {
                "address": tab_address,
                "type_id": tab.type_id,
                "caption": read_mutable_string(
                    data,
                    read_object_address(data, tab, 0),
                ),
                "group_address": read_object_address(data, tab, 32),
                "uuid": read_uuid_object(
                    data,
                    read_object_address(data, tab, 33),
                ),
                "current_request_address": read_object_address(data, tab, 4),
                "pairs": pairs,
            }
        )

    return {
        "root_address": repeater_root_address,
        "tab_collection_address": tab_collection_address,
        "group_collection_address": group_collection_address,
        "tabs": tabs,
        "groups": groups,
    }


def read_identity_index_entries(
    data: bytes | bytearray | memoryview,
    index_address: int,
) -> tuple[dict[str, int], ...]:
    """Read Zpt2 identity-index hash/key/value tuples."""

    index = resolve_compact_object(data, index_address)
    expected_size = read_int32_field(data, index, 2)
    bucket_collection_address = read_object_address(data, index, 3)
    if expected_size is None or bucket_collection_address is None:
        raise ProjectFormatError("identity index is missing a required field")
    if expected_size < 0:
        raise ProjectFormatError(f"negative identity index size: {expected_size}")

    bucket_addresses = read_chunked_collection_slots(
        data,
        bucket_collection_address,
    )
    entries: list[dict[str, int]] = []
    for bucket_index, bucket_address in enumerate(bucket_addresses):
        if bucket_address is None:
            continue
        bucket = resolve_compact_object(data, bucket_address)
        bucket_size = read_int32_field(data, bucket, 0)
        tuple_array_address = read_object_address(data, bucket, 1)
        if bucket_size is None or tuple_array_address is None:
            raise ProjectFormatError(f"bucket {bucket_index} is missing a field")
        if bucket_size < 0:
            raise ProjectFormatError(f"negative bucket size: {bucket_size}")

        tuple_array = parse_variable_array_record(data, tuple_array_address, 24)
        if bucket_size > tuple_array.element_count:
            raise ProjectFormatError(
                f"bucket size {bucket_size} exceeds tuple capacity "
                f"{tuple_array.element_count}"
            )
        for tuple_index in range(bucket_size):
            hash_code, key_address, value = struct.unpack_from(
                ">qqq",
                tuple_array.payload,
                tuple_index * 24,
            )
            if key_address < 0:
                raise ProjectFormatError("identity index contains a negative key")
            entries.append(
                {
                    "bucket": bucket_index,
                    "hash": hash_code,
                    "key_address": key_address,
                    "value": value,
                }
            )

    if len(entries) != expected_size:
        raise ProjectFormatError(
            f"identity index reports {expected_size} entries; decoded {len(entries)}"
        )
    return tuple(entries)


def inspect_target_items(
    data: bytes | bytearray | memoryview,
) -> dict[str, object]:
    """Inspect verified Target/Site Map hierarchy and message records."""

    header = parse_header(data)
    project_root = resolve_compact_object(data, header.project_root)
    target_root_address = read_object_address(data, project_root, 3)
    if target_root_address is None:
        raise ProjectFormatError("project root has no Target root address")
    target_root = resolve_compact_object(data, target_root_address)
    identity_index_address = read_object_address(data, target_root, 3)
    if identity_index_address is None:
        raise ProjectFormatError("Target root has no identity index address")

    entries = read_identity_index_entries(data, identity_index_address)
    nodes: list[dict[str, object]] = []
    for entry in entries:
        key_address = entry["key_address"]
        if key_address == 0:
            continue
        node = resolve_compact_object(data, key_address)
        node_data: dict[str, object] = {
            **entry,
            "type_id": node.type_id,
            "subtype": node.subtype,
            "message_address": None,
            "request": {"address": None},
            "response": {"address": None},
        }

        message_address = (
            read_object_address(data, node, 33) if node.field(33) is not None else None
        )
        node_data["message_address"] = message_address
        if message_address is not None:
            message = resolve_compact_object(data, message_address)
            for label, field_id in (("request", 0), ("response", 1)):
                record_address = read_object_address(data, message, field_id)
                value: dict[str, object] = {"address": record_address}
                if record_address is not None:
                    record = parse_variable_record(data, record_address)
                    value["length"] = record.logical_length
                node_data[label] = value
        nodes.append(node_data)

    return {
        "root_address": target_root_address,
        "identity_index_address": identity_index_address,
        "nodes": nodes,
    }


def read_header(path: Path, *, available_size: int | None = None) -> ProjectHeader:
    """Read an outer header without loading the full project file."""

    with path.open("rb") as project_file:
        data = project_file.read(HEADER_SIZE)
        file_size = os.fstat(project_file.fileno()).st_size
    return parse_header(
        data,
        available_size=file_size if available_size is None else available_size,
    )


class BurpProject:
    """Context-managed, read-only access to one Burp project file."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._project_file = None
        self._data: mmap.mmap | None = None
        self._header: ProjectHeader | None = None

    def __enter__(self) -> BurpProject:
        self.open()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    @property
    def header(self) -> ProjectHeader:
        if self._header is None:
            raise RuntimeError("Burp project is not open")
        return self._header

    @property
    def data(self) -> mmap.mmap:
        if self._data is None:
            raise RuntimeError("Burp project is not open")
        return self._data

    def open(self) -> None:
        if self._data is not None:
            return
        self._header = read_header(self.path)
        self._project_file = self.path.open("rb")
        try:
            self._data = mmap.mmap(
                self._project_file.fileno(),
                length=0,
                access=mmap.ACCESS_READ,
            )
        except Exception:
            self._project_file.close()
            self._project_file = None
            self._header = None
            raise

    def close(self) -> None:
        if self._data is not None:
            self._data.close()
            self._data = None
        if self._project_file is not None:
            self._project_file.close()
            self._project_file = None
        self._header = None

    def read_record(self, offset: int) -> VariableRecord:
        return parse_variable_record(self.data, offset)

    def inspect_proxy_items(self) -> dict[str, object]:
        return inspect_proxy_items(self.data)

    def inspect_project_metadata(self) -> dict[str, object]:
        return inspect_project_metadata(self.data)

    def inspect_repeater_items(self) -> dict[str, object]:
        return inspect_repeater_items(self.data)

    def inspect_target_items(self) -> dict[str, object]:
        return inspect_target_items(self.data)
