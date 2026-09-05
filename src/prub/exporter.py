"""Unified JSON export for supported Burp project HTTP messages."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Protocol

from .parser import BurpProject, ProjectHeader, parse_variable_record


class OpenProject(Protocol):
    header: ProjectHeader
    data: object

    def inspect_project_metadata(self) -> dict[str, object]: ...

    def inspect_proxy_items(self) -> dict[str, object]: ...

    def inspect_repeater_items(self) -> dict[str, object]: ...

    def inspect_target_items(self) -> dict[str, object]: ...


def _encode_record(project: OpenProject, address: int | None) -> str | None:
    if address is None:
        return None
    payload = parse_variable_record(project.data, address).payload
    return base64.b64encode(payload).decode("ascii")


def build_export(project: OpenProject) -> dict[str, object]:
    """Build one export document with separate Burp tool sections."""

    metadata = project.inspect_project_metadata()
    proxy_messages: list[dict[str, object]] = []
    repeater_messages: list[dict[str, object]] = []
    target_messages: list[dict[str, object]] = []

    def message(
        identifier: str,
        request_address: int | None,
        response_address: int | None,
    ) -> dict[str, object]:
        return {
            "id": identifier,
            "request_base64": _encode_record(project, request_address),
            "response_base64": _encode_record(project, response_address),
        }

    proxy = project.inspect_proxy_items()
    seen_proxy_items: set[int] = set()
    for collection in proxy["collections"]:
        for item in collection["items"]:
            item_address = item["address"]
            if item_address in seen_proxy_items:
                continue
            seen_proxy_items.add(item_address)
            variants = item["byte_variants"]
            proxy_messages.append(
                message(
                    f"proxy-{len(proxy_messages) + 1:06d}",
                    variants["15"]["address"],
                    variants["18"]["address"],
                )
            )

    repeater = project.inspect_repeater_items()
    groups = {group["address"]: group for group in repeater["groups"]}
    for tab in repeater["tabs"]:
        group = groups.get(tab["group_address"])
        group_context = None
        if group is not None:
            group_context = {
                "name": group["name"],
                "uuid": group["uuid"],
                "color_id": group["color_id"],
            }
        for pair_index, pair in enumerate(tab["pairs"], start=1):
            repeater_messages.append(
                {
                    **message(
                        f"repeater-{len(repeater_messages) + 1:06d}",
                        pair["request"]["address"],
                        pair["response"]["address"],
                    ),
                    "tab": {
                        "caption": tab["caption"],
                        "uuid": tab["uuid"],
                    },
                    "group": group_context,
                    "pair_index": pair_index,
                }
            )

    target = project.inspect_target_items()
    seen_target_messages: set[tuple[int | None, int | None]] = set()
    for node in target["nodes"]:
        request_address = node["request"]["address"]
        response_address = node["response"]["address"]
        key = (request_address, response_address)
        if key == (None, None) or key in seen_target_messages:
            continue
        seen_target_messages.add(key)
        target_messages.append(
            message(
                f"target-{len(target_messages) + 1:06d}",
                request_address,
                response_address,
            )
        )

    return {
        "burp_schema": project.header.schema_current,
        "project_name": metadata["project_name"],
        "proxy": proxy_messages,
        "repeater": repeater_messages,
        "target": target_messages,
    }


def export_project(project_path: str | Path, output_path: str | Path) -> dict[str, object]:
    """Read a project and write its unified JSON export."""

    with BurpProject(project_path) as project:
        document = build_export(project)
    Path(output_path).write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return document