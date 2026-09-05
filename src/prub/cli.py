"""Command-line interface for prub."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from .exporter import export_project
from .parser import BurpProject


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prub",
        description="Export HTTP messages from Burp Suite project files to JSON.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    metadata = commands.add_parser("metadata", help="show project metadata")
    metadata.add_argument("project", type=Path)

    inspect = commands.add_parser("inspect", help="inspect supported Burp data")
    inspect.add_argument("tool", choices=("proxy", "repeater", "target"))
    inspect.add_argument("project", type=Path)

    record = commands.add_parser("record", help="read one raw byte record")
    record.add_argument("project", type=Path)
    record.add_argument("offset", type=lambda value: int(value, 0))

    export = commands.add_parser("export", help="write unified JSON export")
    export.add_argument("project", type=Path)
    export.add_argument("output", type=Path)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_argument_parser().parse_args(argv)

    if args.command == "export":
        export_project(args.project, args.output)
        return 0

    with BurpProject(args.project) as project:
        if args.command == "metadata":
            output = project.inspect_project_metadata()
        elif args.command == "record":
            record = project.read_record(args.offset)
            output = asdict(record)
            output["payload_base64"] = __import__("base64").b64encode(
                record.payload
            ).decode("ascii")
            del output["payload"]
        elif args.tool == "proxy":
            output = project.inspect_proxy_items()
        elif args.tool == "repeater":
            output = project.inspect_repeater_items()
        else:
            output = project.inspect_target_items()

    print(json.dumps(output, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())