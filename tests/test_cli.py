import contextlib
import io
import unittest
from pathlib import Path
from unittest.mock import patch

from prub.cli import build_argument_parser, main


class CliTests(unittest.TestCase):
    def test_parses_export_command(self) -> None:
        args = build_argument_parser().parse_args(
            ["export", "project.burp", "output.json"]
        )

        self.assertEqual(args.command, "export")
        self.assertEqual(args.project, Path("project.burp"))
        self.assertEqual(args.output, Path("output.json"))

    def test_export_command_calls_unified_exporter(self) -> None:
        with patch("prub.cli.export_project") as exporter:
            result = main(["export", "project.burp", "output.json"])

        self.assertEqual(result, 0)
        exporter.assert_called_once_with(
            Path("project.burp"),
            Path("output.json"),
        )

    def test_old_http_export_flag_is_not_supported(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), self.assertRaises(SystemExit):
            build_argument_parser().parse_args(
                ["--export-proxy", "output", "project.burp"]
            )

        self.assertIn("invalid choice", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()