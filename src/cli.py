import argparse
import json
import sys
from pathlib import Path

from models import EXIT_BUILD_OR_CONFIG_ERROR
from paths import paths_alias
from reporter.report_gen import write_reports


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_BUILD_OR_CONFIG_ERROR, f"{self.prog}: error: {message}\n")


def main(argv=None) -> int:
    parser = Parser(prog="patch_validator")
    commands = parser.add_subparsers(dest="command", required=True)
    report = commands.add_parser(
        "report", help="report existing classified results; does not execute targets"
    )
    report.add_argument("--results", required=True, type=Path)
    validate = commands.add_parser(
        "validate", help="reserved for the build/run/classification pipeline"
    )
    validate.add_argument("--config", required=True, type=Path)
    validate.add_argument("--base", required=True)
    validate.add_argument("--patched", required=True)
    for command in (report, validate):
        command.add_argument("--output-json", type=Path, default=Path("report.json"))
        command.add_argument("--output-md", type=Path, default=Path("SUMMARY.md"))
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            for label, output in (
                ("--output-json", args.output_json),
                ("--output-md", args.output_md),
            ):
                if paths_alias(output, args.config):
                    raise ValueError(
                        f"{label} ({output}) must not overwrite the input "
                        f"config ({args.config})"
                    )
            from validation import run_validation

            result = run_validation(args.config, args.output_json, args.output_md)
            print(f"{result['outcome']} (exit {result['exit_code']})")
            return result["exit_code"]
        else:
            if paths_alias(args.results, args.output_json) or paths_alias(
                args.results, args.output_md
            ):
                raise ValueError("output paths must not overwrite the input results")
            data = json.loads(args.results.read_text(encoding="utf-8"))
        result = write_reports(data, args.output_json, args.output_md)
    except (OSError, ValueError, TypeError) as exc:
        print(f"patch_validator: {exc}", file=sys.stderr)
        return EXIT_BUILD_OR_CONFIG_ERROR
    print(f"{result['outcome']} (exit {result['exit_code']})")
    return result["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
