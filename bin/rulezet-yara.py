#!/usr/bin/env python3
"""
Fetch YARA rules from Rulezet and optionally run them locally.

Examples:
  # Print matching rules
  python rulezet_yara.py --search CVE-2025-53521 --print-rules

  # Save rules locally
  python rulezet_yara.py --search CVE-2025-53521 --save-dir ./rules

  # Fetch + run against one file
  python rulezet_yara.py --search CVE-2025-53521 --run ./sample.bin

  # Fetch + run against a directory recursively
  python rulezet_yara.py --search CVE-2025-53521 --run /tmp/suspicious --recursive
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests


DEFAULT_API_BASE = "https://rulezet.org"
DEFAULT_RULE_DETAIL_URL_PREFIX = "https://rulezet.org/rule/detail_rule/"
DEFAULT_TIMEOUT = 30


@dataclass
class RuleEntry:
    uuid: str
    title: str
    description: str
    author: str
    creation_date: str
    format: str
    content: str

    @property
    def detail_url(self) -> str:
        uuid = self.uuid.strip()
        if not uuid:
            return ""
        return f"{DEFAULT_RULE_DETAIL_URL_PREFIX}{uuid}"


def eprint(*args: object, **kwargs: object) -> None:
    print(*args, file=sys.stderr, **kwargs)


def sanitize_filename(value: str) -> str:
    value = value.strip().replace(" ", "_")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value[:180].strip("._-") or "rule"


def fetch_rules(
    search: str,
    api_base: str = DEFAULT_API_BASE,
    timeout: int = DEFAULT_TIMEOUT,
    verify_tls: bool = True,
) -> List[RuleEntry]:
    url = f"{api_base.rstrip('/')}/api/rule/public/search"
    headers = {"accept": "application/json"}
    params = {"search": search}

    try:
        response = requests.get(
            url,
            headers=headers,
            params=params,
            timeout=timeout,
            verify=verify_tls,
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"HTTP request failed: {exc}") from exc

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError("API did not return valid JSON") from exc

    results = payload.get("results", [])
    if not isinstance(results, list):
        raise RuntimeError("Unexpected API response: 'results' is not a list")

    out: List[RuleEntry] = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if item.get("format") != "yara":
            continue
        content = item.get("content")
        if not isinstance(content, str) or not content.strip():
            continue

        out.append(
            RuleEntry(
                uuid=str(item.get("uuid", "")),
                title=str(item.get("title", "")),
                description=str(item.get("description", "")),
                author=str(item.get("author", "")),
                creation_date=str(item.get("creation_date", "")),
                format=str(item.get("format", "")),
                content=content,
            )
        )

    return out


def save_rules(rules: List[RuleEntry], save_dir: Path) -> List[Path]:
    save_dir.mkdir(parents=True, exist_ok=True)
    written: List[Path] = []

    for rule in rules:
        base = sanitize_filename(rule.title or rule.uuid or "rule")
        suffix = sanitize_filename(rule.uuid) if rule.uuid else "no_uuid"
        path = save_dir / f"{base}__{suffix}.yar"
        path.write_text(rule.content, encoding="utf-8", newline="\n")
        written.append(path)

    return written


def print_rules(rules: List[RuleEntry]) -> None:
    for idx, rule in enumerate(rules, start=1):
        print(f"===== RULE {idx} =====")
        print(f"Title       : {rule.title}")
        print(f"UUID        : {rule.uuid}")
        if rule.detail_url:
            print(f"Rule URL    : {rule.detail_url}")
        print(f"Author      : {rule.author}")
        print(f"Created     : {rule.creation_date}")
        print(f"Description : {rule.description}")
        print(rule.content.rstrip())
        print()


def compile_yara_rules(rules: List[RuleEntry]):
    try:
        import yara  # type: ignore
    except ImportError as exc:
        raise RuntimeError(
            "yara-python is not installed. Install it before using --run."
        ) from exc

    # Use namespaces so duplicate rule names from different results don't collide.
    sources: Dict[str, str] = {}
    namespace_to_rule: Dict[str, RuleEntry] = {}
    skipped_rules: List[Dict[str, str]] = []
    for idx, rule in enumerate(rules, start=1):
        namespace = f"rulezet_{idx}_{sanitize_filename(rule.uuid or rule.title)}"
        try:
            # Compile each rule first so one bad rule does not stop the whole scan.
            yara.compile(source=rule.content)
        except Exception as exc:
            skipped_rules.append(
                {
                    "title": rule.title or "<untitled>",
                    "uuid": rule.uuid or "<no-uuid>",
                    "error": str(exc),
                }
            )
            continue

        sources[namespace] = rule.content
        namespace_to_rule[namespace] = rule

    if not sources:
        raise RuntimeError(
            "Failed to compile YARA rules: all fetched rules failed compilation."
        )

    try:
        compiled = yara.compile(sources=sources)
    except Exception as exc:
        raise RuntimeError(f"Failed to compile YARA rules: {exc}") from exc

    return compiled, skipped_rules, namespace_to_rule


def iter_scan_targets(path: Path, recursive: bool) -> Iterable[Path]:
    if path.is_file():
        yield path
        return

    if not path.is_dir():
        raise RuntimeError(f"Target path does not exist or is not accessible: {path}")

    if recursive:
        for root, _, files in os.walk(path):
            for name in files:
                yield Path(root) / name
    else:
        for entry in path.iterdir():
            if entry.is_file():
                yield entry


def scan_with_yara(
    compiled_rules,
    target: Path,
    namespace_to_rule: Optional[Dict[str, RuleEntry]] = None,
    recursive: bool = False,
    timeout: Optional[int] = None,
    fast: bool = False,
) -> Dict[str, Any]:
    results: Dict[str, Any] = {"target": str(target), "matches": []}

    for file_path in iter_scan_targets(target, recursive=recursive):
        try:
            match_kwargs = {"fast": fast}
            if timeout is not None:
                match_kwargs["timeout"] = int(timeout)
            matches = compiled_rules.match(str(file_path), **match_kwargs)
        except Exception as exc:
            results["matches"].append(
                {
                    "file": str(file_path),
                    "error": str(exc),
                }
            )
            continue

        if not matches:
            continue

        file_matches = []
        for match in matches:
            namespace = getattr(match, "namespace", "")
            source_rule = (namespace_to_rule or {}).get(namespace)
            file_matches.append(
                {
                    "rule": getattr(match, "rule", ""),
                    "namespace": namespace,
                    "uuid": source_rule.uuid if source_rule else "",
                    "rule_url": source_rule.detail_url if source_rule else "",
                    "tags": list(getattr(match, "tags", []) or []),
                    "meta": dict(getattr(match, "meta", {}) or {}),
                }
            )

        results["matches"].append(
            {
                "file": str(file_path),
                "matched_rules": file_matches,
            }
        )

    return results


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Fetch YARA rules from Rulezet and optionally run them locally."
    )
    parser.add_argument(
        "--search",
        required=True,
        help="Search term sent to Rulezet, for example: CVE-2025-53521",
    )
    parser.add_argument(
        "--api-base",
        default=DEFAULT_API_BASE,
        help=f"Rulezet base URL (default: {DEFAULT_API_BASE})",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"HTTP timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--print-rules",
        action="store_true",
        help="Print fetched YARA rules to stdout",
    )
    parser.add_argument(
        "--save-dir",
        type=Path,
        help="Directory where fetched rules will be saved as .yar files",
    )
    parser.add_argument(
        "--run",
        type=Path,
        help="File or directory to scan locally with the fetched rules",
    )
    parser.add_argument(
        "--recursive",
        action="store_true",
        help="Recursively scan subdirectories when --run points to a directory",
    )
    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=None,
        help="Per-file YARA scan timeout in seconds",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Enable YARA fast mode during scanning",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print scan results as JSON",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS certificate verification",
    )
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        rules = fetch_rules(
            search=args.search,
            api_base=args.api_base,
            timeout=args.timeout,
            verify_tls=not args.insecure,
        )
    except Exception as exc:
        eprint(f"[!] Failed to fetch rules: {exc}")
        return 1

    if not rules:
        eprint("[!] No YARA rules found for that search.")
        return 2

    eprint(f"[+] Found {len(rules)} YARA rule(s) for search={args.search!r}")

    if args.print_rules:
        print_rules(rules)

    if args.save_dir:
        try:
            written = save_rules(rules, args.save_dir)
        except Exception as exc:
            eprint(f"[!] Failed to save rules: {exc}")
            return 1

        for path in written:
            eprint(f"[+] Saved: {path}")

    if args.run:
        try:
            compiled, skipped_rules, namespace_to_rule = compile_yara_rules(rules)
            if skipped_rules:
                eprint(
                    f"[!] Skipping {len(skipped_rules)} rule(s) that failed compilation:"
                )
                for skipped in skipped_rules:
                    eprint(
                        "    - "
                        f"title={skipped['title']!r} "
                        f"uuid={skipped['uuid']!r} "
                        f"error={skipped['error']}"
                    )

            scan_result = scan_with_yara(
                compiled_rules=compiled,
                target=args.run,
                namespace_to_rule=namespace_to_rule,
                recursive=args.recursive,
                timeout=args.scan_timeout,
                fast=args.fast,
            )
        except Exception as exc:
            eprint(f"[!] Scan failed: {exc}")
            return 1

        if args.json:
            print(json.dumps(scan_result, indent=2))
        else:
            matches = scan_result.get("matches", [])
            if not matches:
                eprint("[+] No matches.")
            else:
                eprint("[+] Matches:")
                for entry in matches:
                    file_name = entry.get("file", "<unknown>")
                    if "error" in entry:
                        eprint(f"  - {file_name}: ERROR: {entry['error']}")
                        continue

                    matched_rules = entry.get("matched_rules", [])
                    eprint(f"  - {file_name}")
                    for mr in matched_rules:
                        rule = mr.get("rule", "")
                        namespace = mr.get("namespace", "")
                        uuid = mr.get("uuid", "")
                        rule_url = mr.get("rule_url", "")
                        line = f"      * rule={rule} namespace={namespace}"
                        if uuid:
                            line += f" uuid={uuid}"
                        if rule_url:
                            line += f" rule_url={rule_url}"
                        eprint(line)
                        meta = mr.get("meta") or {}
                        if meta:
                            eprint(
                                f"        meta={json.dumps(meta, ensure_ascii=False)}"
                            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
