#!/usr/bin/env python3
"""Verify the imported baseline, optionally against the fixed source commit.

This is a baseline comparison tool: later intentional implementation changes
will be reported as drift rather than silently rewriting the source record.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def digest(value):
    return hashlib.sha256(value).hexdigest()


def function(text, name):
    match = re.search(r"(?ms)^func " + re.escape(name) + r"\(.*?^}\n", text)
    if not match:
        raise ValueError(f"missing function {name}")
    return match.group(0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, help="SparkClaw git checkout")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    manifest = json.loads((root / "extensions/sparkclaw/baseline-manifest.json").read_text())
    revision = manifest["source_revision"]
    seen = set()
    for item in manifest["files"] + manifest["extractions"]:
        target = root / item["target"]
        if item["target"] in seen or not target.resolve().is_relative_to(root):
            raise ValueError("invalid or duplicate target")
        seen.add(item["target"])
        actual = target.read_bytes()
        if digest(actual) != item["target_sha256"]:
            raise ValueError(f"baseline drift: {item['target']}")
        if not args.source:
            continue
        raw = subprocess.check_output(["git", "show", f"{revision}:{item['source']}"], cwd=args.source)
        if "source_sha256" in item and digest(raw) != item["source_sha256"]:
            raise ValueError(f"source drift: {item['source']}")
        text = raw.decode()
        if "transforms" in item:
            for change in item["transforms"]:
                if "replace" in change:
                    before, after = change["replace"]
                    if before not in text:
                        raise ValueError(f"missing replacement input in {item['source']}")
                    text = text.replace(before, after)
                else:
                    text = text.replace(function(text, change["remove_function"]), "", 1)
            expected = text.encode()
            if target.suffix == ".go":
                expected = subprocess.check_output(["gofmt"], input=expected)
            if expected != actual:
                raise ValueError(f"unrecorded source change: {item['target']}")
        else:
            for name in item.get("functions", []):
                if function(text, name) != function(actual.decode(), name):
                    raise ValueError(f"changed extracted function {name}")
            constant_source = text
            if "constants_source" in item:
                constant_source = subprocess.check_output(
                    ["git", "show", f"{revision}:{item['constants_source']}"], cwd=args.source, text=True
                )
            for name in item.get("constants", []):
                pattern = r"(?m)^\s*" + re.escape(name) + r"\s*=\s*(.+)$"
                original = re.search(pattern, constant_source)
                copied = re.search(pattern, actual.decode())
                if not original or not copied or original.group(1) != copied.group(1):
                    raise ValueError(f"changed extracted constant {name}")
    print(f"Verified {len(manifest['files'])} mapped files and {len(manifest['extractions'])} extractions at {revision}")


if __name__ == "__main__":
    main()
