#!/usr/bin/env python3
"""Regenerate standalone shell scripts, or --check their embedded verifier."""
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
start = "# BEGIN GENERATED RELEASE VERIFIER\n"
end = "# END GENERATED RELEASE VERIFIER\n"
block = start + (root / "release-verification.sh").read_text() + end
for name in ("install.sh", "trapd-update.sh"):
    path = root / name
    source = path.read_text()
    before, rest = source.split(start, 1)
    _, after = rest.split(end, 1)
    expected = before + block + after
    if "--check" in sys.argv:
        if source != expected:
            sys.exit(f"{name}: run python3 deploy/embed-release-verifier.py")
    else:
        path.write_text(expected)
