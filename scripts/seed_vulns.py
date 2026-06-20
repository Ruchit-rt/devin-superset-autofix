"""Seed deliberately-vulnerable dependency pins into the fork (for a deterministic demo).

Downgrades a few leaf packages to known-vulnerable versions in requirements/*.txt.
The scanner then reliably flags them; Devin's fix upgrades them back to a version
Superset already tolerates → guaranteed-green PRs.

These are PLANTED FOR A DEMO on a fork — not undiscovered vulnerabilities in
apache/superset. A SEEDED_VULNS.md manifest is written to make that explicit.

Usage:
  python scripts/seed_vulns.py            # dry-run: show the diff only
  python scripts/seed_vulns.py --apply    # write the downgrades + manifest
  python scripts/seed_vulns.py --apply --push   # also git commit + push to the fork
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import CONFIG  # noqa: E402

# package -> (vulnerable version, CVE, note)
SEED = {
    "pyyaml": ("5.3.1", "CVE-2020-14343", "Arbitrary code execution via full_load"),
    "requests": ("2.19.1", "CVE-2018-18074", "Authorization header leak on redirect"),
    "certifi": ("2022.12.7", "CVE-2023-37920", "Bundles compromised e-Tugra root cert"),
    "urllib3": ("1.25.8", "CVE-2020-26137", "CRLF injection via request method"),
    "idna": ("2.8", "CVE-2024-3651", "DoS via resource consumption in idna.encode"),
}

TARGET_FILES = ["requirements/base.txt", "requirements/development.txt"]


def patch_file(path: Path, apply: bool) -> list[tuple[str, str, str]]:
    """Returns list of (package, old_line, new_line) changes."""
    if not path.exists():
        return []
    lines = path.read_text().splitlines()
    changes = []
    for i, line in enumerate(lines):
        for pkg, (vuln, _cve, _note) in SEED.items():
            m = re.match(rf"^{re.escape(pkg)}==(\S+)\s*$", line)
            if m and m.group(1) != vuln:
                new_line = f"{pkg}=={vuln}"
                changes.append((pkg, line.strip(), new_line))
                lines[i] = new_line
    if apply and changes:
        path.write_text("\n".join(lines) + "\n")
    return changes


def write_manifest(root: Path) -> None:
    rows = "\n".join(
        f"| `{pkg}` | `{vuln}` | {cve} | {note} |" for pkg, (vuln, cve, note) in SEED.items()
    )
    (root / "SEEDED_VULNS.md").write_text(
        "# Seeded vulnerabilities (DEMO)\n\n"
        "> ⚠️ These dependency downgrades were **planted intentionally** to demonstrate an\n"
        "> automated CVE-remediation pipeline (Devin). They are **not** undiscovered\n"
        "> vulnerabilities in Apache Superset, and exist only on this fork.\n\n"
        "| Package | Seeded (vulnerable) version | CVE | Issue |\n"
        "|---|---|---|---|\n" + rows + "\n"
    )


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--apply", action="store_true", help="Write the changes (default: dry-run).")
    ap.add_argument("--push", action="store_true", help="git add/commit/push to the fork.")
    args = ap.parse_args()

    root = Path(CONFIG.superset_repo_path).resolve()
    print(f"Target repo checkout: {root}\n")

    all_changes = []
    for rel in TARGET_FILES:
        changes = patch_file(root / rel, apply=args.apply)
        if changes:
            print(f"{rel}:")
            for pkg, old, new in changes:
                print(f"    - {old}  ->  {new}  ({SEED[pkg][1]})")
            all_changes += changes

    if not all_changes:
        print("No changes (packages already at seeded versions or not found).")
        return

    if not args.apply:
        print("\n(dry-run) re-run with --apply to write these downgrades.")
        return

    write_manifest(root)
    print(f"\n✅ Applied {len(all_changes)} downgrade(s) + wrote SEEDED_VULNS.md")

    if args.push:
        subprocess.run(["git", "-C", str(root), "add"] + TARGET_FILES + ["SEEDED_VULNS.md"], check=True)
        subprocess.run(
            ["git", "-C", str(root), "commit", "-m",
             "demo: seed known-vulnerable dependency pins for Devin auto-remediation"],
            check=True,
        )
        subprocess.run(["git", "-C", str(root), "push"], check=True)
        print("✅ Committed and pushed to the fork.")
    else:
        print("\nNext: review, then commit/push the fork (or re-run with --push).")


if __name__ == "__main__":
    main()
