"""Domain knowledge shared across the system.

Single source of truth for: the structured-output schema, the Devin playbook +
knowledge note bodies, the per-CVE prompt, and the machine-readable metadata block
we embed in each GitHub issue (so the dispatcher can recover the finding from a
webhook payload).
"""

from __future__ import annotations

import json
import re
from typing import Any, Optional

# Machine-readable block embedded in every filed issue.
_META_RE = re.compile(r"<!--\s*devin-autofix-meta:\s*(\{.*?\})\s*-->", re.DOTALL)

# JSON Schema (Draft 7) for the typed result Devin returns per session.
STRUCTURED_OUTPUT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "cve_id": {"type": "string"},
        "package": {"type": "string"},
        "old_version": {"type": "string"},
        "new_version": {"type": "string"},
        "severity": {"type": "string"},
        "fixed": {"type": "boolean"},
        "tests_passed": {"type": "boolean"},
        "breaking_changes_fixed": {"type": "string"},
        "pr_url": {"type": "string"},
        "summary": {"type": "string"},
    },
    "required": ["cve_id", "fixed", "summary"],
}

PLAYBOOK_TITLE = "Remediate a dependency CVE (bump + fix breakage)"
PLAYBOOK_MACRO = "!fix-cve"
PLAYBOOK_BODY = """\
You are remediating a known-vulnerable dependency. Follow these steps exactly:

1. Read the linked GitHub issue. Note the CVE id, the affected package, its current
   pinned version, the suggested fixed version, and the advisory URL.
2. Open the advisory and confirm the minimum non-vulnerable version. Prefer the
   smallest bump that clears the CVE to keep blast radius low.
3. Update the pin in the appropriate manifest (`requirements/*.txt` for Python,
   `package.json` + lockfile for the frontend). Update transitive constraints only if
   required to resolve.
4. Resolve any breaking changes the bump introduces in Superset's code. This is the
   important part — the goal is a PR that actually builds, not just a version edit.
5. Run TARGETED tests for the modules that import the package, plus a smoke import.
   Do NOT run the full CI suite — keep ACU usage bounded.
6. Open a pull request against `master`. Title: `fix(deps): bump <package> to clear
   <CVE>`. Body must include `Fixes #<issue_number>`, the CVE id, the version change,
   and a short summary of any code changes.
7. Provide the structured output (fixed, versions, tests_passed, breaking_changes_fixed,
   pr_url, summary).

If the package has no safe version or the fix is not achievable without a large
refactor, set fixed=false and explain why in summary — do not force a broken PR.
"""

KNOWLEDGE_NAME = "Superset dependency-upgrade conventions"
KNOWLEDGE_BODY = """\
- Python dependencies are pinned in `requirements/base.txt` and
  `requirements/development.txt` (compiled from the matching `.in` files).
- Run targeted tests with `pytest tests/unit_tests/<area>` rather than the whole suite.
- PRs target the `master` branch.
- Keep diffs minimal and focused on the single CVE in the issue.
- Do not introduce new `any` types or unrelated changes.
"""


def build_issue_body(finding: dict[str, Any]) -> str:
    meta = json.dumps(
        {
            "cve_id": finding["cve_id"],
            "package": finding["package"],
            "ecosystem": finding.get("ecosystem", "PyPI"),
            "severity": finding.get("severity", "UNKNOWN"),
            "current_version": finding.get("current_version", ""),
            "fixed_version": finding.get("fixed_version", ""),
            "advisory_url": finding.get("advisory_url", ""),
        }
    )
    fixed = finding.get("fixed_version") or "(see advisory)"
    return f"""\
## Vulnerable dependency: `{finding['package']}`

| | |
|---|---|
| **CVE** | {finding['cve_id']} |
| **Severity** | {finding.get('severity', 'UNKNOWN')} |
| **Ecosystem** | {finding.get('ecosystem', 'PyPI')} |
| **Installed** | `{finding.get('current_version', '?')}` |
| **Fixed in** | `{fixed}` |
| **Advisory** | {finding.get('advisory_url', 'N/A')} |

A dependency scan flagged this package as vulnerable. Add the **`devin-auto-fix`**
label to dispatch Devin: it will bump the dependency, fix any breaking changes, run
targeted tests, and open a PR.

<!-- devin-autofix-meta: {meta} -->
"""


def parse_issue_metadata(body: Optional[str]) -> Optional[dict[str, Any]]:
    if not body:
        return None
    match = _META_RE.search(body)
    if not match:
        return None
    try:
        return json.loads(match.group(1))
    except json.JSONDecodeError:
        return None


def build_prompt(finding: dict[str, Any], issue_number: int, repo: str) -> str:
    return f"""\
Remediate a dependency vulnerability in the repository `{repo}`.

- GitHub issue: #{issue_number}
- CVE: {finding['cve_id']} (severity: {finding.get('severity', 'UNKNOWN')})
- Package: {finding['package']}
- Currently pinned: {finding.get('current_version', '?')}
- Fixed in: {finding.get('fixed_version', '(confirm from advisory)')}
- Advisory: {finding.get('advisory_url', 'N/A')}

Follow the attached playbook. Bump the dependency, fix any breaking changes so the
project still builds, run targeted tests, and open a PR against `master` that
references `Fixes #{issue_number}`. Return the structured output when done.
"""
