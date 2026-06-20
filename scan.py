"""Dependency CVE scanner: run osv-scanner (or parse a report) -> curate -> file issues.

This is the *event source*. Detection is cheap and deterministic and stays in our
control plane; only remediation is handed to Devin. Runnable as a CLI or imported by
the Flask `/scan` route and the periodic scheduler.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
from typing import Any, Optional

import playbook
from config import CONFIG, Config
from github_client import GitHubClient
from tracker import SEVERITY_ORDER, Tracker, finding_key

logger = logging.getLogger("scan")


# ── osv-scanner ──────────────────────────────────────────────────────────────
def run_osv_scanner(lockfiles: list[str]) -> dict[str, Any]:
    cmd = ["osv-scanner", "--format", "json"]
    for lf in lockfiles:
        cmd += ["--lockfile", lf]
    logger.info("running: %s", " ".join(cmd))
    try:
        # osv-scanner exits non-zero when vulns are found; that's expected.
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError as exc:
        raise RuntimeError(
            "osv-scanner not found. Install it (brew install osv-scanner) or pass "
            "--report <osv.json>. In Docker it is bundled."
        ) from exc
    if not proc.stdout.strip():
        logger.warning("osv-scanner produced no output (stderr: %s)", proc.stderr[:500])
        return {"results": []}
    return json.loads(proc.stdout)


# ── parsing ──────────────────────────────────────────────────────────────────
def _severity_label(cvss_score: Optional[float], db_severity: Optional[str]) -> str:
    if db_severity:
        return db_severity.upper()
    if cvss_score is None:
        return "UNKNOWN"
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _pick_cve(vuln: dict[str, Any]) -> str:
    for alias in vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return vuln.get("id", "UNKNOWN")


def _fixed_version(vuln: dict[str, Any]) -> str:
    for affected in vuln.get("affected", []):
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                if "fixed" in event:
                    return event["fixed"]
    return ""


def _advisory_url(vuln: dict[str, Any]) -> str:
    for ref in vuln.get("references", []):
        if ref.get("type") == "ADVISORY" and ref.get("url"):
            return ref["url"]
    return f"https://osv.dev/vulnerability/{vuln.get('id', '')}"


def parse_osv_report(data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: dict[str, dict[str, Any]] = {}
    for result in data.get("results", []):
        for pkg in result.get("packages", []):
            p = pkg.get("package", {})
            name, version, ecosystem = p.get("name", ""), p.get("version", ""), p.get("ecosystem", "PyPI")
            # group max_severity gives a CVSS numeric score when present.
            group_score = None
            for group in pkg.get("groups", []):
                try:
                    group_score = float(group.get("max_severity"))
                except (TypeError, ValueError):
                    pass
            for vuln in pkg.get("vulnerabilities", []):
                cve = _pick_cve(vuln)
                db_sev = (vuln.get("database_specific") or {}).get("severity")
                finding = {
                    "cve_id": cve,
                    "package": name,
                    "ecosystem": ecosystem,
                    "current_version": version,
                    "fixed_version": _fixed_version(vuln),
                    "severity": _severity_label(group_score, db_sev),
                    "advisory_url": _advisory_url(vuln),
                    "summary": vuln.get("summary", ""),
                }
                findings[finding_key(cve, name)] = finding  # dedupe
    return list(findings.values())


# ── curation ─────────────────────────────────────────────────────────────────
def curate(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Keep low-blast-radius / allowlisted findings; cap the count for the demo."""
    cve_allow = {c.strip() for c in os.environ.get("CURATE_CVES", "").split(",") if c.strip()}
    pkg_allow = {p.strip().lower() for p in os.environ.get("CURATE_PACKAGES", "").split(",") if p.strip()}
    max_issues = int(os.environ.get("MAX_ISSUES", "8"))

    if cve_allow or pkg_allow:
        findings = [
            f for f in findings
            if f["cve_id"] in cve_allow or f["package"].lower() in pkg_allow
        ]
    # Need a known fixed version to remediate confidently; sort by severity, cap.
    findings = [f for f in findings if f.get("fixed_version")]
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f["severity"], 4))
    return findings[:max_issues]


# ── filing ───────────────────────────────────────────────────────────────────
def file_findings(
    findings: list[dict[str, Any]],
    github: GitHubClient,
    tracker: Tracker,
    cfg: Config,
    auto_label: bool,
) -> list[dict[str, Any]]:
    filed = []
    for f in findings:
        key = finding_key(f["cve_id"], f["package"])
        tracker.upsert_finding(f)
        entry = tracker.get(key)
        if entry and entry.get("issue_number"):
            logger.info("issue already exists for %s (#%s) — skipping", key, entry["issue_number"])
            continue
        labels = [cfg.security_label]
        if auto_label:
            labels.append(cfg.label)
        issue = github.create_issue(
            title=f"[{f['severity']}] {f['cve_id']} in {f['package']} {f.get('current_version', '')}".strip(),
            body=playbook.build_issue_body(f),
            labels=labels,
        )
        tracker.attach_issue(key, issue)
        filed.append({**f, "issue_number": issue["number"], "issue_url": issue["html_url"]})
    return filed


def run_scan_and_file(
    github: GitHubClient,
    tracker: Tracker,
    cfg: Config,
    *,
    report: Optional[str] = None,
    auto_label: Optional[bool] = None,
    print_only: bool = False,
) -> list[dict[str, Any]]:
    if report:
        data = json.loads(open(report).read())
    else:
        data = run_osv_scanner(cfg.lockfile_paths())
    findings = curate(parse_osv_report(data))
    logger.info("curated %d finding(s)", len(findings))
    if print_only:
        for f in findings:
            print(f"  {f['severity']:8} {f['cve_id']:18} {f['package']} "
                  f"{f['current_version']} -> {f['fixed_version']}")
        return findings
    return file_findings(findings, github, tracker, cfg, cfg.auto_label if auto_label is None else auto_label)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Scan Superset deps for CVEs and file issues.")
    ap.add_argument("--report", help="Parse this osv-scanner JSON instead of running the scanner.")
    ap.add_argument("--print", dest="print_only", action="store_true", help="Print findings; don't file.")
    ap.add_argument("--auto-label", action="store_true", help="Apply the trigger label when filing.")
    ap.add_argument("--lockfile", action="append", help="Override lockfile path(s).")
    args = ap.parse_args()

    cfg = CONFIG
    if args.lockfile:
        os.environ["SCAN_LOCKFILES"] = ",".join(args.lockfile)
        cfg = Config()  # re-read with overridden lockfiles

    github = GitHubClient(cfg)
    tracker = Tracker(cfg.data_file)
    filed = run_scan_and_file(
        github, tracker, cfg,
        report=args.report or cfg.scan_report or None,
        auto_label=True if args.auto_label else None,
        print_only=args.print_only,
    )
    if not args.print_only:
        print(f"\nFiled {len(filed)} issue(s):")
        for f in filed:
            print(f"  #{f['issue_number']}  {f['cve_id']}  {f['package']} -> {f['fixed_version']}")


if __name__ == "__main__":
    main()
