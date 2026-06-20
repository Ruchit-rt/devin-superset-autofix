"""Persistent, process-safe store of CVE remediation entries + rolled-up metrics.

One entry per finding (keyed by CVE + package). Reloads the backing JSON on every
access so the CLI scanner and the running server (separate processes) stay consistent.
The poller feeds Devin session state in; the dashboard reads entries + summary() out.
Backs the observability story: status, PRs, ACUs, success rate, MTTR (issue -> PR).
"""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


def _iso_to_epoch(value: Optional[str]) -> Optional[float]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def finding_key(cve_id: str, package: str) -> str:
    return f"{cve_id}:{package.lower()}"  # PyPI names are case-insensitive


class Tracker:
    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.RLock()

    # ── persistence ──────────────────────────────────────────────────────────
    def _load(self) -> dict[str, dict[str, Any]]:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except json.JSONDecodeError:
                return {}
        return {}

    def _save(self, entries: dict[str, dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(entries, indent=2))
        tmp.replace(self._path)

    # ── mutations ────────────────────────────────────────────────────────────
    def upsert_finding(self, finding: dict[str, Any]) -> dict[str, Any]:
        key = finding_key(finding["cve_id"], finding["package"])
        with self._lock:
            entries = self._load()
            entry = entries.get(key, {"key": key, "status": "detected", "detected_at": time.time()})
            entry.update(
                {
                    "cve_id": finding["cve_id"],
                    "package": finding["package"],
                    "ecosystem": finding.get("ecosystem", "PyPI"),
                    "severity": (finding.get("severity") or "UNKNOWN").upper(),
                    "current_version": finding.get("current_version", ""),
                    "fixed_version": finding.get("fixed_version", ""),
                    "advisory_url": finding.get("advisory_url", ""),
                }
            )
            entries[key] = entry
            self._save(entries)
            return entry

    def attach_issue(self, key: str, issue: dict[str, Any]) -> None:
        with self._lock:
            entries = self._load()
            entry = entries.get(key)
            if not entry:
                return
            entry["issue_number"] = issue["number"]
            entry["issue_url"] = issue["html_url"]
            entry["issue_created_at"] = issue["created_at"]
            self._save(entries)

    def record_dispatch(self, key: str, session: dict[str, Any]) -> None:
        with self._lock:
            entries = self._load()
            entry = entries.get(key)
            if not entry:
                return
            entry["session_id"] = session["session_id"]
            entry["session_url"] = session.get("url", "")
            entry["dispatched_at"] = time.time()
            entry["status"] = "dispatched"
            self._save(entries)

    def update_session(self, key: str, info: dict[str, Any]) -> None:
        with self._lock:
            entries = self._load()
            entry = entries.get(key)
            if not entry:
                return
            prs = info.get("pull_requests") or []
            out = info.get("structured_output") or {}
            pr_url = prs[0]["pr_url"] if prs else (out.get("pr_url") or "")
            raw_status = info.get("status", "")
            detail = info.get("status_detail", "")
            entry["acus"] = round(float(info.get("acus_consumed", entry.get("acus", 0)) or 0), 2)
            entry["status_detail"] = detail
            if pr_url:
                entry["pr_url"] = pr_url

            fixed = bool(out.get("fixed")) or bool(pr_url)
            failed = raw_status == "error" or (detail == "finished" and out and out.get("fixed") is False)

            if fixed and entry.get("status") != "fixed":
                entry["status"] = "fixed"
                entry["fixed_at"] = time.time()
                entry["tests_passed"] = out.get("tests_passed")
                if out.get("summary"):
                    entry["summary"] = out["summary"]
            elif failed and not fixed:
                entry["status"] = "failed"
            elif not fixed and raw_status in {"running", "claimed", "new", "resuming"}:
                entry["status"] = "running" if detail == "working" else "dispatched"
            self._save(entries)

    # ── reads ────────────────────────────────────────────────────────────────
    def get(self, key: str) -> Optional[dict[str, Any]]:
        with self._lock:
            return self._load().get(key)

    def find_by_issue(self, number: int) -> Optional[dict[str, Any]]:
        with self._lock:
            return next((e for e in self._load().values() if e.get("issue_number") == number), None)

    def needs_dispatch(self) -> list[dict[str, Any]]:
        with self._lock:
            return [e for e in self._load().values() if e.get("issue_number") and not e.get("session_id")]

    def active(self) -> list[dict[str, Any]]:
        """Entries with a session that hasn't reached a terminal state."""
        with self._lock:
            return [
                e for e in self._load().values()
                if e.get("session_id") and e.get("status") not in {"fixed", "failed"}
            ]

    def all(self) -> list[dict[str, Any]]:
        with self._lock:
            entries = list(self._load().values())
        entries.sort(key=lambda e: (SEVERITY_ORDER.get(e.get("severity", "UNKNOWN"), 4), e.get("cve_id", "")))
        return entries

    def summary(self) -> dict[str, Any]:
        entries = self.all()
        total = len(entries)
        fixed = [e for e in entries if e.get("status") == "fixed"]
        failed = [e for e in entries if e.get("status") == "failed"]
        running = [e for e in entries if e.get("status") in {"running", "dispatched"}]
        prs = [e for e in entries if e.get("pr_url")]
        dispatched = [e for e in entries if e.get("session_id")]

        severity: dict[str, int] = {}
        for e in entries:
            sev = e.get("severity", "UNKNOWN")
            severity[sev] = severity.get(sev, 0) + 1

        mttrs: list[float] = []
        for e in fixed:
            filed = _iso_to_epoch(e.get("issue_created_at"))
            if filed and e.get("fixed_at"):
                mttrs.append(e["fixed_at"] - filed)
        mttr_seconds = round(sum(mttrs) / len(mttrs)) if mttrs else None

        total_acus = round(sum(float(e.get("acus", 0) or 0) for e in entries), 1)
        success_rate = round(100 * len(fixed) / len(dispatched)) if dispatched else None

        return {
            "cves_found": total,
            "in_progress": len(running),
            "fixed": len(fixed),
            "failed": len(failed),
            "prs_opened": len(prs),
            "total_acus": total_acus,
            "success_rate": success_rate,
            "mttr_seconds": mttr_seconds,
            "severity": severity,
        }
