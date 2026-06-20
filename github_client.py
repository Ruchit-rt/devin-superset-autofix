"""GitHub REST client (issues + labels) and webhook signature verification.

Uses the REST API directly via `requests` (no `gh` CLI dependency). In DRY_RUN mode
issues are kept in a local JSON file so the scan→issue→dispatch flow works offline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from pathlib import Path
from typing import Any, Optional

import requests

from config import Config

logger = logging.getLogger("github")

_SIM_LOCK = threading.Lock()


class GitHubClient:
    def __init__(self, config: Config) -> None:
        self.cfg = config
        self._sim_path = Path(config.data_file).parent / "sim_issues.json"

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    # ── Issues ───────────────────────────────────────────────────────────────
    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        if self.cfg.dry_run:
            return self._sim_create_issue(title, body, labels)
        url = f"{self.cfg.github_api}/repos/{self.cfg.target_repo}/issues"
        resp = requests.post(
            url, headers=self._headers(), json={"title": title, "body": body, "labels": labels}, timeout=30
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "number": data["number"],
            "title": data["title"],
            "body": data.get("body", ""),
            "html_url": data["html_url"],
            "created_at": data["created_at"],
            "labels": [lbl["name"] for lbl in data.get("labels", [])],
        }

    def list_issues(self, labels: list[str], state: str = "open") -> list[dict[str, Any]]:
        if self.cfg.dry_run:
            with _SIM_LOCK:
                issues = list(self._sim_load().values())
            return [i for i in issues if set(labels).issubset(set(i.get("labels", [])))]
        url = f"{self.cfg.github_api}/repos/{self.cfg.target_repo}/issues"
        params = {"labels": ",".join(labels), "state": state, "per_page": 100}
        resp = requests.get(url, headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()
        return [
            {
                "number": d["number"],
                "title": d["title"],
                "body": d.get("body", ""),
                "html_url": d["html_url"],
                "created_at": d["created_at"],
                "labels": [lbl["name"] for lbl in d.get("labels", [])],
            }
            for d in resp.json()
            if "pull_request" not in d  # exclude PRs (the issues endpoint returns both)
        ]

    def add_label(self, number: int, label: str) -> None:
        if self.cfg.dry_run:
            with _SIM_LOCK:
                data = self._sim_load()
                issue = data.get(str(number))
                if issue and label not in issue["labels"]:
                    issue["labels"].append(label)
                    self._sim_save(data)
            return
        url = f"{self.cfg.github_api}/repos/{self.cfg.target_repo}/issues/{number}/labels"
        resp = requests.post(url, headers=self._headers(), json={"labels": [label]}, timeout=30)
        resp.raise_for_status()

    # ── Webhook verification ─────────────────────────────────────────────────
    def verify_signature(self, payload: bytes, signature_header: str) -> bool:
        if not self.cfg.webhook_secret:
            logger.warning("WEBHOOK_SECRET not set — skipping signature verification")
            return True
        expected = "sha256=" + hmac.new(
            self.cfg.webhook_secret.encode(), payload, hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expected, signature_header or "")

    # ── Simulation backend ───────────────────────────────────────────────────
    def _sim_load(self) -> dict[str, Any]:
        if self._sim_path.exists():
            return json.loads(self._sim_path.read_text())
        return {}

    def _sim_save(self, data: dict[str, Any]) -> None:
        self._sim_path.parent.mkdir(parents=True, exist_ok=True)
        self._sim_path.write_text(json.dumps(data, indent=2))

    def _sim_create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        with _SIM_LOCK:
            data = self._sim_load()
            number = (max((int(k) for k in data), default=9000)) + 1
            issue = {
                "number": number,
                "title": title,
                "body": body,
                "html_url": f"https://github.com/{self.cfg.target_repo}/issues/{number}",
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "labels": list(labels),
            }
            data[str(number)] = issue
            self._sim_save(data)
        logger.info("[sim] filed issue #%s: %s", number, title)
        return issue
