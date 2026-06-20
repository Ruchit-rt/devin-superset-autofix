"""Thin wrapper around the Devin v3 API.

In DRY_RUN mode every call is simulated locally and deterministically: a created
session "works" for SIM_DURATION_SECONDS and then reports a fixed PR. This lets the
whole pipeline (and the dashboard) be demoed offline, with zero ACUs.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Optional

import requests

from config import Config

logger = logging.getLogger("devin")

_SIM_LOCK = threading.Lock()


class DevinClient:
    def __init__(self, config: Config) -> None:
        self.cfg = config
        self._sim_path = Path(config.data_file).parent / "sim_sessions.json"

    # ── HTTP plumbing (real mode) ────────────────────────────────────────────
    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.cfg.devin_api_key}",
            "Content-Type": "application/json",
        }

    # ── Sessions ─────────────────────────────────────────────────────────────
    def create_session(
        self,
        prompt: str,
        *,
        title: Optional[str] = None,
        tags: Optional[list[str]] = None,
        playbook_id: Optional[str] = None,
        knowledge_ids: Optional[list[str]] = None,
        structured_output_schema: Optional[dict[str, Any]] = None,
        structured_output_required: bool = False,
        max_acu_limit: Optional[int] = None,
        repos: Optional[list[str]] = None,
    ) -> dict[str, Any]:
        body: dict[str, Any] = {"prompt": prompt}
        if title:
            body["title"] = title
        if tags:
            body["tags"] = tags
        if playbook_id:
            body["playbook_id"] = playbook_id
        if knowledge_ids:
            body["knowledge_ids"] = knowledge_ids
        if structured_output_schema:
            body["structured_output_schema"] = structured_output_schema
            body["structured_output_required"] = structured_output_required
        if max_acu_limit is not None:
            body["max_acu_limit"] = max_acu_limit
        if repos:
            body["repos"] = repos
        if self.cfg.devin_mode:
            body["devin_mode"] = self.cfg.devin_mode

        if self.cfg.dry_run:
            return self._sim_create(body)

        resp = requests.post(self.cfg.sessions_url, headers=self._headers(), json=body, timeout=60)
        resp.raise_for_status()
        return resp.json()

    def get_session(self, session_id: str) -> dict[str, Any]:
        if self.cfg.dry_run:
            return self._sim_get(session_id)
        resp = requests.get(
            f"{self.cfg.sessions_url}/{session_id}", headers=self._headers(), timeout=30
        )
        resp.raise_for_status()
        return resp.json()

    def list_sessions(self, tags: Optional[list[str]] = None, first: int = 50) -> list[dict[str, Any]]:
        if self.cfg.dry_run:
            with _SIM_LOCK:
                return [self._sim_project(s) for s in self._sim_load().values()]
        params: dict[str, Any] = {"first": first}
        if tags:
            params["tags"] = tags
        resp = requests.get(self.cfg.sessions_url, headers=self._headers(), params=params, timeout=30)
        resp.raise_for_status()
        return resp.json().get("items", [])

    # ── Playbooks / Knowledge ────────────────────────────────────────────────
    def create_playbook(
        self,
        title: str,
        body: str,
        *,
        macro: Optional[str] = None,
        structured_output_schema: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"title": title, "body": body}
        if macro:
            payload["macro"] = macro
        if structured_output_schema:
            payload["structured_output_schema"] = structured_output_schema
        if self.cfg.dry_run:
            return {"playbook_id": f"playbook-sim-{uuid.uuid4().hex[:8]}", **payload}
        resp = requests.post(self.cfg.playbooks_url, headers=self._headers(), json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()

    def create_knowledge_note(
        self, name: str, body: str, *, trigger: str = "always", pinned_repo: Optional[str] = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"name": name, "body": body, "trigger": trigger, "is_enabled": True}
        if pinned_repo:
            payload["pinned_repo"] = pinned_repo
        if self.cfg.dry_run:
            return {"note_id": f"note-sim-{uuid.uuid4().hex[:8]}", **payload}
        resp = requests.post(self.cfg.knowledge_url, headers=self._headers(), json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()

    # ── Simulation backend ───────────────────────────────────────────────────
    def _sim_load(self) -> dict[str, Any]:
        if self._sim_path.exists():
            return json.loads(self._sim_path.read_text())
        return {}

    def _sim_save(self, data: dict[str, Any]) -> None:
        self._sim_path.parent.mkdir(parents=True, exist_ok=True)
        self._sim_path.write_text(json.dumps(data, indent=2))

    def _sim_create(self, body: dict[str, Any]) -> dict[str, Any]:
        sid = f"devin-sim-{uuid.uuid4().hex[:12]}"
        tags = body.get("tags", [])
        cve = next((t[4:] for t in tags if t.startswith("cve-")), "CVE-UNKNOWN")
        repo = (body.get("repos") or [self.cfg.target_repo])[0]
        record = {
            "session_id": sid,
            "title": body.get("title", ""),
            "tags": tags,
            "cve_id": cve,
            "repo": repo,
            "created_at": time.time(),
        }
        with _SIM_LOCK:
            data = self._sim_load()
            data[sid] = record
            self._sim_save(data)
        logger.info("[sim] created session %s for %s", sid, cve)
        return {
            "session_id": sid,
            "url": f"https://app.devin.ai/sessions/{sid}",
            "is_new_session": True,
            "status": "new",
            "tags": tags,
            "acus_consumed": 0.0,
            "pull_requests": [],
        }

    def _sim_get(self, session_id: str) -> dict[str, Any]:
        with _SIM_LOCK:
            record = self._sim_load().get(session_id)
        if not record:
            return {"session_id": session_id, "status": "error", "status_detail": "not_found"}
        return self._sim_project(record)

    def _sim_project(self, record: dict[str, Any]) -> dict[str, Any]:
        """Derive a live-looking session view from elapsed time."""
        elapsed = time.time() - record["created_at"]
        duration = max(2.0, float(self.cfg.sim_duration_seconds))
        sid = record["session_id"]
        # Deterministic-but-plausible per-session values.
        h = int(hashlib.sha256(sid.encode()).hexdigest(), 16)
        total_acus = round(1.5 + (h % 250) / 100.0, 1)  # 1.5 – 4.0
        pr_number = 40000 + (h % 1500)

        claim_t = max(1.0, duration * 0.15)
        if elapsed < claim_t:
            status, detail, acus, prs, out = "claimed", "", 0.0, [], None
        elif elapsed < duration:
            status, detail = "running", "working"
            acus = round(total_acus * (elapsed / duration), 1)
            prs, out = [], None
        else:
            status, detail = "running", "finished"
            acus = total_acus
            prs = [{"pr_url": f"https://github.com/{record['repo']}/pull/{pr_number}", "pr_state": "open"}]
            out = {
                "cve_id": record["cve_id"],
                "fixed": True,
                "tests_passed": True,
                "pr_url": prs[0]["pr_url"],
                "summary": f"Bumped vulnerable dependency and resolved breakage for {record['cve_id']}.",
            }
        return {
            "session_id": sid,
            "title": record.get("title", ""),
            "status": status,
            "status_detail": detail,
            "acus_consumed": acus,
            "pull_requests": prs,
            "structured_output": out,
            "tags": record.get("tags", []),
            "url": f"https://app.devin.ai/sessions/{sid}",
            "origin": "api",
        }
