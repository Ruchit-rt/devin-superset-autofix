"""Turns an eligible CVE issue into a managed Devin session.

Shared by the webhook handler and the polling fallback, so both go through the same
Devin API path. Idempotent: an issue that already has a session is never dispatched
again (tracker dedupe).
"""

from __future__ import annotations

import logging
from typing import Any, Optional

import playbook
from config import Config
from devin_client import DevinClient
from tracker import Tracker, finding_key

logger = logging.getLogger("dispatcher")


class Dispatcher:
    def __init__(self, devin: DevinClient, tracker: Tracker, config: Config) -> None:
        self.devin = devin
        self.tracker = tracker
        self.cfg = config

    def dispatch_for_issue(self, issue: dict[str, Any]) -> Optional[dict[str, Any]]:
        finding = playbook.parse_issue_metadata(issue.get("body"))
        if not finding:
            logger.info("issue #%s has no devin-autofix metadata — skipping", issue.get("number"))
            return None

        key = finding_key(finding["cve_id"], finding["package"])
        self.tracker.upsert_finding(finding)
        self.tracker.attach_issue(key, issue)

        existing = self.tracker.get(key)
        if existing and existing.get("session_id"):
            logger.info("issue #%s already dispatched (%s) — skipping", issue["number"], existing["session_id"])
            return existing

        session = self.devin.create_session(
            playbook.build_prompt(finding, issue["number"], self.cfg.target_repo),
            title=f"Fix {finding['cve_id']}: bump {finding['package']}",
            tags=[self.cfg.security_label, self.cfg.label, f"cve-{finding['cve_id']}"],
            playbook_id=self.cfg.devin_playbook_id or None,
            knowledge_ids=self.cfg.devin_knowledge_ids or None,
            structured_output_schema=playbook.STRUCTURED_OUTPUT_SCHEMA,
            structured_output_required=True,
            max_acu_limit=self.cfg.max_acu_limit,
            repos=[self.cfg.target_repo],
        )
        self.tracker.record_dispatch(key, session)
        logger.info(
            "dispatched %s for issue #%s -> session %s",
            finding["cve_id"], issue["number"], session["session_id"],
        )
        return self.tracker.get(key)
