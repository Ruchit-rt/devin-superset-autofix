"""Background workers.

1. refresh    — poll Devin for each active session; feed status/PR/ACUs into the tracker.
2. issue poll — fallback trigger: find `devin-auto-fix` issues and dispatch them
                (covers webhook delivery failures; same Devin API path as the webhook).
3. scan       — optional periodic scan (the "periodic trigger").
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

import scan
from config import Config
from devin_client import DevinClient
from dispatcher import Dispatcher
from github_client import GitHubClient
from tracker import Tracker, finding_key

logger = logging.getLogger("poller")


def _loop(name: str, interval: float, fn: Callable[[], None], stop: threading.Event) -> None:
    while not stop.is_set():
        try:
            fn()
        except Exception:  # never let a worker thread die
            logger.exception("%s worker error", name)
        stop.wait(interval)


class Poller:
    def __init__(
        self,
        devin: DevinClient,
        github: GitHubClient,
        tracker: Tracker,
        dispatcher: Dispatcher,
        config: Config,
    ) -> None:
        self.devin = devin
        self.github = github
        self.tracker = tracker
        self.dispatcher = dispatcher
        self.cfg = config
        self._stop = threading.Event()

    # ── individual passes ────────────────────────────────────────────────────
    def refresh_sessions(self) -> None:
        for entry in self.tracker.active():
            info = self.devin.get_session(entry["session_id"])
            self.tracker.update_session(entry["key"], info)

    def poll_issues(self) -> None:
        for issue in self.github.list_issues([self.cfg.label]):
            self.dispatcher.dispatch_for_issue(issue)

    def scheduled_scan(self) -> None:
        scan.run_scan_and_file(self.github, self.tracker, self.cfg)

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        threads = [("refresh", self.cfg.poll_interval, self.refresh_sessions)]
        if self.cfg.enable_issue_polling:
            threads.append(("issue-poll", self.cfg.poll_interval, self.poll_issues))
        if self.cfg.enable_scan_scheduler:
            threads.append(("scan", self.cfg.scan_interval_hours * 3600, self.scheduled_scan))

        for name, interval, fn in threads:
            t = threading.Thread(target=_loop, args=(name, interval, fn, self._stop), daemon=True, name=name)
            t.start()
            logger.info("started %s worker (interval=%ss)", name, interval)

    def stop(self) -> None:
        self._stop.set()
