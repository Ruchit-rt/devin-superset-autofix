"""Central configuration, loaded from environment variables.

Everything is overridable via env so the same image runs in DRY_RUN (offline,
deterministic, no ACUs) for development/demos and against the real Devin + GitHub
APIs in production.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent


def _load_dotenv(path: Path) -> None:
    """Minimal .env loader (no dependency).

    Real environment variables win over the file; within the file, the last
    occurrence of a key wins (so a later override beats an earlier line).
    """
    if not path.exists():
        return
    preexisting = set(os.environ.keys())
    for raw in path.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key in preexisting:  # a real env var takes precedence over the file
            continue
        os.environ[key] = value.strip()


_load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _list(name: str, default: str) -> list[str]:
    raw = os.environ.get(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    # --- Devin API ---
    devin_api_key: str = os.environ.get("DEVIN_API_KEY", "")
    devin_org_id: str = os.environ.get("DEVIN_ORG_ID", "")
    devin_base_url: str = os.environ.get("DEVIN_BASE_URL", "https://api.devin.ai/v3")
    devin_playbook_id: str = os.environ.get("DEVIN_PLAYBOOK_ID", "")
    devin_knowledge_ids: list[str] = field(default_factory=lambda: _list("DEVIN_KNOWLEDGE_IDS", ""))
    devin_mode: str = os.environ.get("DEVIN_MODE", "normal")
    max_acu_limit: int = int(os.environ.get("MAX_ACU_LIMIT", "10"))

    # --- GitHub ---
    github_token: str = os.environ.get("GITHUB_TOKEN", "")
    github_api: str = os.environ.get("GITHUB_API", "https://api.github.com")
    target_repo: str = os.environ.get("TARGET_REPO", "Ruchit-rt/superset")
    webhook_secret: str = os.environ.get("WEBHOOK_SECRET", "")
    label: str = os.environ.get("LABEL", "devin-auto-fix")
    security_label: str = os.environ.get("SECURITY_LABEL", "security")

    # --- Behaviour ---
    dry_run: bool = _bool("DRY_RUN", False)
    auto_label: bool = _bool("AUTO_LABEL", False)
    poll_interval: int = int(os.environ.get("POLL_INTERVAL", "20"))
    scan_interval_hours: float = float(os.environ.get("SCAN_INTERVAL_HOURS", "24"))
    enable_issue_polling: bool = _bool("ENABLE_ISSUE_POLLING", True)
    enable_scan_scheduler: bool = _bool("ENABLE_SCAN_SCHEDULER", False)
    sim_duration_seconds: int = int(os.environ.get("SIM_DURATION_SECONDS", "30"))

    # --- Scanning ---
    # Path to the local checkout of the target repo (used by the scanner + seeder).
    superset_repo_path: str = os.environ.get(
        "SUPERSET_REPO_PATH", str((BASE_DIR / ".." / "..").resolve())
    )
    scan_lockfiles: list[str] = field(
        default_factory=lambda: _list(
            "SCAN_LOCKFILES", "requirements/base.txt,requirements/development.txt"
        )
    )
    # If set, scan parses this osv-scanner JSON instead of invoking the scanner
    # (used by the dry-run demo and any host without osv-scanner installed).
    scan_report: str = os.environ.get("SCAN_REPORT", "")

    # --- Storage ---
    data_file: str = os.environ.get("DATA_FILE", str(BASE_DIR / "data" / "tracker.json"))

    @property
    def sessions_url(self) -> str:
        return f"{self.devin_base_url}/organizations/{self.devin_org_id}/sessions"

    @property
    def playbooks_url(self) -> str:
        return f"{self.devin_base_url}/organizations/{self.devin_org_id}/playbooks"

    @property
    def knowledge_url(self) -> str:
        return f"{self.devin_base_url}/organizations/{self.devin_org_id}/knowledge/notes"

    def lockfile_paths(self) -> list[str]:
        root = Path(self.superset_repo_path)
        return [str(root / lf) for lf in self.scan_lockfiles]


CONFIG = Config()
