"""One-time setup: create the CVE-upgrade playbook + knowledge note in Devin.

Prints the IDs to paste into .env (DEVIN_PLAYBOOK_ID, DEVIN_KNOWLEDGE_IDS).
Run with DRY_RUN=true to preview without calling the API.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import playbook  # noqa: E402
from config import CONFIG  # noqa: E402
from devin_client import DevinClient  # noqa: E402


def main() -> None:
    devin = DevinClient(CONFIG)

    pb = devin.create_playbook(
        playbook.PLAYBOOK_TITLE,
        playbook.PLAYBOOK_BODY,
        macro=playbook.PLAYBOOK_MACRO,
        structured_output_schema=playbook.STRUCTURED_OUTPUT_SCHEMA,
    )
    note = devin.create_knowledge_note(
        playbook.KNOWLEDGE_NAME,
        playbook.KNOWLEDGE_BODY,
        trigger="always",
        pinned_repo=CONFIG.target_repo,
    )

    print("\n✅ Created Devin assets" + (" (simulated)" if CONFIG.dry_run else "") + ":\n")
    print(f"  DEVIN_PLAYBOOK_ID={pb['playbook_id']}")
    print(f"  DEVIN_KNOWLEDGE_IDS={note['note_id']}")
    print("\nPaste these into your .env.\n")


if __name__ == "__main__":
    main()
