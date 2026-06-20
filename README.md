# Devin Superset Auto-Fix — Autonomous Dependency-CVE Remediation

An event-driven automation that uses the **[Devin API](https://docs.devin.ai/api-reference/overview)**
as the core primitive to remediate dependency vulnerabilities in
[Apache Superset](https://github.com/apache/superset).

> **The problem.** Every org has vulnerable dependencies. `pip-audit`/Dependabot even open
> version-bump PRs — but many *break the build*, so they rot in the queue for months and the CVE
> stays open. **Devin closes the loop:** it reads the advisory, bumps the dependency, **fixes the
> breaking changes the bump introduces**, runs targeted tests, and opens a *mergeable* PR. A bump
> that actually compiles is exactly what an autonomous agent does that a bot or codemod can't.

This is the **control plane**; Devin is the star. Detection (a cheap, deterministic scanner) stays
here; only the judgment-heavy remediation is handed to Devin.

---

## Architecture

```text
  our service runs            Flask service (this repo, Docker)            Devin API
  osv-scanner                 ┌──────────────────────────────────────┐  POST /sessions
  on requirements/*.txt       │  scan.py     scan → curate → file      │ ──────────────▶ isolated VM:
        ──files issues──────▶ │  /webhook/github   verify + filter      │                 bump dep,
   (the EVENT: scan results)  │  poller      issues + session status    │ ◀─ GET /sessions  fix breakage,
            │ human approves   │  dispatcher  → Devin API                │   status/PR/ACUs  run tests,
            │ via 'devin-auto- │  tracker     JSON store, dedupe, MTTR   │                  open PR
            ▼ fix' label       │  /dashboard  + /api/sessions            │
   Ruchit-rt/superset issue ──▶└──────────────────────────────────────┘
                                          │ PRs (bump + fix + green) land in
                                          ▼  Ruchit-rt/superset
```

**Two repos:** this one is the *system*; the **Superset fork** (`TARGET_REPO`) holds the seeded
vulnerable pins, the filed CVE issues, and the PRs Devin opens.

**Trigger chain:** scan → file GitHub issue per CVE → human adds the `devin-auto-fix` label →
GitHub **webhook** → dispatcher → **Devin API**. A **polling fallback** (same Devin API path) covers
webhook delivery failures; an optional **scheduler** runs the scan periodically.

---

## Layout

| Path | Role |
|---|---|
| `app.py` | Flask routes: `/webhook/github`, `/scan`, `/api/sessions`, `/dashboard`, `/healthz` |
| `scan.py` | osv-scanner / report → parse → curate → file issues (CLI + importable) |
| `dispatcher.py` | CVE issue → Devin session (prompt + playbook + schema + tags) |
| `devin_client.py` | Devin v3 API wrapper with an offline **DRY_RUN** simulator |
| `github_client.py` | GitHub REST (issues/labels) + HMAC webhook verification |
| `tracker.py` | Persistent JSON store; dedupe by CVE; rolls up metrics (incl. MTTR) |
| `poller.py` | Background workers: session refresh, issue-poll fallback, scan scheduler |
| `playbook.py` | Shared domain knowledge: playbook body, output schema, prompt, issue metadata |
| `templates/dashboard.html` | The security cockpit |
| `scripts/setup_playbook.py` | Create the Devin playbook + knowledge note |
| `scripts/seed_vulns.py` | Plant known-vulnerable pins in the fork (deterministic demo) |

---

## Quickstart — DRY-RUN (no keys, nothing real is called)

`DRY_RUN=true` simulates the Devin + GitHub APIs locally and deterministically, so you can run the
**whole workflow offline** with zero ACUs. Great for development and for the evaluator.

```bash
cp .env.example .env          # defaults already have DRY_RUN=true
pip install -r requirements.txt

# start the service (background workers + dashboard)
python app.py &

# 1) scan results -> file issues (uses the bundled sample report; no scanner needed)
python scan.py --report sample_osv_report.json

# 2) simulate the webhook trigger (issue labeled 'devin-auto-fix')
curl -X POST localhost:8080/webhook/github \
  -H 'X-GitHub-Event: issues' -H 'Content-Type: application/json' \
  -d @sample_webhook_payload.json

# 3) watch the cockpit fill in (sessions go running -> fixed after SIM_DURATION_SECONDS)
open http://localhost:8080/dashboard
```

The polling fallback will also pick up the filed sim-issues and dispatch them automatically.

With Docker: `docker compose up --build` (defaults to DRY_RUN), then open the dashboard.

---

## Real run

1. **Devin service user** → API key + org id (Settings → Service Users).
2. **GitHub PAT** with `repo` scope on your fork.
3. Fill `.env`: set `DRY_RUN=false`, `DEVIN_API_KEY`, `DEVIN_ORG_ID`, `GITHUB_TOKEN`,
   `TARGET_REPO`, `WEBHOOK_SECRET`.

```bash
python scripts/setup_playbook.py        # -> paste DEVIN_PLAYBOOK_ID / DEVIN_KNOWLEDGE_IDS into .env
python scripts/seed_vulns.py --apply     # plant vulnerable pins in the fork (review, then --push)
python scan.py                            # real osv-scanner -> files CVE issues in the fork

docker compose up --build -d && ngrok http 8080
# GitHub fork → Settings → Webhooks → add  https://<ngrok>/webhook/github
#   content-type application/json, secret = WEBHOOK_SECRET, events = Issues
# add the 'devin-auto-fix' label to a CVE issue  →  Devin opens a PR
```

Curate which CVEs are filed with `CURATE_CVES=` / `CURATE_PACKAGES=` / `MAX_ISSUES=`.

---

## Observability — the security cockpit

`GET /dashboard` (data at `GET /api/sessions`) answers *"how do I know this is working?"*:

- **Tiles:** CVEs found · in progress · fixed (PR) · failed · **MTTR (issue → PR)** · PRs · total
  ACUs · success rate.
- **Severity breakdown** chips and a **per-CVE table**: CVE, package, severity, version bump, status,
  Devin session link, PR link, tests, ACUs.
- Backed by session **tags**, **structured output**, and **ACU** totals.

---

## How it maps to the brief

- **Event-driven:** dependency *scan results* file issues; the `devin-auto-fix` *label* fires a GitHub
  *webhook*; a *periodic scheduler* is available too.
- **Devin as a core primitive:** every remediation is a programmatic `POST /sessions`, steered by a
  playbook + structured-output schema; both the webhook and the fallback go through the Devin API
  (we deliberately don't use Devin's built-in automation).
- **Observability:** the cockpit + structured output + ACU accounting.

---

## Next steps / extensions

- **Let Devin do the scanning too** — a scheduled Devin "security scout" session that reconciles
  multiple tools, does **reachability triage** (is the vulnerable path actually called?), surfaces
  novel findings, and self-seeds the backlog (parent→child sessions). Kept as an extension because a
  static scanner is cheaper and deterministic for the baseline — a hybrid is the mature design.
- Auto-label for zero-touch; auto-merge on green CI; more ecosystems; Snyk/Dependabot/Sentry webhook
  sources; run as a GitHub Action in prod (no ngrok).

---

## Note on the seeded vulnerabilities

`scripts/seed_vulns.py` intentionally downgrades a few dependencies on the **fork** so the demo is
deterministic. These are **planted for demonstration**, documented in `SEEDED_VULNS.md` — not
undiscovered vulnerabilities in Apache Superset.
