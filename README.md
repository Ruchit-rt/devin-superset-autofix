# Devin Superset Auto-Fix — Autonomous Dependency-CVE Remediation

An event-driven service that uses the **[Devin API](https://docs.devin.ai/api-reference/overview)** to
remediate dependency vulnerabilities in [Apache Superset](https://github.com/apache/superset)
end-to-end: it bumps the vulnerable package, **fixes the breaking changes the bump introduces**, runs
targeted tests, and opens a *mergeable* pull request.

> **The problem.** Every codebase accumulates vulnerable dependencies. `pip-audit`/Dependabot will even
> open version-bump PRs — but many *break the build*, so they stall in review for months while the CVE
> stays open. An autonomous agent closes that loop: it reads the advisory, applies the bump, repairs the
> resulting breakage, gets tests green, and opens a PR a human can merge. A bump that *actually compiles*
> is the part a bot or codemod can't do.

This repository is the **control plane**: a small Flask service that detects CVEs (with a cheap,
deterministic scanner), files an issue per finding, and — on human approval — hands the judgment-heavy
remediation to Devin via the API. It then tracks every session and surfaces the results on a dashboard.

---

## Architecture

```text
  osv-scanner  (scans requirements/*.txt)
       |
       |  files one GitHub issue per CVE
       v
  GitHub fork  (issues)
       |
       |  a human adds the 'devin-auto-fix' label      [or: polling fallback]
       v
  dispatcher  (webhook -> verify + filter, or poller)
       |
       |  POST /sessions
       v
  Devin API  ->  isolated VM:  bump dep -> fix breakage -> run tests -> open PR
       |
       |  PR lands in the fork    +    GET /sessions streams status back
       v
  tracker  ->  /dashboard   (status, MTTR, engineer-hours saved)
```

*Detection stays local and cheap; only remediation spends an agent. The webhook and the polling fallback
converge on the same dispatcher, and the tracker dedupes so they can't double-dispatch.*

**Two repos.** This one is the *system*. The **Superset fork** (`TARGET_REPO`) holds the seeded
vulnerable pins, the filed CVE issues, and the PRs Devin opens.

**Trigger chain.** scan → file a GitHub issue per CVE → a human adds the `devin-auto-fix` label →
GitHub **webhook** → dispatcher → **Devin API**. A **polling fallback** (the same Devin API path) covers
webhook-delivery failures, and an optional **scheduler** can run the scan periodically. Detection stays
local and cheap; only remediation spends an agent.

---

## Layout

| Path | Role |
|---|---|
| `app.py` | Flask routes: `/webhook/github`, `/scan`, `/api/sessions`, `/dashboard`, `/healthz` |
| `scan.py` | osv-scanner / report → parse → curate → file issues (CLI + importable) |
| `dispatcher.py` | CVE issue → Devin session (prompt + playbook + schema + tags) |
| `devin_client.py` | Devin v3 API wrapper with an offline **DRY_RUN** simulator |
| `github_client.py` | GitHub REST (issues/labels) + HMAC webhook verification |
| `tracker.py` | Persistent JSON store; dedupe by CVE; rolls up metrics (MTTR, hours saved) |
| `poller.py` | Background workers: session refresh, issue-poll fallback, scan scheduler |
| `playbook.py` | Shared domain knowledge: playbook body, output schema, prompt, issue metadata |
| `templates/dashboard.html` | The security cockpit |
| `scripts/setup_playbook.py` | Create the Devin playbook + knowledge note |
| `scripts/seed_vulns.py` | Plant known-vulnerable pins in the fork (deterministic demo) |

---

## Reproduce it on any machine — no keys, no GitHub, no tunnel

The service ships a fully offline **DRY-RUN** mode: `DRY_RUN=true` simulates the Devin *and* GitHub APIs
locally and deterministically. The whole workflow — scan → issue → trigger → session → PR → dashboard —
runs on a laptop with **no API keys, no GitHub access, no ngrok**, and zero ACUs. This is the intended
way to evaluate the project.

```bash
cp .env.example .env          # defaults are already DRY_RUN=true, WEBHOOK_SECRET blank
pip install -r requirements.txt

# start the service (background workers + dashboard on :8080)
python app.py &

# 1) "scan results" -> file issues (uses the bundled sample report; no scanner needed)
python scan.py --report sample_osv_report.json

# 2) the trigger: simulate the GitHub webhook for an issue labeled 'devin-auto-fix'
curl -X POST localhost:8080/webhook/github \
  -H 'X-GitHub-Event: issues' -H 'Content-Type: application/json' \
  -d @sample_webhook_payload.json

# 3) watch the cockpit: the session goes running -> fixed after SIM_DURATION_SECONDS
open http://localhost:8080/dashboard
```

Prefer Docker? `docker compose up --build` (defaults to DRY-RUN), then open the dashboard. Make sure to run `cp .env.example .env` or set upt the `.env` file before running!

**Want it hands-off?** Set `AUTO_LABEL=true` in `.env`. The scanner then applies the trigger label
itself, and the **polling fallback** dispatches every filed issue automatically within `POLL_INTERVAL`
seconds — no webhook curl needed. This is also how a live deployment can run without any inbound tunnel.

---

## How the trigger works live (and why ngrok is optional)

In production the trigger is a real GitHub webhook. GitHub needs a public URL to deliver to, so during a
local live demo that URL is an `ngrok http 8080` tunnel. **The tunnel is only needed for inbound webhook
delivery, and it is optional:** the polling fallback reaches the *same* dispatcher by listing
`devin-auto-fix`-labeled issues over the GitHub API every `POLL_INTERVAL` seconds. So a live run can:

- use a webhook + ngrok (lowest latency), **or**
- skip the tunnel entirely and rely on polling (label an issue → it dispatches within one interval), **or**
- run as a GitHub Action / hosted service in real deployments (no ngrok at all).

You never have to leave a personal tunnel running — it exists only for the duration of a live webhook
demo.

---

## Live run (real Devin + GitHub)

1. **Devin service user** → API key + org id (Settings → Service Users).
2. **GitHub PAT** with `repo` scope on your fork.
3. Fill `.env`: set `DRY_RUN=false`, `DEVIN_API_KEY`, `DEVIN_ORG_ID`, `GITHUB_TOKEN`, `TARGET_REPO`, and
   a real `WEBHOOK_SECRET`.

```bash
python scripts/setup_playbook.py        # -> paste DEVIN_PLAYBOOK_ID / DEVIN_KNOWLEDGE_IDS into .env
python scripts/seed_vulns.py --apply     # plant vulnerable pins in the fork (review, then --push)
python scan.py                            # real osv-scanner -> files CVE issues in the fork

docker compose up --build -d
# Optional, for webhook delivery: ngrok http 8080  ->  add https://<ngrok>/webhook/github
#   (content-type application/json, secret = WEBHOOK_SECRET, events = Issues)
# Add the 'devin-auto-fix' label to a CVE issue -> Devin opens a PR (webhook or polling).
```

Curate which CVEs are filed with `CURATE_CVES=` / `CURATE_PACKAGES=` / `MAX_ISSUES=`.

---

## Observability — the security cockpit

`GET /dashboard` (data at `GET /api/sessions`) answers *"how do I know this is working?"*:

- **Tiles:** CVEs found · in progress · fixed (PR) · failed · **MTTR (issue → PR)** · PRs opened ·
  **Engineer-hours saved** · success rate.
- **Per-CVE table:** CVE, package, severity, version bump, status, Devin session link, PR link, tests,
  and **Devin time** — how long the agent has been (or was) working on that finding.

Two metrics carry the productivity story:

- **MTTR** — mean time from issue filed to PR opened: the headline "how fast does this close CVEs?"
- **Engineer-hours saved** — completed remediations × `HOURS_SAVED_PER_FIX` (a calibratable estimate of
  the manual effort each fix replaces). **Devin time** shows live work duration even before a session
  closes, which is more informative than raw ACU counts while a session is still in flight.

---

## The Devin integration

- Each remediation is a programmatic `POST /sessions` steered by a reusable **playbook** (the upgrade
  recipe, encoded once) and a **structured-output schema** (a typed, machine-readable result per CVE).
- Sessions are **tagged** by CVE so the dashboard can correlate them, and capped with `max_acu_limit`.
- Both the webhook and the polling fallback go through the same Devin API path — the agent is the single
  remediation primitive.

---

## Notes on the demo data

`scripts/seed_vulns.py` intentionally downgrades a few dependencies on the **fork** so the scan is
deterministic. They fall into two groups:

- **Low-blast-radius leaf packages** (`pyyaml`, `requests`, `certifi`, `urllib3`, `idna`): the safe
  version is one Superset already tolerates, so remediation is a clean re-bump — a reliable backbone.
- **A breaking-change case** (`werkzeug`, CVE-2024-34069): the only patched version is a **major**
  upgrade (2.x → 3.x) that removes APIs, so remediating it requires actually fixing the breakage — the
  case that distinguishes an agent from a codemod.

These pins are **planted for demonstration on a fork**, documented in `SEEDED_VULNS.md` — they are not
undiscovered vulnerabilities in Apache Superset.

---

## Extensions

- **Let Devin do the scanning too** — a scheduled "security scout" session that reconciles multiple
  tools, does **reachability triage** (is the vulnerable path actually called?), surfaces novel findings,
  and self-seeds the backlog (parent → child sessions). Kept as an extension because a static scanner is
  cheaper and deterministic for the baseline; a hybrid is the mature design.
- Auto-merge on green CI; more ecosystems (npm/Go/Java); Snyk/Dependabot/Sentry as webhook sources; run
  as a GitHub Action in production (no tunnel).
</content>
</invoke>
