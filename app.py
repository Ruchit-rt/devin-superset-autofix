"""Flask control plane: webhook trigger, manual scan, observability dashboard.

Routes:
  GET  /healthz        liveness
  POST /webhook/github GitHub 'issues' events -> dispatch labeled CVE issues to Devin
  POST /scan           run the scanner now and file issues (manual/live trigger)
  GET  /api/sessions   JSON: rolled-up metrics + per-CVE rows (the cockpit's data)
  GET  /dashboard      the security cockpit (HTML)
"""

from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template, request

import scan
from config import CONFIG
from devin_client import DevinClient
from dispatcher import Dispatcher
from github_client import GitHubClient
from poller import Poller
from tracker import Tracker

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("app")

app = Flask(__name__)

devin = DevinClient(CONFIG)
github = GitHubClient(CONFIG)
tracker = Tracker(CONFIG.data_file)
dispatcher = Dispatcher(devin, tracker, CONFIG)
poller = Poller(devin, github, tracker, dispatcher, CONFIG)

_TRIGGER_ACTIONS = {"labeled", "opened", "reopened"}


@app.get("/healthz")
def healthz():
    return jsonify({"status": "ok", "dry_run": CONFIG.dry_run, "target_repo": CONFIG.target_repo})


@app.post("/webhook/github")
def webhook_github():
    if not github.verify_signature(request.data, request.headers.get("X-Hub-Signature-256", "")):
        return jsonify({"error": "invalid signature"}), 403

    event = request.headers.get("X-GitHub-Event", "")
    if event == "ping":
        return jsonify({"status": "pong"}), 200
    if event != "issues":
        return jsonify({"status": "ignored", "reason": f"event={event}"}), 200

    payload = request.get_json(silent=True) or {}
    action = payload.get("action")
    issue = payload.get("issue") or {}
    labels = [lbl["name"] for lbl in issue.get("labels", [])]

    if action not in _TRIGGER_ACTIONS or CONFIG.label not in labels:
        return jsonify({"status": "ignored", "reason": f"action={action}, labels={labels}"}), 200

    entry = dispatcher.dispatch_for_issue(
        {
            "number": issue["number"],
            "title": issue.get("title", ""),
            "body": issue.get("body", ""),
            "html_url": issue.get("html_url", ""),
            "created_at": issue.get("created_at", ""),
            "labels": labels,
        }
    )
    if not entry:
        return jsonify({"status": "skipped", "reason": "no devin-autofix metadata"}), 200
    return jsonify(
        {"status": "dispatched", "cve_id": entry["cve_id"], "session_id": entry.get("session_id"),
         "session_url": entry.get("session_url")}
    ), 201


@app.post("/scan")
def manual_scan():
    auto = request.args.get("auto_label", "").lower() in {"1", "true", "yes"} or None
    report = request.args.get("report") or CONFIG.scan_report or None
    filed = scan.run_scan_and_file(github, tracker, CONFIG, report=report, auto_label=auto)
    return jsonify({"filed": len(filed), "issues": filed, "summary": tracker.summary()}), 200


@app.get("/api/sessions")
def api_sessions():
    rows = []
    for e in tracker.all():
        rows.append(
            {
                **e,
                "bump": f"{e.get('current_version', '?')} → {e.get('fixed_version', '?')}",
            }
        )
    return jsonify({"summary": tracker.summary(), "sessions": rows, "dry_run": CONFIG.dry_run})


@app.get("/dashboard")
def dashboard():
    return render_template("dashboard.html", repo=CONFIG.target_repo, dry_run=CONFIG.dry_run)


@app.get("/")
def index():
    return dashboard()


if __name__ == "__main__":
    poller.start()
    app.run(host="0.0.0.0", port=8080, use_reloader=False)
