"""End-to-end dry-run check: scan -> file -> dispatch (webhook + polling) -> fixed.

Drives the real Flask routes in-process (no server/ports needed). Deletable.
"""

import json
import os
import time

os.chdir(os.path.dirname(os.path.abspath(__file__)))

import app as A  # noqa: E402

assert A.CONFIG.dry_run, "selftest expects DRY_RUN=true"
c = A.app.test_client()


def check(name, cond):
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}")
    assert cond, name


print("1. health")
check("dry_run on", c.get("/healthz").get_json()["dry_run"] is True)

print("2. scan -> file issues (auto-label so the polling fallback can pick them up)")
r = c.post("/scan?auto_label=true").get_json()
check("filed 5 CVE issues", r["filed"] == 5)
check("cves_found == 5", c.get("/api/sessions").get_json()["summary"]["cves_found"] == 5)

print("3. webhook trigger (sample labeled-issue payload)")
payload = json.load(open("sample_webhook_payload.json"))
resp = c.post("/webhook/github", json=payload, headers={"X-GitHub-Event": "issues"})
check("webhook dispatched (201)", resp.status_code == 201)
check("webhook ignores non-issues event",
      c.post("/webhook/github", json={}, headers={"X-GitHub-Event": "push"}).status_code == 200)

print("4. polling fallback dispatches the rest")
A.poller.poll_issues()
mid = c.get("/api/sessions").get_json()["summary"]
check("all 5 dispatched (in_progress)", mid["in_progress"] == 5)

print(f"5. wait for simulated sessions (~{A.CONFIG.sim_duration_seconds}s) then refresh")
time.sleep(A.CONFIG.sim_duration_seconds + 1)
A.poller.refresh_sessions()

final = c.get("/api/sessions").get_json()["summary"]
print("   summary:", json.dumps(final))
check("fixed == 5", final["fixed"] == 5)
check("prs_opened == 5", final["prs_opened"] == 5)
check("success_rate == 100", final["success_rate"] == 100)
check("MTTR computed", final["mttr_seconds"] is not None)
check("ACUs accrued", final["total_acus"] > 0)

print("6. dedupe: re-dispatching the webhook issue does not create a 2nd session")
before = json.load(open(A.CONFIG.data_file))
c.post("/webhook/github", json=payload, headers={"X-GitHub-Event": "issues"})
after = json.load(open(A.CONFIG.data_file))
check("entry count unchanged", len(before) == len(after))

print("\n✅ ALL CHECKS PASSED")
