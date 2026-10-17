#!/usr/bin/env python3
"""Source regression for the nonpublishing manual-dispatch boundary.

These assertions test exact job-guard source contracts, not GitHub's hosted
expression evaluator or a completed public release.
"""
from pathlib import Path
import re

wf = Path(".github/workflows/release.yml").read_text(encoding="utf-8")
conditions = {}
for job in ("verify-preview", "publish"):
    found = re.findall(rf"(?m)^  {re.escape(job)}:\s*\n    if: (.+)$", wf)
    assert len(found) == 1, f"{job}: missing or duplicate if expression"
    conditions[job] = found[0].strip()

expected = {
    "verify-preview": "github.event_name == 'workflow_dispatch' && startsWith(github.ref, 'refs/heads/')",
    "publish": "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')",
}
assert conditions == expected, f"release guards changed: {conditions!r}"

# These model the two simple guards above, not arbitrary expressions.
def permitted(job: str, event: str, ref: str) -> bool:
    if job == "verify-preview":
        return event == "workflow_dispatch" and ref.startswith("refs/heads/")
    if job == "publish":
        return event == "push" and ref.startswith("refs/tags/v")
    raise AssertionError(job)

cases = (
    ("workflow_dispatch", "refs/heads/feature/test", True, False),
    ("workflow_dispatch", "refs/tags/v9.9.9", False, False),
    ("push", "refs/heads/main", False, False),
    ("push", "refs/tags/v9.9.9", False, True),
    ("push", "refs/tags/unsafe-1", False, False),
    ("pull_request", "refs/pull/15/merge", False, False),
)
for event, ref, preview, publish in cases:
    assert permitted("verify-preview", event, ref) is preview, (event, ref, "preview")
    assert permitted("publish", event, ref) is publish, (event, ref, "publish")

assert wf.count("gh release create ") == 1, "publication command count changed"
publish_body = wf.split("\n  publish:\n", 1)
assert len(publish_body) == 2, "publish job section count changed"
assert "gh release create " in publish_body[1], "publish command escaped guarded job"
assert "bash .github/scripts/verify-release-attestations.sh" in publish_body[1], "release must verify attestations"
assert publish_body[1].index("bash .github/scripts/verify-release-attestations.sh") < publish_body[1].index("gh release create "), "attestations must precede release"

print("RELEASE_EVENT_BOUNDARY_SOURCE_CONTRACT_PASS")
