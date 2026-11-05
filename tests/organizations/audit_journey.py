"""Actual packaged HTTPS consumer against the running authority's immutable outbox."""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlencode
from uuid import UUID

from delivery_journey import require


def permissions(api, *, export):
    path = api.path + "/operators/" + api.operator
    listing, _ = api.call("GET", api.path + "/operators")
    current = next(item for item in listing["operators"] if item["id"] == api.operator)
    tag = f'"{current["id"]}.{current["revision"]}"'
    api.call(
        "PATCH",
        path,
        {
            "active": True,
            "capabilities": ["configure", "provision"] + (["export"] if export else []),
            "reason": "explicit audit export" if export else "revoke audit export",
        },
        tag=tag,
        key="audit-export" if export else "audit-revoke-export",
    )


def history(api):
    events = {}
    query = {"pageSize": 100}
    for _ in range(10):
        page, _ = api.call("GET", api.path + "/audit-events?" + urlencode(query))
        for event in page["events"]:
            require(event["id"] not in events, "history has no duplicate identities")
            events[event["id"]] = event
        cursor = page["pageInfo"].get("nextPageToken")
        if cursor is None:
            return events
        query["pageToken"] = cursor
    message = "finite fixture audit history limit"
    raise RuntimeError(message)


class Consumer:
    def __init__(self, delivery, api, browser):
        self.delivery, self.api, self.browser = delivery, api, browser
        self.root = delivery.directory / "audit-custody"
        self.root.mkdir(mode=0o700)
        self.session = delivery.directory / "audit-session.json"
        self.session.write_text(
            json.dumps(
                {
                    "cookie": api.cookie + "; csrf_token=fixture-csrf",
                    "csrfToken": "fixture-csrf",
                    "origin": "https://admin.example.test",
                }
            )
        )
        self.session.chmod(0o600)
        self.base = f"https://admin.example.test:{browser.port}" + api.path
        self.outcomes = []
        delivery.audit_outcomes = self.outcomes

    def invoke(self, operation, batch=None, *, success=True):
        arguments = [
            self.delivery.package / "bin/aegaeon-organization-audit-consumer",
            operation,
            "--state",
            self.root,
            "--session-file",
            self.session,
        ]
        arguments.extend(["--batch", batch] if batch else ["--base", self.base])
        result = self.delivery.run(arguments, environment=self.delivery.env, timeout=45)
        self.delivery.outputs.extend([result.stdout, result.stderr])
        classes = re.findall(r"^([A-Za-z_][\w.]*(?:Error|Exception)):", result.stderr, re.MULTILINE)
        self.outcomes.append(
            {
                "operation": operation,
                "success": result.returncode == 0,
                "returncode": result.returncode,
                "errorTypes": classes,
            }
        )
        log = self.delivery.directory / f"audit-consumer-{len(self.outcomes)}.log"
        log.write_text(result.stdout + result.stderr)
        log.chmod(0o600)
        require((result.returncode == 0) == success, "packaged audit consumer result")
        return result.stdout.strip()

    def exercise(self):  # noqa: PLR0915 — custody and lost-response ordering
        api = self.api
        original = history(api)
        encoded = json.dumps(original)
        require(
            all(secret not in encoded for secret in self.delivery.secrets)
            and "Invitee@example.test" not in encoded
            and "Member@example.test" not in encoded,
            "actual audit excludes credentials, capabilities and recipient addresses",
        )
        batch = self.invoke("fetch")
        require(str(UUID(batch)) == batch, "consumer prints a plain batch UUID")
        saved = self.root / batch
        manifest_bytes = (saved / "manifest.json").read_bytes()
        manifest = json.loads(manifest_bytes)
        pairs = manifest["request"]["events"]
        require(pairs, "actual immutable events retained")
        payload = json.loads((saved / "batch.json").read_bytes())
        for item in payload["deliveries"]:
            require(original[item["event"]["id"]] == item["event"], "outbox and history agree")
        duplicate = self.invoke("fetch")
        require(
            duplicate != batch
            and (self.root / duplicate / "batch.json").read_bytes()
            == (saved / "batch.json").read_bytes(),
            "duplicate fetch retains exact payload",
        )
        first = self.root / "events" / pairs[0]["id"]
        original_event = first.read_bytes()
        first.write_bytes(b"{}")
        before = len(self.browser.frontend.audit_requests)
        self.invoke("ack", batch, success=False)
        require(
            len(self.browser.frontend.audit_requests) == before,
            "corrupt custody refuses before network",
        )
        self.invoke("fetch", success=False)
        require(
            first.read_bytes() == b"{}", "same ID with different digest never overwrites custody"
        )
        first.write_bytes(original_event)
        require(
            hashlib.sha256(first.read_bytes()).hexdigest() == pairs[0]["sha256"],
            "test restores the exact retained fixture bytes",
        )
        require(not (saved / "receipt.json").exists(), "fetch never implicitly acknowledges")
        self.browser.frontend.drop_audit_ack = True
        self.invoke("ack", batch, success=False)
        require(
            not self.browser.frontend.drop_audit_ack and not (saved / "receipt.json").exists(),
            "actual committed ACK response was lost before receipt retention",
        )
        pending, _ = api.call("GET", api.path + "/audit-events/pending")
        require(
            not ({p["id"] for p in pairs} & {i["event"]["id"] for i in pending["deliveries"]}),
            "lost reply did not roll back the actual acknowledgment",
        )
        self.invoke("ack", batch)
        receipt = (saved / "receipt.json").read_bytes()
        require(json.loads(receipt)["events"] == pairs, "same-key recovery retained exact receipt")
        self.invoke("ack", batch)
        require(
            (saved / "receipt.json").read_bytes() == receipt
            and (saved / "manifest.json").read_bytes() == manifest_bytes,
            "receipt and request remain unchanged across replay",
        )
        require(history(api) == original, "ACK preserves complete immutable history")
        permissions(api, export=False)
        self.invoke("ack", batch, success=False)
        api.call("GET", api.path + "/audit-events", expected=403)
        require(
            (saved / "receipt.json").read_bytes() == receipt, "revoked replay preserves custody"
        )
        return {
            "passed": True,
            "historyEvents": len(original),
            "batchEvents": len(pairs),
            "actualPackagedConsumer": True,
            "duplicateAndDigestConflict": True,
            "durableFetchSeparateFromAck": True,
            "lostCommittedResponseRecovered": True,
            "currentExportRequiredOnReplay": True,
            "immutableHistoryPreserved": True,
            "diskDurabilityQualified": False,
            "cli": self.outcomes,
        }


def exercise(delivery, api, browser):
    api.call("GET", api.path + "/audit-events/pending", expected=403)
    permissions(api, export=True)
    consumer = Consumer(delivery, api, browser)
    try:
        return consumer.exercise()
    finally:
        requests = browser.frontend.audit_requests
        for index in range(2):
            api.counts[index] += len(requests)
        api.journal.extend(requests)
        consumer.session.unlink()
