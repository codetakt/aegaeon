"""Consumer custody, interruption and transport refusal tests; not server proof."""

from __future__ import annotations

import importlib.util
import json
import signal
import subprocess
import sys
import tempfile
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "organization_audit_consumer.py"
SPEC = importlib.util.spec_from_file_location("organization_audit_consumer", SCRIPT)
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)

ENVIRONMENT = "00000000-0000-4000-8000-000000000002"
DOMAIN = "00000000-0000-4000-8000-000000000003"
EVENT = "00000000-0000-4000-8000-000000000004"
ACTOR = "00000000-0000-4000-8000-000000000005"
BASE = f"https://issuer.example/api/v1/teams/{ACTOR}/environments/{ENVIRONMENT}/organization-domains/{DOMAIN}"


def fixture(
    extra: str = '"number":1e+30,"text":"東京/é"',
) -> tuple[bytes, str, bytes, dict[str, str]]:
    raw = (
        f'{{"id":"{EVENT}","environmentId":"{ENVIRONMENT}","domainId":"{DOMAIN}","data":{{{extra}}}}}'
    ).encode()
    digest = consumer.sha(raw)
    pair = {"id": EVENT, "sha256": digest}
    binding = {
        "events": [pair],
        "scope": {"domain_id": DOMAIN, "environment_id": ENVIRONMENT},
        "version": 1,
    }
    tag = '"audit-batch.' + consumer.sha(consumer.encode(binding)) + '"'
    payload = (
        (
            f'{{"version":1,"environmentId":"{ENVIRONMENT}","domainId":"{DOMAIN}","deliveries":[{{"event":'
        ).encode()
        + raw
        + f',"sha256":"{digest}"}}]}}'.encode()
    )
    return payload, tag, raw, pair


def response(manifest: dict[str, Any]) -> tuple[bytes, str]:
    return consumer.encode(
        {
            "version": 1,
            "batchSha256": manifest["etag"][13:-1],
            "events": manifest["request"]["events"],
            "actorId": ACTOR,
            "requestId": "first-ack-request",
            "reason": "durable receiver custody",
        }
    ), manifest["etag"]


class ConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.payload, self.tag, self.raw, self.pair = fixture()

    def retain(self) -> tuple[str, dict[str, Any]]:
        batch = consumer.retain(self.root, BASE, self.payload, self.tag)
        manifest = json.loads((self.root / batch / "manifest.json").read_text())
        return batch, manifest

    def test_exact_utf8_and_number_lexemes_retained(self) -> None:
        batch, manifest = self.retain()
        self.assertEqual((self.root / "events" / EVENT).read_bytes(), self.raw)
        self.assertEqual((self.root / batch / "batch.json").read_bytes(), self.payload)
        self.assertEqual(manifest["request"]["events"], [self.pair])
        with mock.patch.object(consumer, "exchange", return_value=response(manifest)) as network:
            consumer.acknowledge(self.root, batch, {})
            consumer.acknowledge(self.root, batch, {})
        self.assertEqual(network.call_args_list[0], network.call_args_list[1])
        self.assertEqual(
            json.loads((self.root / batch / "receipt.json").read_text()),
            json.loads(response(manifest)[0]),
        )

    def test_bad_scope_hash_ambiguous_json_and_duplicate_ids_refused(self) -> None:
        cases = [
            self.payload.replace(b'"version":1', b'"version":1,"version":1'),
            self.payload.replace(ENVIRONMENT.encode(), ACTOR.encode(), 1),
            self.payload.replace(b"1e+30", b"1e+31"),
            b"x" * 65537,
        ]
        for payload in cases:
            with self.subTest(payload=payload[:70]), self.assertRaises((ValueError, KeyError)):
                consumer.retain(self.root, BASE, payload, self.tag)
        data = json.loads(self.payload)
        data["deliveries"] *= 2
        with self.assertRaises(ValueError):
            consumer.retain(self.root, BASE, consumer.encode(data), self.tag)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_same_event_different_content_never_replaces_custody(self) -> None:
        self.retain()
        payload, tag, _, _ = fixture('"changed":true')
        with self.assertRaisesRegex(ValueError, "different retained content"):
            consumer.retain(self.root, BASE, payload, tag)
        self.assertEqual((self.root / "events" / EVENT).read_bytes(), self.raw)

    def test_lost_reply_preserves_batch_and_original_key(self) -> None:
        batch, manifest = self.retain()
        with (
            mock.patch.object(consumer, "exchange", side_effect=TimeoutError) as failed,
            self.assertRaises(TimeoutError),
        ):
            consumer.acknowledge(self.root, batch, {})
        with mock.patch.object(consumer, "exchange", return_value=response(manifest)) as retried:
            consumer.acknowledge(self.root, batch, {})
        self.assertEqual(failed.call_args, retried.call_args)
        self.assertEqual(json.loads((self.root / batch / "manifest.json").read_text()), manifest)

    def test_corrupt_saved_event_prevents_network(self) -> None:
        batch, _ = self.retain()
        (self.root / "events" / EVENT).write_bytes(b"corrupt")
        with (
            mock.patch.object(consumer, "exchange") as network,
            self.assertRaises(ValueError),
        ):
            consumer.acknowledge(self.root, batch, {})
        network.assert_not_called()

    def test_fsync_failure_prevents_network(self) -> None:
        batch, _ = self.retain()
        with (
            mock.patch.object(consumer.os, "fsync", side_effect=OSError("owned disk fault")),
            mock.patch.object(consumer, "exchange") as network,
            self.assertRaises(OSError),
        ):
            consumer.acknowledge(self.root, batch, {})
        network.assert_not_called()

    def test_private_mode_and_symlink_refusal(self) -> None:
        self.root.chmod(0o755)
        with self.assertRaises(ValueError):
            self.retain()
        self.root.chmod(0o700)
        batch, _ = self.retain()
        target = self.root / batch / "batch.json"
        target.rename(target.with_name("original.json"))
        target.symlink_to("original.json")
        with self.assertRaises(OSError):
            consumer.acknowledge(self.root, batch, {})

    def test_capacity_retains_existing_batch(self) -> None:
        batch, manifest = self.retain()
        with mock.patch.object(consumer, "MAX_BATCHES", 1), self.assertRaises(ValueError):
            self.retain()
        self.assertEqual(json.loads((self.root / batch / "manifest.json").read_text()), manifest)

    def test_killed_writer_never_produces_acknowledgeable_partial_manifest(self) -> None:
        # Kill a real writer after its payload fsync, while its manifest is incomplete.
        script = f"""
import importlib.util,os,signal
s=importlib.util.spec_from_file_location('consumer',{str(SCRIPT)!r})
c=importlib.util.module_from_spec(s)
s.loader.exec_module(c)
original=c.save
def interrupted(name,data,parent):
 if name=='manifest.json':
  original(name,data[:10],parent);os.kill(os.getpid(),signal.SIGKILL)
 return original(name,data,parent)
c.save=interrupted
c.retain({str(self.root)!r},{BASE!r},{self.payload!r},{self.tag!r})
"""
        child = subprocess.run(  # noqa: S603 — fixed test program and owned temporary paths; no shell
            [sys.executable, "-c", script], capture_output=True, timeout=10, check=False
        )
        self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
        batches = [p for p in self.root.iterdir() if p.name != "events"]
        self.assertEqual(len(batches), 1)
        with (
            mock.patch.object(consumer, "exchange") as network,
            self.assertRaises(ValueError),
        ):
            consumer.acknowledge(self.root, batches[0].name, {})
        network.assert_not_called()
        batch, manifest = self.retain()
        with mock.patch.object(consumer, "exchange", return_value=response(manifest)):
            consumer.acknowledge(self.root, batch, {})

    def test_killed_receipt_writer_recovers_original_request(self) -> None:
        batch, manifest = self.retain()
        script = f"""
import importlib.util,os,signal
s=importlib.util.spec_from_file_location('consumer',{str(SCRIPT)!r})
c=importlib.util.module_from_spec(s)
s.loader.exec_module(c)
original=c.os.rename
def interrupted(*args,**kwargs):
 os.kill(os.getpid(),signal.SIGKILL)
c.os.rename=interrupted
with c.directory({str(self.root / batch)!r}) as fd:c.save_receipt({response(manifest)[0]!r},fd)
"""
        child = subprocess.run(  # noqa: S603 — fixed test program and owned temporary paths; no shell
            [sys.executable, "-c", script], capture_output=True, timeout=10, check=False
        )
        self.assertEqual(child.returncode, -signal.SIGKILL, child.stderr)
        self.assertTrue((self.root / batch / ".receipt.pending").exists())
        self.assertFalse((self.root / batch / "receipt.json").exists())
        with mock.patch.object(consumer, "exchange", return_value=response(manifest)) as network:
            consumer.acknowledge(self.root, batch, {})
        self.assertEqual(network.call_args.args[-1][2], manifest["key"])
        self.assertFalse((self.root / batch / ".receipt.pending").exists())
        self.assertTrue((self.root / batch / "receipt.json").exists())

    def test_plaintext_and_wrong_scope_urls_refused(self) -> None:
        for base in [
            BASE.replace("https:", "http:"),
            BASE + "?query=yes",
            BASE + "/",
            BASE.replace(DOMAIN, "organization_" + DOMAIN),
            BASE.replace("issuer.example", "user:password@issuer.example"),
        ]:
            with self.subTest(base=base), self.assertRaises(ValueError):
                consumer.source(base)


if __name__ == "__main__":
    unittest.main()
