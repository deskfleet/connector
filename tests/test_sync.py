import copy
import base64
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import sync_releases as sync

NOW = datetime(2026, 11, 12, tzinfo=timezone.utc)
COMMIT = "a" * 40


def package(name="agent.py", content=b"example; never executed"):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, content)
    return output.getvalue(), {name: sync.sha(content)}


def fixture(sequence=55):
    version = f"gn08.2.{sequence}"
    data, files = package()
    def record(name):
        return {"url": f"{sync.ORIGIN}{name}-{version}-{COMMIT}.zip", "size": len(data), "sha256": sync.sha(data)}
    manifest = {"schemaVersion": "deskbot.connector-update.v1", "sequence": sequence, "version": version,
                "commit": COMMIT, "kind": "patch", "publishedAt": (NOW - timedelta(days=1)).isoformat(),
                "expiresAt": (NOW + timedelta(days=29)).isoformat(), "installerSourceSha256": "b" * 64,
                "artifact": record("deskbot-connector"), "files": files,
                "installers": {target: dict(record("deskbot-installer-" + target), files=files) for target in sync.TARGETS}}
    return manifest, data


def release(manifest, draft=False):
    return {"id": 1, "tag_name": manifest["version"], "body": sync.render_notes(manifest), "draft": draft,
            "html_url": f"https://github.com/deskfleet/connector/releases/tag/{manifest['version']}", "assets": []}


class FakeGitHub:
    def __init__(self, records=()):
        self.records = copy.deepcopy(list(records))
        self.blobs = {}
        self.operations = []
        self.fail_upload = False

    def releases(self):
        return copy.deepcopy(self.records)

    def api(self, path, method="GET", payload=None):
        self.operations.append((method, path))
        if path == "releases" and method == "POST":
            item = {**payload, "id": len(self.records) + 1, "assets": [], "html_url": "https://github.com/deskfleet/connector/releases/tag/" + payload["tag_name"]}
            self.records.append(item)
            return copy.deepcopy(item)
        if path.startswith("releases/assets/") and method == "DELETE":
            asset_id = int(path.rsplit("/", 1)[1])
            for item in self.records:
                item["assets"] = [asset for asset in item["assets"] if asset["id"] != asset_id]
            return None
        item = next(item for item in self.records if item["id"] == int(path.rsplit("/", 1)[1]))
        if method == "PATCH":
            item.update(payload)
        return copy.deepcopy(item)

    def asset(self, asset):
        return self.blobs[asset["id"]]

    def add_asset(self, name, data):
        asset_id = len(self.blobs) + 1
        self.blobs[asset_id] = data
        self.records[0]["assets"].append({"id": asset_id, "name": name})

    def upload(self, tag, paths):
        for index, path in enumerate(paths):
            self.add_asset(path.name, path.read_bytes())
            if self.fail_upload and index == 1:
                raise sync.Blocked("Synthetic upload interruption")


class SyncTests(unittest.TestCase):
    def test_valid_manifest_and_archives(self):
        manifest, data = fixture()
        self.assertEqual(sync.validate_manifest(sync.canonical(manifest), NOW), manifest)
        sync.verify_package(data, manifest["artifact"], manifest["files"])

    def test_duplicate_json_fields_fail(self):
        with self.assertRaises(sync.Blocked):
            sync.parse_json(b'{"sequence":55,"sequence":56}')

    def test_expired_future_naive_and_overlong_timestamps_fail(self):
        for change in ({"expiresAt": NOW.isoformat()}, {"publishedAt": (NOW + timedelta(hours=1)).isoformat()},
                       {"publishedAt": "2026-11-11T00:00:00"}, {"expiresAt": (NOW + timedelta(days=40)).isoformat()}):
            with self.subTest(change=change), self.assertRaises(sync.Blocked):
                manifest, _ = fixture()
                manifest.update(change)
                sync.validate_manifest(sync.canonical(manifest), NOW)

    def test_untrusted_or_unpinned_urls_fail(self):
        for url in ("https://evil.invalid/a.zip", sync.ORIGIN + "latest.zip", sync.ORIGIN + "../x.zip",
                    sync.ORIGIN + "deskbot-connector-gn08.2.55-" + COMMIT + ".zip?x=1"):
            with self.subTest(url=url), self.assertRaises(sync.Blocked):
                manifest, _ = fixture()
                manifest["artifact"]["url"] = url
                sync.validate_manifest(sync.canonical(manifest), NOW)

    def test_invalid_metadata_and_missing_target_fail(self):
        mutations = [lambda m: m.update(sequence=True), lambda m: m.update(commit="bad"),
                     lambda m: m.update(version="../../bad"), lambda m: m["installers"].pop("macos"),
                     lambda m: m["artifact"].update(size=True), lambda m: m["artifact"].update(sha256="invalid")]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(sync.Blocked):
                manifest, _ = fixture()
                mutate(manifest)
                sync.validate_manifest(sync.canonical(manifest), NOW)

    def test_unsafe_archive_names_fail(self):
        for name in ("../agent.py", "/agent.py", "x\\agent.py", "C:/agent.py", "./agent.py"):
            with self.subTest(name=name), self.assertRaises(sync.Blocked):
                sync.validate_files({name: "b" * 64})

    def test_tampered_size_hash_and_file_hash_fail(self):
        manifest, data = fixture()
        for changed_data, record, files in ((data + b"tampered", manifest["artifact"], manifest["files"]),
                                           (data, dict(manifest["artifact"], sha256="0" * 64), manifest["files"]),
                                           (data, manifest["artifact"], {"agent.py": "0" * 64})):
            with self.subTest(record=record), self.assertRaises(sync.Blocked):
                sync.verify_package(changed_data, record, files)

    def test_extra_or_duplicate_archive_entries_fail(self):
        manifest, data = fixture()
        for duplicate in (False, True):
            output = io.BytesIO(data)
            with zipfile.ZipFile(output, "a") as archive:
                archive.writestr("agent.py" if duplicate else "extra.py", b"x")
            changed = output.getvalue()
            with self.subTest(duplicate=duplicate), self.assertRaises(sync.Blocked):
                sync.verify_package(changed, {"size": len(changed), "sha256": sync.sha(changed)}, manifest["files"])

    def test_signature_is_required_before_json_or_packages(self):
        with patch.object(sync, "verify_signature", side_effect=sync.Blocked("bad signature")), self.assertRaises(sync.Blocked):
            sync.verify_feed(fetch=lambda url, maximum: b"untrusted")

    def test_feed_change_during_verification_fails(self):
        manifest, data = fixture()
        reads = []
        def fetch(url, maximum):
            reads.append(url)
            if url == sync.FEED:
                return sync.canonical(manifest) if reads.count(sync.FEED) == 1 else b"different"
            return b"signature" if url.endswith(".sig") else data
        with patch.object(sync, "verify_signature"), self.assertRaises(sync.Blocked):
            sync.verify_feed(fetch=fetch, now=NOW)

    def test_bootstrap_and_history_prevent_rollback_or_identity_reuse(self):
        manifest, _ = fixture()
        baseline = sync.release_marker(manifest)
        for candidate in (fixture(54)[0], dict(manifest, commit="c" * 40), dict(manifest, sequence=56)):
            with self.subTest(candidate=candidate["sequence"]), self.assertRaises(sync.Blocked):
                sync.plan(candidate, [], baseline)
        with self.assertRaises(sync.Blocked):
            sync.plan(manifest, [release(fixture(56)[0])], baseline)
        changed = copy.deepcopy(fixture(56)[0])
        changed["artifact"]["sha256"] = "f" * 64
        with self.assertRaises(sync.Blocked):
            sync.plan(changed, [release(fixture(56)[0])], baseline)

    def test_refresh_is_same_release(self):
        manifest, _ = fixture()
        renewed = dict(manifest, publishedAt=NOW.isoformat(), expiresAt=(NOW + timedelta(days=30)).isoformat(), summary="private commit text")
        record = release(manifest)
        self.assertEqual(sync.release_marker(manifest), sync.release_marker(renewed))
        self.assertEqual(sync.plan(renewed, [record], sync.release_marker(manifest)), record)

    def test_new_release_is_allowed_and_private_summary_is_not_published(self):
        baseline = sync.release_marker(fixture()[0])
        manifest, _ = fixture(56)
        manifest["summary"] = "PRIVATE-DO-NOT-PUBLISH"
        self.assertIsNone(sync.plan(manifest, [], baseline))
        self.assertNotIn("PRIVATE-DO-NOT-PUBLISH", sync.render_notes(manifest))
        self.assertIn("detailed change summary has not been published", sync.render_notes(manifest))

    def test_missing_or_duplicate_marker_fails(self):
        manifest, _ = fixture()
        for body in ("manual record", release(manifest)["body"] * 2):
            with self.assertRaises(sync.Blocked):
                sync.plan(manifest, [dict(release(manifest), body=body)], sync.release_marker(manifest))

    def test_wrong_publication_repository_fails(self):
        with self.assertRaises(sync.Blocked):
            sync.GitHub("someone/else")

    def test_draft_publication_idempotency_and_refresh(self):
        manifest, _ = fixture()
        github = FakeGitHub()
        baseline = sync.release_marker(manifest)
        with tempfile.TemporaryDirectory() as temp, patch.object(sync, "verify_signature"):
            output = Path(temp)
            sync.write_bundle(output, manifest, sync.canonical(manifest), b"signature")
            self.assertEqual(sync.publish(github, manifest, output, COMMIT, baseline)["action"], "published")
            self.assertFalse(github.records[0]["draft"])
            self.assertEqual(len(github.records[0]["assets"]), 4)
            renewed = dict(manifest, publishedAt=NOW.isoformat(), expiresAt=(NOW + timedelta(days=30)).isoformat())
            before = copy.deepcopy(github.operations)
            self.assertEqual(sync.publish(github, renewed, output, COMMIT, baseline)["action"], "unchanged")
            self.assertEqual(github.operations, before)

    def test_partial_upload_stays_draft_and_resumes(self):
        manifest, _ = fixture()
        github = FakeGitHub()
        github.fail_upload = True
        with tempfile.TemporaryDirectory() as temp, patch.object(sync, "verify_signature"):
            output = Path(temp)
            sync.write_bundle(output, manifest, sync.canonical(manifest), b"original-signature")
            with self.assertRaises(sync.Blocked):
                sync.publish(github, manifest, output, COMMIT, sync.release_marker(manifest))
            self.assertTrue(github.records[0]["draft"])
            self.assertEqual([a["name"] for a in github.records[0]["assets"]], ["release.json", "manifest.json"])
            github.fail_upload = False
            renewed = dict(manifest, publishedAt=NOW.isoformat(), expiresAt=(NOW + timedelta(days=30)).isoformat())
            sync.write_bundle(output, renewed, sync.canonical(renewed), b"renewed-signature")
            self.assertEqual(sync.publish(github, renewed, output, COMMIT, sync.release_marker(manifest))["action"], "published")
            blobs = {asset["name"]: github.asset(asset) for asset in github.records[0]["assets"]}
            self.assertEqual(blobs["manifest.json"], sync.canonical(renewed))
            self.assertEqual(blobs["manifest.json.sig"], b"renewed-signature")

    def test_conflicting_or_missing_assets_block_existing_release(self):
        manifest, _ = fixture()
        for name, value in (("release.json", b'{}'), ("SHA256SUMS", b"wrong checksums")):
            with self.subTest(name=name), self.assertRaises(sync.Blocked):
                github = FakeGitHub([release(manifest, draft=True)])
                github.add_asset(name, value)
                sync.verify_existing_assets(github, github.records[0], manifest, False)
        with self.assertRaises(sync.Blocked):
            sync.verify_existing_assets(FakeGitHub(), release(manifest), manifest, True)

    def test_feed_status_changes_only_for_signed_publication_changes(self):
        class StatusGitHub:
            def __init__(self):
                self.current = None
                self.writes = 0

            def api(self, path, method="GET", payload=None, optional=False):
                if method == "GET":
                    return self.current
                self.writes += 1
                self.current = {"content": payload["content"], "sha": str(self.writes)}
        manifest, _ = fixture()
        github = StatusGitHub()
        sync.record_feed_status(github, manifest, sync.canonical(manifest))
        sync.record_feed_status(github, manifest, sync.canonical(manifest))
        self.assertEqual(github.writes, 1)
        renewed = dict(manifest, publishedAt=NOW.isoformat(), expiresAt=(NOW + timedelta(days=30)).isoformat())
        sync.record_feed_status(github, renewed, sync.canonical(renewed))
        self.assertEqual(github.writes, 2)
        with self.assertRaises(sync.Blocked):
            sync.record_feed_status(github, manifest, sync.canonical(manifest))
        stored = json.loads(base64.b64decode(github.current["content"]))
        self.assertEqual(stored["expiresAt"], renewed["expiresAt"])


class RealSignatureTests(unittest.TestCase):
    def test_openssh_signature_tamper_wrong_key_and_namespace(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            key = directory / "key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True, capture_output=True)
            signers = directory / "allowed_signers"
            public = key.with_suffix(".pub").read_text().split()
            signers.write_text("deskbot-release " + " ".join(public[:2]) + "\n")
            payload = directory / "manifest.json"
            raw = sync.canonical(fixture()[0])
            payload.write_bytes(raw)
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "deskbot-connector-release", str(payload)], check=True, capture_output=True)
            signature = Path(str(payload) + ".sig").read_bytes()
            sync.verify_signature(raw, signature, signers)
            for altered_raw, altered_signature in ((raw + b" ", signature), (raw, b"not a signature")):
                with self.assertRaises(sync.Blocked):
                    sync.verify_signature(altered_raw, altered_signature, signers)
            signers.write_text("other-identity " + " ".join(public[:2]) + "\n")
            with self.assertRaises(sync.Blocked):
                sync.verify_signature(raw, signature, signers)
            other_key = directory / "untrusted-key"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(other_key)], check=True, capture_output=True)
            other_public = other_key.with_suffix(".pub").read_text().split()
            signers.write_text("deskbot-release " + " ".join(other_public[:2]) + "\n")
            with self.assertRaises(sync.Blocked):
                sync.verify_signature(raw, signature, signers)
            other = directory / "other.json"
            other.write_bytes(raw)
            subprocess.run(["ssh-keygen", "-Y", "sign", "-f", str(key), "-n", "wrong-namespace", str(other)], check=True, capture_output=True)
            signers.write_text("deskbot-release " + " ".join(public[:2]) + "\n")
            with self.assertRaises(sync.Blocked):
                sync.verify_signature(raw, Path(str(other) + ".sig").read_bytes(), signers)


if __name__ == "__main__":
    unittest.main()
