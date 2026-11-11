#!/usr/bin/env python3
"""Verify the public signed Connector feed and publish its public release record.

Uses only Python's standard library, OpenSSH and gh. Never installs or executes
downloaded packages. No private-repository or signing credentials are needed.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import time
from urllib.error import URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
import zipfile

ROOT = Path(__file__).resolve().parents[1]
FEED = "https://updates.deskfleet.dev/latest.json"
ORIGIN = "https://updates.deskfleet.dev/"
REPOSITORY = "deskfleet/connector"
TARGETS = {"windows": "Windows Connector", "macos": "macOS Connector", "chat-control": "Chat Kit"}
MAX_METADATA = 256 * 1024
MAX_PACKAGE = 32 * 1024 * 1024
VERSION = re.compile(r"gn[0-9]+\.[0-9]+\.[0-9]+")
HEX = re.compile(r"[0-9a-f]{64}")
MARKER = re.compile(r"<!-- deskfleet-release (\{[^\n]*\}) -->")


class Blocked(RuntimeError):
    """Verification or publication must stop."""


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Blocked("Duplicate JSON field")
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(Blocked("Invalid JSON number")))
    except (ValueError, UnicodeError) as error:
        raise Blocked("Invalid JSON") from error


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("Unexpected download redirect")


def download(url, maximum):
    if not url.startswith(ORIGIN):
        raise Blocked("Download must use the official update origin")
    # No Authorization headers, cookies, client certificates or private tokens.
    request = Request(url, headers={"User-Agent": "Deskfleet-public-release-sync", "Cache-Control": "no-cache"})
    opener = build_opener(NoRedirect())
    for attempt in range(3):
        try:
            with opener.open(request, timeout=30) as response:
                if response.status != 200 or response.geturl() != url:
                    raise Blocked("Unexpected download response")
                data = response.read(maximum + 1)
            if not data or len(data) > maximum:
                raise Blocked("Download size is outside the permitted range")
            return data
        except (URLError, TimeoutError, OSError):
            if attempt == 2:
                raise Blocked("Public update download unavailable") from None
            time.sleep(2)


def verify_signature(raw, signature, signers):
    if not raw or len(raw) > MAX_METADATA or not signature or len(signature) > 16384:
        raise Blocked("Manifest or signature size is invalid")
    with tempfile.TemporaryDirectory() as temp:
        signature_path = Path(temp) / "manifest.sig"
        signature_path.write_bytes(signature)
        result = subprocess.run([
            "ssh-keygen", "-Y", "verify", "-f", str(signers),
            "-I", "deskbot-release", "-n", "deskbot-connector-release", "-s", str(signature_path),
        ], input=raw, capture_output=True, timeout=20)
    if result.returncode:
        raise Blocked("Manifest signature does not match the pinned public signers")


def timestamp(value):
    try:
        value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if value.tzinfo is None:
            raise ValueError()
        return value
    except (ValueError, TypeError, AttributeError):
        raise Blocked("Invalid manifest timestamp") from None


def validate_record(record, expected_url):
    if not isinstance(record, dict) or record.get("url") != expected_url:
        raise Blocked("Package URL does not match its pinned version and commit")
    if type(record.get("size")) is not int or not 0 < record["size"] <= MAX_PACKAGE:
        raise Blocked("Invalid package size")
    if not isinstance(record.get("sha256"), str) or not HEX.fullmatch(record["sha256"]):
        raise Blocked("Invalid package SHA-256")


def validate_files(files):
    if not isinstance(files, dict) or not 1 <= len(files) <= 200:
        raise Blocked("Invalid package file list")
    for name, digest in files.items():
        if (not isinstance(name, str) or not name or "\\" in name or "\x00" in name
                or ":" in name or name.startswith("/") or str(PurePosixPath(name)) != name
                or ".." in PurePosixPath(name).parts or not isinstance(digest, str) or not HEX.fullmatch(digest)):
            raise Blocked("Unsafe filename or invalid file SHA-256")


def validate_manifest(raw, now=None):
    manifest = parse_json(raw)
    if not isinstance(manifest, dict) or manifest.get("schemaVersion") != "deskbot.connector-update.v1":
        raise Blocked("Unsupported feed schema")
    version, commit = manifest.get("version"), manifest.get("commit")
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        raise Blocked("Invalid Connector version")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise Blocked("Invalid source revision")
    if type(manifest.get("sequence")) is not int or manifest["sequence"] < 1:
        raise Blocked("Invalid release sequence")
    if manifest.get("kind") not in ("patch", "upgrade"):
        raise Blocked("Unsupported release kind")
    now = now or datetime.now(timezone.utc)
    published, expires = timestamp(manifest.get("publishedAt")), timestamp(manifest.get("expiresAt"))
    if not published <= now < expires or not timedelta(0) < expires - published <= timedelta(days=31):
        raise Blocked("Manifest is expired, not yet valid, or valid for too long")
    if not isinstance(manifest.get("installerSourceSha256"), str) or not HEX.fullmatch(manifest["installerSourceSha256"]):
        raise Blocked("Invalid installer build identity")
    validate_record(manifest.get("artifact"), f"{ORIGIN}deskbot-connector-{version}-{commit}.zip")
    validate_files(manifest.get("files"))
    if not isinstance(manifest.get("installers"), dict) or set(manifest["installers"]) != set(TARGETS):
        raise Blocked("All three supported kits must be present")
    for target, record in manifest["installers"].items():
        validate_record(record, f"{ORIGIN}deskbot-installer-{target}-{version}-{commit}.zip")
        validate_files(record.get("files"))
    return manifest


def identity(manifest):
    # Renewal dates and free-form summaries do not define a software release.
    keys = ("schemaVersion", "version", "sequence", "commit", "kind", "artifact", "files", "installerSourceSha256", "installers")
    return {key: manifest[key] for key in keys}


def release_marker(manifest):
    return {"version": manifest["version"], "sequence": manifest["sequence"], "identitySha256": sha(canonical(identity(manifest)))}


def verify_package(data, record, files):
    if len(data) != record["size"] or sha(data) != record["sha256"]:
        raise Blocked("Downloaded package size or SHA-256 differs from the signed manifest")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) != len(files) or {entry.filename for entry in entries} != set(files):
                raise Blocked("Archive file list differs from the signed manifest")
            if sum(entry.file_size for entry in entries) > 128 * 1024 * 1024:
                raise Blocked("Expanded archive is too large")
            for entry in entries:
                mode = entry.external_attr >> 16
                if entry.is_dir() or stat.S_ISLNK(mode) or entry.flag_bits & 1:
                    raise Blocked("Unsupported archive entry")
                if sha(archive.read(entry)) != files[entry.filename]:
                    raise Blocked("Archive file hash differs from the signed manifest")
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError) as error:
        raise Blocked("Invalid archive") from error


def verify_feed(fetch=download, signers=ROOT / "trust/allowed_signers", now=None):
    raw = fetch(FEED, MAX_METADATA)
    signature = fetch(FEED + ".sig", 16384)
    verify_signature(raw, signature, signers)
    manifest = validate_manifest(raw, now)
    for record, files in [(manifest["artifact"], manifest["files"]), *[(r, r["files"]) for r in manifest["installers"].values()]]:
        verify_package(fetch(record["url"], MAX_PACKAGE), record, files)
    # Publication may have advanced while the kits were being checked. Retry on
    # the next run rather than publish an inconsistent view of mutable metadata.
    if fetch(FEED, MAX_METADATA) != raw or fetch(FEED + ".sig", 16384) != signature:
        raise Blocked("Feed changed during verification; retry against the next stable publication")
    return manifest, raw, signature


def marker_from_release(release):
    matches = MARKER.findall(release.get("body") or "")
    if len(matches) != 1:
        raise Blocked("Existing release lacks a unique synchronization identity")
    marker = parse_json(matches[0])
    if (not isinstance(marker, dict) or set(marker) != {"version", "sequence", "identitySha256"}
            or type(marker["sequence"]) is not int or marker["sequence"] < 1
            or not isinstance(marker["version"], str) or not VERSION.fullmatch(marker["version"])
            or marker["version"] != release.get("tag_name")
            or not isinstance(marker["identitySha256"], str) or not HEX.fullmatch(marker["identitySha256"])):
        raise Blocked("Existing release has an invalid synchronization identity")
    return marker


def plan(manifest, releases, baseline):
    wanted = release_marker(manifest)
    version_tuple = lambda value: tuple(map(int, value[2:].split(".")))
    if wanted["sequence"] < baseline["sequence"] or version_tuple(wanted["version"]) < version_tuple(baseline["version"]):
        raise Blocked("Feed is older than the trusted bootstrap release")
    if (wanted["sequence"] == baseline["sequence"] or wanted["version"] == baseline["version"]) and wanted != baseline:
        raise Blocked("Feed conflicts with the trusted bootstrap identity")
    existing = None
    seen = set()
    for release in releases:
        old = marker_from_release(release)
        if old["sequence"] in seen:
            raise Blocked("Duplicate release sequence")
        seen.add(old["sequence"])
        if old["sequence"] > wanted["sequence"] or version_tuple(old["version"]) > version_tuple(wanted["version"]):
            raise Blocked("Feed would roll back a newer public release")
        if old["sequence"] == wanted["sequence"] or old["version"] == wanted["version"]:
            if old != wanted:
                raise Blocked("Version or sequence was reused for different release bytes")
            existing = release
    return existing


def render_notes(manifest):
    curated = ROOT / "notes" / f"{manifest['version']}.md"
    if curated.is_file():
        changes = curated.read_text(encoding="utf-8").strip()
    else:
        changes = "This record identifies the packages published in Deskfleet's signed Connector feed. A detailed change summary has not been published for this version."
    lines = [f"# Deskfleet Connector {manifest['version']}", "", changes, "", f"Release sequence: **{manifest['sequence']}**.",
             f"Connector build revision: `{manifest['commit']}`.", "", "## Downloads", "",
             "Use the version-specific links below. These are existing signed-feed packages, verified before this release record was published.", "",
             "| Package | Download | Bytes | SHA-256 |", "| --- | --- | ---: | --- |"]
    for target, label in TARGETS.items():
        record = manifest["installers"][target]
        lines.append(f"| {label} | [ZIP]({record['url']}) | {record['size']} | `{record['sha256']}` |")
    lines += ["", "The runtime patch used by automatic updates is included in `SHA256SUMS`; fresh installations should use a kit above.", "",
              "[Setup guide](https://deskfleet.dev/guides/agent-setup) · [Open Deskfleet](https://app.deskfleet.dev) · [Support](mailto:support@deskfleet.dev)", "",
              "## Verification", "",
              "Attached metadata is a snapshot of the verified publication. Its expiry date controls update-feed freshness; archived metadata does not remain a current update authorization after it expires. Renewing the live manifest does not create a new software version.", "",
              "GitHub's generated source archives contain this public release-index tooling, not the private Deskfleet app or the Connector kit. Download a kit using the links above.", "",
              f"<!-- deskfleet-release {canonical(release_marker(manifest)).decode().strip()} -->", ""]
    return "\n".join(lines)


def write_bundle(output, manifest, raw, signature):
    output.mkdir(parents=True, exist_ok=True)
    (output / "release.json").write_bytes(canonical(identity(manifest)))
    (output / "manifest.json").write_bytes(raw)
    (output / "manifest.json.sig").write_bytes(signature)
    checksums = []
    for record in [manifest["artifact"], *manifest["installers"].values()]:
        checksums.append(f"{record['sha256']}  {record['url'].rsplit('/', 1)[1]}")
    (output / "SHA256SUMS").write_text("\n".join(sorted(checksums)) + "\n", encoding="utf-8", newline="\n")
    (output / "release-notes.md").write_text(render_notes(manifest), encoding="utf-8", newline="\n")


class GitHub:
    def __init__(self, repository):
        if repository != REPOSITORY:
            raise Blocked("Publishing is restricted to deskfleet/connector")
        self.repository = repository

    def api(self, path, method="GET", payload=None, optional=False):
        command = ["gh", "api", "--hostname", "github.com", f"repos/{self.repository}/{path}", "--method", method]
        if payload is not None:
            command += ["--input", "-"]
        result = subprocess.run(command, input=canonical(payload) if payload is not None else None, capture_output=True, timeout=90)
        if result.returncode:
            if optional and method == "GET":
                try:
                    if parse_json(result.stdout).get("status") == "404":
                        return None
                except (Blocked, AttributeError):
                    pass
            raise Blocked(f"GitHub API {method} {path.split('?')[0]} failed")
        return parse_json(result.stdout) if result.stdout.strip() else None

    def releases(self):
        result = []
        for page in range(1, 101):
            batch = self.api(f"releases?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise Blocked("Unexpected GitHub release listing")
            result.extend(batch)
            if len(batch) < 100:
                return result
        raise Blocked("Release pagination limit exceeded")

    def asset(self, asset):
        result = subprocess.run(["gh", "api", "--hostname", "github.com", f"repos/{self.repository}/releases/assets/{asset['id']}",
                                 "-H", "Accept: application/octet-stream"], capture_output=True, timeout=90)
        if result.returncode or len(result.stdout) > MAX_METADATA:
            raise Blocked("Could not read the existing release asset")
        return result.stdout

    def upload(self, tag, paths):
        result = subprocess.run(["gh", "release", "upload", tag, "--repo", self.repository, *map(str, paths)], capture_output=True, timeout=120)
        if result.returncode:
            raise Blocked("Release asset upload failed; the draft can be retried")


ASSETS = ("release.json", "manifest.json", "manifest.json.sig", "SHA256SUMS")


def verify_existing_assets(github, release, manifest, require_complete):
    assets = release.get("assets", [])
    names = [asset["name"] for asset in assets]
    if len(names) != len(set(names)) or set(names) - set(ASSETS):
        raise Blocked("Unexpected or duplicate release assets")
    if require_complete and set(names) != set(ASSETS):
        raise Blocked("Published release is missing verification assets")
    downloaded = {asset["name"]: github.asset(asset) for asset in assets}
    if "release.json" in downloaded and parse_json(downloaded["release.json"]) != identity(manifest):
        raise Blocked("Existing release asset has a conflicting identity")
    expected_checksums = "\n".join(sorted(
        f"{record['sha256']}  {record['url'].rsplit('/', 1)[1]}"
        for record in [manifest["artifact"], *manifest["installers"].values()]
    )) + "\n"
    if "SHA256SUMS" in downloaded and downloaded["SHA256SUMS"] != expected_checksums.encode():
        raise Blocked("Existing checksum asset differs from the signed manifest")
    # Archived dates may differ after renewal. The original signed snapshot is
    # checked for signature and identity, not reinterpreted as fresh authority.
    if "manifest.json" in downloaded and "manifest.json.sig" in downloaded:
        verify_signature(downloaded["manifest.json"], downloaded["manifest.json.sig"], ROOT / "trust/allowed_signers")
        if identity(parse_json(downloaded["manifest.json"])) != identity(manifest):
            raise Blocked("Archived signed manifest has a conflicting identity")
    return downloaded


def publish(github, manifest, output, target_commit, baseline):
    if not re.fullmatch(r"[0-9a-f]{40}", target_commit or ""):
        raise Blocked("An exact public tooling commit is required for the release tag")
    existing = plan(manifest, github.releases(), baseline)
    if existing and not existing.get("draft"):
        verify_existing_assets(github, existing, manifest, True)
        return {"action": "unchanged", "url": existing["html_url"]}
    body = (output / "release-notes.md").read_text(encoding="utf-8")
    if existing is None:
        existing = github.api("releases", "POST", {"tag_name": manifest["version"], "target_commitish": target_commit,
                             "name": f"Deskfleet Connector {manifest['version']}", "body": body, "draft": True,
                             "prerelease": False, "generate_release_notes": False})
    downloaded = verify_existing_assets(github, existing, manifest, False)
    # A previous attempt may have left part of its original signed snapshot.
    # Keep that snapshot as a pair; never mix a refreshed manifest and old sig.
    if ("manifest.json" in downloaded) != ("manifest.json.sig" in downloaded):
        original = next(asset for asset in existing["assets"] if asset["name"] in {"manifest.json", "manifest.json.sig"})
        github.api(f"releases/assets/{original['id']}", "DELETE")
        downloaded.pop(original["name"])
    missing = [output / name for name in ASSETS if name not in downloaded]
    if missing:
        github.upload(manifest["version"], missing)
    completed = github.api(f"releases/{existing['id']}")
    verify_existing_assets(github, completed, manifest, True)
    # Re-read history immediately before making a draft public. Workflow
    # concurrency prevents normal races; this also detects a newer manual record.
    plan(manifest, github.releases(), baseline)
    result = github.api(f"releases/{existing['id']}", "PATCH", {"draft": False, "make_latest": "true"})
    return {"action": "published", "url": result["html_url"]}


def record_feed_status(github, manifest, raw):
    # A useful public record changes only when a signed publication changes.
    # Normal freshness renewals therefore also produce repository activity,
    # rather than leaving a healthy public scheduler idle for 60 days.
    content = canonical({key: manifest[key] for key in (
        "version", "sequence", "commit", "publishedAt", "expiresAt")}
        | {"manifestSha256": sha(raw), "feedUrl": FEED})
    path = "contents/status/verified-feed.json"
    previous = github.api(path + "?ref=main", optional=True)
    if previous:
        try:
            old = base64.b64decode(previous["content"], validate=False)
        except (KeyError, ValueError, TypeError):
            raise Blocked("Unexpected public feed-status response") from None
        if old == content:
            return
        parsed = parse_json(old)
        if (type(parsed.get("sequence")) is not int or parsed["sequence"] > manifest["sequence"]
                or (parsed["sequence"] == manifest["sequence"] and timestamp(parsed["publishedAt"]) > timestamp(manifest["publishedAt"]))):
            raise Blocked("Refusing to roll back the public feed-status record")
    payload = {"message": f"Record verified Connector {manifest['version']} feed publication",
               "branch": "main", "content": base64.b64encode(content).decode()}
    if previous:
        payload["sha"] = previous["sha"]
    github.api(path, "PUT", payload)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=ROOT / ".sync-output")
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--target-commit")
    args = parser.parse_args()
    manifest, raw, signature = verify_feed()
    baseline = parse_json((ROOT / "trust/bootstrap-release.json").read_bytes())
    plan(manifest, [], baseline)
    write_bundle(args.output, manifest, raw, signature)
    result = {"action": "verified", "version": manifest["version"], "sequence": manifest["sequence"]}
    if args.publish:
        github = GitHub(REPOSITORY)
        result.update(publish(github, manifest, args.output, args.target_commit, baseline))
        record_feed_status(github, manifest, raw)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Blocked as error:
        raise SystemExit(f"Release synchronization stopped: {error}")
