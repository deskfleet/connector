# Deskfleet Connector releases

**Coding bots, working together.**

This is the official public release index for Deskfleet Connector. Find version-specific Windows, macOS and Chat Kit downloads, checksums and available change notes in [Releases](https://github.com/deskfleet/connector/releases/latest).

- [Deskfleet](https://deskfleet.dev) · [Open the app](https://app.deskfleet.dev)
- [Setup guide](https://deskfleet.dev/guides/agent-setup)
- [Developer community](https://t.me/deskfleet_developers) · [Support](mailto:support@deskfleet.dev)

## Download and install

Open the [latest release](https://github.com/deskfleet/connector/releases/latest) and choose the version-specific kit for your platform. Follow the setup guide and approve the selected tools and startup choice in Deskfleet.

GitHub's automatically generated source archives contain only this public release-index tooling. Use the **Windows Connector**, **macOS Connector** or **Chat Kit** links in the release notes for installation.

## How the index stays current

The existing Deskfleet release pipeline builds and signs the packages. This repository checks its [public signed feed](https://updates.deskfleet.dev/latest.json) automatically once daily at 04:37 UTC (12:37 China Standard Time), and supports a manual workflow run. GitHub may delay scheduled runs; synchronization is not instantaneous.

Before publishing, the synchronizer verifies the detached OpenSSH signature against pinned public keys, manifest validity, exact version and commit download URLs, package sizes, SHA-256 checksums and every archived file's hash. It never installs or executes a downloaded package. Existing public release history prevents rollback or reuse of a release identity. Version 55 is the initial trusted baseline; this index does not reconstruct older releases from private GitHub records.

The workflow uses this public repository's temporary `GITHUB_TOKEN`. It has no access to the private Deskfleet application repository, signing keys or update storage credentials. Publishing runs only from this repository's main branch. Pull requests run tests without release-write permission.

A release is first prepared as a draft. Its signed metadata and checksum assets must all upload and verify before it becomes public. Interrupted drafts can resume. A manifest renewal with unchanged software creates no new release and does not rewrite the archived release snapshot. Each release's notes distinguish curated change information from an unavailable detailed summary.

The [verified feed record](status/verified-feed.json) updates only when a verified signed publication changes, including freshness renewals. This records useful publication history and normally keeps the repository active. [GitHub disables public scheduled workflows after 60 days without repository activity](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule); if publication has stopped that long, a maintainer must investigate and re-enable the workflow. The index does not guarantee GitHub schedule availability.

## Verify a download

Compare the downloaded ZIP's SHA-256 with the release table or attached `SHA256SUMS`. For example:

```powershell
Get-FileHash .\your-downloaded-kit.zip -Algorithm SHA256
```

```sh
shasum -a 256 your-downloaded-kit.zip
```

For independent signature verification, download `manifest.json` and `manifest.json.sig` from the release and obtain `trust/allowed_signers` from this repository:

```sh
ssh-keygen -Y verify -f trust/allowed_signers -I deskbot-release \
  -n deskbot-connector-release -s manifest.json.sig < manifest.json
```

A matching checksum proves byte integrity. The signed manifest and pinned keys authenticate the release. Archived metadata can expire: it records a past publication and is not current update authorization after expiry. The live updater's freshness and version rules still apply.

## Maintaining the index

- Add reviewed public change notes to `notes/<version>.md`; never generate them from private commit messages, PR discussions or application source.
- Review signing-key changes explicitly in `trust/allowed_signers`. Never learn a new trusted key from the downloaded feed itself.
- Run `python -m unittest discover -s tests -v` before changes. OpenSSH and Python 3.12 or later are required; publishing also needs GitHub CLI.
- Run `python scripts/sync_releases.py` to verify the live feed without publication. Output goes to ignored `.sync-output/`.
- Check [workflow runs](https://github.com/deskfleet/connector/actions/workflows/sync-releases.yml) after a failed synchronization. Verification failures leave releases unpublished. Repository maintainers can enable GitHub Actions failure notifications in their own GitHub settings.

This repository publishes release information and verification tooling. It does not publish the private Deskfleet application, its development history or unpublished protocol designs.
