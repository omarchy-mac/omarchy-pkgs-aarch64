# Offline package-signing handoff

This interface never chooses a signer, generates a production key, signs a package, creates a release, or publishes anything. Maintainers must approve who attests the previously unsigned archives and their provenance. The current local snapshots remain unchanged and publication remains gated on authority, final signed-artifact qualification, published upgrades and canary results.

## Trust inputs

Local commands require an explicit binary public verification keyring and a JSON array of approved full uppercase fingerprints. Approval can name a primary key (including its cryptographically bound signing subkeys) or an exact signing-key fingerprint. Every package signer, including preserved upstream/ALARM imports, must be approved; presence in a keyring alone is insufficient. Never derive the approved list from the response ZIP or snapshot manifest.

Workflows read only the separately reviewed, committed `signing/public-keyring.gpg` and `signing/approved-signers.json`. Neither file is supplied by this change. An absent/empty/malformed policy fails closed. Maintainers must keep that trusted public keyring current for revocations/expiry and approve its distribution/rotation; verification does not fetch keys or revocations from the network. No private key or signer token belongs here.

Strict verification uses GnuPG with an isolated temporary home, the explicit public keyring, no default keyring/config or automatic key retrieval/import, and current signature/key validity checks. Expired/revoked/invalid signature statuses fail even when VALIDSIG is also emitted. Explicit approved fingerprints replace owner-trust selection; they do not suppress expiry/revocation checks. Repository/manifest authentication and client mandatory-signature enforcement remain separate policy work; this change does not alter `Optional TrustAll` or sign metadata implicitly.

## Request, external response and immutable import

First verify the exact input snapshot and emit a request for only its unsigned packages:

```bash
python3 scripts/channel-signatures.py request --snapshot unsigned-snapshot --input-manifest-sha256 INPUT_MANIFEST_SHA256 --signature-keyring PUBLIC_KEYRING --output signing-request.json
```

The request records package names, versions, archive filenames/hashes, source/recipe/build inputs and the exact original manifest hash. Review it and retain its SHA256. Supply the request and those unchanged archive bytes to the approved external signer using the maintainer's chosen process. This repository deliberately provides no production signer adapter.

The response directory must contain exactly one binary detached `.sig` file per requested archive, with the archive filename plus `.sig`. Missing/extra files, symlinks and replacement signatures for already signed imports are rejected. Import with independently trusted verification inputs:

```bash
python3 scripts/channel-signatures.py import --snapshot unsigned-snapshot --request signing-request.json --request-sha256 REVIEWED_REQUEST_SHA256 --signatures detached-response --signature-keyring PUBLIC_KEYRING --approved-signers APPROVED_POLICY_JSON --publisher-sha EXACT_ASSEMBLY_GIT_SHA --output signed-snapshot
```

Import verifies every signature and preserves every archive and already accepted imported signature byte. Source/request/trust inputs are rechecked around staging. It generates new repository databases with the exact detached signatures embedded, checks both database aliases and their files inventories, and writes a new manifest. The output path must not exist. The original `desktop_build` provenance remains distinct from the new `publisher_sha`/`signing_assembly` identity, which records input/request hashes and verification policy hashes. Signature addition attests selected archive bytes; it does not manufacture their original build provenance.

The signed manifest has a new identity and needs new qualification. Earlier unsigned-manifest receipts do not qualify it. RC→stable promotion verifies complete approved signing first, then preserves the same archive/signature/database bytes. Edge→RC filters development identities and regenerates databases while retaining original build/signing provenance; the normal manual workflow instead builds a release pair for RC. No promotion re-signs packages.

## Manual signed-artifact publication handoff

After independently qualifying the final signed snapshot, prepare a ZIP containing only its regular files at the ZIP root:

```bash
python3 - <<'PY'
from pathlib import Path
from zipfile import ZipFile
with ZipFile('signed-snapshot.zip', 'x') as archive:
  for path in sorted(Path('signed-snapshot').iterdir()):
    if not path.is_file() or path.is_symlink():
      raise SystemExit('Only regular snapshot files are allowed')
    archive.write(path, path.name)
PY
sha256sum signed-snapshot.zip signed-snapshot/channel-manifest.json
```

A maintainer can place that reviewed ZIP in a staging release **in this same repository**, using their separately authorized publishing access. This implementation performs no upload or release creation. Dispatch `ARM package channels` with `operation=publish-signed`, the channel, `signed_artifact_tag`, exact `signed_artifact_name`, `signed_artifact_sha256`, and the qualified final hash as `source_manifest_sha256`.

The workflow restricts downloads to its own repository, verifies both pinned hashes, rejects duplicate/traversal/nonregular/symlink/directory ZIP entries and extra/missing files, and performs complete approved signature/database verification before channel writes. Trust files come from the workflow checkout, not the ZIP. Publication still requires precreated destination releases and the shared lock; existing differently signed bytes under an immutable filename are rejected before uploads.

The existing build-run publication route also runs the same strict gate, but unsigned builds cannot use it. Automatic edge likewise fails closed on unsigned output and remains incomplete until an approved signing stage plus exact signed-manifest requalification is integrated. These interfaces make the manual external-signing path reviewable without claiming unattended release readiness.

## Offline regression tests

`python3 scripts/test-channel-signatures.py` creates explicitly disposable keys only in short temporary `/tmp` GNUPGHOME directories, cleans their agents and secret files, and never uses a host keyring or publishing credentials. It exercises real detached signatures, approved/unapproved keys and signing subkeys, expired/revoked keys/signatures, omitted signatures/inventory, immutable byte/provenance promotion, tampered archives, database signature mismatches, safe ZIP ingestion and pre-write rejection. Required tools are Python, GnuPG, bsdtar and repo-add; the existing self-test container supplies them. Test signatures are not production trust material and are never emitted into snapshots under review.
