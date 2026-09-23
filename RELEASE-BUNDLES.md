# Retained RC and final package bundles

`release-bundle.py` stages and validates complete local repositories and prints read-only publication plans. It deliberately has no remote execution mode. The existing `scripts/publish.sh` remains the rolling edge publisher; never send RC archives to that script. Actual publication, immutable remote snapshot creation, writer exclusion and cross-lane failure recovery require a separately reviewed operation. A successful plan does not mean a release was published.

## Stage and validate

Use a disk-backed output directory with enough space for the complete candidate and rollback inventories. Files are copied with reflinks where supported. Existing bundle output directories are never replaced, and `check` rejects changed, missing or additional files.

```bash
python3 scripts/release-bundle.py stage \
  --base-db /disk/capture/omarchy-aarch64.db.tar.zst \
  --base-packages /disk/capture/packages \
  --candidates /disk/validated-candidate-inputs \
  --source /disk/exact-source-export \
  --source-git /disk/desktop-repository \
  --source-commit FULL_SOURCE_COMMIT \
  --release 4.0.3rc1 \
  --output /disk/bundles/4.0.3rc1-1
python3 scripts/release-bundle.py check /disk/bundles/4.0.3rc1-1
```

The signed-candidate input directory must contain exactly one `omarchy`, `omarchy-settings`, `omarchy-keyring`, `omarchy-mac-keyring`, and `ttf-jetbrains-mono-nerd-basic` archive and the builder's `build-inputs.txt`, plus optional detached signatures. Legacy unsigned bundle inspection can still read the prior four-package candidate set, but sealing requires all five. The recorded source/recipe revisions, source version, clean state and non-custom recipe selection must match the exact source being staged. Source files, symlinks and executable modes are compared to the complete Git tree. Untracked/ignored files and extra directories are rejected; a clean `git status` alone is insufficient. An exact exported tree can use `--source-git` to supply its authoritative Git objects.

The captured database must match every baseline archive's filename, package identity, architecture, size and SHA256. The bundle retains all unrelated baseline packages, replaces the atomic candidate set, and runs real `repo-add` over the full inventory to produce complete `.db` and `.files` databases. `rollback/` retains every original archive, the exact captured selected database and a full files database. `manifest.json` binds those bytes to the source file map, recipe pin, desktop builder/overlay hashes and this publisher tool's hash. External/system dependencies remain a separate transaction-validation gate.

Never rebuild an existing filename with different bytes. For unchanged font/keyring packages, compare the actual source payload to captured archives first, explicitly accounting for excluded build metadata; then supply the captured exact bytes as declared reused candidates. If their source payload changed, bump pkgrel and validate the replacement. The manifest lists reused candidates. Reuse is not established by matching package version alone.

`stage` preserves an unsigned qualification bundle without asserting signer authority. `seal` imports only the protected signing subkey, verifies the pinned primary and subkey fingerprints, signs every package and both database aliases, rebuilds the databases with embedded signatures, and verifies the result using only the pinned public key. It also signs the rollback inventory; unsigned rollback cannot satisfy the strict client policy.

## Publisher readiness (manual, disposable keys only)

After source review and separate execution authorization, select **Tests → Run workflow**, choose the reviewed ref, enable `publisher_readiness`, and leave `retained_rc4_trust` false. The normal self-tests still run. No production signing environment, production secret reference, image push, or release publication is part of this job.

The ARM job builds the existing `.github/publisher.Dockerfile` once, with the pinned `menci/archlinuxarm` linux/arm64 manifest `sha256:d114341f1d343655963104d05554b4df73bae77a0d4c09c47a1b2f69f45886d2`. The pin was verified through Docker Hub's read-only registry API: the response body SHA256 matched the manifest digest and its config blob (`sha256:478a857709a16f54ada4fde5cc2ff3f2f2050aeb46369ba618174d668982e61d`) verified `linux/arm64`. Bootstrap still installs current repository tools; this is not a reproducible-build claim. The job logs the actual image inspect output and records its config ID, source commit, base manifest and recipe/bootstrap hashes in its summary. Both fixture containers run by that exact job-local image ID, not by a mutable tag.

Preparation reuses the existing release-bundle native fixture to generate synthetic package/database inputs and disposable keys, then removes the primary key home. The second container mounts those unsigned inputs and code read-only, with numeric non-root UID/GID, no network, read-only root, dropped capabilities, no-new-privileges, and runner-owned disk-backed scratch/output. It verifies the runtime restrictions and calls the real `package-signing.preflight` with the checked-out public production policy (no production private key). It then uses the unchanged RC4 feeder's private-pipe framing and parser primitives to pass the disposable subkey to mutable buffers in the test-only child, calls `seal`, and independently checks every output signature. Input bytes must remain unchanged and deliberately corrupted output must be rejected.

This is a test fixture, not an RC5 production launcher. It does not bypass or change the RC4 hardcoded repository, inventory, image or provenance contracts. Disposable fixture credentials briefly occupy mode-0600 files on runner disk, are deleted before the child starts, and are neither logged nor uploaded. Child output remains suppressed by the existing feeder. No image archive or signed candidate is retained: the job-local image identity is **not** an immutable cross-job production handoff. Production acquisition, key delivery, retained artifact binding, client trust/install qualification and publication still need their separately approved paths.

Portable checks: `python3 scripts/test-release-bundle.py BundleIsolationTests -v` and `python3 scripts/test-publisher-readiness.py -v` (PyYAML required). The latter checks workflow structure only. Native GnuPG/archive/container readiness is established only by a successful authorized hosted run, not by these local tests or source review.

## Qualification receipt and read-only plans

After the actual tests and review pass, record their report in a JSON receipt. This is an explicit local attestation bound to exact files, not a test runner or cryptographic signer:

```json
{
  "manifest_sha256": "SHA256_OF_MANIFEST_JSON",
  "checks": {
    "source_payload": "pass",
    "package_contract": "pass",
    "fresh_install": "pass",
    "released_upgrade": "pass",
    "review": "pass"
  },
  "report": "qualification-report.md",
  "report_sha256": "SHA256_OF_REPORT"
}
```

The report path is relative to the receipt. Record the actual scope and remaining hardware coverage honestly. Do not fabricate passes to satisfy the planner. For final unsigned 4.0.3, also record `"released_upgrade_from": "4.0.2-2"` and `"hardware_checks": {"m1_reboot_runtime": "pass", "m2_reboot_runtime": "pass"}`. The unsigned publisher requires these fields and a fresh receipt for the final bundle; the report must contain the actual physical observations.

```bash
python3 scripts/release-bundle.py publish \
  --bundle /disk/bundles/4.0.3rc1-1 --validation /disk/rc-validation.json \
  --repo omarchy-mac/omarchy-pkgs-aarch64 --lane rc > /disk/rc-publication-plan.json
```

Plans perform `gh release view` and, when asset digests are unavailable, read-only downloads. Lane release objects must already exist; the planner does not interpret network/API failure as an absent lane or create releases. An empty lane can be bootstrapped by a later approved operation. Existing lanes must match the captured baseline, or already select the exact candidate database. Other states fail before a plan is returned. Partial bootstrap assets are accepted only if their bytes belong to the exact candidate inventory.

The plan requires a complete immutable remote snapshot, including rollback and validation evidence, before lane mutation. It then lists package uploads without `--clobber`, a fresh selected-database check, and database alias uploads with `.db` last, followed by readback. Retain previous package/snapshot bytes; do not run rolling garbage collection against RC/stable. Stop at the first failed upload so no selected database references a missing package. The planner validates ordering and preconditions; it does **not** execute or prove network failure recovery. Snapshot upload/download tooling and the guarded alias executor remain release gates.

## Final version and legacy edge clients

Rebuild `4.0.3` after changing only the source `version` file from the tested RC. Use the same recipe pin, overlay, builder and publisher. Revalidate the actual final archives and obtain a separate receipt. The final package pair must have final metadata and different bytes; renaming RC archives cannot promote them.

Stage one final bundle against stable's current captured inventory and another against the latest captured edge inventory. The edge bundle must use exactly the same four final artifacts and preserve every other current edge application. Capture immediately before the reviewed promotion window, with all writers excluded by the shared `edge-publish` workflow concurrency group or explicitly paused. This reaches existing legacy edge clients without sending them an RC or downgrading unrelated rolling applications.

```bash
python3 scripts/release-bundle.py promote \
  --rc-bundle /disk/bundles/4.0.3rc1-1 --rc-validation /disk/rc-validation.json \
  --bundle /disk/bundles/4.0.3-1-stable --validation /disk/final-stable-validation.json \
  --edge-bundle /disk/bundles/4.0.3-1-edge --edge-validation /disk/final-edge-validation.json \
  --repo omarchy-mac/omarchy-pkgs-aarch64 > /disk/promotion-plan.json
```

Both lane preflights must pass before the planner emits a promotion plan. Cross-lane publication is not atomic. The later executor must retain both prior snapshots and report/recover any partial promotion explicitly. RC publication accepts only `--lane rc`; final edge publication is represented only through the controlled final promotion plan.

Run the offline native archive/database fixtures with `PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-release-bundle.py -v`. They use a `gh` recorder that rejects every remote mutation. These tests establish local repository mechanics and planning guards, not final release qualification or hosted publication reliability.

## Publication policy

A complete unsigned bundle with a fresh qualification receipt can be published to RC or stable through the manual [unsigned release lifecycle](docs/unsigned-release-lifecycle.md). This uses the same immutable snapshot, exact package-byte checks, and database-last selection as the historical RC4 bootstrap. The final edge-first step uses the same retained bundle through `scripts/publish.sh`, which preserves edge-only packages. Stable checks the public edge archive hashes before selecting its database.

The `publish` and `promote` commands in this file remain read-only planners for the optional signed path and still require a sealed bundle. See [SIGNING.md](SIGNING.md) before deliberately enabling required signatures. Do not enable a strict client policy while the lanes remain unsigned.
