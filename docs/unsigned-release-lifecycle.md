# Unsigned edge → RC → stable releases

New edge, RC, and stable clients use `SigLevel = Optional TrustAll`. An unsigned package or database is therefore installable; a client already configured to require fork signatures still fails closed. Do not weaken that client's policy automatically. Document a separate opt-in recovery when its owner wants to return to the unsigned lanes. The `omarchy-mac-keyring` package is delivered as an ordinary dependency so clients can acquire the public material before any future signing decision; its presence does not turn on signature enforcement.

The package repository publishes mutable `edge`, `rc`, and `stable` GitHub releases. Pacman clients stay on their existing lane URL. For RC and stable, the publisher prepares a complete immutable snapshot and verifies it publicly before selecting the mutable lane database. All lane publishers upload packages before database aliases and `.db` last. Replacing separate GitHub assets is not atomic: a client may see a transient missing database during a clobber. If any upload or readback fails, stop for operator review, retain both snapshots, inspect the live selection, and retry the **same** retained bytes or perform a reviewed rollback. Never rebuild an interrupted candidate.

The qualified unsigned edge publisher and scheduled rolling publishers retain superseded package archives. Download and retain the qualified publication's `previous-edge.db` evidence artifact before it expires; archive retention alone does not preserve prior database bytes. Archive cleanup requires a separate reviewed policy; scheduled publication does not delete them.

## RC candidate

1. Commit desktop source with `version` set to `X.Y.ZrcN`, review the exact source and recipe pins, and build the complete unsigned bundle with **Prepare complete baseline artifact**. Capture the current RC inventory first with **Retain read-only baseline capture**. The manifest binds the archives, database, source commit, recipe, and builder inputs.
2. Qualify that exact bundle with source payload and package contract checks, a fresh install, a real upgrade from the released version, and review. Retain a separate `qualification.json` plus report bound to the manifest hash. The receipt format is in [RELEASE-BUNDLES.md](../RELEASE-BUNDLES.md).
3. Dispatch **Publish qualified unsigned lane** with `lane=rc`, the bundle artifact/run, qualification artifact/run, exact manifest and source hashes, and the approved current RC `.db` SHA256 (`absent` only for a new RC lane). Review its `dry_run=true` plan. Execute with both acceptance switches only after review.
4. Verify the public RC database, referenced archives, installation, and upgrade. Record the RC bundle and receipt for final lineage checks.

The current edge baseline supplies the exact `omarchy-steam-fex` archive for both RC and stable bundles; the RC producer builds `omarchy-mac-keyring` as a candidate. Qualification must test installation and runtime dependencies for both packages, not merely their presence in the database.

## Final source and qualification

1. Graduate the qualified RC by changing **only** the desktop source `version` file to `X.Y.Z`. Any other source fix needs another RC and qualification. Build new final `omarchy` and `omarchy-settings` archives; RC archives cannot be renamed because the package metadata and bytes change.
2. Stage one complete final unsigned bundle from the exact final source. For the first stable release, use a captured edge baseline filtered to the catalog; later releases can use a captured stable baseline. The rolling edge database may contain additional packages and is not replaced with the stable bundle database.
3. Qualify the **final** bundle separately. For 4.0.3, the receipt must record `released_upgrade_from: "4.0.2-2"` and `hardware_checks` with `m1_reboot_runtime` and `m2_reboot_runtime` both `pass`. The report must describe the real 4.0.2-2 upgrade, fresh install, physical Mac reboot and runtime observations, package contract, source payload, and review. The publisher rejects a missing or stale receipt. Use the qualified RC bundle and receipt to prove that the final source changed only in `version`.

## Edge first, then stable

1. Dispatch **Publish qualified unsigned lane** with `lane=edge`, the **same final bundle and receipt**, and the qualified RC bundle and receipt. Supply the approved current edge `.db` SHA256. Review dry run, then execute. This path stages the five exact candidate archives from the final bundle and calls the existing `scripts/publish.sh` edge publisher under the shared `edge-publish` lock. It keeps other packages already selected by edge; the complete RC and stable bundles also retain `omarchy-steam-fex` from the approved capture. It retains superseded edge assets for reviewed rollback, saves the approved prior and verified final edge databases in the workflow evidence artifact, rejects a signed edge, and does not push a README change to `main`. Download and retain that evidence before its Actions artifact retention expires.
2. Record the new public edge `.db` SHA256 from the publication result. Verify edge clients and both public desktop archive hashes against the final bundle. If edge fails, stop; stable must not select the final version.
3. Dispatch the same workflow with `lane=stable`, the **same final bundle and receipt**, the qualified RC bundle and receipt, the approved current stable `.db` SHA256 (`absent` for the first stable release), and `expected_edge_db` equal to the verified public edge hash. Dry run first. The stable publisher checks that edge's selected database and public `omarchy` and `omarchy-settings` archive bytes still match the final bundle before and after stable selection. It publishes a regular GitHub release, performs complete public readback, then marks stable as GitHub's latest release.
4. Verify public stable installation and upgrade, including the agreed M1 and M2 runtime checks. Publish the separate `vX.Y.Z` desktop source release **last**, after the package lanes and clients pass. The hourly desktop updater may then discover that source release; the edge publisher refuses changed bytes under an unchanged package filename.

The protected manual workflow is available after this branch is reviewed and merged; its `package-signing` environment currently allows the default branch and requires its configured reviewer. This workflow does not import signing credentials. Do not dispatch it from an unreviewed branch. It never pushes a commit to `main`.

### Local dry run

The workflow invokes the same publisher script as a local dry run. A final edge or stable run also needs `--rc-bundle`, `--rc-validation`, `--rc-manifest-sha256`, and `--rc-source-commit`; stable additionally needs `--expected-edge-db`.

```bash
python3 scripts/publish-unsigned-lane.py \
  --bundle /disk/bundles/CANDIDATE \
  --validation /disk/qualification/qualification.json \
  --manifest-sha256 APPROVED_MANIFEST_SHA256 \
  --source-commit EXACT_SOURCE_COMMIT \
  --publisher-commit EXACT_PUBLISHER_COMMIT \
  --expected-db APPROVED_CURRENT_LANE_DB_SHA256_OR_absent \
  --lane rc \
  --accept-unsigned-publication
```

This command is read-only. Add `--execute --accept-mutable-alias-window` only after reviewing the exact plan. A local execution must exclude other writers for its entire duration; the workflow holds the shared lock automatically.
