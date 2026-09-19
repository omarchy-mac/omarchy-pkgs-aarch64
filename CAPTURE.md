# Frozen RC baseline capture and retained handoff (Phases A2–A3)

`bootstrap-rc.py capture` is a **read-only remote operation**. It retains an
approved baseline and optional partial overlay for local inspection and offline
integrity verification. It does not publish, adopt or delete unreferenced assets.
Use Linux with the existing bootstrap dependencies (`repo-add`, `bsdtar`, etc.),
disk-backed temporary storage and the existing storage reserve. Output must be a
new directory; interrupted output is not reusable as a successful capture.

```sh
python3 scripts/bootstrap-rc.py capture \
  --lane edge --database-sha256 "$APPROVED_EDGE_DB_SHA256" \
  --overlay-lane rc --overlay-database-sha256 "$APPROVED_RC_DB_SHA256" \
  --output /durable/rc4-capture
```

The overlay options are optional and must be supplied together. Both hashes must
be exact lowercase SHA256 values approved independently, not copied blindly from
an error message. Capture verifies public selected DB bytes at the start and
re-reads each selected lane with fresh release metadata before writing its success
manifest. Drift fails closed without `capture-manifest.json`. This detects
before/after drift, not an atomic multi-lane snapshot or all transient changes;
cooperating writers should still be excluded during capture.

## Retained artifact

- `catalog.json`: frozen package catalog used to select this capture. Future
  changes to checkout `packages.json` do not change offline requirements.
- `sources/edge.db` and/or `sources/rc.db`: exact original approved database
  bytes (the compressed DB and public selected alias must have equal hashes).
- `sources/<lane>-build-inputs.txt`: exact known provenance bytes, when present.
  Their hashes identify downloaded bytes, not authenticated build claims.
- `packages/`: one archive per selected package name, with overlay precedence.
  Archive hashes/sizes and package identities are checked against the original
  approved database records. Catalog extras are not imported. The existing
  baseline exception for a missing fork keyring remains; an RC baseline or any
  overlay must supply the installed trust anchor.
- Root database/files aliases: filtered repository rebuilt from selected bytes.
- `capture.json`: compatibility fields plus selected package origins, per-lane
  catalog exclusions and all observed remote asset metadata. `metadata-only`
  observations are **not downloaded-byte verification**, even if GitHub includes
  its own digest in the nested metadata. `downloaded-verified` observations point
  to retained files and locally calculated hashes. Superseded baseline archives,
  excluded packages, signatures and other unretained assets remain metadata-only.
  Known `build-inputs.txt` provenance is retained; unreferenced assets are recorded
  without download, adoption or deletion. Remote observations describe the initial
  listing, not a guarantee that the entire asset list stayed unchanged.
- `capture-manifest.json`: schema 1, SHA256 map of every retained regular file
  except the manifest itself. Capture prints its SHA256 for **external approval**.

## Offline verification

Retain the entire directory and approve/store the emitted digest separately.
Never derive the approval digest from the received artifact in the verification
command; doing so only checks self-consistency, not approved identity.

```sh
python3 scripts/bootstrap-rc.py check-capture \
  --capture /durable/rc4-capture \
  --manifest-sha256 "$EXTERNALLY_APPROVED_CAPTURE_MANIFEST_SHA256"
```

This command never contacts GitHub and does not read current `packages.json`.
It checks the approved manifest digest and schema, safe relative paths, exact file
inventory, hashes, absence of symlinks/special files, source and filtered database
identities, archive contents, frozen catalog, package origins and reconciliation
evidence. Missing, added or changed files fail; directory/file symlinks fail.
An approved capture must be protected against concurrent local mutation while
checking or using it. Empty directories are not artifact files and are not hashed.

## Retained workflow handoff

1. Run the manual `capture-rc-baseline.yml` with the independently approved
   baseline lane/database digest and optional overlay lane/database digest. For
   initial edge-to-partial-RC reconciliation select `overlay_lane=rc`; for a
   complete published RC baseline or final edge conversion select `none`.
   This workflow has only `contents: read`, no signing credentials, no package
   builds and no publication. It retains `rc-baseline-capture-<run-id>-<attempt>`
   and capture logs for 90 days; its summary reports the capture manifest digest.
2. Inspect the retained catalog, source DBs and capture evidence. Approve and
   record `capture-manifest.json` SHA256 externally. A run ID or artifact name
   alone is not approval. Retain a durable copy if needed beyond artifact expiry.
3. Run `prepare-rc-baseline.yml` with `capture_run_id`, exact
   `capture_artifact_name`, operator-supplied `capture_manifest_sha256`, reviewed
   `source_commit`, explicit `pkgrel` and the existing `edge_conversion` choice.
   Downloads are restricted to the same repository. There are no live lane/DB
   inputs, release-asset preflight or recapture in this workflow. Immutable
   filename conflicts against captured bytes remain checked at staging; current
   remote publication conflicts remain the publisher's responsibility.
4. Preparation checks the externally approved capture offline **before package
   builds**, then checks it again at staging. Capture is outside writable build
   directories and mounted separately at `/capture:ro` in verification, build
   and staging containers. Only vendor/build/cache/temp directories are writable
   to the builder; staging uses separate writable output/temp mounts. No Docker
   socket or privileged mode is supplied to package builds.
5. The retained unsigned artifact is still separately reviewed and supplied to
   the existing signing workflow. Its bundle manifest digest is a different
   approval from the capture digest. No signing activation is implied.

For local staging, an external approval is mandatory in both CLI and function
API. Missing, invalid or wrong approval, or changed capture contents, fail before
candidate or output mutation:

```sh
python3 scripts/bootstrap-rc.py stage-input \
  --capture /durable/rc4-capture \
  --capture-manifest-sha256 "$EXTERNALLY_APPROVED_CAPTURE_MANIFEST_SHA256" \
  --built /durable/built --candidates /durable/new-candidates \
  --source /reviewed/desktop --source-commit "$SOURCE_COMMIT" \
  --pkgrel "$PKGREL" --output /durable/new-unsigned-bundle
```

Keep capture immutable throughout local use too: the function cannot stop an
unrelated host process writing concurrently. Do not put capture under a writable
build mount or expose another writable alias of it.

## Derived provenance and compatibility

Frozen bundles retain `provenance/catalog.json`, `capture.json` and
`capture-manifest.json`, plus `capture_manifest_sha256` in their own manifest.
Bundle checking ties those bytes and the baseline DB to the approved capture,
checks the complete retained catalog inventory and rejects incomplete provenance.
Signing preserves the provenance and checks it again. Frozen validation does not
read live `packages.json` or contact GitHub; original source DBs and the full
capture stay in the separately retained capture artifact.

Legacy `release-bundle.stage` callers without capture provenance retain their
existing API and checks; legacy bootstrap validation still requires the current
catalog. This compatibility is not a bypass in `stage-input`, which always needs
external capture approval. Downstream approval of the derived bundle manifest
also binds its capture digest; keep both approval records.

## Hosted inspection-only checkpoint

`inspect-retained-capture.yml` is a deliberately one-capture, manual-only inspector for run `35445613014`, attempt `1`, artifact `10584274342` (`rc-baseline-capture-35445613014-1`). It has only `contents: read` and `actions: read`; there is no signing environment, package build, recapture, publisher, rolling-edge change or build dispatch. Tool-container preparation installs verification utilities, not release packages. All full artifact transfer and inspection run on GitHub-hosted runners. Local tests create only tiny synthetic archives.

The reviewed identity record is `scripts/retained-capture-35445613014.json`. Its database hashes were independently operator-approved. The capture-manifest digest `a1a8cf9bb2b75fd4b76377d229118d2333e7cbf4efa75f9b99422ffa7506fa14` and filtered database digest/count/exclusions are recorded evidence from the successful capture step in [run 35445613014](https://github.com/omarchy-mac/omarchy-pkgs-aarch64/actions/runs/35445613014), NOT operator approval of a build. The catalog hash is the exact `packages.json` at capture checkout `caa0c0fad797722fe7b0819abcb1e6f02e685f15`. The ZIP digest is a separate transport identity and is never used as the capture-manifest approval input.

The fetch stage re-reads exact repository IDs, run/attempt/workflow/commit/status and unexpired artifact ID/name/size/digest, and compares the published log result against the reviewed record. It downloads only that artifact ID, rejects ZIP size/digest mismatches before extraction, rejects unsafe/duplicate/nonregular paths, bounds extraction and reserves disk space. There is no name-based artifact search or live release-package download. Missing/expired evidence is a hard failure, not permission to recapture or substitute another run.

The offline stage receives no token, has `--network none`, and mounts both capture and fetched evidence read-only. It invokes the existing `check_capture` verifier using the previously recorded digest, not a newly computed digest substituted as approval. It independently compares actual source DB hashes against the approved inputs, verifies frozen catalog identity and published capture evidence, and reports the actual manifest digest, full selected inventory with versions/hashes/origins, reconciliation exclusions, observation counts and retained provenance claims. The report is capped at 256 KiB and uploaded alone; no package archives are re-uploaded. Provenance and metadata-only observations remain explicitly qualified rather than asserted as authenticated builds or verified remote bytes.

The unapproved proposal is `source_commit=79b074a8921ae2e195451991eda987445bcae962`, `pkgrel=2`, `edge_conversion=false` (desktop `4.0.3rc4`, recipe pin `19ef4b560ffd6f26df67665400394278065cf437`). This is the merged/tagged RC4 source named by published RC provenance, not RC5 or desktop main. The report checks retained RC provenance corroboration and captured metadata for candidate pair filename conflicts. The existing RC4 `-1` identity must not be rebuilt and overwritten; `-2` is a proposal, not a reservation. Extra-package reuse still requires the existing later functional/trust comparisons. Source selection, manifest approval and preparation authorization remain external.

Deployment is a separate gate: a new manual workflow must exist on the default branch before it is dispatchable. A feature-branch PR and passing fixture CI do not complete that deployment or the full hosted inspection. Do not add automatic triggers, merge, bypass protection or repurpose an existing build workflow to get around this gate. After separately authorized deployment, the bounded inspection command is:

```sh
gh workflow run inspect-retained-capture.yml --repo omarchy-mac/omarchy-pkgs-aarch64 --ref main
```

Inspect the resulting run and its `retained-capture-inspection-<run-id>-<attempt>` report before proposing any next action. This command is inspection-only and cannot approve or dispatch preparation. Future captures require a separately reviewed identity-record change, not unvalidated dispatch inputs.

## Explicit boundaries

Capture approval does not establish signer trust for all packages, runtime
qualification, publication readiness or channel activation. Signing policy,
separate signing/publication workflow and rolling edge publisher are unchanged.
Local real archive/DB/disposable-key tests, workflow contract checks and Linux
read-only mount probes are not hosted Actions execution. Artifact upload/download,
GitHub environment approvals and a full hosted package build remain unexecuted
until a separately authorized workflow run.
