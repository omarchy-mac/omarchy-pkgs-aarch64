# Frozen RC baseline capture (Phase A2)

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

## Explicit boundaries

This is a usable retained capture and offline verifier, **not a locked end-to-end
release pipeline**. Workflow artifact handoff, mandatory approved-manifest
consumption by `stage-input`, and downstream live-catalog validation changes are
later phases. Existing stage compatibility is retained; running `stage-input`
alone does not enforce this new external approval. Capture does not establish
signer trust for all packages, runtime qualification, publication readiness or
channel activation. No edge publisher, signing policy or workflow is changed.
