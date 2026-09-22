# Exact edge-keyring dry-run (nonpublishing)

Use the existing **Tests** workflow (`.github/workflows/test.yml`), manual input
`edge_keyring_dryrun=true`. It is already registered on the default branch; the
reviewed feature branch can therefore be selected with `--ref`, without merging.
The branch must first be reviewed, committed and pushed by the delivery owner.
No commit, push, dispatch or merge is performed by this patch.

After review and authorization, the one hosted invocation is:

```sh
gh workflow run test.yml -R omarchy-mac/omarchy-pkgs-aarch64 \
  --ref edge-keyring-no-build-dryrun \
  -f edge_keyring_dryrun=true \
  -f publisher_readiness=false -f retained_rc4_trust=false
```

Record the resulting run ID and verify its head SHA is the reviewed branch tip.
A rejected dispatch is not permission to merge or retry through another path.
The existing self-test job also runs; the other manual jobs remain disabled.

## Boundaries

- Hosted `ubuntu-24.04-arm` only. Builds the existing publisher **tool image**,
  not repository packages; never starts a local container or VM.
- `contents: read`, `actions: read`; no signing environment or production secrets.
  The ephemeral read-only GitHub token is used only for host-side acquisition and
  recheck, never passed into the native container.
- Shared `edge-publish` concurrency with `cancel-in-progress: false` and
  `queue: max` on this job only. This job will not replace pending work or cancel
  running work: up to 100 jobs may wait; if full, the new dry-run is canceled
  instead of evicting pending work. Other unchanged single-queue writers can still
  cancel this dry-run while it is pending; this is not a global queue-policy change.
  Once running, this job holds the lock during tool preparation and testing,
  briefly delaying edge.
- Fresh complete paginated edge asset metadata is read after acquiring the lock,
  checked again after acquisition and after the native test. A concurrent writer
  outside this lock makes the run fail; this is not publication authorization.
- RC release `390634001`, asset `570814012`, exact archive
  `omarchy-mac-keyring-20260914-2-any.pkg.tar.xz`, 9,740 bytes,
  SHA-256 `8ca587d9c24d36cd2e67237ca69b3eeac1b3726e691228131d6d062d258cdfb7`.
  All three public keyring files must match source
  `fec792c8784a8bfd48d401a6d3c0bff5ec896860`; public certificate SHA-256
  `118b1a5b48a74a2dd993860c4dc3f9d477d5c47c3b1422ea40e8e91f3c7e73d1`.
  This is exact-byte consistency, not independent trust authentication.
- Reject an already indexed/published keyring, strict/signature-marked edge,
  orphan assets, inconsistent aliases, incomplete DB/files inventory or drift.
  No historical edge DB hash/count is silently treated as current.

## What runs

`scripts/edge-keyring-dryrun.py --acquire INPUTS` downloads only the selected
keyring and four small edge DB assets, checks hashes/public payload and retains
ordinary API metadata. The workflow runs this under the shared edge lock.

`--native INPUTS OUTPUT` runs the real `scripts/publish.sh` with `DRY_RUN=1` and
real native `repo-add`, offline, with no credentials. A test-only read adapter
serves the captured release metadata and DB bytes; it rejects every write. No
native tool is mocked. All pre-existing raw description and files records must
remain byte-identical, with exactly one new keyring record. Filename, compressed
size and SHA-256 are reconciled with the complete release inventory; version is
included in the exact preserved descriptions.

A second run starts from that derived snapshot, adds one tiny synthetic unrelated
archive (not a repository package build), and proves all records including the
keyring survive, with no garbage-collection deletion planned. This tests the
normal publisher path, not a live subsequent publication or a client transaction.

`--recheck INPUTS` confirms the live metadata has not changed. Ordinary Actions
artifacts retain the snapshots, logs, report and four derived assets. Only
`output/keyring-result/` contains the proposed keyring-only databases;
`output/next-publication-fixture-result/` contains a synthetic package and must
never be published. Native failure logs are retained with `if: always()`.

The only publisher change is exporting all four generated DB assets (and their
existing signatures in strict mode) through its existing `DB_OUT`. Insertion,
collision checks, upload ordering, signing selection and garbage collection are
unchanged. The complete existing native release suites remain wired into CI.

## Local checks versus remaining gate

Portable tests (no native package manager or container):

```sh
PATH=/opt/homebrew/opt/coreutils/libexec/gnubin:$PATH \
TMPDIR=/Users/naeem/.hermes/cache/scratch \
PYTHONDONTWRITEBYTECODE=1 \
/Users/naeem/.hermes/hermes-agent/venv/bin/python \
  scripts/test-edge-keyring-dryrun.py -v
```

These cover guards, transport rejection, pagination, full-record comparison,
inventory reconciliation and invocation contracts. They do **not** establish
native preservation. That remaining gate is the single reviewed hosted run above.
Passing it still does not authorize release writes, policy conversion, signing,
client mutation or any merge.
