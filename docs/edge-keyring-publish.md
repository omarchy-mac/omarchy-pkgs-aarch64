# Exact retained edge keyring bootstrap publication

This is a single-use, unsigned bootstrap transport, not the normal incremental
publisher. It never invokes `publish.sh`, `repo-add`, a builder, signer, GC,
RC/stable publisher, or client tooling. It consumes only the selected successful
experiment's retained bytes. The existing rolling publishers are unchanged.

## Bound input

- Repository: `omarchy-mac/omarchy-pkgs-aarch64` (`1327386148`).
- Dry-run: `35714377495`, attempt `1`, successful manual `.github/workflows/test.yml`.
- Producer checkout: `f3f17d7e952c8c99d5a1d87dbe39b9f477cda94d`.
- Artifact: `10689146736`, `edge-keyring-dryrun-35714377495-1`.
- ZIP: 2366438 bytes, SHA-256
  `30a59068366d011fe085dfdb96861596cc6929bec1fff4d29a6fb9960317c8f7`.
- Target edge release: `367100318`; complete baseline is the pinned artifact's
  `inputs/edge-assets.json` (58 assets, 54 package records).
- The helper pins before/after DB/files hashes and sizes and the exact 9740-byte
  keyring package hash. It reuses the dry-run helper's complete DB/files inventory
  and raw-record preservation checks. No command-line identity overrides exist.
- Only fixed allowlisted ZIP members are extracted. Nothing from
  `next-publication-fixture-result` is extracted or published.

## Execution and protection requirements

Implementation alone does **not** authorize commit, push, dispatch or publication.
The operator must first review this complete patch, freeze its new execution SHA,
and obtain the separately required execution/protection decision. The producer
SHA above is not the new execution SHA.

The existing `test.yml` workflow has an opt-in `edge-keyring-publish` job. Only
that job requests `contents: write`; the workflow default is `contents: read`.
It uses the existing `package-signing-edge` environment and the shared
`edge-publish` concurrency group with `queue: max`, `cancel-in-progress: false`.
It holds the job lock during acquisition, validation, both pre-write snapshots,
all mutations and postflight reads. This can delay ordinary edge publishers.
Other writers must honor that same lock; it cannot exclude manual outside writers.

Read-only inspection during preparation found that `package-signing-edge`
permits **only the `main` branch** (custom branch policy ID `59893893`), and has
no required-reviewer rule. The feature branch therefore cannot execute this job
under the current gate. Do not remove the environment, use an administrator
bypass, silently change its branch policy, or merge to main as a workaround.
A separately approved protection/deployment decision is required. The patch does
not change environment settings or claim that an approval button exists.

After that decision, verify that the selected named dispatch ref resolves to the
exact final reviewed execution commit, then dispatch the already registered
`test.yml` with these explicit inputs:

```text
edge_keyring_publish=true
edge_keyring_publish_sha=<full final reviewed execution commit SHA>
edge_keyring_dryrun=false
publisher_readiness=false
retained_rc4_trust=false
```

The helper requires hosted Actions, the exact repository name and numeric ID,
`workflow_dispatch`, run attempt 1, and equality of the reviewed SHA, `GITHUB_SHA`
and checked-out `HEAD`. It rejects reruns. Contradictory opt-in flags skip the
publication job and all other jobs; inspect the exact run/job rather than treating
a skipped workflow as a publication. No production signing secret is referenced.
Hosted Ubuntu must provide `python3`, `gh`, `git`, and `zstd`; the job checks them
before acquisition. It creates no runtime/tool image and performs no builds.
The pinned artifact must remain unexpired and downloadable. There is no fallback
to another run/artifact, reconstruction or regeneration if it is unavailable.

## Mutations and verification

After validation, the helper takes a fresh complete paginated edge inventory,
checks the release ID and exact baseline identities, downloads and hash-checks
all four live baseline aliases, then repeats the complete inventory/release check
immediately before the first write. Any drift aborts with zero writes.

Mutation order is fixed:

1. Add `omarchy-mac-keyring-20260914-2-any.pkg.tar.xz`.
2. Replace `omarchy-aarch64.files.tar.zst`.
3. Replace `omarchy-aarch64.files`.
4. Replace `omarchy-aarch64.db.tar.zst`.
5. Replace `omarchy-aarch64.db` last.

GitHub replacement is **not atomic**: each of the four approved database assets
is deleted by its captured immutable asset ID, then uploaded under the same name.
This is the transient deletion inherent in clobbering, not package deletion or
orphan GC. Clients can encounter temporarily missing/mixed aliases. The keyring
package is uploaded first; no existing package is deleted or overwritten.

Every upload response must bind the exact name/size/hash. Postflight requires the
complete API inventory (all unchanged original identities plus exactly five
uploaded identities), unauthenticated public byte-for-byte readback of all five
assets, and another complete API/release snapshot. Expected final inventory is
59 assets / 55 package records. Successful verification is retained as
`verified-edge-assets.json` in the run's evidence artifact.

Any exception once writes start reports **PARTIAL PUBLICATION POSSIBLE** and
stops. There is no automatic rollback, retry, resume, GC, or second dispatch.
A network failure can occur after a server-side write, and job cancellation or
timeout can prevent a final message. Treat either as uncertain partial state;
inspect the complete live inventory and exact bytes and obtain a new bounded
recovery authorization. Artifact-upload failure also does not mean publication
failed. Never rerun this job to infer or repair its outcome.

## Offline checks

```sh
python3 scripts/test-edge-keyring-publish.py -v
python3 scripts/test-edge-keyring-dryrun.py -v
```

To additionally verify the retained tiny DB/keyring archives and run the real
selected bytes through the synthetic transport, set `EDGE_BOOTSTRAP_TEST_EVIDENCE`
to the previously downloaded experiment directory. This test-only environment
variable is not consumed by the production helper. The tests compare all input
file bytes before/after, and never make live API writes. Synthetic transport
success is not hosted execution, authenticated client trust, signing activation
or client-update qualification.
