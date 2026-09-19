# Package signing and bootstrap

The fork has a separate `omarchy-mac-keyring`; it does not replace upstream
`omarchy-keyring`, Arch Linux ARM or Asahi trust. The reviewed public certificate
and primary/subkey fingerprints are in `pkgbuilds/omarchy-mac-keyring/`.
Only public material belongs in Git. Keep the primary offline before production
use; the generated candidate still requires custody transfer from its restricted
owner-host staging location.

The client keyring contains only the new primary
`FBD6874D423C418DDB6D143EECE19CDDE306DBD2`. The active publisher signer remains
subkey `D791ED0C72439D9F8757421258043B2770A25762` under that primary.
`trusted_primary_fingerprints` contains exactly this primary; the public-key
digest binds the shipped keyring. The previous public certificate is no longer
shipped and remains recoverable from Git history. No revocations are introduced.
This is a pre-activation candidate; it does not implement conversion of an
already old-signed feed. Both repositories must ship identical public keyring
and trusted-list bytes before RC4 is tagged.

The non-publishing credential validator checks the workflow commit itself
(`${{ github.sha }}`), so merged helper changes cannot silently leave it testing
an earlier publisher. It remains main-only and uses both signing environments.

Configure two separate GitHub Environments (YAML does not configure these):

- `package-signing-edge`: deployment branch `main` only, **no required reviewer**.
  Scheduled rolling updates must remain unattended. Only the publishing job
  receives its secrets; build jobs and no-op runs do not enter this environment.
- `package-signing`: reviewed publishing branches and required approval for
  manual RC publication, artifact production and rare full edge conversion.

Both signing environments stage the replacement in new secrets
`PACMAN_SIGNING_SUBKEY_B64_20260914` and `PACMAN_SIGNING_PASSPHRASE_20260914`,
and new variables `PACMAN_SIGNING_PRIMARY_FPR_20260914` and
`PACMAN_SIGNING_SUBKEY_FPR_20260914`. Workflows map these to the unchanged
`PACMAN_SIGNING_*` process interface. Preserve the previous unsuffixed entries;
no overwrite or deletion is required. Populate all four replacement entries in
both environments before enabling the new workflow revision. The read-only
producer receives neither secret.

ASCII whitespace and line wrapping are removed from the base64 input before
strict decoding. One trailing LF or CRLF is removed from the passphrase; internal
newlines and empty values are rejected, while significant spaces are preserved.
Malformed base64 was already rejected through `ValueError`; normalization adds
copy/paste compatibility without relaxing decoded key checks.

The decoded secret must contain only the protected signing subkey with a dummy
primary. The helper refuses a usable primary, additional usable secret subkeys,
missing credentials, mismatched public-key hashes/fingerprints, and expired,
revoked or wrong-signer signatures. Its private GnuPG directory is ephemeral,
mode 700, disk-backed and isolated from the user's keyring. Credentials are not
passed as command arguments. Signing tools are installed in a separate image
build before credentials become available; package builds never receive them.
Actions references are pinned. Environment restrictions remain an external
configuration requirement; repository YAML alone cannot enforce approval.

## Two-stage trust transition

First deliver the public bootstrap material through the separately reviewed
exact source/key fingerprint. The unsigned 4.0.3rc4 candidate is the explicitly
disclosed final use of the existing `Optional TrustAll` fork policy. It installs
and populates `omarchy-mac-keyring` without fetching a key from a keyserver.
A package signed only by its own unknown key cannot bootstrap trust itself.
The no-email UID is supported through the checked-in public certificate,
without relying on keyserver UID publication.

Then build the source with the fork keyring dependency and stage all five
candidate inputs: matching omarchy/settings, upstream keyring/font and the new
fork keyring. The initial inventory contains 52 packages: the previous 51 plus
`omarchy-mac-keyring`. Every retained archive must come from the reviewed captured
hash inventory. Reuse package bytes; signing adds detached artifacts.

`release-bundle.py stage` retains the unsigned qualification artifact.
`release-bundle.py seal --bundle UNSIGNED --output NEW_SIGNED` derives a new
signed bundle, signs every selected and rollback archive, rebuilds the databases
with embedded package signatures, signs all four database aliases, and performs
independent public-only verification. The default public certificate and policy
are in-tree; `--public-key` and `--trust-policy` exist for explicit fixture or
reviewed rotation inputs. The original captured rollback DB remains hash-bound
under provenance; the operational rollback DB is rebuilt and signed. No unsigned
rollback or unsigned publication fallback is allowed. Obtain a new validation
receipt bound to the signed manifest; the unsigned receipt cannot be reused.

The strict policy is `PackageRequired DatabaseRequired TrustedOnly`.
`check` retains legacy unsigned-bundle integrity inspection, but `publish`
refuses an unsigned bundle. Published package/signature filenames are immutable;
identical retries reuse verified existing signature bytes.

## Activation and automated edge updates

The default bundle publication command is still a read-only plan. It prepares
an immutable snapshot URL and requires full public readback before authenticated
client Server activation. It does not execute GitHub writes or invent a mutable
selector implementation. If a client cannot activate that exact reviewed URL,
stop; desktop integration is a separate requirement.

`--mutable-alias` explicitly opts into a compatibility plan. GitHub cannot replace
`.db` and `.db.sig` in one transaction, so a short fail-closed mismatch is possible.
Retain the matched prior signed snapshot and use exact retries/readback. Do not
claim atomic database/signature replacement. Automated legacy edge publishing
retains this compatibility behavior and the shared `edge-publish` writer lock.
Before conversion, an entirely unsigned approved edge database selects the
legacy unsigned publisher and requires no signer. A signing marker, any detached
signature asset, or embedded package signature permanently selects strict
verification. Missing or invalid signatures then stop the job; there is no
unsigned fallback. Updating PR/main code alone does not convert edge. No-op
detection still skips publication; previously it was update runs that would
have waited for review or failed on the unsigned baseline.

First run **Prepare complete baseline artifact** with `edge_conversion=true`,
an exact final source commit and the approved edge DB hash. Its no-secret build
compares functional payloads for all five rebuilt inputs and reuses the exact
published archives; changed package identity/payload fails. This emits the
complete input artifact consumed by conversion.

For an RC rebuild, provide an explicit positive `pkgrel` workflow input. The
producer passes it through as `OMARCHY_PKGREL`, verifies the rebuilt `omarchy`
and `omarchy-settings` identities, and preflights the target lane before the
large artifact build. Never overwrite an existing filename with different
bytes; choose a new package release number instead.

When the target RC release is only a partial inventory, prepare from the
complete edge baseline with the approved RC database hash as an overlay. The
producer preserves exact bytes for every package already present in RC and
records both baseline hashes; a transition must never use edge bytes for an
existing RC filename.

The manual **Convert approved edge inventory to signing** workflow uses
`package-signing` and the shared `edge-publish` writer lock. It requires a retained
complete **final stable** bundle matching every archive/version/hash in the
approved currently published edge database. RC bundles are refused. The approved
baseline must already include the exact fork keyring (public certificate, trusted
fingerprint and empty initial revoked file), and the operator must explicitly
confirm that clients completed trust bootstrap. Package presence alone does not
prove that clients trust it. If no exact matching retained bundle exists, stop
and prepare/review one; rebuilding different bytes under the same filename is
not an acceptable conversion input.

The workflow defaults to dry-run, seals and independently verifies the bundle,
and retains its exact signed artifact before any mutation. Publication first
creates and publicly verifies the immutable signed snapshot, then adds permanent
`edge-signing.json` before any edge signature or database change. All package
bytes remain unchanged. A partial conversion leaves strict mode selected and
requires retry with that exact retained signed artifact and original approved DB
hash. The marker must never be removed to regain unsigned publishing. Database
aliases/signatures still have a transient fail-closed selection window. Converted
edge resumes unattended signed updates; GC preserves current archive signatures.
An interrupted rolling archive upload can regenerate only a missing signature
for hash-identical bytes, reuse an existing valid signature, and reject collisions.
For an unchanged filename, the three desktop-owned extras may reuse the exact
published archive after functional comparison; the fork keyring must additionally
match the approved certificate/trust/revocation payload. Changed functional data
still requires a version/pkgrel bump. Incoming build artifacts remain unchanged;
workflow smoke uses the normalized actual published archives under
`DB_OUT/smoke-packages`.
Later rolling database/signature interruption may require manual recovery of a
matching signed database; do not treat arbitrary failures as a downgrade signal.

Smoke checks still resolve the whole database and use HEAD requests for every
package URL. Publisher jobs reuse their hash-matched changed archives for native
verification; standalone checks fetch the smallest package. Set `SMOKE_FULL=1`
for an explicit complete download, or `SMOKE_PACKAGES=name,...` for a subset.

Rotation/revocation requires reviewed keyring/public-policy updates and a newly
verified signed inventory. Current verification intentionally authorizes one
exact active primary/subkey pair, so do not rotate environment fingerprints
alone. Tests use disposable fixture keys and isolated pacman trust; they never
establish production secret custody or GitHub environment configuration.

## Manual initial RC bootstrap

The manual producer and both publication workflows do not run on push, PR or schedule.
GitHub requires their workflow files to be present on the default branch before
manual dispatch is available ([GitHub documentation](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)).
A PR branch push alone does not activate them; default-branch deployment remains
a separately authorized step. All use the protected `package-signing` Environment. The producer has read-only
repository permission and receives no signing secret:

1. First run **Retain read-only baseline capture** with the selected baseline lane
   and reviewed database SHA256, plus an optional approved partial overlay.
   Select `edge` with an `rc` overlay for initial RC4 reconciliation; select the
   published `rc` RC4 baseline without overlay for RC5. Review the retained capture
   and separately approve its manifest SHA256. Then run **Prepare complete baseline
   artifact** with that same-repository capture run ID/name, externally approved
   capture manifest digest, exact desktop source commit and explicit pkgrel.
   See [CAPTURE.md](CAPTURE.md) for the handoff and read-only mount contract.
   Capture is a separate manual read-only workflow with no signing Environment;
   preparation retains its existing protected Environment. Preparation does not
   recapture or consult live lanes. It verifies before building and again at staging;
   RC5 staging rejects an edge capture. It builds the five inputs canonically on
   ARM from the source's recipe pin, and compares reused upstream keyring/font
   payloads. An unchanged fork-keyring filename is reused byte-for-byte from the
   captured RC4 baseline after matching its public key, trust fingerprint, empty
   revocation file and functional payload; any changed payload requires an explicit
   version/pkgrel bump. This preserves archive identity when the signed stage adds its detached
   signature. Comparison uses `bsdtar` for compression portability and excludes only
   build-date/packager/comments, `.BUILDINFO`, `.MTREE` and timestamps. File contents, types, links, modes and ownership must agree. It stages
   the complete retained `catalog.json` inventory and uploads
   `unsigned-rc-baseline-RUN-ATTEMPT` plus logs containing the manifest digest.
   A changed baseline, missing package or functional reuse mismatch stops it.
   This proves build/capture/integrity, not runtime qualification; review and test
   the actual resulting package artifacts before approving their manifest.
2. For the final old-trust bridge only, use **Final old-trust RC4 publication**
   (`scripts/publish-rc4-transition.py`) with the prepared unsigned RC4 artifact.
   Its exact 52-package inventory must include the unsigned fork keyring, with
   the approved public key/fingerprint and present empty revocation file, so
   existing 4.0.2 clients can acquire the new trust anchor. Both dry-run and execute
   require explicit final-old-trust acceptance; execute also requires alias-window
   acceptance. RC5, strict manifests, detached or embedded candidate signatures, signed current DBs
   and newer current pair versions are rejected. This workflow receives no signing
   secrets, never targets edge/stable, and uses a distinct `rc4-old-trust-*`
   immutable snapshot with complete readback before RC selection. Existing-client
   installation and trust verification is a separate required gate: this tool
   does not assert or perform client migration. Never use this path after strict
   signing activation; it is not an unsigned rollback or fallback facility.
3. After the existing-client trust gate passes, prepare and qualify RC5 using the
   captured RC4 baseline, then run **Bootstrap signed RC baseline** with that
   RC5 artifact run ID/name, approved manifest/source hashes and current RC DB hash
   (or `absent`). Start with the default dry-run. It seals and checks the entire
   candidate and rollback inventory, retaining `signed-rc-baseline-RUN-ATTEMPT`
   before any network mutation. A subsequent execute requires the protected
   Environment approval and explicit mutable-alias-window acceptance.

The executable tool is `scripts/bootstrap-rc.py`; the separate workflows call its
`capture`, `check-capture`, `stage-input`, `prepare` and `publish` subcommands. `publish` is read-only
unless `--execute --accept-mutable-alias-window` are both present, and its only
allowed destination is `rc` in this repository. It cannot publish edge/stable.

Execution first creates/verifies a complete immutable prerelease snapshot,
including the signed bundle's rollback/provenance and the approved previous RC
DB when present. It resolves actual Git tag commits, refuses mismatched orphan
tags, and creates an exact non-force publisher tag before creating a draft. It verifies public snapshot bytes before touching RC. It then
uploads and reads back all package/signature assets before replacing DB/signature
aliases. A new RC release remains a draft until complete readback. Both releases
are prereleases and never become `latest`. Existing archives/signatures are never
clobbered. Superseded names are allowed only when referenced by the exact approved
previous DB; they remain until complete new public readback, then are removed.
Unexpected administrator assets, changed archives, API failures and mismatched
readbacks stop the operation. The previous DB retained in the immutable snapshot
allows cleanup authorization to be reconstructed after interruption.

For an interrupted execution, reuse the exact **signed** artifact, its manifest
hash, the same publisher commit and original expected RC DB value. Do not reseal:
new signature timestamps/DB bytes would collide with already uploaded assets.
The tool accepts either the approved old selection or the exact target selection
while resuming. If clobbering the final `.db` was interrupted after deletion,
it resumes only with the complete verified public snapshot, approved previous DB,
all exact candidate package/signature assets and the exact target `.db.sig`. Any
other missing-selection state requires operator review. It does not guess that
an API error means an absent release.
If failure occurs after RC became public, leave the signed snapshot/artifact and
logs intact and retry those exact bytes. A changed external selection requires
operator review rather than an automatic rollback. The canonical signed bundle
contains a verified rollback dataset; activating rollback remains a separate
reviewed operation. The mutable `.db`/`.sig` mismatch window is explicitly accepted,
not described as atomic. All other writers must honor the shared `edge-publish`
concurrency group or be excluded for this operation.

No real workflow execution or release publication is performed by the test suite.

## Temporary storage and producer exclusion

`publish.sh` and `smoke-test.sh` explicitly validate `TMPDIR` with `findmnt`,
export `TMP`/`TEMP` to the same disk-backed location, and reject tmpfs/ramfs.
If unset, the default is
`$XDG_CACHE_HOME/omarchy-publisher/tmp` (or `$HOME/.cache/...`). Workflows verify
runner storage; tests bind a verified disk directory to short paths for GnuPG
sockets. Remove only task-owned scratch after evidence is retained.

Sourcing `common.sh` does not select temporary storage. Build, detection, and
self-test scripts retain normal `mktemp` behavior; set a verified disk-backed
`TMPDIR` (and matching `TMP`/`TEMP`) when running them locally. For root-run
builds, that path must also be traversable by the unprivileged `builder` user.

The artifact producer has its own non-cancelling `rc-baseline-producer` lock.
It does not hold the live writer lock while awaiting approval or compiling;
exact captured database hashes and publication preflight detect baseline drift.
The two rolling publishers and every alias-changing manual workflow share
`edge-publish`, also without cancellation.

## Signing subkey rotation runbook

The current signing subkey expires **2027-09-14T12:50:13Z**. Begin a reviewed
rotation well before that instant:

1. Verify expiry/fingerprints from the public certificate and retain the current
   signed inventory, keyring and policy. Keep the primary offline.
2. On the offline owner-controlled system, add the replacement signing subkey,
   export only the protected subkey with a dummy primary, and prepare updated
   public certificate/keyring with a new version/pkgrel. Never put secret material
   in Git, logs, command-line arguments or RAM-backed temporary files.
3. Deliver the new public keyring while the old trusted signer is still valid.
   Require evidence that target clients received the new trust before changing
   the publisher signer. Preserve overlap and recovery access; revoke a compromised
   signer through the reviewed public revocation/keyring delivery process.
4. Review a migration supporting the overlap/complete signed inventory and
   immutable signature filenames before changing Environment fingerprints.
   Current verification allows one exact active primary/subkey pair; simply
   rotating variables would reject the old baseline. The initial edge conversion
   is deliberately **not** a general rotation implementation and must not overwrite
   an existing signature with different bytes.
5. Independently verify the new signed inventory and client acceptance, then
   retire the old signer through the reviewed migration. If a gate fails, stop
   and retain the last valid matched inventory; never disable verification.

These are operator gates, not evidence that rotation or Environment configuration
has already been performed. Production signing and client bootstrap remain
separately authorized operations.
