# Package signing and bootstrap

The fork has a separate `omarchy-mac-keyring`; it does not replace upstream
`omarchy-keyring`, Arch Linux ARM or Asahi trust. The reviewed public certificate
and primary/subkey fingerprints are in `pkgbuilds/omarchy-mac-keyring/`.
Only public material belongs in Git. The primary remains offline.

Both publishing jobs use the `package-signing` GitHub Environment. Restrict this
environment to reviewed publishing branches and required approval. Configure:

- Secrets: `PACMAN_SIGNING_SUBKEY_B64`, `PACMAN_SIGNING_PASSPHRASE`.
- Variables: `PACMAN_SIGNING_PRIMARY_FPR`, `PACMAN_SIGNING_SUBKEY_FPR`.

The base64 secret must contain only the protected signing subkey with a dummy
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
It now requires a signed existing baseline: bootstrap that baseline explicitly
before enabling scheduled jobs. Archives and signatures upload before DB assets;
GC keeps signatures for every retained current archive.

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

1. Run **Prepare complete RC baseline artifact** with an approved exact desktop
   source commit, selected baseline lane and its reviewed database SHA256. Select
   `edge` for initial RC4 preparation; select the published `rc` RC4 baseline for
   RC5. RC5 staging rejects an edge capture. It captures every
   baseline archive against that database, builds the five inputs canonically on
   ARM from the source's recipe pin, and compares reused upstream keyring/font
   payloads. An unchanged fork-keyring filename is reused byte-for-byte from the
   captured RC4 baseline after matching its public key, trust fingerprint, empty
   revocation file and functional payload; any changed payload requires an explicit
   version/pkgrel bump. This preserves archive identity when the signed stage adds its detached
   signature. Comparison excludes build-date/comments, `.BUILDINFO`, `.MTREE` and timestamps
   only. File contents, types, links, modes and ownership must agree. It stages
   the complete 52-name `packages.json` inventory and uploads
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

The executable tool is `scripts/bootstrap-rc.py`; the workflow calls its
`capture`, `stage-input`, `prepare` and `publish` subcommands. `publish` is read-only
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
