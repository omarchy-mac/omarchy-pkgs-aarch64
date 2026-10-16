# Signed image dependency snapshots

The image candidate desktop and its two video dependencies are built by `build-quattro-image-inputs.yml`. The remaining custom packages can be captured from this repository's published edge inventory and signed as a separate, immutable Actions artifact. This avoids depending on another desktop fork's custom-package snapshot without changing live edge or rebuilding already published archives.

`Retain signed image dependency snapshot` is manual and main-only. Supply the reviewed SHA256 of the published `omarchy-aarch64.db` (identical to `.db.tar.zst`). The no-secret capture job derives its inventory from that exact complete database, including published extras such as `omarchy-steam-fex`. It reuses the existing capture helper to check archive identities, sizes, hashes and database membership, retain origin evidence, and reject a database that changes during capture. `packages.json` is not edited or used to silently drop published extras.

The signing job validates that retained capture and the same selected origin database without network access. It copies all packages except `omarchy`, `omarchy-settings`, `omarchy-mac`, `avd-fw` and `libva-v4l2_request-avd`; those five names belong to the separately authenticated experimental candidate bundle. It signs every copied archive, `origin.db`, and `manifest.json` with the existing approved signing subkey. Package bytes and versions remain unchanged. Signatures authenticate these captured bytes; they do not retroactively establish reproducible builds, source provenance, runtime safety or boot qualification.

Both jobs have only `contents: read`. The workflow creates no release, changes no repository database or channel selector, invokes no publisher, and does not bootstrap trust on clients. It uses `package-signing-edge` solely for the existing signing credentials; that environment name does not cause edge publication. Production secrets are available only to the network-disabled signing step. Existing edge users continue to see the unsigned feed.

Retained outputs last 90 days:

- `image-dependency-capture-<run>-<attempt>`: complete original inventory and capture evidence.
- `signed-image-dependencies-<run>-<attempt>`: selected package archives and detached signatures, original repository database and signature, signed manifest.

An image consumer must pin the manifest checksum, authenticate its signature against the independently pinned public key, verify every archive's hash and signature, and reject candidate-name substitutions or missing/extra packages. It must combine this set with the separately verified five-package candidate and pinned Arch Linux ARM/Asahi inputs, then resolve and test the complete dependency transaction. A successful capture/sign run alone does not establish a complete or bootable image. Do not upload these signatures to live edge as a shortcut: `Optional TrustAll` clients still need the signing public key, and live edge has a separate coordinated trust transition.

## Experimental Limine profile

Local `seal` and `verify` accept `--boot-profile limine` for the coordinated schema-4 candidate. This writes dependency schema 2 with `boot_profile: limine` and `candidate_schema: 4`. Its fixed exclusion set is the complete thirteen-package candidate plus the replaced `omarchy-apple-boot` and `omarchy-first-boot` packages. Capture still freezes every original database member; filtering occurs only after validating the complete capture. Callers cannot supply arbitrary exclusion names.

The default remains schema 1 with the original five exclusions, and the existing workflow still selects that default. A schema-2 snapshot requires explicit profile selection for verification. The image consumer must also match the independently authenticated candidate profile, reject candidate/dependency/platform overlap, and require the separately authenticated ALARM Limine package before enabling assembly. This profile does not select an image build or change installed-system trust.
