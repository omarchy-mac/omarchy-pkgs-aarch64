# Quattro image input candidates

`Build quattro image inputs` builds `omarchy`, `omarchy-settings`, and `omarchy-mac` from one recorded commit of `omacom/omarchy-mac`. Its purpose is to provide the first inputs for a development Apple Silicon image built with the shared desktop branch.

## Delivery boundary

This workflow runs only through `workflow_dispatch`. Its token has `contents: read`, checkout credentials are not retained, and the job has no signing secrets or publishing environment. It uploads unsigned Actions artifacts for 30 days. It does not create a GitHub release, run `repo-add`, update a pacman database, install packages, or register a package in `packages.json`. The existing hourly release jobs do not call it or consume its artifacts. Ordinary Omarchy Mac updates therefore cannot pick up these candidates through this workflow.

Artifacts in this public repository are downloadable; they are development inputs, not a private distribution channel. A future signed development snapshot or installer catalog needs a separate reviewed change. Do not upload these packages to `edge`, RC, or stable while testing the image path.

## Run a build

After the workflow is merged into the default branch, select **Actions → Build quattro image inputs → Run workflow**. Leave `source_ref` as `quattro-upstream`, or supply a full commit SHA to reproduce a selected source. The checkout resolves the ref once, and all three packages record that exact commit.

The native ARM runner uses an Arch Linux ARM container resolved to an image digest. `makepkg` and the source tests run as an ordinary user. Desktop recipes come from the commit in `scripts/quattro-image-inputs-recipes-revision`, with this repository's existing `omarchy-first-run-packages.patch` applied through its checked preparation helper. This carries the ARM Snapper dependency and keyboard backlight unit while retaining newer upstream packaged defaults. The desktop aggregate tests also read upstream ISO source, pinned in `scripts/quattro-image-inputs-iso-revision`; this is a test dependency, not an Apple image build. The add-on recipe comes from this package repository's recorded commit. Only temporary recipes have their source and candidate versions changed. The generated recipes and compatibility patch are retained with the artifacts.

The desktop pair shares `<source version>.quattro.r<source timestamp>.g<short SHA>` and a run-specific package release. The add-on retains `packages/omarchy-mac/version`, with a run-specific package release. These versions identify candidates; they do not define a future public release version or upgrade policy. Never promote a candidate merely because its version sorts above another package.

Successful builds retain one `quattro-image-inputs-<run ID>-<attempt>` artifact containing all three package archives, `manifest.json`, `SHA256SUMS`, `ownership.json`, generated recipes and `.SRCINFO`, source package manifests, and test/build logs. The packages include their normal `.BUILDINFO` plus the recorded source revision. Failed runs retain diagnostic logs, but never a complete candidate artifact.

For an equivalent local build on native aarch64, use clean, committed package tooling and existing Git checkouts containing the selected desktop commit and recipe pin:

```bash
python3 scripts/build-quattro-image-inputs.py \
  /path/to/desktop FULL_DESKTOP_COMMIT \
  /path/to/omarchy-pkgs /path/to/omarchy-iso /absolute/new/output 1 1
```

Build tools must already be installed (`base-devel`, Git, Python, jq, Node.js, ImageMagick, systemd, and the utilities used by the source tests). The script never installs missing dependencies on the host. Use a fresh output directory and a distinct run ID for another local candidate.

## What a successful build proves

The desktop aggregate suite and standalone add-on suite pass. All packages record the same source commit, the desktop pair's dependency/version relationship matches, transferred microphone and Wi-Fi files belong only to the add-on, and no package payloads overlap. The add-on remains kernel-neutral and does not own administrator configuration under `/etc` or `/boot`.

This is not yet a complete image dependency snapshot or a boot qualification. `makepkg --nodeps` avoids installing the desktop into the build environment; runtime dependency resolution, actual installation hooks, system/user provisioning, signed repository selection, and physical boot are explicitly marked untested in the manifest. The next image-builder change must resolve the full base and Apple manifests against recorded dependency inputs, install all three candidates before hardware setup, and exercise the existing installer end to end. Temporary live staging and encrypted-copy experiments remain separate work.
