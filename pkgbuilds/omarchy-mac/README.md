# omarchy-mac candidate

The independent source lives at `packages/omarchy-mac/` in `omacom/omarchy-mac`. `PKGBUILD` pins collaboration commit `20b8ae0fb6e2593172226f9f8cf0bb79e666d2aa` and packages only that directory. It supplies no kernel, installer, replacement settings package or trust configuration. Nothing here registers the add-on with the rolling updater.

Run `makepkg --nosign` in this directory. `prepare()` copies the add-on away from the surrounding desktop tree before running tests or staging it. The artifact records its source revision and attribution.

## Automatic candidate builds (temporary)

The existing hourly `update-omarchy-mac.yml` workflow calls `build-mac-addon-candidate.yml` as an independent job. It polls `omacom/omarchy-mac:quattro-upstream`, resolves its head to a full commit, and builds when that source or the relevant recipe/build inputs differ from a retained successful main-branch build. Failed/cancelled jobs remain retryable; expired artifacts trigger a rebuild. PR and fork artifacts cannot suppress the trusted hourly build. This starts when the workflow change is merged into this repository's `main` branch.

PRs changing the recipe or candidate builder run the same ARM build for verification. Builds use the checked-in recipe at a recorded recipe commit, with the source SHA and source version substituted into a temporary PKGBUILD. The reviewed release pin is not rewritten. The generated `pkgrel` is `<recipe pkgrel>.<GitHub run ID><four-digit attempt>` so candidate archives are distinguishable. For later release publication, preserve the selected artifact's version or choose a version that supersedes any distributed candidate, for example `0.1.0-5` after `0.1.0-4.<run><attempt>`.

Each successful run retains the unsigned package, generated PKGBUILD and `.SRCINFO`, standalone test/build log, `.BUILDINFO`, image digest, source/recipe revisions and checksums as Actions artifacts for 30 days. No candidate is installed or published to the repository database. The generic ARM build image runs the standalone tests as an unprivileged user, but does not resolve Omarchy's runtime dependencies or perform physical qualification. Installer delivery, the initial ownership transition and signed publication still follow the release process below.

## Release workflow

Develop the add-on on the shared desktop branch, but release it independently. A desktop commit does not automatically become a package release. The source pin identifies what was reviewed and tested; it does not pin the build environment or dependencies by itself.

1. **Select the add-on release.** When releasing changed add-on behavior, update `packages/omarchy-mac/version` in the source repository. Use a namespaced tag such as `omarchy-mac-v0.1.0` to label the chosen source commit, separate from desktop release tags. Retain release commits and never move a published tag. Tag creation is a release-maintainer step; this recipe does not create tags or GitHub releases.
2. **Propose the recipe update.** Set `_commit` to that full commit SHA and `pkgver` to the source version. Reset `pkgrel` to `1` only when `pkgver` increases; increment it for a packaging-only release or rebuild of the same source version. Never replace a published artifact with different contents under the same package version/release. Regenerate `.SRCINFO` with `makepkg --printsrcinfo > .SRCINFO` in the recipe directory and submit the changes together in a PR.
3. **Build and validate the candidate.** Run the independent package tests, inspect the staged payload and runtime dependencies, and record the source/recipe revisions, build inputs and artifact checksums. When changing a desktop interface or file owner, build the compatible runtime/settings packages and exercise the complete upgrade, repeated setup and rollback. Hardware-affecting changes need the relevant physical checks.
4. **Approve publication separately from source integration.** Select the signed delivery path and retain the validated artifacts and recovery set. For the first release, publish the compatible runtime/settings/add-on set before installer inputs or existing-user migrations require it. Include `omarchy-steam-fex` in transitions from runtimes that still own its launcher. An add-on-only install against the old file owners must remain a clean rejection, not an overwrite workaround.
5. **Allow independent updates after the ownership transition.** Later add-on fixes can ship on their own when desktop interfaces and dependencies remain compatible. Interface, dependency or ownership changes require a coordinated release again. Testers receive repository packages; they do not need to follow the source branch or maintain a dev link.

The current `0.1.0-4` candidate deliberately retains `20b8ae0f`, the source used for its build and physical trial. The cleaned shared history has identical add-on contents. Do not advance the pin merely to match a newer desktop head. If `0.1.0-4` is selected for first publication, keep that release number; do not reset it to `0.1.0-1`. Changes elsewhere in the desktop repository, or documentation-only recipe edits, do not require rebuilding the add-on.

## How publication fits this repository

After the first coordinated delivery is qualified, register the add-on as a local recipe in `packages.json` in a separate publication change. The general updater reads local `pkgver`/`pkgrel` and compares them with the repository database. Once registered, merging a version bump makes it eligible for a scheduled build/publication, so that recipe PR must carry the release validation and approval. The existing dry-run mode can exercise the build without publishing; a successful dry run does not itself promote its artifacts or qualify the coordinated ownership transition.

Despite its name, the publishing part of `update-omarchy-mac.yml` handles the fork's desktop runtime/settings pair. Its new independent add-on job only builds candidate artifacts. Do not feed add-on tags into its desktop release detection. Future automation could open recipe PRs when namespaced add-on tags appear; it should resolve a tag to an exact SHA and retain the same review and validation steps. That automation and add-on registration are not implemented by this candidate PR.

## Candidate transaction checks

From the recipe repository root, build the matching runtime/settings candidates with:

```bash
scripts/build-mac-candidate-pair.sh /path/to/desktop /path/to/omarchy-pkgs /tmp/mac-candidate
scripts/build-mac-candidate-pair.sh /path/to/desktop /path/to/omarchy-pkgs /tmp/mac-baseline baseline
scripts/verify-mac-candidate.py /tmp/mac-candidate/artifacts/*.pkg.tar.xz pkgbuilds/omarchy-mac/*.pkg.tar.xz --baseline /tmp/mac-baseline/artifacts/*.pkg.tar.xz --output /tmp/mac-ownership.json
scripts/test-mac-effective-config.sh pkgbuilds/omarchy-mac/*.pkg.tar.xz
```

Companion builds archive recorded desktop objects and upstream recipe commit `6d27290193109c07b0134360d382e64790ae5dda`. The candidate-only recipe adaptation retains the existing keyboard ALS unit and installs the microphone user unit only when it exists in the desktop source. Thus the baseline settings package owns the old unit and the candidate settings package relinquishes it to the add-on. Runtime commands follow source removal. No broad overwrite options or conflicting ownership exclusions are needed.

The verifier checks source revisions, contents, actual add-on dependencies and unique file ownership, then runs real pacman fresh, rejected add-on-only installation, full-baseline upgrade, repeat, rollback/retry and re-upgrade transactions in scratch roots under fakeroot. It seeds the installed base package database so dependency checks stay enabled. Scriptlets and hooks are disabled to keep the host untouched. Those tests do not prove signed repository selection, install hooks, boot or physical hardware behavior.

Fresh Apple images must consume the desktop's `install/omarchy-apple.packages` before hardware setup. Existing users get the add-on through the desktop transition. Physical M1/M2 testing, a signed staging source, boot tests, and separately recorded Aurora qualification remain release-promotion gates. Do not add this candidate to `packages.json`, invoke publication scripts, or alter repository trust as part of a source build.
