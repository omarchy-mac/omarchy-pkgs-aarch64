# omarchy-mac candidate

The independent source lives at `packages/omarchy-mac/` in `omacom/omarchy-mac`. `PKGBUILD` pins collaboration commit `20b8ae0fb6e2593172226f9f8cf0bb79e666d2aa` and packages only that directory. It supplies no kernel, installer, replacement settings package or trust configuration. Nothing here registers the add-on with the rolling updater.

Run `makepkg --nosign` in this directory. `prepare()` copies the add-on away from the surrounding desktop tree before running tests or staging it. The artifact records its source revision and attribution.

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
