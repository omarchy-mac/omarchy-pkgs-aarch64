# Additional experimental image dependencies

The full Quattro base list requires `asdcontrol`, `tobi-try`, and `qemu-user-static-binfmt`. They were absent from the captured 50-package edge snapshot. QEMU's binfmt package also requires `qemu-user-static`.

These recipes are imported without modification for candidate validation. They are not added to `packages.json` and must not be published to edge as part of this image work.

- `asdcontrol/PKGBUILD`, `asdcontrol/asdcontrol.sudoers`, and `tobi-try/PKGBUILD`: omacom/omarchy-pkgs commit `4b60e4cd95972c16fbf3da634522a955cf7bf36c`. Existing maintainer attribution is preserved.
- `qemu-user-static/PKGBUILD` and `qemu-user-static/qemu-binfmt-conf.sh`: Marcelo's maralcbr/omarchy-pkgs commit `83973903b7deb9b56ce75f02b432fba0561d6293`. The recipe repackages the checksum-pinned Debian ARM64 static QEMU binaries because Arch Linux ARM omits the static user emulators. Preserve the upstream QEMU licenses and Debian copyright record shipped by the recipe.

All four outputs build successfully in a disposable native ARM container. The candidate builder now uses these recipes in its schema-3 nine-package artifact; the full image transaction and boot remain separate validation.
