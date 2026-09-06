#!/usr/bin/env bash
# Install the tooling the other scripts need inside an Arch container.
#   bash scripts/container-bootstrap.sh [build|full]
#
# "build" skips github-cli: build jobs never touch the release, and every
# package installed here is unpacked under emulation, so the ~15MB of gh and
# its dependencies is pure cost on the slowest path we have.
set -euo pipefail

role="${1:-full}"
case "$role" in
  build) pkgs=(git jq);              required=(git jq makepkg bsdtar file) ;;
  full)  pkgs=(git jq github-cli);   required=(git jq gh repo-add vercmp bsdtar) ;;
  *) echo "==> ERROR: unknown role '$role' (want build|full)" >&2; exit 1 ;;
esac

# pacman 7 sandboxes its downloader with Landlock, which qemu-user does not
# implement and a container may not permit. Retry rather than disable
# unconditionally, so an environment that can sandbox keeps doing so.
if ! pacman -Syu --noconfirm --needed "${pkgs[@]}"; then
  echo "==> pacman -Syu failed; retrying with --disable-sandbox" >&2
  pacman -Syu --noconfirm --needed --disable-sandbox "${pkgs[@]}"
  # Not every later pacman call in this container is ours to pass a flag to.
  # update-omarchy-mac.yml hands control to build-packages.sh from the
  # omarchy-mac checkout, which installs its own makedepends (imagemagick)
  # and hits the same Landlock failure with no retry of its own. Record what
  # the retry just proved so the rest of the container inherits it. Still not
  # unconditional: we only reach this after the sandboxed attempt failed.
  if ! grep -qx 'DisableSandbox' /etc/pacman.conf; then
    echo "==> recording DisableSandbox in pacman.conf for later callers" >&2
    sed -i '/^\[options\]/a DisableSandbox' /etc/pacman.conf
  fi
fi

for c in "${required[@]}"; do
  command -v "$c" >/dev/null || { echo "==> ERROR: $c missing after bootstrap" >&2; exit 1; }
done
echo "==> Container ready ($role): $(uname -m), $(pacman -Q pacman)"
