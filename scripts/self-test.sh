#!/usr/bin/env bash
# Self-tests for the logic that would fail silently rather than loudly:
# epoch filename handling, package identification, the ELF audit, and db
# parsing. Everything here is offline and takes a couple of seconds.
#
#   bash scripts/self-test.sh
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh
source scripts/omarchy-mac-release.sh

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  \033[1;32mok\033[0m   %s\n' "$1"; }
no()   { fail=$((fail+1)); printf '  \033[1;31mFAIL\033[0m %s\n     %s\n' "$1" "${2:-}"; }
is()   { [[ "$2" == "$3" ]] && ok "$1" || no "$1" "expected '$3', got '$2'"; }

work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT

# --- crafted ELF objects: e_machine at offset 18 ----------------------------
mkelf() { # machine path [class]
  python3 - "$1" "$2" "${3:-2}" <<'PY'
import struct, sys, os
machine, path, cls = int(sys.argv[1]), sys.argv[2], int(sys.argv[3])
os.makedirs(os.path.dirname(path), exist_ok=True)
h = bytearray(64)
h[0:4] = b'\x7fELF'; h[4] = cls; h[5] = 1; h[6] = 1
h[16:18] = struct.pack('<H', 3)
h[18:20] = struct.pack('<H', machine)
h[20:24] = struct.pack('<I', 1)
open(path, 'wb').write(bytes(h) + b'\0' * 128)
PY
}
mkpkg() { # dir out-name  -> a .pkg.tar.xz with a .PKGINFO
  local dir="$1" out="$2" name="$3"
  printf 'pkgname = %s\npkgver = 1.0-1\narch = aarch64\n' "$name" > "$dir/.PKGINFO"
  ( cd "$dir" && tar -cf - .PKGINFO ./* 2>/dev/null | xz > "$out" )
}

echo "== epoch / asset names"
is "colon becomes dot"        "$(sanitize_asset_name 'brave-1:1.93-1-aarch64.pkg.tar.xz')" 'brave-1.1.93-1-aarch64.pkg.tar.xz'
is "no colon is untouched"    "$(sanitize_asset_name 'mise-2026.8-1-aarch64.pkg.tar.xz')"  'mise-2026.8-1-aarch64.pkg.tar.xz'
is "sanitising is idempotent" "$(sanitize_asset_name "$(sanitize_asset_name 'a-1:2-1.pkg.tar.xz')")" 'a-1.2-1.pkg.tar.xz'

echo "== vercmp assumptions the detect logic relies on"
is "epoch beats a bigger plain version" "$(vercmp '1:1.0-1' '9.9-1')"          1
is "pkgrel breaks a version tie"        "$(vercmp '2026.8.14-4' '2026.8.14-1')" 1
is "equal versions compare equal"       "$(vercmp '1.2.3-1' '1.2.3-1')"         0
is "VCS r16 sorts above r9"             "$(vercmp '0.2.1.r16.g0ef9b30-1' '0.2.1.r9.ge2f30ff-1')" 1

echo "== Omarchy Mac release coordinates"
parse_release_tag v4.0.2
is "plain tag uses pkgver" "$RELEASE_PKGVER" '4.0.2'
is "plain tag defaults pkgrel" "$RELEASE_PKGREL" '1'
is "plain tag maps to package version" "$RELEASE_VERSION" '4.0.2-1'
parse_release_tag v4.0.2-3
is "Mac rebuild tag sets pkgrel" "$RELEASE_PKGREL" '3'
parse_release_tag v4.1.0rc2-1
is "attached prerelease is accepted" "$RELEASE_VERSION" '4.1.0rc2-1'
( parse_release_tag v4.1.0-rc2 ) >/dev/null 2>&1 \
  && no "separated prerelease is rejected" "accepted a tag pacman orders incorrectly" \
  || ok "separated prerelease is rejected"

echo "== package identification (.PKGINFO, not the filename)"
mkdir -p "$work/p1/usr/bin"; mkelf 183 "$work/p1/usr/bin/tool"
mkpkg "$work/p1" "$work/yaru-icon-theme-26.04-1-any.pkg.tar.xz" "yaru-icon-theme"
is "reads pkgname from .PKGINFO" "$(artifact_pkgname "$work/yaru-icon-theme-26.04-1-any.pkg.tar.xz")" 'yaru-icon-theme'
mkdir -p "$work/p2/usr/bin"; mkelf 183 "$work/p2/usr/bin/tool"
mkpkg "$work/p2" "$work/weird-name-1:2.3-4-aarch64.pkg.tar.xz" "brave-origin-bin"
is "unaffected by an epoch in the filename" "$(artifact_pkgname "$work/weird-name-1:2.3-4-aarch64.pkg.tar.xz")" 'brave-origin-bin'

echo "== ELF audit"
mkdir -p "$work/arm/usr/bin"; mkelf 183 "$work/arm/usr/bin/app"
mkpkg "$work/arm" "$work/clean.pkg.tar.xz" clean
( ALLOW_FOREIGN_ELF="" audit_elf "$work/clean.pkg.tar.xz" ) >/dev/null 2>&1 \
  && ok "aarch64-only package passes" || no "aarch64-only package passes" "audit rejected a clean package"

mkdir -p "$work/x86/usr/bin"; mkelf 183 "$work/x86/usr/bin/app"; mkelf 62 "$work/x86/usr/bin/rogue"
mkpkg "$work/x86" "$work/x86.pkg.tar.xz" x86pkg
( ALLOW_FOREIGN_ELF="" audit_elf "$work/x86.pkg.tar.xz" ) >/dev/null 2>&1 \
  && no "x86-64 object is rejected" "audit accepted an x86-64 payload" || ok "x86-64 object is rejected"

mkdir -p "$work/i386/usr/bin"; mkelf 183 "$work/i386/usr/bin/app"; mkelf 3 "$work/i386/usr/bin/rogue" 1
mkpkg "$work/i386" "$work/i386.pkg.tar.xz" i386pkg
( ALLOW_FOREIGN_ELF="" audit_elf "$work/i386.pkg.tar.xz" ) >/dev/null 2>&1 \
  && no "i386 object is rejected" "audit accepted an i386 payload" || ok "i386 object is rejected"

# 32-bit ARM is bundled by Electron apps and must not trip the audit
mkdir -p "$work/arm32/usr/lib"; mkelf 183 "$work/arm32/usr/lib/app"; mkelf 40 "$work/arm32/usr/lib/legacy.so" 1
mkpkg "$work/arm32" "$work/arm32.pkg.tar.xz" arm32pkg
( ALLOW_FOREIGN_ELF="" audit_elf "$work/arm32.pkg.tar.xz" ) >/dev/null 2>&1 \
  && ok "bundled 32-bit ARM does not trip the audit" || no "bundled 32-bit ARM does not trip the audit" "ARM32 treated as foreign"

mkdir -p "$work/pb/usr/lib/node/prebuilds/linux-x64"
mkelf 183 "$work/pb/usr/lib/node/app"; mkelf 62 "$work/pb/usr/lib/node/prebuilds/linux-x64/n.node"
mkpkg "$work/pb" "$work/pb.pkg.tar.xz" pbpkg
( ALLOW_FOREIGN_ELF='*/prebuilds/*' audit_elf "$work/pb.pkg.tar.xz" ) >/dev/null 2>&1 \
  && ok "allowance permits x86 under the named glob" || no "allowance permits x86 under the named glob" "glob did not match"
( ALLOW_FOREIGN_ELF="" audit_elf "$work/pb.pkg.tar.xz" ) >/dev/null 2>&1 \
  && no "allowance is required, not implied" "passed without an allowance" || ok "allowance is required, not implied"
# the allowance must not become a blanket exemption
mkdir -p "$work/sneak/usr/bin" "$work/sneak/usr/lib/prebuilds"
mkelf 183 "$work/sneak/usr/lib/prebuilds/ok"; mkelf 62 "$work/sneak/usr/bin/main"
mkpkg "$work/sneak" "$work/sneak.pkg.tar.xz" sneakpkg
( ALLOW_FOREIGN_ELF='*/prebuilds/*' audit_elf "$work/sneak.pkg.tar.xz" ) >/dev/null 2>&1 \
  && no "x86 outside the glob still fails" "allowance leaked to /usr/bin" || ok "x86 outside the glob still fails"

echo "== repo db parsing"
mkdir -p "$work/db/foo-1:2.3-4"
{ echo '%NAME%'; echo 'foo'; echo; echo '%VERSION%'; echo '1:2.3-4'; echo;
  echo '%FILENAME%'; echo 'foo-1.2.3-4-aarch64.pkg.tar.xz'; echo;
  echo '%BUILDDATE%'; echo '1787109270'; } > "$work/db/foo-1:2.3-4/desc"
( cd "$work/db" && tar -cf - . | zstd -q -o "$work/test.db.tar.zst" )
is "db_versions reads the epoch version"  "$(db_versions   "$work/test.db.tar.zst")" "$(printf 'foo\t1:2.3-4')"
is "db_filenames reads the sanitised name" "$(db_filenames "$work/test.db.tar.zst")" 'foo-1.2.3-4-aarch64.pkg.tar.xz'
is "db_builddates reads BUILDDATE"        "$(db_builddates "$work/test.db.tar.zst")" "$(printf 'foo\t1787109270')"

echo "== manifest is coherent"
is "manifest parses"           "$(jq -e 'type' packages.json 2>/dev/null)" '"object"'
dupes="$(jq -r '.packages | group_by(.name) | map(select(length > 1)) | length' packages.json)"
is "no duplicate package names" "$dupes" '0'
bad="$(jq -r '.packages | map(select(.category as $c | ["any","repack","compile"] | index($c) | not)) | length' packages.json)"
is "every category is known"    "$bad" '0'
badsrc="$(jq -r '.packages | map(select(.source as $s | ["aur","omarchy-pkgs","omarchy-mac","local"] | index($s) | not)) | length' packages.json)"
is "every source is known"      "$badsrc" '0'
nolocal=0
while read -r base; do
  [[ -f "pkgbuilds/$base/PKGBUILD" ]] || nolocal=$((nolocal+1))
done < <(jq -r '.packages | map(select(.source == "local")) | .[].pkgbase' packages.json | sort -u)
is "every local source has an in-tree PKGBUILD" "$nolocal" '0'
# exclude_build_deps only ever removes a dep from the build-time install, so
# the risk it carries is dropping something a package actually needs to
# compile. Only "compile" installs runtime depends at all, so the field is
# meaningless anywhere else and a stray one means a misunderstanding. The
# matcher is checked separately for exactness.
badexcl="$(jq -r '.packages | map(select(.exclude_build_deps and (.category != "compile"))) | length' packages.json)"
is "exclude_build_deps only on compile packages" "$badexcl" '0'
# detect-updates.sh unions both fields across a pkgbase group, so one member
# adding a name to extra_makedepends while another excludes it would have them
# cancel. build-package.sh dies on that, but catching it here is cheaper.
clash="$(jq -r '.packages | group_by(.pkgbase)
  | map({ x: (map(.extra_makedepends // []) | add), e: (map(.exclude_build_deps // []) | add) })
  | map(select(((.x - (.x - .e)) | length) > 0)) | length' packages.json)"
is "no name is both an extra makedepend and excluded" "$clash" '0'

echo "== build-time dep exclusion"
EXCLUDE_BUILD_DEPS='hyprland'
build_dep_excluded hyprland  && ok "named dep is excluded"    || no "named dep is excluded"
build_dep_excluded gtk4      && no "unnamed dep is kept"      || ok "unnamed dep is kept"
# A prefix must not match: excluding "hyprland" must leave hyprland-guiutils.
build_dep_excluded hyprland-guiutils && no "prefix does not match" || ok "prefix does not match"
EXCLUDE_BUILD_DEPS='hyprland,xdg-desktop-portal-hyprland'
build_dep_excluded xdg-desktop-portal-hyprland && ok "second entry in the list matches" || no "second entry in the list matches"
EXCLUDE_BUILD_DEPS=''
build_dep_excluded hyprland && no "empty list excludes nothing" || ok "empty list excludes nothing"

echo "== Omarchy Mac atomic package policy"
# These invoke the script rather than the sourced function on purpose. It only
# applies `set -euo pipefail` when executed directly, which is how CI runs it,
# and that setting is what turns a SIGPIPE from `grep -q` into a failed check.
# Calling the function in-process silently skips the mode the bug lives in.
mkdir -p "$work/mac-source" "$work/mac-build/omarchy/usr/share/omarchy/install/helpers" \
  "$work/mac-build/settings" "$work/mac-stage"
printf '4.0.2\n' > "$work/mac-source/version"
cat > "$work/mac-build/omarchy/.PKGINFO" <<'INFO'
pkgname = omarchy
pkgver = 4.0.2-1
arch = aarch64
depend = omarchy-settings=4.0.2
depend = iwd
depend = networkmanager
INFO
touch "$work/mac-build/omarchy/usr/share/omarchy/install/helpers/arm-package-sources.sh"
# Pad the listing so `bsdtar | grep -Fxq` really does exit before the producer
# finishes. A handful of files never triggers it, so a small fixture would let
# the SIGPIPE-under-pipefail bug through — which is exactly what happened: CI
# failed on a 1861-entry package while the tests stayed green.
mkdir -p "$work/mac-build/omarchy/usr/share/omarchy/themes"
for i in $(seq 1 2000); do : > "$work/mac-build/omarchy/usr/share/omarchy/themes/filler-$i.conf"; done
# Order matters: the matched path has to come early with plenty of output
# after it, or grep -q reaches the end anyway and never closes the pipe early.
( cd "$work/mac-build/omarchy" \
    && tar -cf - .PKGINFO ./usr/share/omarchy/install ./usr/share/omarchy/themes \
     | xz > "$work/mac-build/omarchy-4.0.2-1-aarch64.pkg.tar.xz" )
cat > "$work/mac-build/settings/.PKGINFO" <<'INFO'
pkgname = omarchy-settings
pkgver = 4.0.2-1
arch = aarch64
INFO
mkdir -p "$work/mac-build/settings/etc/mkinitcpio.conf.d"
cat > "$work/mac-build/settings/etc/mkinitcpio.conf.d/omarchy_hooks.conf" <<'HOOKS'
HOOKS=(base udev plymouth keyboard autodetect microcode modconf kms)
# insert the asahi hook after base, where Asahi Alarm puts it
HOOKS
( cd "$work/mac-build/settings" && tar -cf - . | xz > "$work/mac-build/omarchy-settings-4.0.2-1-aarch64.pkg.tar.xz" )
( RELEASE_TAG=v4.0.2-1 SOURCE_DIR="$work/mac-source" PKGDIR="$work/mac-build" \
    STAGING_DIR="$work/mac-stage" bash scripts/omarchy-mac-release.sh verify ) >/dev/null 2>&1 \
  && ok "matching safe pair verifies" || no "matching safe pair verifies" "policy rejected a safe pair"
is "both packages stage together" "$(find "$work/mac-stage" -name '*.pkg.tar.*' | wc -l)" '2'

# Dropping the hook is the boot-breaking case: the package installs fine and
# the machine wedges at the next mkinitcpio run, with no display to say why.
rm -rf "$work/mac-build/settings/etc/mkinitcpio.conf.d"
( cd "$work/mac-build/settings" && tar -cf - . | xz > "$work/mac-build/omarchy-settings-4.0.2-1-aarch64.pkg.tar.xz" )
( RELEASE_TAG=v4.0.2-1 SOURCE_DIR="$work/mac-source" PKGDIR="$work/mac-build" \
    STAGING_DIR="$work/mac-stage" bash scripts/omarchy-mac-release.sh verify ) >/dev/null 2>&1 \
  && no "missing asahi hook is rejected" "settings package without the asahi hook passed" \
  || ok "missing asahi hook is rejected"

# A present-but-empty drop-in restores nothing, so a path check alone is not
# enough -- the content has to name the hook.
mkdir -p "$work/mac-build/settings/etc/mkinitcpio.conf.d"
printf 'HOOKS=(base udev autodetect modconf block filesystems fsck)\n' \
  > "$work/mac-build/settings/etc/mkinitcpio.conf.d/omarchy_hooks.conf"
( cd "$work/mac-build/settings" && tar -cf - . | xz > "$work/mac-build/omarchy-settings-4.0.2-1-aarch64.pkg.tar.xz" )
( RELEASE_TAG=v4.0.2-1 SOURCE_DIR="$work/mac-source" PKGDIR="$work/mac-build" \
    STAGING_DIR="$work/mac-stage" bash scripts/omarchy-mac-release.sh verify ) >/dev/null 2>&1 \
  && no "hook drop-in without asahi is rejected" "a drop-in that stages no firmware passed" \
  || ok "hook drop-in without asahi is rejected"

# omarchy's own depends decide what else ships: the keyring and font are built
# by the same run and are in no other repo we carry, so an omarchy that needs
# them must publish them.
mkdir -p "$work/mac-extra" "$work/mac-xstage"
# The previous case left a deliberately-broken settings package behind; this
# case needs a good one, so rebuild it with the asahi hook restored.
mkdir -p "$work/mac-build/settings/etc/mkinitcpio.conf.d"
cat > "$work/mac-build/settings/etc/mkinitcpio.conf.d/omarchy_hooks.conf" <<'HOOKS'
HOOKS=(base udev plymouth keyboard autodetect microcode modconf kms)
# insert the asahi hook after base, where Asahi Alarm puts it
HOOKS
( cd "$work/mac-build/settings" && tar -cf - . | xz > "$work/mac-extra/omarchy-settings-4.0.2-1-aarch64.pkg.tar.xz" )
cat > "$work/mac-build/omarchy/.PKGINFO" <<'INFO'
pkgname = omarchy
pkgver = 4.0.2-1
arch = aarch64
depend = omarchy-settings=4.0.2
depend = iwd
depend = networkmanager
depend = omarchy-keyring
depend = ttf-jetbrains-mono-nerd-basic
INFO
( cd "$work/mac-build/omarchy" \
    && tar -cf - .PKGINFO ./usr/share/omarchy/install ./usr/share/omarchy/themes \
     | xz > "$work/mac-extra/omarchy-4.0.2-1-aarch64.pkg.tar.xz" )
mkpkgany() { mkdir -p "$work/x-$1"; printf 'pkgname = %s\npkgver = 1-1\narch = any\n' "$1" > "$work/x-$1/.PKGINFO"
  ( cd "$work/x-$1" && tar -cf - .PKGINFO | xz > "$work/mac-extra/$1-1-1-any.pkg.tar.xz" ); }

# declared and present -> all four stage
mkpkgany omarchy-keyring; mkpkgany ttf-jetbrains-mono-nerd-basic
( RELEASE_TAG=v4.0.2-1 SOURCE_DIR="$work/mac-source" PKGDIR="$work/mac-extra" STAGING_DIR="$work/mac-xstage" \
    bash scripts/omarchy-mac-release.sh verify ) >/dev/null 2>&1
is "omarchy's dependency packages are published too" \
  "$(find "$work/mac-xstage" -name '*.pkg.tar.*' | wc -l | tr -d ' ')" '4'

# declared but missing -> refuse, rather than publish an uninstallable omarchy
rm -f "$work/mac-extra/omarchy-keyring-1-1-any.pkg.tar.xz"
( RELEASE_TAG=v4.0.2-1 SOURCE_DIR="$work/mac-source" PKGDIR="$work/mac-extra" STAGING_DIR="$work/mac-xstage" \
    bash scripts/omarchy-mac-release.sh verify ) >/dev/null 2>&1 \
  && no "a missing dependency package is rejected" "published an omarchy whose depend is unavailable" \
  || ok "a missing dependency package is rejected"

echo
if (( fail )); then
  printf '\033[1;31m%d passed, %d FAILED\033[0m\n' "$pass" "$fail"; exit 1
fi
printf '\033[1;32mall %d self-tests passed\033[0m\n' "$pass"
