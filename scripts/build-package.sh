#!/usr/bin/env bash
# Build one pkgbase and stage the wanted artifacts into OUTDIR.
#
#   PKGBASE=mise-bin SOURCE=aur CATEGORY=repack PKGNAMES=mise-bin \
#     OUTDIR=./staging scripts/build-package.sh
#
# Env:
#   PKGBASE     pkgbase to build
#   SOURCE      aur | omarchy-pkgs | local
#   CATEGORY    any | repack
#   PKGNAMES    comma-separated pkgnames to keep (a split pkgbase builds more)
#   OUTDIR      where to stage the kept artifacts
#   IGNOREARCH  true to pass --ignorearch (for PKGBUILDs missing aarch64)
#   EXCLUDE_BUILD_DEPS  comma-separated depends to skip installing at build time
#
# This must run inside an aarch64 environment. On a native ARM runner that is
# free; on an x86 runner it is an emulated aarch64 container (binfmt + qemu).
#
# An earlier design forced CARCH=aarch64 inside an x86 container instead, on
# the theory that 'repack' PKGBUILDs only extract a vendor-prebuilt ARM binary.
# That is false: mise-bin's package() runs the ARM `mise` three times to
# generate shell completions, and any upstream PKGBUILD may start doing the
# same at any time. Emulating the target arch is the only version of this that
# does not silently rot.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh

: "${PKGBASE:?}" "${SOURCE:?}" "${CATEGORY:?}" "${PKGNAMES:?}" "${OUTDIR:?}"
IGNOREARCH="${IGNOREARCH:-false}"
EXTRA_MAKEDEPENDS="${EXTRA_MAKEDEPENDS:-}"
EXCLUDE_BUILD_DEPS="${EXCLUDE_BUILD_DEPS:-}"
ALLOW_FOREIGN_ELF="${ALLOW_FOREIGN_ELF:-}"

case "$CATEGORY" in
  any)             want_arch=any ;;
  repack|compile)  want_arch=aarch64 ;;
  *) die "unknown category '$CATEGORY' (want any, repack or compile)" ;;
esac

OUTDIR="$(mkdir -p "$OUTDIR" && cd "$OUTDIR" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/out" "$work/srcdest"

# makepkg refuses to run as root. In a container we start as root, so make an
# unprivileged builder and hand it the tree.
if [[ "$(id -u)" -eq 0 ]]; then
  id -u builder &>/dev/null || useradd -m builder
  as_builder() { runuser -u builder -- "$@"; }
else
  as_builder() { "$@"; }
fi

# pacman 7 sandboxes its downloader with Landlock, which qemu-user does not
# implement, so a plain -Sy dies inside an emulated container. Retry rather
# than disable unconditionally, so a native ARM runner keeps the sandbox.
pacman_install() {
  pacman -Sy --noconfirm --needed --asdeps "$@" && return 0
  warn "pacman -Sy failed; retrying with --disable-sandbox (expected under emulation)"
  pacman -Sy --noconfirm --needed --asdeps --disable-sandbox "$@"
}

# --- fetch the PKGBUILD -----------------------------------------------------
src="$work/src"
case "$SOURCE" in
  aur)
    log "Cloning AUR pkgbase '$PKGBASE'"
    git clone --depth 1 "https://aur.archlinux.org/$PKGBASE.git" "$src" \
      || die "could not clone AUR pkgbase '$PKGBASE'"
    ;;
  omarchy-pkgs)
    log "Sparse-checking out $OMARCHY_PKGS_REPO pkgbuilds/$PKGBASE"
    # Whole directory, not just the PKGBUILD: several of these carry local
    # source files (launcher scripts, .install hooks) alongside it.
    git clone --depth 1 --filter=blob:none --sparse \
      "https://github.com/$OMARCHY_PKGS_REPO.git" "$work/oma" \
      || die "could not clone $OMARCHY_PKGS_REPO"
    git -C "$work/oma" sparse-checkout set "pkgbuilds/$PKGBASE" \
      || die "no pkgbuilds/$PKGBASE in $OMARCHY_PKGS_REPO"
    [[ -f "$work/oma/pkgbuilds/$PKGBASE/PKGBUILD" ]] \
      || die "no PKGBUILD at pkgbuilds/$PKGBASE"
    mv "$work/oma/pkgbuilds/$PKGBASE" "$src"
    ;;
  local)
    # PKGBUILDs this repo carries itself, for packages that exist nowhere in a
    # form an aarch64 build can use (see packages.json for the why per package).
    log "Copying in-tree pkgbuilds/$PKGBASE"
    [[ -f "pkgbuilds/$PKGBASE/PKGBUILD" ]] || die "no PKGBUILD at pkgbuilds/$PKGBASE"
    cp -r "pkgbuilds/$PKGBASE" "$src"
    ;;
  *) die "unknown source '$SOURCE'" ;;
esac

# --- makepkg.conf -----------------------------------------------------------
conf="$work/makepkg.conf"
cp /etc/makepkg.conf "$conf"
{
  echo ""
  echo "# --- overrides written by scripts/build-package.sh ---"
  # Pinned so the repo stays homogeneous; every existing asset is .pkg.tar.xz.
  echo "PKGEXT='$PKGEXT_WANTED'"
  echo "SRCEXT='.src.tar.gz'"
  echo "PKGDEST='$work/out'"
  echo "SRCDEST='$work/srcdest'"
} >> "$conf"

# Fail loudly rather than quietly producing an x86 package with an aarch64
# name. This is cheap and catches a missing binfmt registration immediately.
host_arch="$(uname -m)"
[[ "$host_arch" == "aarch64" ]] \
  || die "must build on aarch64 (native or emulated); this is $host_arch. On an x86 runner, register binfmt and run inside an aarch64 container."
log "PKGEXT=$PKGEXT_WANTED, build arch=$host_arch, target arch=$want_arch"

chown -R builder: "$work" 2>/dev/null || true

# --- makedepends ------------------------------------------------------------
# --printsrcinfo expands arch-specific arrays for us. It sources the PKGBUILD,
# which is the same trust boundary as building it.
srcinfo="$work/.SRCINFO"
( cd "$src" && as_builder makepkg --config "$conf" --printsrcinfo ) > "$srcinfo" \
  || die "could not parse PKGBUILD for $PKGBASE"

# "compile" additionally needs runtime depends present at build time: linking
# tensaku wants gtk4 and libadwaita headers, not just rustc. "any" and "repack"
# never compile against anything, so installing their depends would be waste.
if [[ "$CATEGORY" == "compile" ]]; then
  dep_re='^[[:space:]]*(make|check)?depends(_[[:alnum:]_]+)?[[:space:]]*=[[:space:]]*(.+)'
else
  dep_re='^[[:space:]]*(make|check)depends(_[[:alnum:]_]+)?[[:space:]]*=[[:space:]]*(.+)'
fi

mapfile -t deps < <(
  {
    sed -nE "s/$dep_re/\3/p" "$srcinfo" \
      | sed -E 's/[<>=].*$//' | tr -d ' '
    # Some PKGBUILDs call tooling they never declare — yaru's build() uses
    # arch-meson, which ships in devtools. packages.json records those.
    [[ -n "$EXTRA_MAKEDEPENDS" ]] && tr ',' '\n' <<< "$EXTRA_MAKEDEPENDS"
  } | sed '/^$/d' | sort -u
)
# The build-time half of that list, collected separately. exclude_build_deps
# is only ever meant to drop a *runtime* depend, but $deps has both kinds
# merged by this point and a name can appear in both arrays. Without this the
# exclusion could cancel a genuine makedepend, and since makepkg runs --nodeps
# nothing would catch it until build() failed on a missing header.
build_dep_re='^[[:space:]]*(make|check)depends(_[[:alnum:]_]+)?[[:space:]]*=[[:space:]]*(.+)'
mapfile -t build_deps < <(
  {
    sed -nE "s/$build_dep_re/\3/p" "$srcinfo" \
      | sed -E 's/[<>=].*$//' | tr -d ' '
    [[ -n "$EXTRA_MAKEDEPENDS" ]] && tr ',' '\n' <<< "$EXTRA_MAKEDEPENDS"
  } | sed '/^$/d' | sort -u
)

# packages.json can name depends that must not be installed to build. See
# build_dep_excluded: this is for runtime-only depends whose availability is
# not our problem, and it never changes what the built package declares.
if [[ -n "$EXCLUDE_BUILD_DEPS" ]] && ((${#deps[@]})); then
  keep_deps=()
  for d in "${deps[@]}"; do
    if build_dep_excluded "$d"; then
      # Refuse rather than quietly do the wrong thing: if the PKGBUILD also
      # declares it as a makedepend then the build genuinely needs it, the
      # exclusion cannot be honoured, and the manifest is what has to change.
      if printf '%s\n' "${build_deps[@]+"${build_deps[@]}"}" | grep -qxF -- "$d"; then
        die "exclude_build_deps names '$d', but $PKGBASE declares it as a make/checkdepend, so the build needs it. Remove it from exclude_build_deps in packages.json."
      fi
      log "Skipping runtime dep '$d' at build time (exclude_build_deps)"
    else
      keep_deps+=("$d")
    fi
  done

  # An entry matching nothing has outlived its reason -- upstream renamed or
  # dropped the dep. Harmless to the build, but it should not sit there
  # pretending to do something.
  IFS=',' read -r -a excl_names <<< "$EXCLUDE_BUILD_DEPS"
  for e in "${excl_names[@]}"; do
    [[ -n "$e" ]] || continue
    printf '%s\n' "${deps[@]}" | grep -qxF -- "$e" \
      || warn "exclude_build_deps names '$e', which $PKGBASE does not declare — stale manifest entry?"
  done

  deps=("${keep_deps[@]+"${keep_deps[@]}"}")
fi

if ((${#deps[@]})); then
  log "Installing build deps: ${deps[*]}"
  if [[ "$(id -u)" -eq 0 ]]; then
    pacman_install "${deps[@]}" || die "could not install build deps: ${deps[*]}"
  else
    warn "not root; assuming build deps are present: ${deps[*]}"
  fi
else
  log "No build deps declared"
fi

# --- build ------------------------------------------------------------------
# --nodeps: runtime depends are irrelevant to producing the artifact, and for
# repack builds they are aarch64 packages an x86 runner could not install.
# --nocheck: test suites want checkdepends and a native target.
mkflags=(--config "$conf" --nodeps --nocheck --noconfirm --force --clean)
[[ "$IGNOREARCH" == "true" ]] && mkflags+=(--ignorearch)
log "Building $PKGBASE"
( cd "$src" && as_builder makepkg "${mkflags[@]}" ) || die "makepkg failed for $PKGBASE"

# --- collect and verify -----------------------------------------------------
shopt -s nullglob
built=("$work/out"/*"$PKGEXT_WANTED")
((${#built[@]})) || die "$PKGBASE produced no $PKGEXT_WANTED artifact"
log "Built ${#built[@]} artifact(s): $(printf '%s ' "${built[@]##*/}")"

# The failure this guards against is shipping an x86 payload under an aarch64
# filename. It deliberately does NOT demand that every ELF be aarch64: the
# openai-codex-desktop Electron bundle legitimately carries 32-bit ARM
# libraries, and rejecting those is a false positive.
#

kept=0
IFS=',' read -r -a wanted <<< "$PKGNAMES"
for name in "${wanted[@]}"; do
  found=""
  for pkg in "${built[@]}"; do
    [[ "$(artifact_pkgname "$pkg")" == "$name" ]] && { found="$pkg"; break; }
  done
  [[ -n "$found" ]] || die "$PKGBASE did not produce an artifact for '$name'"

  base="$(basename "$found")"
  [[ "$base" == *"-$want_arch$PKGEXT_WANTED" ]] \
    || die "$base is not a '-$want_arch$PKGEXT_WANTED' artifact"
  log "Keeping $base"
  [[ "$CATEGORY" == "repack" ]] && audit_elf "$found"

  # An epoch puts a ':' in the filename, which neither a GitHub release asset
  # nor an actions/upload-artifact path can contain. Rename here so the name is
  # already safe by the time repo-add records it as %FILENAME%.
  safe="$(sanitize_asset_name "$base")"
  [[ "$safe" == "$base" ]] || log "  staging as $safe (':' cannot survive an upload)"
  cp "$found" "$OUTDIR/$safe"
  kept=$((kept + 1))
done

log "Staged $kept artifact(s) in $OUTDIR"
