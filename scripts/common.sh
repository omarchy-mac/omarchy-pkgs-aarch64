# Shared helpers. Source this; don't execute it.
# shellcheck shell=bash

MANIFEST="${MANIFEST:-packages.json}"

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m==> WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m==> ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

manifest() { jq -r "$1" "$MANIFEST"; }

DB_NAME="$(manifest '.repo.db')"
REPO_TAG="${REPO_TAG:-$(manifest '.repo.tag')}"
PKGEXT_WANTED="$(manifest '.repo.pkgext')"
OMARCHY_PKGS_REPO="$(manifest '.repo.omarchy_pkgs_repo')"

# GitHub release assets cannot contain ':', so an epoch'd version arrives as
# 'pkg-1.1.2-3-...' rather than 'pkg-1:1.2-3-...'. repo-add takes %FILENAME%
# verbatim from the file it is handed, so the rename must happen *before*
# repo-add or the db points at a URL that 404s.
sanitize_asset_name() { printf '%s' "${1//:/.}"; }

# Read every %NAME% -> %VERSION% pair out of a repo db tarball.
db_versions() {
  local db="$1" tmp
  tmp="$(mktemp -d)"
  tar -xf "$db" -C "$tmp"
  local d
  for d in "$tmp"/*/; do
    [[ -f "$d/desc" ]] || continue
    printf '%s\t%s\n' \
      "$(sed -n '/^%NAME%$/{n;p;}' "$d/desc")" \
      "$(sed -n '/^%VERSION%$/{n;p;}' "$d/desc")"
  done
  rm -rf "$tmp"
}

# Read every %NAME% -> %BUILDDATE% pair out of a repo db tarball. Used to age
# VCS packages, whose version can never signal that a rebuild is due.
db_builddates() {
  local db="$1" tmp
  tmp="$(mktemp -d)"
  tar -xf "$db" -C "$tmp"
  local d
  for d in "$tmp"/*/; do
    [[ -f "$d/desc" ]] || continue
    printf '%s\t%s\n' \
      "$(sed -n '/^%NAME%$/{n;p;}' "$d/desc")" \
      "$(sed -n '/^%BUILDDATE%$/{n;p;}' "$d/desc")"
  done
  rm -rf "$tmp"
}

# Read every %FILENAME% out of a repo db tarball.
db_filenames() {
  local db="$1" tmp
  tmp="$(mktemp -d)"
  tar -xf "$db" -C "$tmp"
  local d
  for d in "$tmp"/*/; do
    [[ -f "$d/desc" ]] || continue
    sed -n '/^%FILENAME%$/{n;p;}' "$d/desc"
  done
  rm -rf "$tmp"
}

# Fetch the current db from the rolling release. Both dbs are needed before
# repo-add runs: it only carries forward entries from the db files present in
# its working directory, so omitting .files.tar.zst silently truncates the
# files db to whatever is being added right now.
fetch_current_dbs() {
  local dest="$1"
  mkdir -p "$dest"
  log "Fetching current $DB_NAME db from release '$REPO_TAG'"
  gh release download "$REPO_TAG" --repo "$GH_REPO" --dir "$dest" --clobber \
    --pattern "$DB_NAME.db.tar.zst" --pattern "$DB_NAME.files.tar.zst" \
    || die "could not download the current db from release '$REPO_TAG'"
  [[ -f "$dest/$DB_NAME.db.tar.zst" ]] || die "release '$REPO_TAG' has no $DB_NAME.db.tar.zst"
}

# --- package inspection ------------------------------------------------------
# These live here rather than in build-package.sh so scripts/self-test.sh can
# exercise them directly. They are the fiddliest logic in the repo.
ALLOW_FOREIGN_ELF="${ALLOW_FOREIGN_ELF:-}"
EXCLUDE_BUILD_DEPS="${EXCLUDE_BUILD_DEPS:-}"

# Read the name from .PKGINFO rather than inferring it from the filename.
# Authoritative for split pkgbases, where several artifacts share a prefix
# (yaru builds 9 subpackages; dotnet-core-2.1 builds 2).
artifact_pkgname() {
  local name
  name="$(bsdtar -xOqf "$1" .PKGINFO 2>/dev/null \
    | awk -F' = ' '/^pkgname = /{print $2; exit}')"
  [[ -n "$name" ]] || die "could not read pkgname from $1 (.PKGINFO missing?)"
  printf '%s' "$name"
}
# e_machine is read straight out of the ELF header rather than matched against
# file(1)'s prose, which spells the same architecture several ways ("x86-64",
# "Intel 80386", "Intel i386").
elf_machine() {
  local bytes lo hi
  bytes="$(od -An -tu1 -j18 -N2 -- "$1" 2>/dev/null)" || return 1
  read -r lo hi <<< "$bytes"
  [[ -n "$lo" && -n "$hi" ]] || return 1
  printf '%s' "$(( lo + hi * 256 ))"
}
# Vendors bundle native modules for every platform they support. Those are
# expected and unused here, but the allowance is a path glob rather than a
# blanket exemption, so an x86 binary somewhere that matters still fails.
elf_allowed() {
  local rel="$1" pat pats
  [[ -n "$ALLOW_FOREIGN_ELF" ]] || return 1
  IFS=',' read -r -a pats <<< "$ALLOW_FOREIGN_ELF"
  for pat in "${pats[@]}"; do
    [[ -n "$pat" ]] || continue
    # shellcheck disable=SC2053  # glob match is the point
    [[ "$rel" == $pat ]] && return 0
  done
  return 1
}
# "compile" builds install runtime depends as well as makedepends, because
# several of those are what the build actually links against: tensaku needs
# gtk4 and libadwaita headers, not just rustc. A dep that is only ever needed
# at runtime is a different matter. It can become uninstallable for reasons
# that have nothing to do with this build -- ALARM rebuilt aquamarine past a
# soname its own hyprland still required, which made hyprland uninstallable
# for days -- and a Rust binary does not link against a compositor. Naming one
# here drops it from the build-time install only; the built package still
# declares it, so pacman still pulls it in on a user's machine. Whether a name
# really is runtime-only is not this matcher's job to know: build-package.sh
# checks it against the make/checkdepends and refuses the build if it is both.
build_dep_excluded() {
  local dep="$1" ex exs
  [[ -n "$EXCLUDE_BUILD_DEPS" ]] || return 1
  IFS=',' read -r -a exs <<< "$EXCLUDE_BUILD_DEPS"
  for ex in "${exs[@]}"; do
    [[ -n "$ex" ]] || continue
    # Exact names, not globs as elf_allowed uses: this drops entries from an
    # install list, and a stray glob quietly removing a real build dep would
    # surface much later and much less clearly than a missing-package error.
    [[ "$dep" == "$ex" ]] && return 0
  done
  return 1
}
audit_elf() {
  local pkg="$1" tmp list arm=0 x86=0 other=0 allowed=0 m rel
  tmp="$(mktemp -d)"; list="$tmp.list"
  bsdtar -xf "$pkg" -C "$tmp" 2>/dev/null || die "could not extract $pkg"

  # One batched file(1) call to find the ELF objects, then read each header.
  command find "$tmp" -type f -print0 | xargs -0 -r file -N -- 2>/dev/null \
    | sed -n 's/^\(.*\): ELF .*/\1/p' > "$list" || true

  while IFS= read -r f; do
    [[ -n "$f" ]] || continue
    m="$(elf_machine "$f")" || continue
    case "$m" in
      183) arm=$((arm + 1)) ;;        # EM_AARCH64
      62|3)                             # EM_X86_64, EM_386
            rel="${f#"$tmp"}"
            if elf_allowed "$rel"; then
              allowed=$((allowed + 1))
            else
              x86=$((x86 + 1)); warn "  x86 object: $rel"
            fi ;;
      *) other=$((other + 1)) ;;      # EM_ARM (40) and friends: not our problem
    esac
  done < "$list"
  rm -rf "$tmp" "$list"

  log "  ELF audit: $arm aarch64, $x86 x86, $other other-arch, $allowed allowed-foreign"
  (( x86 == 0 )) || die "$pkg carries $x86 x86 ELF object(s) — this is not an aarch64 build"
  (( arm > 0 ))  || die "$pkg contains no aarch64 ELF objects — expected a prebuilt ARM payload"
}
