#!/usr/bin/env bash
# Prove the published repo is actually consumable: sync the db the way pacman
# does, resolve every package in it, and confirm each URL really exists.
#
#   GH_REPO=owner/name scripts/smoke-test.sh
#
# This is the check that would have caught the epoch filename problem, where
# the db names an asset GitHub cannot serve.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
source scripts/common.sh

: "${GH_REPO:?GH_REPO must be set (owner/name)}"
SERVER="https://github.com/$GH_REPO/releases/download/$REPO_TAG"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/db" "$work/root" "$work/cache" "$work/keyring"
chmod 700 "$work/keyring"
# Only the reviewed public key enters this isolated test trust database.
pacman-key --gpgdir "$work/keyring" --init
pacman-key --gpgdir "$work/keyring" --add pkgbuilds/omarchy-mac-keyring/omarchy-mac.gpg
primary=$(python3 -c 'import json;print(json.load(open("pkgbuilds/omarchy-mac-keyring/signing-policy.json"))["primary_fingerprint"])')
pacman-key --gpgdir "$work/keyring" --lsign-key "$primary"

cat > "$work/pacman.conf" <<CONF
[options]
HoldPkg = pacman glibc
Architecture = aarch64
SigLevel = PackageRequired DatabaseRequired TrustedOnly
GPGDir = $work/keyring
CacheDir = $work/cache
[$DB_NAME]
SigLevel = PackageRequired DatabaseRequired TrustedOnly
Server = $SERVER
CONF

log "Syncing $DB_NAME from $SERVER"
pacman --config "$work/pacman.conf" --dbpath "$work/db" --root "$work/root" \
  -Sy --noconfirm >/dev/null 2>&1 \
  || pacman --config "$work/pacman.conf" --dbpath "$work/db" --root "$work/root" \
       -Sy --noconfirm --disable-sandbox >/dev/null \
  || die "pacman could not sync the repo"

mapfile -t pkgs < <(pacman --config "$work/pacman.conf" --dbpath "$work/db" \
  --root "$work/root" -Sl "$DB_NAME" | awk '{print $2}')
(( ${#pkgs[@]} > 0 )) || die "pacman synced the db but it lists no packages"
log "Repo advertises ${#pkgs[@]} package(s)"

# -Sddp makes pacman resolve each package to the exact URL it would fetch,
# without dragging in the dependency closure (no other repo is configured
# here, and the point is to check our own assets).
mapfile -t urls < <(pacman --config "$work/pacman.conf" --dbpath "$work/db" \
  --root "$work/root" -Sddp "${pkgs[@]/#/$DB_NAME/}" 2>/dev/null)
(( ${#urls[@]} == ${#pkgs[@]} )) \
  || die "pacman resolved ${#urls[@]} URL(s) for ${#pkgs[@]} package(s)"

log "Checking that all ${#urls[@]} package URLs are reachable"
failed=0
for url in "${urls[@]}"; do
  code="$(curl -sSL -o /dev/null -w '%{http_code}' --retry 2 --max-time 60 -r 0-0 "$url" || echo 000)"
  if [[ "$code" != "200" && "$code" != "206" ]]; then
    warn "  $code  $url"
    failed=$((failed + 1))
  fi
done

(( failed == 0 )) || die "$failed package URL(s) in the db are not fetchable"
log "All ${#urls[@]} package URLs resolve and are fetchable"

for f in "$DB_NAME.db" "$DB_NAME.db.tar.zst" "$DB_NAME.files" "$DB_NAME.files.tar.zst"; do
  code="$(curl -sSL -o /dev/null -w '%{http_code}' --max-time 60 "$SERVER/$f" || echo 000)"
  [[ "$code" == "200" ]] || die "$f is not served ($code) — pacman fetches these directly"
done
log "All four db assets are served as real files"
# Real package downloads exercise libalpm signature verification, not just HEAD.
pacman --config "$work/pacman.conf" --dbpath "$work/db" --root "$work/root" \
  -Sddw --noconfirm "${pkgs[@]/#/$DB_NAME/}" || die "strict package verification failed"
python3 scripts/package-signing.py verify-packages "$work/cache"
gpgconf --homedir "$work/keyring" --kill gpg-agent 2>/dev/null || true
