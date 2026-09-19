#!/bin/bash
# Build local companion artifacts only; never install or publish them.
set -euo pipefail
source_tree=${1:?Usage: build-mac-candidate-pair.sh DESKTOP_REPO UPSTREAM_RECIPES OUTPUT [candidate|baseline]}
recipe_tree=${2:?}
output=${3:?}
[[ $output == /* && ! -e $output ]] || { echo 'Use a new absolute output directory' >&2; exit 1; }
source_commit=b76c6d79cfe5e5c05c22fdeb83f60b6b872f72c2
case ${4:-candidate} in
  candidate) ;;
  baseline) source_commit=350c46550b99688cdb5224408edd5870de2ca07b ;;
  *) echo 'Expected candidate or baseline' >&2; exit 2 ;;
esac
recipe_commit=6d27290193109c07b0134360d382e64790ae5dda
# Archive recorded objects, so dirty worktrees cannot contaminate candidates.
git -C "$source_tree" cat-file -e "$source_commit^{commit}"
git -C "$recipe_tree" cat-file -e "$recipe_commit^{commit}"
mkdir -p "$output/source" "$output/recipes" "$output/artifacts"
git -C "$source_tree" archive "$source_commit" | tar -x -C "$output/source"
git -C "$recipe_tree" archive "$recipe_commit" pkgbuilds/omarchy pkgbuilds/omarchy-settings | tar -x -C "$output/recipes"
python3 - "$output/recipes/pkgbuilds" "$source_commit" <<'PY'
from pathlib import Path
import sys
root, commit = Path(sys.argv[1]), sys.argv[2]
# Candidate-only version: not a rolling-feed version or publication recipe.
version = '4.0.3.r' + ('0' if commit.startswith('350c4655') else '1') + '.mac.' + commit[:8]
for name in ('omarchy', 'omarchy-settings'):
    path = root/name/'PKGBUILD'
    lines = path.read_text().splitlines()
    changes = {'pkgver': version, 'pkgrel': '1', '_commit': "'"+commit+"'", '_tag': "''"}
    for key, value in changes.items():
        found = [i for i, line in enumerate(lines) if line.startswith(key+'=')]
        assert len(found) == 1, (name, key)
        lines[found[0]] = key+'='+value
    text = '\n'.join(lines)+'\n'
    if name == 'omarchy-settings':
        # Existing upstream recipe enumerates units. Keep ALS outside this
        # extraction and make old/new audio ownership explicit for rehearsals.
        anchor = '  # Marks app.slice (and only app.slice)'
        assert text.count(anchor) == 1
        text = text.replace(anchor, '''  for unit in omarchy-brightness-keyboard-auto omarchy-asahi-mic; do
    if [[ -f default/systemd/user/$unit.service ]]; then
      install -Dm644 "default/systemd/user/$unit.service" "$pkgdir/usr/lib/systemd/user/$unit.service"
    fi
  done
'''+anchor)
    # Preserve exact desktop provenance in each artifact.
    anchor = '  cd "$srcdir/omarchy"\n'
    assert text.count(anchor) == 1
    text = text.replace(anchor, anchor + '''  install -Dm644 /dev/stdin "$pkgdir/usr/share/doc/'''+name+'''/source-revision" <<'REVISION'
'''+commit+'''
REVISION
''')
    path.write_text(text)
PY
for package in omarchy omarchy-settings; do
  (
    cd "$output/recipes/pkgbuilds/$package"
    OMARCHY_SRC="$output/source" PKGDEST="$output/artifacts" makepkg --nodeps --nosign --cleanbuild
  )
done
printf 'desktop=%s\nupstream_recipes=%s\n' "$source_commit" "$recipe_commit" >"$output/revisions"
sha256sum "$output/artifacts/"*.pkg.tar.* >"$output/SHA256SUMS"
