# Omarchy Steam launcher for Apple Silicon

`omarchy-steam-fex` installs `/usr/bin/omarchy-launch-steam` for the
Asahi Linux `steam`, `muvm` and `FEX-Emu` stack. `FEX-Emu` is the
asahi-alarm package that owns `/usr/bin/FEXBash`. Python is required for
the Steam UI patch. The package is restricted to aarch64 and needs no
compilation or Omarchy installation.

The launcher is copied from [omarchy-mx-mac at commit
1c153d34e53d126b4de2eb1ef8f6b478404a1168](https://github.com/scottjones/omarchy-mx-mac/blob/1c153d34e53d126b4de2eb1ef8f6b478404a1168/bin/omarchy-launch-steam),
whose contents match the requested `5e8e1188` copy. The only adaptation is
replacing `omarchy-cmd-present` with Bash's `command -v`; the JavaScript
regex and replacement are unchanged.

`omarchy-launch-steam --prepare` creates the current user's Steam desktop
override and patches matching Steam UI chunks, preserving the first original
as `.omarchy-bak`. Launching Steam performs the same preparation once the
client is installed. User files are managed at runtime, never by `package()`
or an installation hook. The system Steam launcher and desktop file remain
owned by the `steam` package.

For Omarchy integration, `omarchy-install-gaming-steam` can call
`omarchy-pkg-add omarchy-steam-fex`, then run
`omarchy-launch-steam --prepare` as the desktop user. Gate the Install row
with `omarchy-pkg-available omarchy-steam-fex`. Once this package is available
to users, remove the in-tree `bin/omarchy-launch-steam`; the command name and
`gtk-launch steam` entry stay the same.

The manifest uses `repack` with `allow_empty_elf: true` for this script-only
aarch64 package. `any` would require an `arch=('any')` artifact in this repo's
builder. The recipe and bundled sources can also be carried upstream later.

Run the offline behavior tests with:

```sh
python3 scripts/test-omarchy-steam-fex.py
```
