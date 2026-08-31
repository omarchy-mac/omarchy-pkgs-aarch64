# omarchy-pkgs-aarch64

Unofficial **aarch64** builds of Omarchy's own packages, for Apple Silicon Macs
running [Asahi Linux](https://asahilinux.org/) and the
[omarchy-mac](https://github.com/omarchy-mac/omarchy-mac) fork.

## Why this exists

Omarchy's package repo at `pkgs.omarchy.org` publishes **x86_64 only** —
`edge/aarch64` and `stable/aarch64` both return 404. So on ARM, every package
that lives in Omarchy's own repo is simply unavailable, which leaves keybindings
pointing at binaries that can't be installed. `SUPER + CTRL + Q` (calculator)
and `SUPER + SHIFT + W` (writer) are the visible casualties.

Nothing is patched here. Sources are unmodified; only the build architecture
changes. Packages come from four places:

- **Omarchy's own repo** ([omacom-io/omarchy-pkgs](https://github.com/omacom-io/omarchy-pkgs)),
  built with that repo's tooling, which already supports ARM:
  `./bin/build --arch aarch64 --package omacalc omacut omawrite`
- **The AUR**, built with `makepkg` from the published PKGBUILD.
- **`any`-architecture packages**, which need no rebuild at all — the AUR
  artifact is reused as-is.
- **In-tree PKGBUILDs** ([`pkgbuilds/`](pkgbuilds), `source: local` in
  `packages.json`), for software that exists nowhere in a form an aarch64
  build can use. Currently only `obs-studio`: absent from Arch Linux ARM
  entirely, and every AUR pkgbase hardcodes obsproject's prebuilt CEF browser
  bundle, which is published for x86_64 only. Ours builds upstream's
  unmodified release sources with `ENABLE_BROWSER=OFF` — no browser
  source/dock, everything else enabled.

## Packages

| Package | Version | Provides |
|---------|---------|----------|
| `aether` | 4.29.8-1 | Wallpaper-driven desktop theming |
| `brave-origin-bin` | 1:1.94.117-1 | Minimalist browser from the Brave team |
| `cliamp` | 1.63.2-1 | Retro terminal music player |
| `dotnet-host-bin` | 10.0.11.sdk400-1 | .NET CLI driver |
| `dotnet-runtime-2.1` | 2.1.30.sdk818-1 | .NET Core 2.1 runtime |
| `dotnet-sdk-2.1` | 2.1.30.sdk818-1 | .NET Core 2.1 SDK |
| `herdr` | 0.8.2-1 | Terminal workspace manager for AI coding agents |
| `hypa-ttfx-bin` | 0.3.1-1 | Hypa terminal text effects |
| `hyprland-preview-share-picker-git` | 0.2.1.r16.g0ef9b30-1 | Share picker with window/monitor previews |
| `localsend` | 1.18.2-1 | Cross-platform AirDrop alternative |
| `mise-bin` | 2026.8.15-1 | Dev tools, env vars, task runner |
| `obs-studio` | 32.2.2-1 | Video recording and live streaming (no browser source) |
| `obsidian-appimage` | 1.12.7-1 | Markdown knowledge base (AppImage) |
| `omacalc` | 0.2.2-1 | Calculator — bound to `SUPER + CTRL + Q` |
| `omacut` | 0.4.0-1 | Video length trimmer |
| `omarchy-emacs` | 1.10.1-1 | Emacs theme/font syncing for Omarchy |
| `omarchy-webapp-theme` | 0.3.6-1 | Theme Slack, Discord, GitHub et al. to match Omarchy |
| `omawrite` | 0.5.0-1 | Markdown writing app — bound to `SUPER + SHIFT + W` |
| `openai-codex-desktop` | 26.820.80927-1 | ChatGPT desktop app with Codex |
| `tensaku` | 0.28.0-1 | Screenshot annotation for Wayland |
| `ttf-ia-writer` | 20181225-1 | iA Writer font subset |
| `ttfx` | 0.3.2-1 | Terminal text effects, static binary |
| `tzupdate` | 3.1.0-1 | Set timezone from IP geolocation |
| `ufw-docker` | 251123-1 | Fix the Docker/UFW security flaw |
| `xdg-terminal-exec` | 0.14.3-1 | Launch desktop apps with `Terminal=true` |
| `yaru-icon-theme` | 26.04.5.1ubuntu-1 | Yaru default Ubuntu icon theme |
| `yay` | 13.0.1-1 | Pacman wrapper and AUR helper |

## Usage

Add to `/etc/pacman.conf`:

```ini
[omarchy-aarch64]
SigLevel = Optional TrustAll
Server = https://github.com/omarchy-mac/omarchy-pkgs-aarch64/releases/download/edge
```

Then:

```bash
sudo pacman -Sy
sudo pacman -S omacalc omawrite omacut   # or any package from the table
```

Assets live on a single rolling `edge` tag and are replaced in place, so the
`Server` URL never changes.

## Caveats

- **Unofficial.** Not affiliated with or endorsed by Omarchy or 37signals.
  Upstream owes you nothing for these builds; report packaging bugs here, not
  to them.
- **Unsigned.** Hence `SigLevel = Optional TrustAll`, which is what Omarchy's
  own `pacman.conf` uses for its repo. If you'd rather not trust unsigned
  packages, build them yourself: the Omarchy ones with the command below, the
  AUR ones with `makepkg` from their PKGBUILD.
- **Partly automated.** A scheduled workflow refreshes the
  architecture-independent packages and the prebuilt-ARM repacks. The packages
  that compile from source are still rebuilt by hand and can drift behind
  upstream — see [Automation](#automation) for which is which.

## Automation

[`.github/workflows/update-packages.yml`](.github/workflows/update-packages.yml)
runs every six hours. It compares each package's upstream version against the
version in the published db and rebuilds only what moved, so a typical run does
nothing. It never publishes a version older than the one already in the repo,
which is what would make `pacman -Syu` offer you a downgrade.

The packages differ only in where they can be built:

| Group | Count | Automated |
|-------|-------|-----------|
| `any` — `arch=('any')`, architecture-independent | 6 | yes |
| `repack` — ships a vendor-prebuilt ARM binary | 9 | yes |
| `compile` — built from source | 12 | yes |

Two packages in the repo are deliberately **not** automated, and say so in
`packages.json` rather than being silently absent. Both are built from
[omarchy-mac](https://github.com/omarchy-mac/omarchy-mac) and carry Apple
Silicon patches that rebuilding from upstream's PKGBUILD would discard.

`omarchy` drops the `limine` bootloader dependencies, which mean nothing on a
Mac. `omarchy-settings` goes further: it re-inserts the `asahi` mkinitcpio hook
that stages Apple Silicon firmware, without which the next `mkinitcpio` run
produces an initramfs that cannot drive the display or Wi-Fi and the boot wedges
— it also drops the `btrfs-overlayfs` hook that needs `limine-snapper-sync`,
sets trackpad defaults, and adds around 19 files including an `asahi-alarm`
pacman mirrorlist. Rebuild both by hand from the fork; do not remove their
`skip`.

`herdr` currently fails to build anywhere: its PKGBUILD pins `zig0.15`, which
Arch dropped from `[extra]` on the move to `zig 0.16`. It is left to fail
visibly rather than carrying a from-source Zig toolchain build, and
`fail-fast: false` stops it blocking anything else.

`hyprland-preview-share-picker-git` is a VCS package whose AUR `pkgver` is
stale by construction, so a version diff can never trigger it. It rebuilds on a
7-day timer measured from `%BUILDDATE%` in the published db.

[`packages.json`](packages.json) records which group each package belongs to and
where its PKGBUILD comes from — the AUR for most, `omacom-io/omarchy-pkgs` for
the five that aren't in the AUR, and this repo's own `pkgbuilds/` for
`obs-studio`. The source is per-package on purpose: for
`omarchy-emacs` the AUR leads Omarchy's own repo, so switching it would be a
downgrade.

Builds run on `ubuntu-24.04-arm`, which is free for public repos; detection and
publishing run on x86, since neither `vercmp` nor `repo-add` cares about the
target architecture.

Every build needs a real aarch64 environment. Forcing `CARCH=aarch64` inside an
x86 container looks like it ought to work for the repacks — they only unpack a
binary someone else built — but several of those PKGBUILDs execute the ARM
binary while packaging it. `mise-bin` runs `mise completion` three times to
generate its shell completions. Emulating aarch64 on an x86 runner does work,
but a free native ARM runner makes it pointless.

Publishing is ordered so the repo is never internally inconsistent: package
assets upload first, then the four db files with `.db` last, and only then are
superseded package assets deleted. A package whose version carries an epoch is
renamed before `repo-add` sees it, because a GitHub release asset cannot contain
a `:` — the db records `1:1.93.138-1` as the version but
`brave-origin-bin-1.1.93.138-1-aarch64.pkg.tar.xz` as the filename.

Running it by hand:

```bash
gh workflow run update-packages.yml                        # everything in scope
gh workflow run update-packages.yml -f packages=mise-bin   # one package
gh workflow run update-packages.yml -f dry_run=true        # build, verify, publish nothing
```

[`scripts/self-test.sh`](scripts/self-test.sh) covers the parts that would fail
quietly rather than loudly — epoch filename handling, reading a package's name
from its `.PKGINFO`, the ELF audit and its allowances, and repo db parsing. It
is offline, takes a couple of seconds, and runs on every push and pull request.
A failed scheduled run opens an issue rather than only turning a run red.

The scripts under [`scripts/`](scripts) are plain bash and run outside CI too.
`scripts/smoke-test.sh` is the useful one on its own: it syncs the published repo
the way pacman does and checks that every package the db advertises is actually
fetchable.

## Building these yourself

Omarchy's own packages:

```bash
git clone https://github.com/omacom-io/omarchy-pkgs
cd omarchy-pkgs
./bin/build --arch aarch64 --package omacalc omacut omawrite
```

Requires Docker. On an x86_64 host it sets up QEMU automatically; on ARM it
builds natively. Each of these takes well under a minute.

Everything else comes from the AUR — clone the package and run `makepkg`.
Packages marked `arch=('any')` need no rebuild at all; the AUR artifact works
on ARM unchanged.
