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

Application sources are unmodified. The Omarchy Mac package pair carries a
small, checked packaging patch described below. Packages come from four places:

- **Omarchy's own repo** ([omacom-io/omarchy-pkgs](https://github.com/omacom-io/omarchy-pkgs)),
  built with that repo's tooling, which already supports ARM:
  `./bin/build --arch aarch64 --package omacalc omacut omawrite`
- **The AUR**, built with `makepkg` from the published PKGBUILD.
- **`any`-architecture packages**, which need no rebuild at all — the AUR
  artifact is reused as-is.
- **In-tree PKGBUILDs** ([`pkgbuilds/`](pkgbuilds), `source: local` in
  `packages.json`), for software that exists nowhere in a form an aarch64
  build can use. `obs-studio` is absent from Arch Linux ARM entirely, and
  every AUR pkgbase hardcodes obsproject's prebuilt CEF browser bundle, which
  is published for x86_64 only; ours builds upstream's unmodified release
  sources with `ENABLE_BROWSER=OFF` — no browser source/dock, everything else
  enabled. `pinta` is Omarchy's default simple image editor, but the AUR
  recipe is `arch=('x86_64')` and hardcodes `linux-x64`; ALARM has none, and
  `ignorearch` on that recipe would still emit x64. Ours is that recipe with
  `arch=('aarch64')` and `linux-arm64`, depending on this repo's
  `dotnet-*-bin` packages rather than Arch extra names that do not exist on
  ARM. `avd-fw` and `libva-v4l2_request-avd` are in no repository at all,
  and together turn on hardware video decode on Apple Silicon.

## Packages

| Package | Version | Provides |
|---------|---------|----------|
| `aether` | 4.29.8-1 | Wallpaper-driven desktop theming |
| `aspnet-runtime-bin` | 10.0.11.sdk400-1 | ASP.NET Core runtime |
| `aspnet-targeting-pack-bin` | 10.0.11.sdk400-1 | ASP.NET Core targeting pack |
| `avd-fw` | 0.1-1 | Apple Video Decoder firmware — H.264/HEVC/VP9 hardware decode |
| `brave-origin-bin` | 1:1.95.101-1 | Minimalist browser from the Brave team |
| `cliamp` | 2.2.0-1 | Retro terminal music player |
| `dotnet-host-bin` | 10.0.11.sdk400-1 | .NET CLI driver |
| `dotnet-runtime-2.1` | 2.1.30.sdk818-1 | .NET Core 2.1 runtime |
| `dotnet-runtime-bin` | 10.0.11.sdk400-1 | .NET runtime |
| `dotnet-sdk-2.1` | 2.1.30.sdk818-1 | .NET Core 2.1 SDK |
| `dotnet-sdk-bin` | 10.0.11.sdk400-1 | .NET SDK |
| `dotnet-targeting-pack-bin` | 10.0.11.sdk400-1 | .NET targeting pack |
| `ghostty` | 1.3.1-1 | Stable terminal emulator |
| `ghostty-nautilus` | 1.3.1-1 | Open in Ghostty extension for GNOME Files |
| `ghostty-shell-integration` | 1.3.1-1 | Ghostty shell integration scripts |
| `ghostty-terminfo` | 1.3.1-1 | `xterm-ghostty` terminal definition |
| `herdr` | 0.8.2-1 | Terminal workspace manager for AI coding agents |
| `hermes-desktop` | 2026.9.7-1 | Native desktop shell for Hermes Agent |
| `hypa-ttfx-bin` | 0.3.1-1 | Hypa terminal text effects |
| `hyprland-preview-share-picker-git` | 0.2.1.r16.g0ef9b30-1 | Share picker with window/monitor previews |
| `libva-v4l2_request-avd` | 1.3-1 | VA-API driver so applications can reach the Apple Video Decoder |
| `localsend` | 1.18.2-1 | Cross-platform AirDrop alternative |
| `mise-bin` | 2026.9.5-1 | Dev tools, env vars, task runner |
| `obs-studio` | 32.2.2-1 | Video recording and live streaming (no browser source) |
| `obsidian-appimage` | 1.13.7-2 | Markdown knowledge base (AppImage) |
| `omacalc` | 0.2.2-1 | Calculator — bound to `SUPER + CTRL + Q` |
| `omacut` | 0.4.0-1 | Video length trimmer |
| `omarchy` | 4.0.2-2 | Omarchy Mac scripts and desktop runtime |
| `omarchy-emacs` | 1.10.1-1 | Emacs theme/font syncing for Omarchy |
| `omarchy-settings` | 4.0.2-2 | Apple Silicon system and user defaults |
| `omarchy-webapp-theme` | 0.3.6-1 | Theme Slack, Discord, GitHub et al. to match Omarchy |
| `omawrite` | 0.5.0-1 | Markdown writing app — bound to `SUPER + SHIFT + W` |
| `openai-codex-desktop` | 26.908.40834-1 | ChatGPT desktop app with Codex |
| `pinta` | 3.1.2-1 | Simple image editor |
| `tensaku` | 0.29.0-1 | Screenshot annotation for Wayland |
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
- **Legacy packages are unsigned.** Hence `SigLevel = Optional TrustAll`, which is what Omarchy's
  own `pacman.conf` uses for its repo. If you'd rather not trust unsigned
  packages, build them yourself: the Omarchy ones with the command below, the
  AUR ones with `makepkg` from their PKGBUILD.
- **Automated.** Scheduled workflows refresh the general package set and the
  fork-owned Omarchy Mac package pair independently. See [Automation](#automation).

## Automation

[`.github/workflows/update-packages.yml`](.github/workflows/update-packages.yml)
runs every six hours. It compares each package's upstream version against the
version in the published db and rebuilds only what moved, so a typical run does
nothing. It never publishes a version older than the one already in the repo,
which is what would make `pacman -Syu` offer you a downgrade.

The packages differ only in where they can be built:

| Group | Count | Automated |
|-------|-------|-----------|
| `any` — `arch=('any')`, architecture-independent | 7 | yes |
| `repack` — ships a vendor-prebuilt ARM binary | 14 | yes |
| `compile` — built from source | 19 | yes |

Two packages stay deliberately excluded from that generic matrix. `omarchy`
and `omarchy-settings` are built as an atomic pair by
[`update-omarchy-mac.yml`](.github/workflows/update-omarchy-mac.yml), which
checks hourly for a new [Omarchy Mac](https://github.com/omarchy-mac/omarchy-mac)
release. It checks out the exact release tag, builds both packages on a native
ARM runner, and refuses to publish unless their versions match and the aarch64
dependency and payload contracts hold. Failures in unrelated AUR packages
therefore cannot block an Omarchy Mac release, and one half of the pair can
never publish by itself.

Before building the pair, `scripts/prepare-omarchy-recipes.sh` applies the
checked-in recipe changes from [upstream PR #341](https://github.com/omacom/omarchy-pkgs/pull/341):
Snapper is required on ARM, and settings packages install the keyboard-backlight
user service when the release source contains it. The patch includes stable and
development recipes, accepts an already-applied patch, and stops on conflicting
upstream changes. Release verification requires Snapper while still rejecting
Limine, and verifies the packaged keyboard service against the release source.
Remove the carried patch once the upstream recipes provide these fixes.

This changes future builds, not existing release assets. Publishing still needs
an appropriately versioned Omarchy Mac release. Desktop CI that checks out
`omacom/omarchy-pkgs` directly does not use this patch automatically.

`ghostty` builds the stable upstream release with its required Zig toolchain,
verified by checksum and used only during the build. Its four split packages
are built together. Each manifest entry excludes the sibling runtime packages
from build-time dependency installation, so the first build does not try to
install its own unpublished output, including when just one split package is
selected. The finished packages retain those runtime dependencies. Manpages
are omitted because `pandoc-cli` is unavailable in Arch Linux ARM.

`herdr` currently fails to build anywhere: its PKGBUILD pins `zig0.15`, which
Arch dropped from `[extra]` on the move to `zig 0.16`. It is left to fail
visibly rather than carrying a from-source Zig toolchain build, and
`fail-fast: false` stops it blocking anything else.

`hermes-desktop` carries the ARM recipe fixes from
[upstream PR #373](https://github.com/omacom/omarchy-pkgs/pull/373) locally.
`scripts/prepare-hermes-recipe.sh` enables `aarch64` and selects Electron's
`linux-arm64-unpacked` output before the generic builder reads the recipe.
It accepts the same fixes already applied upstream and fails on conflicting
recipe changes. The patch preserves upstream's `pkgver` and `pkgrel`, keeping
version detection consistent with the published package. Remove this patch
and its build hook once upstream includes the fixes.

`hyprland-preview-share-picker-git` is a VCS package whose AUR `pkgver` is
stale by construction, so a version diff can never trigger it. It rebuilds on a
7-day timer measured from `%BUILDDATE%` in the published db.

[`packages.json`](packages.json) records which group each package belongs to and
where its PKGBUILD comes from — the AUR for most, `omacom-io/omarchy-pkgs` for
the five that aren't in the AUR, and this repo's own `pkgbuilds/` for
`obs-studio` and `pinta`. The source is per-package on purpose: for
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
gh workflow run update-omarchy-mac.yml -f release_tag=v4.0.2-1 -f dry_run=true
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

## Isolated ARM channels

The `ARM package channels` workflow builds complete managed snapshots for `channel-stable`, `channel-rc`, and `channel-edge`. These are package repository releases, not desktop source branches. The old `edge` release remains a compatibility endpoint for existing stable clients; this workflow never publishes to it or deletes its assets. ALARM and Asahi base repositories remain rolling.

Every snapshot contains the managed ARM overlay and the selected compositor stack plus the ABI dependencies resolved for it, including ALARM providers such as Aquamarine. Both database aliases refer to that same inventory. Unsigned preparation remains available but is explicitly unqualified for publication. Every isolated-channel publication and promotion requires a valid approved signature for every package, including the desktop pair and overlay dependencies. Existing imported signatures and archives are preserved byte-for-byte. The client optional-signature policy is unchanged; this publisher gate does not invent a client trust root or a production signer.

1. Dispatch `operation=build` with exact desktop and recipe SHAs, a channel, package release integer, and a complete baseline release. Source tags are not required. Edge builds produce `omarchy-dev`/`omarchy-settings-dev`; RC and stable builds produce `omarchy`/`omarchy-settings`. The runtime version comes from the selected source commit.
2. Edge refreshes the selected signed compositor dependency transaction. RC/final builds with a `channel-*` baseline preserve those frozen dependencies. To cut RC, build the release pair using `baseline_tag=channel-edge`; development archives are never renamed into release packages.
3. Use the offline signing handoff in [signing/README.md](signing/README.md) for any unsigned packages. It creates a new immutable snapshot with new database/manifest hashes and the original archive/build provenance. Qualify that final signed snapshot using its exact archives, manifest, source/recipe/assembly SHAs and recorded dependency inputs. `operation=publish-signed` ingests a same-repository staging ZIP pinned by ZIP and qualified final manifest hashes. The older `operation=publish` build-run path remains available only for already fully signed, qualified build artifacts; it cannot publish an unsigned build.
4. Build the final version into RC and validate those archives. Dispatch `operation=promote`, `channel=stable`, with the exact qualified RC manifest SHA-256. Promotion copies the same package, signature and database bytes; it never rebuilds them. The source manifest hash prevents a moving RC channel from silently substituting another candidate.

Create the three destination GitHub releases explicitly before the first publication. All new channel publishing jobs share `channel-publish` concurrency. Package archives and signatures upload before the database; a filename already published with different bytes is rejected before mutation. Old package assets remain available for clients holding an older database.

For local/offline preparation, `scripts/channel-snapshot.py prepare --help` documents the required inventory and immutable input SHAs. `verify`, `promote`, and `publish` use the same implementation as CI. Basic `verify` checks preparation integrity and is not a publication approval. Use `verify --require-all-signatures --signature-keyring PUBLIC_KEYRING --approved-signers POLICY_JSON` for the mandatory publication check; `publish` and `promote` always require both explicit trust inputs. Workflow trust comes only from separately approved committed `signing/public-keyring.gpg` and `signing/approved-signers.json`, never from a signature bundle. Those files are intentionally absent until maintainers choose and approve the authority.

The historical published `4.0.2-2` pair can be captured with `--bootstrap --recipe-sha unknown` and its actual source SHA; its missing historical recipe provenance is recorded as null. Such a snapshot is deliberately not eligible for client channel switching. First deploy and qualify a channel-capable stable compatibility package, since the old update helper would reintroduce official edge after a downgrade. Dev activation similarly requires a Mac source checkout containing the channel implementation; a still-old default branch is rejected before changing the client configuration.

The manual channel workflow remains explicitly dispatched. An automatic edge workflow is prepared locally as described below; it is not activated by these local changes. Existing legacy update workflows continue their current jobs. Ordinary stable clients must not be moved to the new URLs until the compatibility stable snapshot is available and tested.

### Local edge planning (not activated)

`python3 scripts/edge-plan.py --baseline channel-manifest.json --desired desired.json` produces a deterministic plan and the captured baseline manifest hash. The desired JSON supplies full `source_sha`, `recipe_sha`, and `publisher_sha`, the calculated development `pkgver` without package release, and a complete `packages` inventory with `name`, `version`, `sha256`, and optional `signature_sha256`. Only relevant managed package identities are compared; unrelated repository database changes do not trigger work. Resolve branch names to immutable commits before invoking it.

Unchanged inputs return `skip`. Source, recipe, or publisher implementation changes return `build`; Arch `vercmp` rejects version regressions, an unchanged version increments the published integer release, and a newer version starts at release 1. Dependency-only changes return `reuse`. Repacked dependency versions, missing managed packages, malformed baselines, and historical bootstrap snapshots are rejected. The first edge plan requires explicit `--bootstrap` against a channel-capable stable manifest; this flag does not assert that hardware qualification happened.

For a reuse plan, invoke the collector with its normal captured database/import arguments, an empty desktop overlay, and `--reuse-edge-manifest channel-manifest.json --source-sha FULL_SHA --recipe-sha FULL_SHA`. The collector requires the database inventory and signatures to match that manifest and source/recipe commits to match the existing desktop build exactly. It downloads the same development archives and signatures, rejects replacement desktop imports/overlays, and records their original `desktop_build` separately from the new snapshot publisher. Snapshot preparation preserves and validates that provenance.

The local `edge-follow.yml` workflow now wires these helpers together. Once reviewed and deployed, its hourly/manual prepare job resolves the configured source and recipe branches, records immutable commits, evaluates the pinned development recipes’ own version functions, and captures both the legacy overlay feed (excluding desktop pairs) and the complete signed compositor dependency closure. Source, recipe, or publisher changes rebuild the development pair. Changed ancillary recipe versions are included; unchanged ancillary archives retain their existing bytes. Dependency downgrades and same-version repacks require manual review.

`edge-execution.py` rejects candidate archives whose pair version, dependency inventory, reuse bytes, or provenance differ from the plan. A separate job runs the pinned source tests against the pinned recipes. Another fresh native ARM container installs the exact staged desktop pair and compositor archives through normal pacman transactions, resolves their dependencies from the staged repository, and checks every selected managed version and the dependency database. Optional mutually exclusive overlay packages are not forced into the same installation. Its qualification report binds the exact manifest and plan hashes. The container image is pinned by digest; installed base versions are recorded because ALARM remains rolling. This is package-install qualification, not M1/M2/M3 session, suspend, audio, or encrypted fresh-install validation.

Only the final job receives write access. It requires both test and installation jobs to succeed, rejects incomplete/unapproved package signing before any write, validates the qualification hashes, takes the shared `channel-publish` lock, and rejects a changed published baseline before publishing exclusively to `channel-edge`. Automatic edge remains incomplete for release use: unsigned builds now fail closed, and there is no production signing adapter or automated signed-artifact requalification stage yet. A chosen signer integration or separately reviewed signed requalification path is still required; rejection of unsigned output is a safeguard, not finished automation. Preparation and installation receive no publishing token. The workflow requires an existing functional channel-edge manifest and cannot bootstrap automatically from legacy edge. The legacy overlay endpoint is read as an input and never modified.

All workflow changes remain local until explicitly approved for deployment. No schedule has been activated and no package has been published by this preparation.
