# Aurora package candidate prototype

This is a proposed packaging contribution for Aurora, maintained initially in `omarchy-mac/omarchy-pkgs-aarch64`. It is not an official Aurora release channel. Aurora has not approved release responsibilities or signing ownership. No workflow here signs or publishes the candidate, enables an installed-system update channel, or qualifies hardware.

## Attribution and inputs

The recipes are adapted from Marcelo Alcantara's `maralcbr/omarchy-pkgs` revision `3caea4693df7c472d57809b5c6b05b07579c1f7a`, the source associated with his published Aurora reference set. The kernel recipe also credits the original Asahi package authors Jos Dehaes and Matthias Kurz. `scripts/aurora-candidate-inputs.json` records both the original and adapted file digests. Aurora/Asahi/m1n1 source licensing is retained by the recipes and their installed license files.

The kernel source is `2439016d2e8d3a0d8aebcd243f29604a91f201c9`; m1n1 is `06a4601a351ebfd1abb6abba9a44c34e40d94776` with Marcelo's compatible CIO alias patch. Do not substitute the head of either source branch. The m1n1 source URL currently redirects from Aurora Silicon to `omacom/m1n1`; the source archive checksum remains authoritative.

Adaptations: kernel release `7.1.12.aurora2-7.1` and m1n1 release `1.6.1.aurora1-2.1` distinguish our rebuilt output; the kernel obeys `OMARCHY_BUILD_JOBS`; m1n1 retains the source project's logos rather than embedding Omarchy logos, and its embedded version names a candidate. No Omarchy desktop package is a dependency. These are new binaries requiring independent qualification, not reproductions of Marcelo's tested artifacts.

## Build and inspect

The `Build Aurora candidate` workflow is manually dispatched after merge. Before merge, adding `build-aurora-candidate` to the draft PR explicitly enables the ARM build; further changes to that opted-in PR build new candidates. Removing the label stops future builds. There is no scheduled build. Review the exact PR head before opting in.

The native `ubuntu-24.04-arm` worker resolves the base container tag to a digest once, uses only ALARM repositories, installs build dependencies, and runs makepkg as an unprivileged user with no signing credentials. Runtime dependencies are deferred; all declared build dependencies are checked before makepkg's dependency bypass. The read-only source mount and clean source check prevent accidental build edits from changing the input identity.

The artifact contains three unsigned packages, an input lock, build logs, provenance and a success manifest. A failed attempt may retain partial packages and logs but has no success manifest. The verifier checks recipe digests, native architecture, exact package versions, complete output inventory, matching kernel/header module directories, Apple DTBs, replacement contracts and exclusive file ownership. `.BUILDINFO` must match the recorded installed dependency inventory. Source archives and downloaded Rust toolchain files are hashed after build.

Run `python3 scripts/test-aurora-candidate.py` for pure rejection tests and `python3 scripts/aurora-candidate.py check-inputs` to check recipe inputs. A local build must run inside a disposable native ARM container, never on the installed system; use the workflow as the reference invocation.

## Qualification and promotion

Candidate output is not install-ready. Runtime dependency resolution, installed-package hooks, m1n1/U-Boot/kernel/DTB compatibility, encryption and physical behavior require separate qualification. `runtime_dependency_qualification` is false and `hardware_qualification` is empty until independently recorded evidence exists. No Aurora Mesa is included.

The installer/image consumer belongs in `omacom/omarchy-mac-installer`; kernel-neutral hardware support and Apple boot integration remain in `omacom/omarchy-mac`. Our Asahi candidate and tested build 25 remain available. The first Aurora trial targets Scott's M3, followed by Chris's exact M3 Pro model. It is frozen, invited and disposable: testers must accept that a failure can require Linux reinstallation. Existing-quattro migration retains its separate data-preservation goal.

Before official release work, agree with Aurora on source/compatibility-set approval, release approvers, signing-key ownership, operators, hardware evidence and failure response. A future separate signing job must verify the exact complete retained set, sign packages and repository metadata without rebuilding, and retain one immutable release identity. Promotion chooses a reviewed release; withdrawal prevents future selection without rewriting old artifacts. Test that path using disposable keys before introducing protected production credentials. Do not copy Marcelo's production identities or keys into our installed trust configuration.

## Limits and resources

The builder image digest and installed dependency versions are recorded, but ALARM dependencies are resolved at build time; this is not a reproducible dependency snapshot. Rustup downloads are not vendored, although their resulting toolchain files are hashed. No bit-for-bit reproducibility is claimed. CI retains artifacts for 30 days; copy qualified evidence into durable release storage before treating a candidate as long-lived.

ARM CI avoids dependence on Scott's M4 for compilation. Image assembly and VM testing still need adequate disk space. Do not remove unrelated work or baseline images to make space. This draft is review-only: do not merge, publish or enable updates as part of the prototype.
