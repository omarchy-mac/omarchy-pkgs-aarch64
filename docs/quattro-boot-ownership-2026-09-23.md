# Coordinated boot helper ownership

The hardware package remains kernel-neutral. `omarchy-mac-boot` now additionally stages runtime boot helpers and lifecycle modules from `packages/omarchy-mac/boot` at the recipe's pinned `_runtime_commit`. Its existing conversion/firmware/first-boot files, replacement metadata and configuration backups stay in this package repository.

The boot release increases from 9 to 10. Schema-4 candidates substitute their exact runtime commit, record both the recipe revision and runtime revision, and require the exact desktop package version. Admission checks require every transferred command/module to have exactly one owner, `omarchy-mac-boot`. A mixed old boot/new desktop candidate is rejected. Schema 3 remains the default; no workflow enables the new profile or publishes packages.

The source tests exercise staging, replacement metadata, marker/first-boot behavior, provenance and ownership rejection. A real package transaction and new-image boot qualification are required before deployment. Future existing-quattro migration must additionally test old installed ownership, source-shadowing files, configuration/migration history and old factory roots; see the companion runtime migration assessment. No migration or repository-trust change is introduced here.
