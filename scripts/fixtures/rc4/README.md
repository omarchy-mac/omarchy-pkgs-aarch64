# Historical RC4 catalog

`packages.json` contains the 52 package names from repository commit
`4ec0e47c4e407da96466b1bb1a8736b37066753a`, before `omarchy-steam-fex` was added.
It fixes the test input for the one-shot RC4 old-trust transition. Keep it
unchanged when adding packages to the current catalog.

The bootstrap tests use these names with generated archives and disposable
signing keys. Rolling edge tests continue to use the repository's current
`packages.json`, so new packages participate in their inventory checks.
