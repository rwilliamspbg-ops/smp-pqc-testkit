# Releasing

## One-time setup (done)

`.github/workflows/publish.yml` publishes `smp-pqc-core`, `smp-pqc-network`,
`smp-pqc-inventory`, and `smp-pqc-cli` to crates.io automatically when a
`vX.Y.Z` tag is pushed. It needs a **`CARGO_REGISTRY_TOKEN` repository
secret** — a crates.io API token with publish rights for these crate names
— added under the repo's Settings → Secrets and variables → Actions.
**This secret is already set on this repo** (confirmed via `gh secret
list`), so pushing a `vX.Y.Z` tag really does publish to crates.io -- it
is not a dry run. Double-check the version bump and CHANGELOG before
tagging; there is no "undo" once a version is live (crates.io only
supports yanking, which doesn't remove the version from the index, just
discourages new dependents from resolving to it).

`smp-pqc-bench` is `publish = false` (bench-only, no library — nothing for
a consumer to depend on) and is never published. `smp-pqc-verify` is a Lean
4 project, not a Cargo crate, and isn't part of this at all.

## Cutting a release

1. Bump the version in the **one place** that matters:
   `[workspace.package].version` in the root `Cargo.toml`. Every crate
   inherits it via `version.workspace = true`.
2. Update the matching path-dependency version pins in
   `smp-pqc-cli/Cargo.toml` (`smp-pqc-core`, `smp-pqc-network`,
   `smp-pqc-inventory` each have a `version = "..."` that must equal the
   new version — the publish workflow checks this and fails loudly if it
   drifts, rather than silently publishing a `smp-pqc-cli` that declares
   the wrong dependency version).
3. Add a new section to `CHANGELOG.md`, moving `[Unreleased]`'s contents
   under the new version heading with today's date, in the same style as
   the existing `[0.1.0]` entry.
4. Run the full local verification pass before tagging (matches what CI
   checks, run here first so a red CI run doesn't happen on a pushed tag).
   `just release-check` runs all of this in one shot:
   ```bash
   cargo build --workspace --all-targets --locked
   cargo test --workspace --locked
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo doc --workspace --no-deps
   cargo deny check
   (cd smp-pqc-verify && lake build)
   ```
   Also worth a manual check before a major release: CI's `msrv` job
   pins an exact toolchain (see `rust-version` in the root `Cargo.toml`)
   that isn't covered by the commands above unless you have it installed
   locally (`just msrv`).
5. Commit (`Release vX.Y.Z` or similar), then tag and push:
   ```bash
   git tag -a vX.Y.Z -m "vX.Y.Z - <one-line summary>"
   git push origin main
   git push origin vX.Y.Z
   ```
6. If the `CARGO_REGISTRY_TOKEN` secret is set, pushing the tag triggers
   `.github/workflows/publish.yml`, which publishes in dependency order
   (`smp-pqc-core` → `smp-pqc-network`/`smp-pqc-inventory` → `smp-pqc-cli`,
   with short waits between stages for crates.io's index to catch up).
   Watch the Actions run; a failure partway through (e.g. a transient
   registry issue) is safe to fix and re-run via `workflow_dispatch` --
   `cargo publish` on an already-published version just fails cleanly
   rather than double-publishing.
7. Optionally create a GitHub Release from the tag (`gh release create
   vX.Y.Z --title "..." --notes-file CHANGELOG.md`, trimmed to the new
   section) — this is separate from the crates.io publish and doesn't
   happen automatically.

## Why one workspace version instead of independent per-crate versions

All four published crates share `[workspace.package].version`, so a single
bump moves all of them together. This trades away independent versioning
(you can't bump just `smp-pqc-network` without also bumping
`smp-pqc-core`) for a much simpler mental model and release process, which
is the right trade for a workspace this size where the crates are
developed and released together anyway.
