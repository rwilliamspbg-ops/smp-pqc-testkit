# Contributing to SMP-PQC-Testkit

Thank you for considering contributing to the SMP-PQC-Testkit! We welcome contributions from the community.

## How to Contribute

There are many ways to contribute to this project:

1. **Report bugs** - If you find a bug, please open an issue with a clear description and steps to reproduce.
2. **Suggest features** - Have an idea for a new feature? Open an issue to discuss it.
3. **Improve documentation** - Help us improve our documentation by fixing typos, adding examples, or writing tutorials.
4. **Fix bugs** - Look for issues labeled `good first issue` or `help wanted` and submit a pull request.
5. **Implement features** - Work on implementing new features from our roadmap or your own ideas.

## Development Setup

To set up your development environment:

1. Fork the repository on GitHub
2. Clone your fork locally:
   ```bash
   git clone https://github.com/your-username/smp-pqc-testkit.git
   ```
3. Install Rust toolchain (if not already installed):
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```
4. Install dependencies. `cargo-deny` and `cargo-llvm-cov` match what CI
   enforces (see `.github/workflows/ci.yml`); `cargo-fuzz`/`cargo-sort` are
   used for the fuzz target and Cargo.toml key ordering, respectively.
   Also install [`just`](https://github.com/casey/just) if you want the
   `justfile` shortcuts below (optional -- every recipe is a thin wrapper
   around a plain `cargo`/`cargo-*` command, so it's not required):
   ```bash
   cd smp-pqc-testkit
   cargo install --locked cargo-fuzz cargo-sort cargo-deny cargo-llvm-cov
   ```
5. Build the project:
   ```bash
   cargo build --workspace
   # or: just build
   ```
6. Run the tests:
   ```bash
   cargo test --workspace
   # or: just test
   ```

This workspace also pins a minimum supported Rust version (MSRV) in
`[workspace.package].rust-version` in the root `Cargo.toml`, checked in CI's
`msrv` job. If you bump a dependency and CI's `msrv` job fails, either avoid
the feature that raised the floor or bump `rust-version` to match (with a
comment explaining what raised it, following the existing one).

## Making Changes

1. Create a new branch for your feature or bugfix:
   ```bash
   git checkout -b feature-or-bugfix-name
   ```
2. Make your changes, ensuring to follow the code style guidelines.
3. Add tests for any new functionality.
4. Ensure all tests pass:
   ```bash
   cargo test --workspace
   ```
5. Format your code with rustfmt:
   ```bash
   cargo fmt --all
   ```
6. Check for clippy warnings:
   ```bash
   cargo clippy --workspace --all-targets -- -D warnings
   ```
7. If you touched dependencies, run the supply-chain gate (RustSec
   advisories, license compliance, banned crates/sources):
   ```bash
   cargo deny check
   ```

   `just release-check` runs steps 4-7 (plus `cargo doc` and the Lean
   proofs) in one shot -- the same set CI enforces on every push.
7. Commit your changes:
   ```bash
   git commit -am "Add feature or fix bug"
   ```
8. Push to your fork:
   ```bash
   git push origin feature-or-bugfix-name
   ```
9. Open a pull request against the `main` branch of the original repository.

## Code Style

We follow the Rust standard formatting rules enforced by `rustfmt`. Please run `cargo fmt` before submitting your code.

We also use `clippy` to catch common mistakes and improve code quality. We aim for zero warnings, so please run `cargo clippy` and fix any warnings before submitting.

## Writing Commit Messages

Please follow these guidelines for commit messages:

- Use the present tense ("Add feature" not "Added feature")
- Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
- Limit the first line to 72 characters or less
- Reference issues and pull requests liberally after the first line
- Consider starting the commit message with an applicable emoji:
  - :art: `:art:` for design/format changes
  - :racehorse: `:racehorse:` for performance improvements
  - :non-potable_water: `:non-potable_water:` for memory leak fixes
  - :memo: `:memo:` for documentation
  - :penguin: `:penguin:` for Linux-specific changes
  - :apple: `:apple:` for macOS-specific changes
  - :checkered_flag: `:checkered_flag:` for Windows-specific changes
  - :bug: `:bug:` for bug fixes
  - :fire: `:fire:` for removing code or files
  - :green_heart: `:green_heart:` for fixing the CI build
  - :white_check_mark: `:white_check_mark:` for adding tests
  - :lock: `:lock:` for fixing security issues
  - :arrow_up: `:arrow_up:` for upgrading dependencies
  - :arrow_down: `:arrow_down:` for downgrading dependencies
  - :shirt: `:shirt:` for removing linter warnings

## Pull Request Process

1. Ensure your code passes all tests and linters.
2. Update the documentation if necessary (README, docstrings, etc.).
3. The PR should have a clear title and description.
4. Keep your PR focused on a single change or feature.
5. Be responsive to feedback and make requested changes promptly.
6. Once approved, a maintainer will merge your PR.

## Reporting Security Issues

Please see our [SECURITY.md](SECURITY.md) file for details on how to report security vulnerabilities.

## Getting Help

If you need help with your contribution, feel free to:
- Ask questions in the issue tracker
- Reach out to maintainers directly
- Look at existing issues and pull requests for examples

Thank you again for your contribution!