# Why this exists

There's no shortage of post-quantum cryptography implementations. liboqs
and PQClean between them cover nearly every NIST candidate, in C, with
bindings for a dozen languages. So why build another one?

**This isn't another implementation.** smp-pqc-testkit doesn't implement
ML-KEM, ML-DSA, or SLH-DSA from scratch — it wraps the pure-Rust
RustCrypto crates that already do. What it adds is the layer most PQC
tooling skips: proving the wiring is correct, and telling you what a real
connection actually negotiated instead of what a config file claims it
should negotiate.

Three gaps this project kept running into, that motivated building it:

**"It compiles and round-trips" isn't validation.** A KEM or signature
scheme can pass every internal test a project writes for itself and still
be wrong in a way that matches NIST's spec on the happy path but drifts on
an edge case — a boundary condition in encoding, an RNG misuse, an
implicit-rejection branch that's almost right. `smp-pqc-core/tests/acvp.rs`
runs the wrapped RustCrypto crates against NIST's own ACVP-Server
reference vectors, not just against themselves. That's a categorically
different (and stronger) claim than "our test suite passes."

**Advertised support isn't negotiated support.** A hybrid TLS or SSH
handshake can be configured for PQC and silently fall back to its
classical leg — misconfiguration, a downgrade, a library that offers a
hybrid group but never actually selects it. `smp-pqc-network`'s `scan tls`
and `scan ssh` report the algorithm a connection *actually negotiated*,
by driving a real handshake, not by reading a config file or a server's
advertised cipher suite list.

**Memory safety matters for the tool checking your memory safety.** A test
kit that's itself written in C, linking against C implementations of the
algorithms it's meant to validate, has a harder time claiming it's adding
a safety margin. This project is Rust wrapping Rust — RustCrypto's
implementations, not this project's own unaudited primitive code — and
where it does add its own logic (the hybrid KEM combiner, signature-report
aggregation), that logic is proved control-flow-correct in Lean 4, not
just unit-tested.

**What this project won't pretend to be.** It's not a from-scratch,
independently-audited implementation of the underlying lattice math — no
project this size can honestly claim that, and NIST's ACVP process plus
academic cryptanalysis are what that job actually belongs to. It doesn't
cover every NIST candidate (no Falcon, Classic McEliece, BIKE, HQC) — see
[docs/ROADMAP.md](ROADMAP.md) for why that's a deliberate choice, not an
oversight. And every "not implemented yet" subcommand in the CLI exits
with a specific, honest error instead of faking output — that's not a
minor detail, it's the same principle as the rest of this list applied to
the tool's own UX.

If you need broader algorithm coverage or cross-language bindings, liboqs
is the right tool — see [docs/comparison.md](comparison.md) for the full
picture. If you're already building on RustCrypto and want confidence
that ML-KEM/ML-DSA/SLH-DSA are wired correctly, that a handshake really
went PQC, and that your dependency tree's crypto posture is visible — this
is what that looks like.
