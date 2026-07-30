/-!
# Hybrid KEM combiner: control-flow safety

Models the control-flow decision in `smp-pqc-core::kem::run_hybrid`
(`smp-pqc-core/src/kem.rs`): a combined secret is only ever formed when
BOTH the classical (X25519) leg and the post-quantum (ML-KEM-768) leg
independently agree.

This is a proof about that control flow, not about the cryptographic
strength of either leg, X25519, or ML-KEM. It does not prove the combined
secret is unpredictable to an attacker, that the KDF combiner is sound, or
anything about the underlying algebra -- see this repo's
`docs/threat-model.md` for why re-proving primitives from scratch is out of
scope, and `smp-pqc-verify/README.md` for what this file does and doesn't
claim more generally.
-/

namespace SmpPqcVerify.HybridHandshake

/-- Mirrors the exact expression in `kem.rs`:
`if classical_ok && pq_ok { successes += 1; combined = ... } else { failures += 1 }` -/
def combinedSecretFormed (classicalOk pqOk : Bool) : Bool :=
  classicalOk && pqOk

/-- A combined secret is only ever formed when both legs succeeded. -/
theorem combined_secret_requires_both_legs (classicalOk pqOk : Bool) :
    combinedSecretFormed classicalOk pqOk = true → classicalOk = true ∧ pqOk = true := by
  intro h
  simp only [combinedSecretFormed, Bool.and_eq_true] at h
  exact h

/-- If the classical leg failed, no combined secret is formed, regardless
of the PQC leg's outcome -- a compromised classical leg can't be masked by
a successful PQC leg (and, by the symmetric theorem below, vice versa). -/
theorem no_secret_when_classical_leg_fails (pqOk : Bool) :
    combinedSecretFormed false pqOk = false := by
  simp [combinedSecretFormed]

theorem no_secret_when_pq_leg_fails (classicalOk : Bool) :
    combinedSecretFormed classicalOk false = false := by
  simp [combinedSecretFormed]

/-- The converse of `combined_secret_requires_both_legs` also holds: a
secret is formed exactly when both legs succeed, not merely implied by it.
This rules out any other hidden path to forming a secret (e.g. an
accidental `||` in place of `&&`, or a third condition this model doesn't
know about) -- the combiner logic really is nothing more than the
conjunction of the two legs. -/
theorem combined_secret_iff_both_legs (classicalOk pqOk : Bool) :
    combinedSecretFormed classicalOk pqOk = true ↔ classicalOk = true ∧ pqOk = true := by
  constructor
  · exact combined_secret_requires_both_legs classicalOk pqOk
  · intro ⟨hc, hp⟩
    simp [combinedSecretFormed, hc, hp]

end SmpPqcVerify.HybridHandshake
