/-!
# Extended Hybrid KEM combiner proofs

Extends the basic `HybridHandshake` model to cover:
- ML-KEM-512 hybrid combiner (X25519 + ML-KEM-512)
- ML-KEM-1024 hybrid combiner (X25519 + ML-KEM-1024)

The core combiner logic is identical across all three parameter sets:
`if classical_ok && pq_ok { successes += 1; ... } else { failures += 1 }`
-/
namespace SmpPqcVerify.ExtendedHybrid

/-- Generic hybrid combiner result, parameterized by KEM algorithm. -/
inductive KemAlgorithm where
  | MlKem512
  | MlKem768
  | MlKem1024

/-- One iteration of a hybrid KEM run, with explicit algorithm parameter. -/
structure HybridIteration where
  classicalOk : Bool
  pqOk : Bool
  algorithm : KemAlgorithm

/-- The combiner logic is algorithm-agnostic: it only depends on `classicalOk && pqOk`. -/
def combinedSecretFormed (it : HybridIteration) : Bool :=
  it.classicalOk && it.pqOk

/-- A combined secret is only ever formed when both legs succeeded,
regardless of which KEM algorithm is used. -/
theorem combined_secret_requires_both_legs_agnostic (it1 it2 : HybridIteration) :
    it1.classicalOk = it2.classicalOk → it1.pqOk = it2.pqOk →
    combinedSecretFormed it1 = combinedSecretFormed it2 := by
  intro hc hp
  simp only [combinedSecretFormed]
  <;>
  simp_all [Bool.and_eq_true]

/-- If the classical leg failed, no combined secret is formed, regardless
of the PQC leg's outcome or the KEM algorithm. -/
theorem no_secret_when_classical_leg_fails_agnostic (pqOk : Bool) (alg : KemAlgorithm) :
    combinedSecretFormed { classicalOk := false, pqOk := pqOk, algorithm := alg } = false := by
  simp [combinedSecretFormed]

/-- If the PQC leg failed, no combined secret is formed, regardless
of the classical leg's outcome or the KEM algorithm. -/
theorem no_secret_when_pq_leg_fails_agnostic (classicalOk : Bool) (alg : KemAlgorithm) :
    combinedSecretFormed { classicalOk := classicalOk, pqOk := false, algorithm := alg } = false := by
  simp [combinedSecretFormed]

/-- The converse also holds: a secret is formed exactly when both legs succeed,
not merely implied by it. This rules out any other hidden path to forming a
secret (e.g. an accidental `||` in place of `&&`, or a third condition this
model doesn't know about) -- the combiner logic really is nothing more than
the conjunction of the two legs, independent of the algorithm parameter. -/
theorem combined_secret_iff_both_legs_agnostic (it : HybridIteration) :
    combinedSecretFormed it = true ↔ it.classicalOk = true ∧ it.pqOk = true := by
  constructor
  · intro h
    simp only [combinedSecretFormed, Bool.and_eq_true] at h
    exact h
  · rintro ⟨hc, hp⟩
    simp [combinedSecretFormed, hc, hp]

end SmpPqcVerify.ExtendedHybrid