/-!
# Extended Hybrid KEM combiner proofs

Extends the basic `HybridHandshake` model to cover:
- ML-KEM-512 hybrid combiner (X25519 + ML-KEM-512)
- ML-KEM-1024 hybrid combiner (X25519 + ML-KEM-1024)
- CLI-level invariants from `smp-pqc-core::kem::run` and `run_hybrid`

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

/-- Report mirrors `HybridKemReport` from `smp-pqc-core`. -/
structure HybridReport where
  iterations : Nat
  successes : Nat
  failures : Nat
  combinedSecretLen : Nat

def initialHybridReport : HybridReport :=
  { iterations := 0, successes := 0, failures := 0, combinedSecretLen := 0 }

/-- One step of the fold in `run_hybrid`'s loop body. -/
def foldHybrid (r : HybridReport) (it : HybridIteration) : HybridReport :=
  { iterations := r.iterations + 1,
    successes := r.successes + (if it.classicalOk && it.pqOk then 1 else 0),
    failures := r.failures + (if it.classicalOk && it.pqOk then 0 else 1),
    combinedSecretLen := if it.classicalOk && it.pqOk then 64 else r.combinedSecretLen }

/-- Folds over all iterations. -/
def runHybridReport (iterations : List HybridIteration) : HybridReport :=
  iterations.foldl foldHybrid initialHybridReport

/-- The combiner logic is algorithm-agnostic: it only depends on `classicalOk && pqOk`. -/
theorem foldHybrid_algorithm_agnostic (r : HybridReport) (it1 it2 : HybridIteration) :
    it1.classicalOk = it2.classicalOk → it1.pqOk = it2.pqOk →
    (foldHybrid r it1).successes = (foldHybrid r it2).successes := by
  intro hc hp
  simp only [foldHybrid, HybridReport.mk.injEq] at *
  <;> split_ifs <;> simp_all [hc, hp]
  <;> norm_num
  <;> omega

/-- `successes + failures = iterations` invariant holds for every fold step. -/
theorem foldHybrid_inv (r : HybridReport) (it : HybridIteration) :
    r.successes + r.failures = r.iterations →
    (foldHybrid r it).successes + (foldHybrid r it).failures = (foldHybrid r it).iterations := by
  intro h
  simp only [foldHybrid, HybridReport.mk.injEq] at *
  <;> split_ifs <;> simp_all [Nat.add_assoc]
  <;> ring_nf at *
  <;> omega

/-- The invariant holds for the full run. -/
theorem runHybridReport_inv (iterations : List HybridIteration) :
    (runHybridReport iterations).successes + (runHybridReport iterations).failures = (runHybridReport iterations).iterations := by
  have h : ∀ (r : HybridReport) (ls : List HybridIteration), r.successes + r.failures = r.iterations → (ls.foldl foldHybrid r).successes + (ls.foldl foldHybrid r).failures = (ls.foldl foldHybrid r).iterations := by
    intro r
    induction' ls with hd tl ih generalizing r
    · simp
    · have h₁ := foldHybrid_inv r hd
      have h₂ := ih (foldHybrid r hd)
      simp [foldHybrid] at h₁ h₂ ⊢
      <;> split_ifs at h₁ h₂ ⊢ <;>
      (try omega) <;>
      (try simp_all [HybridReport.mk.injEq]) <;>
      (try ring_nf at * <;> omega) <;>
      (try omega)
  have h₁ := h initialHybridReport iterations
  simp [runHybridReport] at h₁ ⊢
  <;> simp_all [initialHybridReport]
  <;> norm_num
  <;> omega

/-- `combinedSecretLen` is 64 when there's at least one success, 0 otherwise. -/
theorem combined_secret_len_correct (iterations : List HybridIteration) :
    (runHybridReport iterations).combinedSecretLen = 64 ↔ (runHybridReport iterations).successes > 0 := by
  have h : ∀ (r : HybridReport) (ls : List HybridIteration),
    (ls.foldl foldHybrid r).combinedSecretLen = 64 ↔ (ls.foldl foldHybrid r).successes > 0 := by
    intro r
    induction' ls with hd tl ih generalizing r
    · simp [foldHybrid]
    · have h₁ := ih (foldHybrid r hd)
      simp [foldHybrid, HybridReport.mk.injEq] at h₁ ⊢
      <;> split_ifs <;> simp_all [Nat.succ_eq_add_one, Nat.pos_iff_ne_zero]
      <;> omega
  have h₁ := h initialHybridReport iterations
  simp [runHybridReport] at h₁ ⊢
  <;> simp_all [initialHybridReport]
  <;> norm_num

end SmpPqcVerify.ExtendedHybrid