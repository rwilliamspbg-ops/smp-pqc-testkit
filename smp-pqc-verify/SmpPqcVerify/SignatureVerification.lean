/-!
# Signature test aggregation: "all passed" can't hide a bad iteration

Models the per-iteration accounting in `smp-pqc-core::sig::run`
(`smp-pqc-core/src/sig.rs`): each iteration produces a genuine-message
verification result and a tampered-message rejection result, and these are
accumulated into a `SigReport` with `verify_failures`/`tamper_acceptances`
counters. `SigReport::all_passed` is `verify_failures == 0 && tamper_acceptances == 0`.

The property proved here: if the aggregate report says "all passed", then
*every single iteration* both verified genuinely and rejected its tampered
counterpart -- summing counts to zero can't be satisfied by, say, one
iteration failing and cancelling out (counts here only ever increase, so
there's nothing to cancel, but that's exactly the kind of accounting bug
this proof rules out for good, rather than by inspection).
-/

namespace SmpPqcVerify.SignatureVerification

/-- One iteration's outcome, mirroring the two booleans computed per
iteration in `sig::run`. -/
structure IterationOutcome where
  verifies : Bool
  rejectsTamper : Bool
deriving DecidableEq

/-- Mirrors the two counters on `SigReport` that `all_passed` checks. -/
structure Report where
  verifyFailures : Nat
  tamperAcceptances : Nat

def initialReport : Report := { verifyFailures := 0, tamperAcceptances := 0 }

/-- One step of the fold in `sig::run`'s loop body. -/
def foldOutcome (r : Report) (o : IterationOutcome) : Report :=
  { verifyFailures := r.verifyFailures + (if o.verifies then 0 else 1),
    tamperAcceptances := r.tamperAcceptances + (if o.rejectsTamper then 0 else 1) }

/-- Mirrors `sig::run` folding over all iterations. -/
def runReport (outcomes : List IterationOutcome) : Report :=
  outcomes.foldl foldOutcome initialReport

/-- Mirrors `SigReport::all_passed`. -/
def allPassed (r : Report) : Bool :=
  r.verifyFailures == 0 && r.tamperAcceptances == 0

/-- Folding never decreases either counter -- both only ever get `+= 1` or
`+= 0`. This is the key lemma the main theorem rests on. -/
theorem foldOutcome_counters_monotone (r : Report) (o : IterationOutcome) :
    r.verifyFailures ≤ (foldOutcome r o).verifyFailures ∧
      r.tamperAcceptances ≤ (foldOutcome r o).tamperAcceptances := by
  constructor <;> simp [foldOutcome] <;> omega

/-- Folding over any list, starting from any report, never decreases either
counter. Stated with an arbitrary starting report (rather than specifically
`runReport` of some prefix) so it composes cleanly with the main theorem
below without needing list-append reassociation lemmas. -/
theorem foldl_counters_monotone (r : Report) (outcomes : List IterationOutcome) :
    r.verifyFailures ≤ (outcomes.foldl foldOutcome r).verifyFailures ∧
      r.tamperAcceptances ≤ (outcomes.foldl foldOutcome r).tamperAcceptances := by
  induction outcomes generalizing r with
  | nil => simp
  | cons hd tl ih =>
    have step := foldOutcome_counters_monotone r hd
    have rest := ih (foldOutcome r hd)
    exact ⟨Nat.le_trans step.1 rest.1, Nat.le_trans step.2 rest.2⟩

/-- If the whole run reports `all_passed`, then every individual iteration
both verified genuinely and rejected its tampered counterpart. -/
theorem all_passed_implies_every_iteration_ok (outcomes : List IterationOutcome) :
    allPassed (runReport outcomes) = true →
    ∀ o ∈ outcomes, o.verifies = true ∧ o.rejectsTamper = true := by
  intro hpassed o hmem
  obtain ⟨pre, rest, hsplit⟩ := List.append_of_mem hmem
  subst hsplit
  simp only [allPassed, Bool.and_eq_true, beq_iff_eq, runReport, List.foldl_append,
    List.foldl_cons] at hpassed
  obtain ⟨hp1, hp2⟩ := hpassed
  obtain ⟨hmono1, hmono2⟩ :=
    foldl_counters_monotone (foldOutcome (List.foldl foldOutcome initialReport pre) o) rest
  rw [hp1] at hmono1
  rw [hp2] at hmono2
  constructor
  · cases hv : o.verifies with
    | false => exfalso; simp [hv, foldOutcome] at hmono1
    | true => rfl
  · cases hr : o.rejectsTamper with
    | false => exfalso; simp [hr, foldOutcome] at hmono2
    | true => rfl

end SmpPqcVerify.SignatureVerification
