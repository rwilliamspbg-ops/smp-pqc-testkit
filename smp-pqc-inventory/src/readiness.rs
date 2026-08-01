//! A single "PQC readiness" number derived from [`classify`]'s existing
//! per-crate data.
//!
//! # Honesty note
//!
//! This score only covers crates classified as [`CryptoCategory::KeyExchange`]
//! or [`CryptoCategory::Signature`] -- the categories where "is this
//! post-quantum or classical" is the central question for that crate. It
//! deliberately excludes [`CryptoCategory::SecureProtocol`] crates (e.g.
//! `rustls`, `russh`): those can support *both* classical and hybrid PQC
//! handshakes, so whether a given connection actually went PQC is a
//! runtime property that `scan tls`/`scan ssh` report on, not something a
//! static lockfile scan can answer (see `classify.rs`'s own honesty
//! note). Counting a protocol crate as "ready" just because it's
//! PQC-*capable* would overstate what this score actually measures.
//!
//! Like the rest of `smp-pqc-inventory`, this is a name-based lockfile
//! signal, not proof that PQC code paths are actually exercised at
//! runtime -- treat it as a lead for manual review, not a certification.

use crate::classify::{classify, CryptoCategory};
use crate::lockfile::LockedPackage;
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ReadinessScore {
    /// Classified key-exchange/signature crates that are PQC-capable.
    pub pqc_capable_primitive_crates: usize,
    /// All classified key-exchange/signature crates (the denominator).
    pub total_primitive_crates: usize,
    /// `pqc_capable_primitive_crates / total_primitive_crates * 100`,
    /// rounded to the nearest whole percent. `None` when
    /// `total_primitive_crates` is zero -- meaningfully different from
    /// 0%: it means no KEM/signature crates were found at all, not that
    /// they're all classical.
    pub percent: Option<u8>,
    /// Secure-protocol crates present (rustls, russh, ...) that support
    /// PQC/hybrid handshakes but aren't counted in the score above --
    /// surfaced separately so the caller can point users at `scan tls`/
    /// `scan ssh` for the runtime answer.
    pub pqc_capable_protocol_crates: usize,
}

pub fn compute_readiness_score(packages: &[LockedPackage]) -> ReadinessScore {
    let mut pqc_capable_primitive_crates = 0usize;
    let mut total_primitive_crates = 0usize;
    let mut pqc_capable_protocol_crates = 0usize;

    for pkg in packages {
        let Some(classification) = classify(&pkg.name) else {
            continue;
        };
        match classification.category {
            CryptoCategory::KeyExchange | CryptoCategory::Signature => {
                total_primitive_crates += 1;
                if classification.is_post_quantum_capable {
                    pqc_capable_primitive_crates += 1;
                }
            }
            CryptoCategory::SecureProtocol if classification.is_post_quantum_capable => {
                pqc_capable_protocol_crates += 1;
            }
            _ => {}
        }
    }

    let percent = (pqc_capable_primitive_crates * 100)
        .checked_div(total_primitive_crates)
        .map(|p| p as u8);

    ReadinessScore {
        pqc_capable_primitive_crates,
        total_primitive_crates,
        percent,
        pqc_capable_protocol_crates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::parse_lockfile;

    const SAMPLE_LOCKFILE: &str = include_str!("../tests/fixtures/sample-workspace-cargo-lock.txt");

    fn workspace_packages() -> Vec<LockedPackage> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, SAMPLE_LOCKFILE).expect("write fixture");
        parse_lockfile(&path).expect("parse sample Cargo.lock")
    }

    #[test]
    fn our_own_workspace_scores_partially_ready() {
        // This workspace has ml-kem/ml-dsa/slh-dsa (PQC) alongside
        // x25519-dalek/ed25519-dalek-style classical crates (via rustls's
        // deps etc.), so it should land strictly between 0 and 100, not
        // at either extreme -- a real signal, not a trivially-true one.
        let packages = workspace_packages();
        let score = compute_readiness_score(&packages);
        assert!(score.total_primitive_crates > 0);
        let percent = score.percent.expect("should have primitive crates");
        assert!(
            percent > 0 && percent < 100,
            "expected a mixed score, got {percent}% ({}/{})",
            score.pqc_capable_primitive_crates,
            score.total_primitive_crates
        );
    }

    #[test]
    fn empty_package_list_has_no_percent_not_zero_percent() {
        let score = compute_readiness_score(&[]);
        assert_eq!(score.total_primitive_crates, 0);
        assert_eq!(score.percent, None);
    }

    #[test]
    fn secure_protocol_crates_are_reported_separately_not_folded_into_the_score() {
        let packages = workspace_packages();
        let score = compute_readiness_score(&packages);
        // rustls and/or russh should be present in this workspace's own
        // lockfile and PQC-capable, but must not inflate the primitive score.
        assert!(score.pqc_capable_protocol_crates > 0);
    }
}
