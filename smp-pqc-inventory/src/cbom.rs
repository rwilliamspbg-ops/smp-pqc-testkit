//! CycloneDX-shaped cryptography bill of materials (CBOM) generation.
//!
//! This covers the core `cryptographic-asset` component fields (asset type,
//! algorithm primitive) plus the generic `properties` extension mechanism
//! (used for this project's own category/PQC-capability/note metadata,
//! which isn't part of the standard schema). It has not been run through a
//! formal CycloneDX schema validator -- treat it as CycloneDX-shaped and
//! CycloneDX-inspired, not as a certified-conformant document.

use crate::classify::{classify, CryptoCategory};
use crate::lockfile::LockedPackage;
use serde::Serialize;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

#[derive(Serialize)]
pub struct CbomDocument {
    #[serde(rename = "bomFormat")]
    pub bom_format: &'static str,
    #[serde(rename = "specVersion")]
    pub spec_version: &'static str,
    #[serde(rename = "serialNumber")]
    pub serial_number: String,
    pub version: u32,
    pub metadata: Metadata,
    pub components: Vec<Component>,
}

#[derive(Serialize)]
pub struct Metadata {
    pub timestamp: String,
    pub tools: Tools,
}

#[derive(Serialize)]
pub struct Tools {
    pub components: Vec<ToolComponent>,
}

#[derive(Serialize)]
pub struct ToolComponent {
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Serialize)]
pub struct Component {
    #[serde(rename = "bom-ref")]
    pub bom_ref: String,
    #[serde(rename = "type")]
    pub type_: &'static str,
    pub name: String,
    pub version: String,
    #[serde(rename = "cryptoProperties")]
    pub crypto_properties: CryptoProperties,
    pub properties: Vec<Property>,
}

#[derive(Serialize)]
pub struct CryptoProperties {
    #[serde(rename = "assetType")]
    pub asset_type: &'static str,
    #[serde(
        rename = "algorithmProperties",
        skip_serializing_if = "Option::is_none"
    )]
    pub algorithm_properties: Option<AlgorithmProperties>,
}

#[derive(Serialize)]
pub struct AlgorithmProperties {
    pub primitive: &'static str,
}

#[derive(Serialize)]
pub struct Property {
    pub name: &'static str,
    pub value: String,
}

fn asset_type_and_primitive(category: CryptoCategory) -> (&'static str, Option<&'static str>) {
    match category {
        CryptoCategory::KeyExchange => ("algorithm", Some("kem")),
        CryptoCategory::Signature => ("algorithm", Some("signature")),
        CryptoCategory::SymmetricCipher => ("algorithm", Some("cipher")),
        CryptoCategory::HashFunction => ("algorithm", Some("hash")),
        CryptoCategory::Mac => ("algorithm", Some("mac")),
        CryptoCategory::RandomNumberGenerator => ("algorithm", Some("drbg")),
        CryptoCategory::SecureProtocol => ("protocol", None),
        CryptoCategory::CryptoUtility => ("related-material", None),
    }
}

/// Build a CBOM containing only crates recognized as cryptographic (or
/// crypto-adjacent) by [`classify`]. Non-cryptographic dependencies are
/// deliberately omitted -- a CBOM is about cryptographic assets, not the
/// full dependency tree (see `smp-pqc inventory` without `--cbom` for a
/// full listing that also reports what wasn't classified).
pub fn build_cbom(packages: &[LockedPackage]) -> CbomDocument {
    let mut components: Vec<Component> = packages
        .iter()
        .filter_map(|pkg| {
            let classification = classify(&pkg.name)?;
            let (asset_type, primitive) = asset_type_and_primitive(classification.category);
            Some(Component {
                bom_ref: format!("{}@{}", pkg.name, pkg.version),
                type_: "cryptographic-asset",
                name: pkg.name.clone(),
                version: pkg.version.clone(),
                crypto_properties: CryptoProperties {
                    asset_type,
                    algorithm_properties: primitive.map(|p| AlgorithmProperties { primitive: p }),
                },
                properties: vec![
                    Property {
                        name: "smp-pqc:category",
                        value: format!("{:?}", classification.category),
                    },
                    Property {
                        name: "smp-pqc:is-post-quantum-capable",
                        value: classification.is_post_quantum_capable.to_string(),
                    },
                    Property {
                        name: "smp-pqc:note",
                        value: classification.note.to_string(),
                    },
                ],
            })
        })
        .collect();
    components.sort_by(|a, b| a.name.cmp(&b.name).then(a.version.cmp(&b.version)));

    CbomDocument {
        bom_format: "CycloneDX",
        spec_version: "1.6",
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: Metadata {
            timestamp: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string()),
            tools: Tools {
                components: vec![ToolComponent {
                    type_: "application",
                    name: "smp-pqc-inventory",
                    version: env!("CARGO_PKG_VERSION"),
                }],
            },
        },
        components,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lockfile::parse_lockfile;

    // Same bundled real-world lockfile snapshot as lockfile.rs's tests --
    // see that module's `SAMPLE_LOCKFILE` doc comment for why this isn't
    // reached via a `../` path into the parent workspace.
    const SAMPLE_LOCKFILE: &str = include_str!("../tests/fixtures/sample-workspace-cargo-lock.txt");

    fn workspace_packages() -> Vec<LockedPackage> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("Cargo.lock");
        std::fs::write(&path, SAMPLE_LOCKFILE).expect("write fixture");
        parse_lockfile(&path).expect("parse sample Cargo.lock")
    }

    #[test]
    fn cbom_only_contains_classified_crypto_assets() {
        let packages = workspace_packages();
        let total = packages.len();
        let cbom = build_cbom(&packages);
        assert!(
            cbom.components.len() < total,
            "should filter out non-crypto deps"
        );
        assert!(!cbom.components.is_empty());
        for c in &cbom.components {
            assert_eq!(c.type_, "cryptographic-asset");
        }
    }

    #[test]
    fn cbom_detects_our_own_pqc_crates() {
        let packages = workspace_packages();
        let cbom = build_cbom(&packages);
        for expected in ["ml-kem", "ml-dsa", "slh-dsa"] {
            let component = cbom
                .components
                .iter()
                .find(|c| c.name == expected)
                .unwrap_or_else(|| panic!("{expected} should appear in the CBOM"));
            let pqc_prop = component
                .properties
                .iter()
                .find(|p| p.name == "smp-pqc:is-post-quantum-capable")
                .unwrap();
            assert_eq!(pqc_prop.value, "true");
        }
    }

    #[test]
    fn cbom_serializes_to_valid_json_with_expected_top_level_shape() {
        let packages = workspace_packages();
        let cbom = build_cbom(&packages);
        let json = serde_json::to_value(&cbom).unwrap();
        assert_eq!(json["bomFormat"], "CycloneDX");
        assert_eq!(json["specVersion"], "1.6");
        assert!(json["serialNumber"]
            .as_str()
            .unwrap()
            .starts_with("urn:uuid:"));
        assert!(!json["components"].as_array().unwrap().is_empty());
    }

    #[test]
    fn cbom_is_deterministic_given_the_same_input_modulo_timestamp_and_serial() {
        let packages = workspace_packages();
        let a = build_cbom(&packages);
        let b = build_cbom(&packages);
        let names_a: Vec<_> = a.components.iter().map(|c| &c.name).collect();
        let names_b: Vec<_> = b.components.iter().map(|c| &c.name).collect();
        assert_eq!(names_a, names_b, "component ordering should be stable");
    }
}
