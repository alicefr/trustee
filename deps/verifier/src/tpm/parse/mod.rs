use serde::{Deserialize, Serialize};
use tss_esapi::{
    interface_types::{algorithm::HashingAlgorithm, structure_tags::AttestationType},
    structures::{
        Attest, AttestInfo, CertifyInfo, EccSignature, HashAgile, PcrSelection, PcrSelectionList,
        QuoteInfo, RsaSignature, Signature,
    },
    tss2_esys::TPMT_HA,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerializableAttestationType {
    Certify,
    Quote,
    SessionAudit,
    CommandAudit,
    Time,
    Creation,
    Nv,
    NvDigest,
}

impl From<AttestationType> for SerializableAttestationType {
    fn from(value: AttestationType) -> Self {
        match value {
            AttestationType::Certify => Self::Certify,
            AttestationType::Quote => Self::Quote,
            AttestationType::SessionAudit => Self::SessionAudit,
            AttestationType::CommandAudit => Self::CommandAudit,
            AttestationType::Time => Self::Time,
            AttestationType::Creation => Self::Creation,
            AttestationType::Nv => Self::Nv,
            AttestationType::NvDigest => Self::NvDigest,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerializableHashingAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Sm3_256,
    Sha3_256,
    Sha3_384,
    Sha3_512,
    Null,
}

impl From<HashingAlgorithm> for SerializableHashingAlgorithm {
    fn from(value: HashingAlgorithm) -> Self {
        match value {
            HashingAlgorithm::Sha1 => Self::Sha1,
            HashingAlgorithm::Sha256 => Self::Sha256,
            HashingAlgorithm::Sha384 => Self::Sha384,
            HashingAlgorithm::Sha512 => Self::Sha512,
            HashingAlgorithm::Sm3_256 => Self::Sm3_256,
            HashingAlgorithm::Sha3_256 => Self::Sha3_256,
            HashingAlgorithm::Sha3_384 => Self::Sha3_384,
            HashingAlgorithm::Sha3_512 => Self::Sha3_512,
            HashingAlgorithm::Null => Self::Null,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializablePcrSelection {
    hashing_algorithm: SerializableHashingAlgorithm,
    pcr_slot_collection: Vec<u32>,
}

impl From<PcrSelection> for SerializablePcrSelection {
    fn from(value: PcrSelection) -> Self {
        SerializablePcrSelection {
            hashing_algorithm: value.hashing_algorithm().into(),
            pcr_slot_collection: value
                .selected()
                .iter()
                .cloned()
                .map(Into::into)
                .collect::<Vec<u32>>(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct SerializablePcrSelectionList {
    items: Vec<SerializablePcrSelection>,
}

impl From<PcrSelectionList> for SerializablePcrSelectionList {
    fn from(value: PcrSelectionList) -> Self {
        SerializablePcrSelectionList {
            items: value
                .get_selections()
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableQuoteInfo {
    pub pcr_selection: SerializablePcrSelectionList,
    pub pcr_digest: Vec<u8>,
}

impl From<QuoteInfo> for SerializableQuoteInfo {
    fn from(value: QuoteInfo) -> Self {
        SerializableQuoteInfo {
            pcr_selection: value.pcr_selection().clone().into(),
            pcr_digest: value.pcr_digest().value().to_vec(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializableCertifyInfo {
    pub name: Vec<u8>,
    pub qualified_name: Vec<u8>,
}

impl From<CertifyInfo> for SerializableCertifyInfo {
    fn from(value: CertifyInfo) -> Self {
        SerializableCertifyInfo {
            name: value.name().value().to_vec(),
            qualified_name: value.qualified_name().value().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SerializableAttestInfo {
    Certify { info: SerializableCertifyInfo },
    Quote { info: SerializableQuoteInfo },
}

impl From<&AttestInfo> for SerializableAttestInfo {
    fn from(value: &AttestInfo) -> Self {
        match value {
            AttestInfo::Quote { info } => SerializableAttestInfo::Quote {
                info: info.clone().into(), // assuming QuoteInfo implements Clone + Into
            },
            AttestInfo::Certify { info } => SerializableAttestInfo::Certify {
                info: info.clone().into(),
            },
            // TODO add the rest of the type to avoid the panic
            _ => panic!("Unsupported variant in SerializableAttestInfo"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableAttest {
    pub attestation_type: SerializableAttestationType,
    pub qualified_signer: Vec<u8>,
    pub firmware_version: u64,
    pub attested: SerializableAttestInfo,
}

impl From<Attest> for SerializableAttest {
    fn from(value: Attest) -> Self {
        SerializableAttest {
            attestation_type: value.attestation_type().into(),
            qualified_signer: value.qualified_signer().value().to_vec(),
            firmware_version: value.firmware_version(),
            attested: value.attested().into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableRsaSignature {
    hashing_algorithm: SerializableHashingAlgorithm,
    signature: Vec<u8>,
}

impl From<RsaSignature> for SerializableRsaSignature {
    fn from(value: RsaSignature) -> Self {
        SerializableRsaSignature {
            hashing_algorithm: value.hashing_algorithm().into(),
            signature: value.signature().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializableEccSignature {
    hashing_algorithm: SerializableHashingAlgorithm,
    signature_r: Vec<u8>,
    signature_s: Vec<u8>,
}

impl From<EccSignature> for SerializableEccSignature {
    fn from(value: EccSignature) -> Self {
        SerializableEccSignature {
            hashing_algorithm: value.hashing_algorithm().into(),
            signature_r: value.signature_r().to_vec(),
            signature_s: value.signature_s().to_vec(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SerializableSignature {
    RsaSsa(SerializableRsaSignature),
    RsaPss(SerializableRsaSignature),
    EcDsa(SerializableEccSignature),
    EcDaa(SerializableEccSignature),
    Sm2(SerializableEccSignature),
    EcSchnorr(SerializableEccSignature),
    Hmac,
    Null,
}

impl From<Signature> for SerializableSignature {
    fn from(sig: Signature) -> Self {
        match sig {
            Signature::RsaSsa(inner) => SerializableSignature::RsaSsa(inner.into()),
            Signature::RsaPss(inner) => SerializableSignature::RsaPss(inner.into()),
            Signature::EcDsa(inner) => SerializableSignature::EcDsa(inner.into()),
            Signature::EcDaa(inner) => SerializableSignature::EcDaa(inner.into()),
            Signature::Sm2(inner) => SerializableSignature::Sm2(inner.into()),
            Signature::EcSchnorr(inner) => SerializableSignature::EcSchnorr(inner.into()),
            Signature::Hmac(_) => panic!("hmac not supported"), // TODO: methods to get the digest and algorithm aren't public
            Signature::Null => SerializableSignature::Null,
        }
    }
}
