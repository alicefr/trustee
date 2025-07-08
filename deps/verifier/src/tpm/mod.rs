use crate::{InitDataHash, ReportData};
use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{TeeClass, TeeEvidence, TeeEvidenceParsedClaim, Verifier};
pub mod parse;

#[derive(Debug, Default)]
pub struct TpmVerifier {}

#[derive(Serialize, Deserialize, Debug)]
struct Evidence {
    attest: parse::SerializableAttest,
    signature: parse::SerializableSignature,
}

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let evidence = serde_json::from_value::<Evidence>(evidence)
            .context("Failed to deserialize TPM evidence")?;

        let claims = parse_evidence(&evidence.attest)?;
        Ok((claims, "tpm".to_string()))
    }
}
pub(crate) fn parse_evidence(report: &parse::SerializableAttest) -> Result<TeeEvidenceParsedClaim> {
    let quote = match &report.attested {
        parse::SerializableAttestInfo::Quote { info } => info,
        _ => bail!("failed to parse attestation"),
    };
    let claims = json!({
        "pcr-selection": quote.pcr_selection,
        "pcr-digest": quote.pcr_digest,
    });
    Ok(claims as TeeEvidenceParsedClaim)
}
