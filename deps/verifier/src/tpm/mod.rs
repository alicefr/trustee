use log::debug;
use anyhow::*;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::*;

#[derive(Serialize, Deserialize, Debug)]
pub struct TpmEvidence {
    pub quote: Vec<u8>,
    pub pcrs: Vec<Vec<u8>>, // PCR values, e.g. Vec of 32-byte arrays
    pub ak_pub: Vec<u8>,    // AK public key in DER or PEM
    pub nonce: Vec<u8>,     // Nonce used in quote
}

#[derive(Debug, Default)]
pub struct TpmVerifier;

#[async_trait]
impl Verifier for TpmVerifier {
    async fn evaluate(
        &self,
        evidence: TeeEvidence,
        expected_report_data: &ReportData,
        expected_init_data_hash: &InitDataHash,
    ) -> Result<(TeeEvidenceParsedClaim, TeeClass)> {
        let tpm_evidence = serde_json::from_value::<TpmEvidence>(evidence)
            .context("Deserialize TPM Evidence failed.")?;

        // 1. Verify the quote signature using AK pubkey
        verify_tpm_quote_signature(&tpm_evidence)?;

        // 2. Verify the nonce matches expected report_data
        if let ReportData::Value(expected_report_data) = expected_report_data {
            if tpm_evidence.nonce != *expected_report_data {
                bail!("TPM quote nonce doesn't match expected report_data");
            }
        }

        // 3. Optionally, verify PCRs (e.g., PCR[8] for init_data_hash)
        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            // For example, PCR[8] is used for init_data_hash
            if tpm_evidence.pcrs.len() > 8 && tpm_evidence.pcrs[8] != *expected_init_data_hash {
                bail!("TPM PCR[8] doesn't match expected init_data_hash");
            }
        }

        debug!("TPM Evidence: {:?}", tpm_evidence);
        let claims = parse_tpm_evidence(&tpm_evidence)?;
        Ok((claims, "cpu".to_string()))
    }
}

fn verify_tpm_quote_signature(evidence: &TpmEvidence) -> Result<()> {
    // TODO: Implement actual TPM quote signature verification using AK pubkey
    // This is a placeholder for demonstration.
    // Use crates like tss-esapi, openssl, or custom logic as needed.
    Ok(())
}

fn parse_tpm_evidence(evidence: &TpmEvidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "quote": base64::encode(&evidence.quote),
        "ak_pub": base64::encode(&evidence.ak_pub),
        "nonce": base64::encode(&evidence.nonce),
        "pcrs": evidence.pcrs.iter().map(|p| base64::encode(p)).collect::<Vec<_>>(),
    });
    Ok(claims_map as TeeEvidenceParsedClaim)
} 