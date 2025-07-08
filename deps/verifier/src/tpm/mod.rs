use log::debug;
use anyhow::*;
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::json;
use base64::Engine;

use super::*;

#[derive(Deserialize, Debug)]
pub struct Evidence {
    pub svn: String,
    pub report_data: String,
    pub tpm_quote: TpmQuote,
}

#[derive(Deserialize, Debug)]
pub struct TpmQuote {
    pub signature: String,
    pub message: String,
    pub pcrs: Vec<String>,
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
        let ev = serde_json::from_value::<Evidence>(evidence)
            .context("Deserialize TPM Evidence failed.")?;
        let tpm_quote = &ev.tpm_quote;

        // 1. Verify the quote signature using AK pubkey (placeholder)
        verify_tpm_quote_signature(tpm_quote)?;

        // 2. Verify the nonce matches expected report_data
        if let ReportData::Value(expected_report_data) = expected_report_data {
            let nonce = base64::engine::general_purpose::STANDARD
                .decode(&ev.report_data)
                .context("base64 decode report_data for TPM evidence")?;
            if *expected_report_data != nonce {
                bail!("TPM quote nonce doesn't match expected report_data");
            }
        }

        // 3. Optionally, verify PCRs (e.g., PCR[8] for init_data_hash)
        if let InitDataHash::Value(expected_init_data_hash) = expected_init_data_hash {
            if tpm_quote.pcrs.len() > 8 {
                let pcr8 = base64::engine::general_purpose::STANDARD
                    .decode(&tpm_quote.pcrs[8])
                    .context("base64 decode PCR[8] for TPM evidence")?;
                if *expected_init_data_hash != pcr8 {
                    bail!("TPM PCR[8] doesn't match expected init_data_hash");
                }
            }
        }

        debug!("TPM Evidence (nested): {:?}", tpm_quote);
        let claims = parse_tpm_evidence(&ev)?;
        Ok((claims, "cpu".to_string()))
    }
}

pub fn verify_tpm_quote_signature(_tpm_quote: &TpmQuote) -> Result<()> {
    // TODO: Implement actual TPM quote signature verification using AK pubkey
    // This is a placeholder for demonstration.
    Ok(())
}

pub fn parse_tpm_evidence(ev: &Evidence) -> Result<TeeEvidenceParsedClaim> {
    let claims_map = json!({
        "svn": ev.svn,
        "report_data": ev.report_data,
        "signature": ev.tpm_quote.signature,
        "message": ev.tpm_quote.message,
        "pcrs": ev.tpm_quote.pcrs,
    });
    Ok(claims_map as TeeEvidenceParsedClaim)
} 