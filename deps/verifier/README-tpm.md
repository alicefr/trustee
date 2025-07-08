# TPM Verifier for TEE Attestation

## Overview
This module implements a TPM quote verifier for TEE attestation, enabling support for TPM-based attesters. It is designed to work with the `Tpm` variant of the `Tee` enum

## Evidence Format
The expected evidence format for the TPM verifier is a JSON object with the following fields:

```
{
  "quote": <base64-encoded TPM quote bytes>,
  "pcrs": [<base64-encoded PCR0>, <base64-encoded PCR1>, ...],
  "ak_pub": <base64-encoded AK public key (DER or PEM)>,
  "nonce": <base64-encoded nonce used in quote>
}
```

- `quote`: The TPM attestation quote, as produced by the attester.
- `pcrs`: The set of PCR values measured during attestation (typically PCR[8] is used for init data binding).
- `ak_pub`: The Attestation Key public key used to verify the quote signature.
- `nonce`: The nonce/challenge used in the quote, must match the expected report data.

## Verification Steps
1. **Signature Verification**: The quote's signature is verified using the provided AK public key.
2. **Nonce Check**: The nonce in the quote must match the expected report data.
3. **PCR Check**: Optionally, PCR[8] is checked against the expected init data hash.

## Usage
- Enable the `tpm-verifier` feature in the `verifier` and `attestation-service` crates.
- Use the `Tee::Tpm` variant in attestation requests.
- The verifier can be selected automatically via the `to_verifier` function.

## Integration
- The `Tee` enum must include a `Tpm` variant (provided by the patched `kbs-types` crate).
- The `kbs-client` and `kbs` crates support TPM attestation via the `tpm-attester` feature.
- The sample verifier can demonstrate TPM quote verification logic if the feature is enabled.

## References
- TPM attester implementation: [guest-components/tpm branch](https://github.com/bpradipt/guest-components/commits/tpm)
- `kbs-types` crate (patched): [bpradipt/kbs-types/tree/tpm](https://github.com/bpradipt/kbs-types/tree/tpm)

## Example
To use the TPM verifier, ensure your attestation request uses the `Tpm` TEE type and provides evidence in the above format. Enable the `tpm-verifier` feature in your build:

```
cargo build --features tpm-verifier
``` 