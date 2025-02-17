use crate::crypto::keccak256sum;
use crate::{Result, VERIFIER_VERSION};
use alloy_sol_types::SolValue;
use anyhow::bail;
use core::fmt::Display;
use dcap_types::{
    quotes::body::{EnclaveReport, QuoteBody, TD10ReportBody},
    Status, ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE,
};
use x509_parser::certificate::Validity;

/**
 * ValidityIntersection represents the intersection of the validity periods of multiple certificates or other DCAP collaterals.
 *
 * This is used to determine the overall validity period of the collaterals that are being verified.
 */
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidityIntersection {
    /// The maximum not_before seconds timestamp of all certificates
    pub not_before_max: u64,
    /// The minimum not_after seconds timestamp of all certificates
    pub not_after_min: u64,
}

impl Default for ValidityIntersection {
    fn default() -> Self {
        ValidityIntersection {
            not_before_max: 0,
            not_after_min: u64::MAX,
        }
    }
}

impl Display for ValidityIntersection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "(not_before: {}, not_after: {})",
            self.not_before_max, self.not_after_min
        )
    }
}

impl ValidityIntersection {
    /// Create a new ValidityIntersection from a certificate validity.
    pub fn with_certificate(self, certificate_validity: &Validity) -> Result<Self> {
        let not_before = certificate_validity.not_before.timestamp().try_into()?;
        let not_after = certificate_validity.not_after.timestamp().try_into()?;
        Ok(ValidityIntersection {
            not_before_max: self.not_before_max.max(not_before),
            not_after_min: self.not_after_min.min(not_after),
        })
    }

    /// Create a new ValidityIntersection from intersection of two ValidityIntersections.
    pub fn with_other(self, other: Self) -> Self {
        ValidityIntersection {
            not_before_max: self.not_before_max.max(other.not_before_max),
            not_after_min: self.not_after_min.min(other.not_after_min),
        }
    }

    /// Validate the intersection.
    pub fn validate(&self) -> bool {
        self.not_before_max < self.not_after_min
    }

    /// Validate the intersection against the current time.
    ///
    /// * `current_timestamp` - the current time in seconds since the Unix epoch
    pub fn validate_time(&self, current_timestamp: u64) -> bool {
        current_timestamp >= self.not_before_max && current_timestamp <= self.not_after_min
    }

    /// Return Self if valid, otherwise returns the error message
    ///
    /// * `current_timestamp` - the current time in seconds since the Unix epoch
    pub fn validate_or_error(self, current_timestamp: u64) -> Result<Self> {
        if self.validate_time(current_timestamp) {
            Ok(self)
        } else {
            bail!(
                "invalid ValidityIntersection: {} current={}",
                self,
                current_timestamp
            );
        }
    }
}

impl TryFrom<&Validity> for ValidityIntersection {
    type Error = anyhow::Error;

    fn try_from(validity: &Validity) -> Result<Self> {
        let not_before = validity.not_before.timestamp().try_into()?;
        let not_after = validity.not_after.timestamp().try_into()?;
        Ok(ValidityIntersection {
            not_before_max: not_before,
            not_after_min: not_after,
        })
    }
}

/// QuoteVerificationOutput is the output of the quote verification process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteVerificationOutput {
    /// verifier version
    /// length: 2 bytes
    pub version: u16,
    /// QE version
    /// length: 2 bytes
    pub quote_version: u16,
    /// TEE type
    /// length: 4 bytes
    pub tee_type: u32,
    /// TCB status
    /// length: 1 byte
    pub tcb_status: Status,
    /// Minimum TCB evaluation data number
    /// length: 4 bytes
    pub min_tcb_evaluation_data_number: u32,
    /// FMSPC
    /// length: 6 bytes
    pub fmspc: [u8; 6],
    /// SGX Intel Root CA hash (Root of Trust)
    /// length: 32 bytes
    pub sgx_intel_root_ca_hash: [u8; 32],
    /// Validity intersection of the collaterals
    /// length: 16 bytes
    pub validity: ValidityIntersection,
    /// Attestation quote body
    /// variable length: (SGX_ENCLAVE_REPORT = 384; TD10_REPORT = 584)
    pub quote_body: QuoteBody,
    /// Advisory IDs
    /// variable length
    pub advisory_ids: Vec<String>,
}

impl QuoteVerificationOutput {
    /// Calculate the hash of the verification output.
    pub fn hash(&self) -> [u8; 32] {
        keccak256sum(&self.to_bytes())
    }

    /// Serialize the verification output to bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output_vec = Vec::new();

        output_vec.extend_from_slice(&self.version.to_be_bytes());
        output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
        output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
        output_vec.push(self.tcb_status.as_u8());
        output_vec.extend_from_slice(&self.min_tcb_evaluation_data_number.to_be_bytes());
        output_vec.extend_from_slice(&self.fmspc);
        output_vec.extend_from_slice(&self.sgx_intel_root_ca_hash);
        output_vec.extend_from_slice(&self.validity.not_before_max.to_be_bytes());
        output_vec.extend_from_slice(&self.validity.not_after_min.to_be_bytes());

        match self.quote_body {
            QuoteBody::SGXQuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            }
            QuoteBody::TD10QuoteBody(body) => {
                output_vec.extend_from_slice(&body.to_bytes());
            }
        }

        output_vec.extend_from_slice(self.advisory_ids.abi_encode().as_slice());

        output_vec
    }

    /// Deserialize the verification output from bytes.
    pub fn from_bytes(slice: &[u8]) -> Result<QuoteVerificationOutput> {
        let mut version = [0; 2];
        version.copy_from_slice(&slice[0..2]);
        let version = u16::from_be_bytes(version);
        if version != VERIFIER_VERSION {
            bail!("unsupported verifier version: {}", version);
        }
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[2..4]);
        let mut tee_type = [0; 4];
        tee_type.copy_from_slice(&slice[4..8]);
        let tcb_status = Status::from_u8(slice[8])?;
        let mut min_tcb_evaluation_data_number = [0; 4];
        min_tcb_evaluation_data_number.copy_from_slice(&slice[9..13]);
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[13..19]);

        let mut sgx_intel_root_ca_hash = [0; 32];
        sgx_intel_root_ca_hash.copy_from_slice(&slice[19..51]);

        let mut not_before_max = [0; 8];
        not_before_max.copy_from_slice(&slice[51..59]);
        let mut not_after_min = [0; 8];
        not_after_min.copy_from_slice(&slice[59..67]);

        const QUOTE_BODY_OFFSET: usize = 67;
        let (quote_body, advisory_ids_offset) = match u32::from_be_bytes(tee_type) {
            SGX_TEE_TYPE => {
                let raw_quote_body =
                    &slice[QUOTE_BODY_OFFSET..QUOTE_BODY_OFFSET + ENCLAVE_REPORT_LEN];
                (
                    QuoteBody::SGXQuoteBody(EnclaveReport::from_bytes(raw_quote_body)?),
                    QUOTE_BODY_OFFSET + ENCLAVE_REPORT_LEN,
                )
            }
            TDX_TEE_TYPE => {
                let raw_quote_body = &slice[QUOTE_BODY_OFFSET..QUOTE_BODY_OFFSET + TD10_REPORT_LEN];
                (
                    QuoteBody::TD10QuoteBody(TD10ReportBody::from_bytes(raw_quote_body)?),
                    QUOTE_BODY_OFFSET + TD10_REPORT_LEN,
                )
            }
            t => bail!("unknown TEE type: {}", t),
        };

        let advisory_ids = <Vec<String>>::abi_decode(&slice[advisory_ids_offset..], true)?;

        Ok(QuoteVerificationOutput {
            version,
            quote_version: u16::from_be_bytes(quote_version),
            tee_type: u32::from_be_bytes(tee_type),
            tcb_status,
            min_tcb_evaluation_data_number: u32::from_be_bytes(min_tcb_evaluation_data_number),
            fmspc,
            sgx_intel_root_ca_hash,
            validity: ValidityIntersection {
                not_before_max: u64::from_be_bytes(not_before_max),
                not_after_min: u64::from_be_bytes(not_after_min),
            },
            quote_body,
            advisory_ids,
        })
    }
}
