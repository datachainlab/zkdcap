use crate::Result;
use alloy_sol_types::SolValue;
use anyhow::bail;
use core::fmt::Display;
use core::str::FromStr;
use dcap_types::{
    quotes::body::{EnclaveReport, QuoteBody, TD10ReportBody},
    EnclaveIdentityV2TcbStatus, TcbInfoV3TcbStatus, ENCLAVE_REPORT_LEN, SGX_TEE_TYPE,
    TD10_REPORT_LEN, TDX_TEE_TYPE,
};
use serde::{Deserialize, Serialize};
use x509_parser::certificate::Validity;

/// The version of the output format.
pub const QV_OUTPUT_VERSION: u16 = 0;

/// QuoteVerificationOutput is the output of the quote verification process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuoteVerificationOutput {
    /// The version of the output format.
    ///
    /// A verifier of the output must check this version to ensure expected output format.
    pub version: u16,
    /// The format version of the quote that was verified.
    ///
    /// Currently, the supported versions are: 3, 4
    pub quote_version: u16,
    /// The TEE type of the quote that was verified.
    ///
    /// 0x00000000: SGX
    /// 0x00000081: TDX
    pub tee_type: u32,
    /// The status of the quote verification result.
    ///
    /// Please refer to the `Status` values for the details.
    pub status: Status,
    /// Minimum TCB evaluation data number
    ///
    /// This is the minimum TCB evaluation data number of the collateral used for the verification of the quote.
    pub min_tcb_evaluation_data_number: u32,
    /// The FMSPC of the platform that generated the quote.
    pub fmspc: [u8; 6],
    /// A keccak256 hash of Intel Root CA certificate.
    ///
    /// This is corresponding to the Intel Root CA certificate for the collateral to verify the quote.
    pub sgx_intel_root_ca_hash: [u8; 32],
    /// Validity intersection of the collateral
    ///
    /// This is the intersection of the validity periods of all certificates and other QV collateral.
    /// The verifier of the output should check this validity intersection to ensure the overall validity of the collateral.
    pub validity: ValidityIntersection,
    /// The body of the quote that was verified.
    pub quote_body: QuoteBody,
    /// The advisory IDs that are associated with the platform or QE that generated the quote.
    ///
    /// e.g., INTEL-SA-00001, INTEL-SA-00002
    pub advisory_ids: Vec<String>,
}

impl QuoteVerificationOutput {
    /// Serialize the verification output to bytes.
    ///
    /// The serialization format is as follows:
    /// - version: 2 bytes
    /// - quote_version: 2 bytes
    /// - tee_type: 4 bytes
    /// - status: 1 byte
    /// - min_tcb_evaluation_data_number: 4 bytes
    /// - fmspc: 6 bytes
    /// - sgx_intel_root_ca_hash: 32 bytes
    /// - validity.not_before_max: 8 bytes
    /// - validity.not_after_min: 8 bytes
    /// - quote_body: SGX_ENCLAVE_REPORT(384 bytes) or TD10_REPORT(584 bytes)
    /// - advisory_ids: variable length
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output_vec = Vec::new();

        output_vec.extend_from_slice(&self.version.to_be_bytes());
        output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
        output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
        output_vec.push(self.status.as_u8());
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
    ///
    /// Please refer to `to_bytes` for the serialization format.
    pub fn from_bytes(slice: &[u8]) -> Result<QuoteVerificationOutput> {
        let mut version = [0; 2];
        version.copy_from_slice(&slice[0..2]);
        let version = u16::from_be_bytes(version);
        if version != QV_OUTPUT_VERSION {
            bail!("unexpected version: {}", version);
        }
        let mut quote_version = [0; 2];
        quote_version.copy_from_slice(&slice[2..4]);
        let mut tee_type = [0; 4];
        tee_type.copy_from_slice(&slice[4..8]);
        let status = Status::from_u8(slice[8])?;
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
            status,
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

/// Status for quote verification result
///
/// These status values are based on
/// <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h#L66>.
/// However, our implementation does not define some statuses(e.g., STATUS_TCB_NOT_SUPPORTED). If the result corresponds those statuses, our verifier returns an error instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Status {
    /// equivalent to STATUS_OK
    Ok = 0,
    /// equivalent to STATUS_TCB_OUT_OF_DATE
    TcbOutOfDate = 1,
    /// equivalent to STATUS_TCB_REVOKED
    TcbRevoked = 2,
    /// equivalent to STATUS_TCB_CONFIGURATION_NEEDED
    TcbConfigurationNeeded = 3,
    /// equivalent to STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED
    TcbOutOfDateConfigurationNeeded = 4,
    /// equivalent to STATUS_TCB_SW_HARDENING_NEEDED
    TcbSwHardenningNeeded = 5,
    /// equivalent to STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED
    TcbConfigurationAndSwHardenningNeeded = 6,
}

impl Status {
    /// Convert the status to u8
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

    /// Convert u8 to Status
    pub fn from_u8(u: u8) -> Result<Self> {
        Ok(match u {
            0 => Status::Ok,
            1 => Status::TcbOutOfDate,
            2 => Status::TcbRevoked,
            3 => Status::TcbConfigurationNeeded,
            4 => Status::TcbOutOfDateConfigurationNeeded,
            5 => Status::TcbSwHardenningNeeded,
            6 => Status::TcbConfigurationAndSwHardenningNeeded,
            _ => bail!("unrecognized Status: {}", u),
        })
    }

    /// Converge TCB status with QE TCB status
    ///
    /// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L83>
    /// # Arguments
    /// * `tcb_status` - The TCB status of the platform or the status converged from the TCB status of the platform and the TDX module
    /// * `qe_tcb_status` - The TCB status of the QE
    pub fn converge_tcb_status_with_qe_tcb(
        tcb_status: TcbInfoV3TcbStatus,
        qe_tcb_status: EnclaveIdentityV2TcbStatus,
    ) -> Self {
        // NOTE: STATUS_SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED is not defined in our implementation, so we do not handle it here.
        match qe_tcb_status {
            // equivalent to STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
            EnclaveIdentityV2TcbStatus::OutOfDate => {
                if tcb_status == TcbInfoV3TcbStatus::UpToDate
                    || tcb_status == TcbInfoV3TcbStatus::SWHardeningNeeded
                {
                    return Status::TcbOutOfDate;
                } else if tcb_status == TcbInfoV3TcbStatus::ConfigurationNeeded
                    || tcb_status == TcbInfoV3TcbStatus::ConfigurationAndSWHardeningNeeded
                {
                    return Status::TcbOutOfDateConfigurationNeeded;
                }
            }
            // equivalent to STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
            EnclaveIdentityV2TcbStatus::Revoked => return Status::TcbRevoked,
            // equivalent to STATUS_OK
            EnclaveIdentityV2TcbStatus::UpToDate => {}
        }

        match tcb_status {
            TcbInfoV3TcbStatus::UpToDate => Status::Ok,
            TcbInfoV3TcbStatus::SWHardeningNeeded => Status::TcbSwHardenningNeeded,
            TcbInfoV3TcbStatus::ConfigurationNeeded => Status::TcbConfigurationNeeded,
            TcbInfoV3TcbStatus::ConfigurationAndSWHardeningNeeded => {
                Status::TcbConfigurationAndSwHardenningNeeded
            }
            TcbInfoV3TcbStatus::OutOfDate => Status::TcbOutOfDate,
            TcbInfoV3TcbStatus::OutOfDateConfigurationNeeded => {
                Status::TcbOutOfDateConfigurationNeeded
            }
            TcbInfoV3TcbStatus::Revoked => Status::TcbRevoked,
        }
    }
}

impl Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status_str = match self {
            Status::Ok => "UpToDate",
            Status::TcbOutOfDate => "OutOfDate",
            Status::TcbRevoked => "Revoked",
            Status::TcbConfigurationNeeded => "ConfigurationNeeded",
            Status::TcbOutOfDateConfigurationNeeded => "OutOfDateConfigurationNeeded",
            Status::TcbSwHardenningNeeded => "SWHardeningNeeded",
            Status::TcbConfigurationAndSwHardenningNeeded => "ConfigurationAndSWHardeningNeeded",
        };
        write!(f, "{}", status_str)
    }
}

impl FromStr for Status {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Status::Ok,
            "OutOfDate" => Status::TcbOutOfDate,
            "Revoked" => Status::TcbRevoked,
            "ConfigurationNeeded" => Status::TcbConfigurationNeeded,
            "OutOfDateConfigurationNeeded" => Status::TcbOutOfDateConfigurationNeeded,
            "SWHardeningNeeded" => Status::TcbSwHardenningNeeded,
            "ConfigurationAndSWHardeningNeeded" => Status::TcbConfigurationAndSwHardenningNeeded,
            _ => bail!("unrecognized Status: {}", s),
        })
    }
}

/// ValidityIntersection represents the intersection of the validity periods of multiple certificates or other DCAP collaterals.
///
/// This is used to determine the overall validity period of the collaterals that are being verified.
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
