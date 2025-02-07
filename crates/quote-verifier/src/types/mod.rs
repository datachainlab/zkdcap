use core::fmt::Display;
use std::str::FromStr;

use self::quotes::body::*;
use crate::{
    constants::{
        ENCLAVE_REPORT_LEN, SGX_TEE_TYPE, TD10_REPORT_LEN, TDX_TEE_TYPE, VERIFIER_VERSION,
    },
    utils::hash::keccak256sum,
    Result,
};
use alloy_sol_types::SolValue;
use anyhow::bail;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::Validity;

pub mod cert;
pub mod collaterals;
pub mod crl;
pub mod enclave_identity;
pub mod quotes;
pub mod tcbinfo;

/*
tcbStatus:
    type: string
    enum:
        - UpToDate
        - OutOfDate
        - Revoked
    description: >-
        TCB level status. One of the following values:

        "UpToDate" - TCB level of the SGX platform is up-to-date.

        "OutOfDate" - TCB level of SGX platform is outdated.

        "Revoked" - TCB level of SGX platform is revoked.
        The platform is not trustworthy.
 */
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveIdentityV2TcbStatus {
    UpToDate,  // equivalent to STATUS_OK
    OutOfDate, // equivalent to STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
    Revoked,   // equivalent to STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
}

impl EnclaveIdentityV2TcbStatus {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Self::UpToDate,
            "OutOfDate" => Self::OutOfDate,
            "Revoked" => Self::Revoked,
            _ => bail!("unrecognized EnclaveIdentityV2TcbStatus: {}", s),
        })
    }
}

/*
// TcbInfoV3
tcbStatus:
    type: string
    enum:
        - UpToDate
        - SWHardeningNeeded
        - ConfigurationNeeded
        - ConfigurationAndSWHardeningNeeded
        - OutOfDate
        - OutOfDateConfigurationNeeded
        - Revoked
    description: >-
        TCB level status. One of the following values:

        "UpToDate" - TCB level of the SGX platform is up-to-date.

        "SWHardeningNeeded" - TCB level of the SGX platform
        is up-to-date but due to certain issues affecting the
        platform, additional SW Hardening in the attesting
        SGX enclaves may be needed.

        "ConfigurationNeeded" - TCB level of the SGX platform
        is up-to-date but additional configuration of SGX
        platform may be needed.

        "ConfigurationAndSWHardeningNeeded" - TCB level of the
        SGX platform is up-to-date but additional configuration
        for the platform and SW Hardening in the attesting SGX
        enclaves may be needed.

        "OutOfDate" - TCB level of SGX platform is outdated.

        "OutOfDateConfigurationNeeded" - TCB level of SGX
        platform is outdated and additional configuration
        of SGX platform may be needed.

        "Revoked" - TCB level of SGX platform is revoked.
        The platform is not trustworthy.
 */
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcbInfoV3TcbStatus {
    UpToDate,
    SWHardeningNeeded,
    ConfigurationNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDate,
    OutOfDateConfigurationNeeded,
    Revoked,
}

impl TcbInfoV3TcbStatus {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Self::UpToDate,
            "SWHardeningNeeded" => Self::SWHardeningNeeded,
            "ConfigurationNeeded" => Self::ConfigurationNeeded,
            "ConfigurationAndSWHardeningNeeded" => Self::ConfigurationAndSWHardeningNeeded,
            "OutOfDate" => Self::OutOfDate,
            "OutOfDateConfigurationNeeded" => Self::OutOfDateConfigurationNeeded,
            "Revoked" => Self::Revoked,
            _ => bail!("unrecognized TcbInfoV3TcbStatus: {}", s),
        })
    }
}

/*
tcbStatus:
    type: string
    enum:
        - UpToDate
        - OutOfDate
        - Revoked
    description: >-
        TCB level status. One of the following values:

        "UpToDate" - TCB level of the TDX SEAM Module is up-to-date.

        "OutOfDate" - TCB level of TDX SEAM Module is outdated.

        "Revoked" - TCB level of TDX SEAM Module is revoked.
        The platform is not trustworthy.
*/
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TdxModuleTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}

impl TdxModuleTcbStatus {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Self::UpToDate,
            "OutOfDate" => Self::OutOfDate,
            "Revoked" => Self::Revoked,
            _ => bail!("unrecognized TdxModuleTcbStatus: {}", s),
        })
    }
}

impl From<TdxModuleTcbStatus> for TdxModuleTcbValidationStatus {
    fn from(status: TdxModuleTcbStatus) -> Self {
        match status {
            TdxModuleTcbStatus::UpToDate => TdxModuleTcbValidationStatus::Ok,
            TdxModuleTcbStatus::OutOfDate => TdxModuleTcbValidationStatus::TcbOutOfDate,
            TdxModuleTcbStatus::Revoked => TdxModuleTcbValidationStatus::TcbRevoked,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TdxModuleTcbValidationStatus {
    Ok,
    TdxModuleMismatch,
    TcbOutOfDate,
    TcbRevoked,
    TcbConfigurationNeeded,
    TcbOutOfDateConfigurationNeeded,
    TcbNotSupported,
    TcbUnrecognizedStatus,
}

/// ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/10176d4833d72d34f287d00a27c63d757a3c1f99/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h#L66
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum Status {
    Ok = 0,
    TcbOutOfDate = 1,
    TcbRevoked = 2,
    TcbConfigurationNeeded = 3,
    TcbOutOfDateConfigurationNeeded = 4,
    TcbSwHardenningNeeded = 5,
    TcbConfigurationAndSwHardenningNeeded = 6,
}

impl Status {
    pub fn as_u8(&self) -> u8 {
        *self as u8
    }

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
            bail!("invalid ValidityIntersection: {}", self)
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

/// VerifiedOutput is the output of the dcap quote verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOutput {
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

impl VerifiedOutput {
    pub fn hash(&self) -> [u8; 32] {
        keccak256sum(&self.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut output_vec = Vec::new();

        output_vec.extend_from_slice(&self.version.to_be_bytes());
        output_vec.extend_from_slice(&self.quote_version.to_be_bytes());
        output_vec.extend_from_slice(&self.tee_type.to_be_bytes());
        output_vec.push(self.tcb_status.as_u8());
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

    pub fn from_bytes(slice: &[u8]) -> Result<VerifiedOutput> {
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
        let mut fmspc = [0; 6];
        fmspc.copy_from_slice(&slice[9..15]);

        let mut sgx_intel_root_ca_hash = [0; 32];
        sgx_intel_root_ca_hash.copy_from_slice(&slice[15..47]);

        let mut not_before_max = [0; 8];
        not_before_max.copy_from_slice(&slice[47..55]);
        let mut not_after_min = [0; 8];
        not_after_min.copy_from_slice(&slice[55..63]);

        const QUOTE_BODY_OFFSET: usize = 63;
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

        Ok(VerifiedOutput {
            version,
            quote_version: u16::from_be_bytes(quote_version),
            tee_type: u32::from_be_bytes(tee_type),
            tcb_status,
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
