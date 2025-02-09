use anyhow::bail;
use core::fmt::Display;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

pub mod cert;
pub mod enclave_identity;
pub mod quotes;
pub mod tcbinfo;
pub mod utils;

pub const SGX_TEE_TYPE: u32 = 0x00000000;
pub const TDX_TEE_TYPE: u32 = 0x00000081;

pub const ECDSA_256_WITH_P256_CURVE: u16 = 2;

pub const HEADER_LEN: usize = 48;

pub const ENCLAVE_REPORT_LEN: usize = 384;
pub const TD10_REPORT_LEN: usize = 584;
pub const TD15_REPORT_LEN: usize = 684;

pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];

pub(crate) type Result<T> = core::result::Result<T, anyhow::Error>;

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
