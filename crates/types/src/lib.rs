use anyhow::bail;
use core::fmt::Display;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

pub mod cert;
pub mod enclave_identity;
pub mod quotes;
pub mod tcbinfo;
pub mod utils;

/// ref. p.68 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub const QUOTE_FORMAT_V3: u16 = 3;
/// ref. p.37 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf>
pub const QUOTE_FORMAT_V4: u16 = 4;
/// ref. p.37 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf>
pub const SGX_TEE_TYPE: u32 = 0x00000000;
/// ref. p.37 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf>
pub const TDX_TEE_TYPE: u32 = 0x00000081;

/// ref. p.68 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub const ECDSA_256_WITH_P256_CURVE: u16 = 2;
/// ref. p.68 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub const INTEL_QE_VENDOR_ID: [u8; 16] = [
    0x93, 0x9A, 0x72, 0x33, 0xF7, 0x9C, 0x4C, 0xA9, 0x94, 0x0A, 0x0D, 0xB3, 0x95, 0x7F, 0x06, 0x07,
];
/// ref. p.67 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub const QUOTE_HEADER_LEN: usize = 48;
/// ref. p.69 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
pub const ENCLAVE_REPORT_LEN: usize = 384;
/// ref. p.37 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/Intel_TDX_DCAP_Quoting_Library_API.pdf>
pub const TD10_REPORT_LEN: usize = 584;

pub(crate) type Result<T> = core::result::Result<T, anyhow::Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnclaveIdentityV2TcbStatus {
    /// TCB level of the SGX platform is up-to-date.
    UpToDate,
    /// TCB level of SGX platform is outdated.
    OutOfDate,
    /// TCB level of SGX platform is revoked. The platform is not trustworthy.
    Revoked,
}

impl FromStr for EnclaveIdentityV2TcbStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Ok(match s {
            "UpToDate" => Self::UpToDate,
            "OutOfDate" => Self::OutOfDate,
            "Revoked" => Self::Revoked,
            _ => bail!("unrecognized EnclaveIdentityV2TcbStatus: {}", s),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcbInfoV3TcbStatus {
    /// TCB level of the SGX platform is up-to-date.
    UpToDate,
    /// TCB level of the SGX platform is up-to-date but due to certain issues affecting the platform, additional SW Hardening in the attesting SGX enclaves may be needed.
    SWHardeningNeeded,
    /// TCB level of the SGX platform is up-to-date but additional configuration of SGX platform may be needed.
    ConfigurationNeeded,
    /// TCB level of the SGX platform is up-to-date but additional configuration for the platform and SW Hardening in the attesting SGX enclaves may be needed.
    ConfigurationAndSWHardeningNeeded,
    /// TCB level of SGX platform is outdated.
    OutOfDate,
    /// TCB level of SGX platform is outdated and additional configuration of SGX platform may be needed.
    OutOfDateConfigurationNeeded,
    /// TCB level of SGX platform is revoked. The platform is not trustworthy.
    Revoked,
}

impl FromStr for TcbInfoV3TcbStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
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

/// TCB level status of TDX SEAM Module
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TdxModuleTcbStatus {
    /// TCB level of the TDX SEAM Module is up-to-date.
    UpToDate,
    /// TCB level of TDX SEAM Module is outdated.
    OutOfDate,
    /// TCB level of TDX SEAM Module is revoked. The platform is not trustworthy.
    Revoked,
}

impl FromStr for TdxModuleTcbStatus {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
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

/// Status for quote verification result
/// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/10176d4833d72d34f287d00a27c63d757a3c1f99/Src/AttestationLibrary/include/SgxEcdsaAttestation/QuoteVerification.h#L66>
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
