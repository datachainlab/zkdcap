use crate::TdxModuleTcbStatus;
use anyhow::bail;
use core::str::FromStr;
use serde::{Deserialize, Serialize};

/// TCB Info structure
pub enum TcbInfo {
    V3(TcbInfoV3),
}

/// TCB Info V3 structure with signature
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3 {
    /// TCB Info V3 Inner structure
    pub tcb_info: TcbInfoV3Inner,
    /// Base 16-encoded string representation of signature calculated over tcbInfo body without whitespaces using TCB Signing Key
    pub signature: String,
}

/// TCB Info V3 Inner structure
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3Inner {
    /// Identifier of the TCB Info issued by Intel. Supported values are SGX or TDX.
    pub id: String,
    /// Version of the structure
    pub version: u32,
    /// Representation of date and time the TCB information was created. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    pub issue_date: String,
    /// Representation of date and time by which next TCB information will be issued. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    pub next_update: String,
    /// Base 16-encoded string representation of FMSPC (Family-Model-Stepping-Platform-CustomSKU)
    pub fmspc: String,
    /// Base 16-encoded string representation of PCE identifier
    pub pce_id: String,
    /// Type of TCB level composition that determines TCB level comparison logic
    pub tcb_type: u64,
    /// A monotonically increasing sequence number changed when Intel updates the content of the TCB evaluation data set: TCB Info, QE Idenity and QVE Identity.
    /// The tcbEvaluationDataNumber update is synchronized across TCB Info for all flavors of SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE Identity.
    /// This sequence number allows users to easily determine when a particular TCB Info/QE Idenity/QVE Identiy superseedes another TCB Info/QE Identity/QVE Identity (value: current TCB Recovery event number stored in the database).
    pub tcb_evaluation_data_number: u32,
    /// This field is optional. It will be present only in context of TDX TCB Info.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module: Option<TdxModule>,
    /// This field is optional. It will be present only in context of TDX TCB Info when the platform supports more than one TDX SEAM Module.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdx_module_identities: Option<Vec<TdxModuleIdentities>>,
    /// Sorted list of supported TCB levels for given FMSPC encoded as a JSON array of TCB level objects
    pub tcb_levels: Vec<TcbInfoV3TcbLevelItem>,
}

impl TcbInfoV3Inner {
    /// Returns the issue date as a `chrono::DateTime<chrono::FixedOffset>`.
    pub fn issue_date(&self) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::ParseError> {
        chrono::DateTime::parse_from_rfc3339(&self.issue_date)
    }

    /// Returns the next update date as a `chrono::DateTime<chrono::FixedOffset>`.
    pub fn next_update(&self) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::ParseError> {
        chrono::DateTime::parse_from_rfc3339(&self.next_update)
    }

    /// Returns the FMSPC
    pub fn fmspc(&self) -> Result<[u8; 6], anyhow::Error> {
        let mut fmspc = [0; 6];
        let fmspc_bytes = hex::decode(&self.fmspc)?;
        fmspc.copy_from_slice(&fmspc_bytes);
        Ok(fmspc)
    }

    /// Returns the PCE ID
    pub fn pce_id(&self) -> Result<[u8; 2], anyhow::Error> {
        let mut pce_id = [0; 2];
        let pce_id_bytes = hex::decode(&self.pce_id)?;
        pce_id.copy_from_slice(&pce_id_bytes);
        Ok(pce_id)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModule {
    /// Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer. The length of the string is 96 characters.
    pub mrsigner: String,
    /// Hex-encoded byte array (8 bytes) representing attributes "golden" value.
    pub attributes: String,
    /// Hex-encoded byte array (8 bytes) representing mask to be applied to TDX SEAM module’s attributes value retrieved from the platform
    pub attributes_mask: String,
}

impl TdxModule {
    /// Returns the MRSIGNER
    pub fn mrsigner(&self) -> Result<[u8; 48], anyhow::Error> {
        let mut mrsigner = [0; 48];
        let mrsigner_bytes = hex::decode(&self.mrsigner)?;
        mrsigner.copy_from_slice(&mrsigner_bytes);
        Ok(mrsigner)
    }

    /// Returns the attributes
    pub fn attributes(&self) -> Result<u64, anyhow::Error> {
        if self.attributes.len() != 16 {
            bail!("Invalid u64 str length");
        }
        match u64::from_str_radix(&self.attributes, 16) {
            Ok(ret) => Ok(ret),
            Err(_) => bail!("Invalid hex character found"),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentities {
    /// Identifier of TDX Module
    pub id: String,
    /// Base 16-encoded string representation of the measurement of a TDX SEAM module’s signer. The length of the string is 96 characters.
    pub mrsigner: String,
    /// Base 16-encoded string representation of the byte array (8 bytes) representing attributes "golden" value.
    pub attributes: String,
    /// Base 16-encoded string representation of the byte array (8 bytes) representing mask to be applied to TDX SEAM module’s
    /// attributes value retrieved from the platform
    pub attributes_mask: String,
    /// List of TCB levels for the TDX SEAM module
    pub tcb_levels: Vec<TdxModuleIdentitiesTcbLevelItem>,
}

impl TdxModuleIdentities {
    /// Returns the MRSIGNER
    pub fn mrsigner(&self) -> Result<[u8; 48], anyhow::Error> {
        let mut mrsigner = [0; 48];
        let mrsigner_bytes = hex::decode(&self.mrsigner)?;
        mrsigner.copy_from_slice(&mrsigner_bytes);
        Ok(mrsigner)
    }

    /// Returns the attributes
    pub fn attributes(&self) -> Result<u64, anyhow::Error> {
        if self.attributes.len() != 16 {
            bail!("Invalid u64 str length");
        }
        match u64::from_str_radix(&self.attributes, 16) {
            Ok(ret) => Ok(ret),
            Err(_) => bail!("Invalid hex character found"),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevelItem {
    /// TCB level of the TDX SEAM Module
    pub tcb: TdxModuleIdentitiesTcbLevel,
    /// Representation of date and time the TCB information was created. The time shall be in UTC and the encoding shall be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    pub tcb_date: String,
    /// TCB level status. One of the following values:
    /// "UpToDate" - TCB level of the TDX SEAM Module is up-to-date.
    /// "SWHardeningNeeded" - TCB level of the TDX SEAM Module is up-to-date but due to certain issues affecting the platform, additional SW Hardening in the attesting TDX enclaves may be needed.
    /// "ConfigurationNeeded" - TCB level of the TDX SEAM Module is up-to-date but additional configuration of TDX platform may be needed.
    /// "ConfigurationAndSWHardeningNeeded" - TCB level of the TDX SEAM Module is up-to-date but additional configuration for the platform and SW Hardening in the attesting TDX enclaves may be needed.
    /// "OutOfDate" - TCB level of TDX SEAM Module is outdated.
    /// "OutOfDateConfigurationNeeded" - TCB level of TDX SEAM Module is outdated and additional configuration of TDX platform may be needed.
    /// "Revoked" - TCB level of TDX SEAM Module is revoked. The platform is not trustworthy.
    pub tcb_status: String,
    /// Array of Advisory IDs referring to Intel security advisories that provide insight into the reason(s) for the value of tcbStatus for this TCB level when the value is not UpToDate.
    /// This field is optional. It will be present only if the list of Advisory IDs is not empty.
    /// Note: The value can be different for different FMSPCs.
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

impl TdxModuleIdentitiesTcbLevelItem {
    /// Returns the TCB status of the TDX module
    pub fn tcb_status(&self) -> Result<TdxModuleTcbStatus, anyhow::Error> {
        TdxModuleTcbStatus::from_str(&self.tcb_status)
    }
}

/// TDX SEAM module’s ISV SVN
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TdxModuleIdentitiesTcbLevel {
    pub isvsvn: u8,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevelItem {
    pub tcb: TcbInfoV3TcbLevel,
    pub tcb_date: String,
    pub tcb_status: String,
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfoV3TcbLevel {
    pub sgxtcbcomponents: [TcbComponent; 16],
    pub pcesvn: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tdxtcbcomponents: Option<[TcbComponent; 16]>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbComponent {
    pub svn: u8, // SVN of TCB Component.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>, // Category of TCB Component (e.g. BIOS, OS/VMM).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename(serialize = "type", deserialize = "type"))]
    pub type_: Option<String>, // Type of TCB Component (e.g. SGX Late Microcode Update, TXT SINIT).
}
