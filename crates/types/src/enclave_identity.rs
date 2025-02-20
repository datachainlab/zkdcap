use serde::{Deserialize, Serialize};

/// SGX Enclave Identity data structure with signature
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentityV2 {
    /// SGX Enclave Identity data structure
    pub enclave_identity: EnclaveIdentityV2Inner,
    /// Hex-encoded string representation of a signature calculated over qeIdentity body (without whitespaces) using TCB Info Signing Key.
    pub signature: String,
}

/// SGX Enclave Identity data structure
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentityV2Inner {
    /// Identifier of the SGX Enclave issued by Intel. Supported values are QE, QVE and TD_QE
    pub id: String,
    /// Version of the structure
    pub version: u64,
    /// Representation of date and time the Enclave Identity information
    /// was created. The time shall be in UTC and the encoding shall
    /// be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
    pub issue_date: String,
    /// Representation of date and time by which next Enclave Identity
    /// information will be issued. The time shall be in
    /// UTC and the encoding shall be compliant to ISO 8601 standard
    /// (YYYY-MM-DDThh:mm:ssZ)
    pub next_update: String,
    /// A monotonically increasing sequence number changed
    /// when Intel updates the content of the TCB evaluation data
    /// set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber
    /// update is synchronized across TCB Info for all flavors of
    /// SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE
    /// Identity. This sequence number allows users to easily determine
    /// when a particular TCB Info/QE Idenity/QVE Identiy superseedes
    /// another TCB Info/QE Identity/QVE Identity (value: current
    /// TCB Recovery event number stored in the database).
    pub tcb_evaluation_data_number: u32,
    /// Base 16-encoded string representing miscselect "golden" value (upon applying mask).
    pub miscselect: String,
    /// Base 16-encoded string representing mask to be applied to miscselect value retrieved from the platform.
    pub miscselect_mask: String,
    /// Base 16-encoded string representing attributes "golden" value (upon applying mask).
    pub attributes: String,
    /// Base 16-encoded string representing mask to be applied to attributes value retrieved from the platform.
    pub attributes_mask: String,
    /// Base 16-encoded string representing mrsigner hash.
    pub mrsigner: String,
    /// Enclave Product ID.
    pub isvprodid: u16,
    /// Sorted list of supported Enclave TCB levels for given
    /// QVE encoded as a JSON array of Enclave TCB level objects.
    pub tcb_levels: Vec<EnclaveIdentityV2TcbLevelItem>,
}

impl EnclaveIdentityV2Inner {
    /// Returns the issue date as a `chrono::DateTime<chrono::FixedOffset>`.
    pub fn issue_date(&self) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::ParseError> {
        chrono::DateTime::parse_from_rfc3339(&self.issue_date)
    }

    /// Returns the next update date as a `chrono::DateTime<chrono::FixedOffset>`.
    pub fn next_update(&self) -> Result<chrono::DateTime<chrono::FixedOffset>, chrono::ParseError> {
        chrono::DateTime::parse_from_rfc3339(&self.next_update)
    }

    /// Returns the mrsigner hash
    pub fn mrsigner(&self) -> Result<[u8; 32], anyhow::Error> {
        let mrsigner = hex::decode(&self.mrsigner)?;
        if mrsigner.len() != 32 {
            return Err(anyhow::anyhow!("Invalid mrsigner length"));
        }
        let mut signer = [0u8; 32];
        signer.copy_from_slice(&mrsigner);
        Ok(signer)
    }

    /// Returns the miscselect mask
    pub fn miscselect_mask(&self) -> Result<u32, anyhow::Error> {
        let miscselect_mask = hex::decode(&self.miscselect_mask)?;
        if miscselect_mask.len() != 4 {
            return Err(anyhow::anyhow!("Invalid miscselect mask length"));
        }
        Ok(u32::from_le_bytes(miscselect_mask.try_into().unwrap()))
    }

    /// Returns the miscselect
    pub fn miscselect(&self) -> Result<u32, anyhow::Error> {
        let miscselect = hex::decode(&self.miscselect)?;
        if miscselect.len() != 4 {
            return Err(anyhow::anyhow!("Invalid miscselect length"));
        }
        Ok(u32::from_le_bytes(miscselect.try_into().unwrap()))
    }

    /// Returns the attributes mask
    pub fn attributes_mask(&self) -> Result<[u8; 16], anyhow::Error> {
        let attributes_mask = hex::decode(&self.attributes_mask)?;
        if attributes_mask.len() != 16 {
            return Err(anyhow::anyhow!("Invalid attributes mask length"));
        }
        let mut mask = [0u8; 16];
        mask.copy_from_slice(&attributes_mask);
        Ok(mask)
    }

    /// Returns the attributes
    pub fn attributes(&self) -> Result<[u8; 16], anyhow::Error> {
        let attributes = hex::decode(&self.attributes)?;
        if attributes.len() != 16 {
            return Err(anyhow::anyhow!("Invalid attributes length"));
        }
        let mut attr = [0u8; 16];
        attr.copy_from_slice(&attributes);
        Ok(attr)
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentityV2TcbLevelItem {
    /// SGX Enclave's ISV SVN
    pub tcb: EnclaveIdentityV2TcbLevel,
    /// If there are security advisories published by Intel after tcbDate
    /// that are for issues whose mitigations are currently enforced* by SGX attestation,
    /// then the value of tcbStatus for the TCB level will not be UpToDate.
    /// Otherwise (i.e., either no advisories after or not currently enforced),
    /// the value of tcbStatus for the TCB level will not be OutOfDate.
    pub tcb_date: String,
    /// TCB level status. One of the following values:
    /// "UpToDate" - TCB level of the SGX platform is up-to-date.
    /// "OutOfDate" - TCB level of SGX platform is outdated.
    /// "Revoked" - TCB level of SGX platform is revoked.
    /// The platform is not trustworthy.
    pub tcb_status: String,
    /// Array of Advisory IDs referring to Intel security advisories that
    /// provide insight into the reason(s) for the value of tcbStatus for
    /// this TCB level when the value is not UpToDate.
    /// This field is optional. It will be present only
    /// if the list of Advisory IDs is not empty.
    #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Vec<String>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentityV2TcbLevel {
    pub isvsvn: u16,
}
