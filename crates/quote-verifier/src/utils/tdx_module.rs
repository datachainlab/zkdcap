use anyhow::bail;

use crate::types::tcbinfo::TcbInfoV3;
use crate::types::{TcbInfoV3TcbStatus, TdxModuleTcbStatus, TdxModuleTcbValidationStatus};
use crate::Result;

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
pub fn get_tdx_module_identity_and_tcb(
    tee_tcb_svn: &[u8; 16],
    tcb_info_v3: &TcbInfoV3,
) -> Result<(TdxModuleTcbValidationStatus, Vec<String>, [u8; 48], u64)> {
    let tdx_module = if let Some(tdx_module_obj) = &tcb_info_v3.tcb_info.tdx_module {
        tdx_module_obj
    } else {
        bail!("TDX module not found");
    };

    let tdx_module_isv_svn = tee_tcb_svn[0];
    let tdx_module_version = tee_tcb_svn[1];

    if tdx_module_version == 0 {
        // we assume the quote header version is greater than 3
        let mut mrsigner: [u8; 48] = [0; 48];
        mrsigner.copy_from_slice(&hex::decode(&tdx_module.mrsigner)?);

        return Ok((
            TdxModuleTcbValidationStatus::Ok,
            Default::default(),
            mrsigner,
            from_str_to_u64(tdx_module.attributes.as_str())?,
        ));
    }

    let id = format!("TDX_{:02x}", tdx_module_version);
    if let Some(tdx_module_identities) = &tcb_info_v3.tcb_info.tdx_module_identities {
        for tdx_module_identity in tdx_module_identities.iter().filter(|m| m.id == id) {
            for tcb_level in &tdx_module_identity.tcb_levels {
                if tdx_module_isv_svn >= tcb_level.tcb.isvsvn {
                    let mut mrsigner: [u8; 48] = [0; 48];
                    mrsigner.copy_from_slice(&hex::decode(&tdx_module_identity.mrsigner)?);
                    return Ok((
                        TdxModuleTcbStatus::from_str(tcb_level.tcb_status.as_str())?.into(),
                        tcb_level.advisory_ids.clone().unwrap_or_default(),
                        mrsigner,
                        from_str_to_u64(tdx_module_identity.attributes.as_str())?,
                    ));
                }
            }
        }
        Ok((
            TdxModuleTcbValidationStatus::TcbNotSupported,
            Default::default(),
            [0; 48],
            0,
        ))
    } else {
        Ok((
            TdxModuleTcbValidationStatus::TdxModuleMismatch,
            Default::default(),
            [0; 48],
            0,
        ))
    }
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L137
pub fn converge_tcb_status_with_tdx_module_tcb(
    tcb_status: TcbInfoV3TcbStatus,
    tdx_module_tcb_status: TdxModuleTcbValidationStatus,
) -> TcbInfoV3TcbStatus {
    match tdx_module_tcb_status {
        TdxModuleTcbValidationStatus::TcbOutOfDate => match tcb_status {
            TcbInfoV3TcbStatus::UpToDate | TcbInfoV3TcbStatus::SWHardeningNeeded => {
                TcbInfoV3TcbStatus::OutOfDate
            }
            TcbInfoV3TcbStatus::ConfigurationNeeded
            | TcbInfoV3TcbStatus::ConfigurationAndSWHardeningNeeded => {
                TcbInfoV3TcbStatus::OutOfDateConfigurationNeeded
            }
            _ => tcb_status,
        },
        TdxModuleTcbValidationStatus::TcbRevoked => TcbInfoV3TcbStatus::Revoked,
        _ => tcb_status,
    }
}

fn from_str_to_u64(str: &str) -> Result<u64> {
    if str.len() != 16 {
        bail!("Invalid u64 str length");
    }

    match u64::from_str_radix(str, 16) {
        Ok(ret) => Ok(ret),
        Err(_) => bail!("Invalid hex character found"),
    }
}
