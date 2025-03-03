use crate::Result;
use anyhow::Context;
use core::str::FromStr;
use dcap_types::tcb_info::TcbInfoV3;
use dcap_types::{TcbInfoV3TcbStatus, TdxModuleTcbStatus, TdxModuleTcbValidationStatus};

/// Get the TCB status of the TDX module corresponding to the given SVN.
///
/// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97>
///      <https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-tdx-v4>
///
/// # Arguments
/// - `tee_tcb_svn`: The SVN of the TEE TCB extracted from the `TD10ReportBody`
/// - `tcb_info_v3`: The TDX TCB Info V3
/// # Returns
/// - The TCB status of the TDX module
pub fn check_tdx_module_tcb_status(
    tee_tcb_svn: &[u8; 16],
    tcb_info_v3: &TcbInfoV3,
) -> Result<(TdxModuleTcbValidationStatus, Vec<String>, [u8; 48], u64)> {
    let tdx_module = tcb_info_v3
        .tcb_info
        .tdx_module
        .as_ref()
        .context("TDX module not found")?;

    let tdx_module_isv_svn = tee_tcb_svn[0];
    let tdx_module_version = tee_tcb_svn[1];

    if tdx_module_version == 0 {
        // we assume the quote header version is greater than 3
        return Ok((
            TdxModuleTcbValidationStatus::Ok,
            Default::default(),
            tdx_module.mrsigner()?,
            tdx_module.attributes()?,
        ));
    }

    let tdx_module_identity_id = format!("TDX_{:02x}", tdx_module_version);
    if let Some(tdx_module_identities) = &tcb_info_v3.tcb_info.tdx_module_identities {
        for tdx_module_identity in tdx_module_identities
            .iter()
            .filter(|m| m.id == tdx_module_identity_id)
        {
            for tcb_level in &tdx_module_identity.tcb_levels {
                if tdx_module_isv_svn >= tcb_level.tcb.isvsvn {
                    return Ok((
                        TdxModuleTcbStatus::from_str(tcb_level.tcb_status.as_str())?.into(),
                        tcb_level.advisory_ids.clone().unwrap_or_default(),
                        tdx_module_identity.mrsigner()?,
                        tdx_module_identity.attributes()?,
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

/// Converge TCB status with TDX module TCB status
///
/// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L137>
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
