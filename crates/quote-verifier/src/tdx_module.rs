use crate::Result;
use anyhow::Context;
use dcap_types::tcb_info::TcbInfoV3;
use dcap_types::{TcbInfoV3TcbStatus, TdxModuleTcbValidationStatus};

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

    let tdx_module_identity_id = format!("TDX_{:02X}", tdx_module_version);
    if let Some(tdx_module_identities) = &tcb_info_v3.tcb_info.tdx_module_identities {
        for tdx_module_identity in tdx_module_identities
            .iter()
            .filter(|m| m.id.to_uppercase() == tdx_module_identity_id)
        {
            for tcb_level in &tdx_module_identity.tcb_levels {
                if tdx_module_isv_svn >= tcb_level.tcb.isvsvn {
                    return Ok((
                        tcb_level.tcb_status()?.into(),
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

#[cfg(test)]
mod test {
    use super::*;
    use dcap_collaterals::tcb_info::{
        TcbInfoV3Builder, TdxModuleBuilder, TdxModuleIdentitiesBuilder,
        TdxModuleIdentitiesTcbLevelItemBuilder,
    };
    use dcap_types::{tcb_info::TdxModuleIdentitiesTcbLevel, TdxModuleTcbStatus};

    #[test]
    fn test_check_tdx_module_tcb_status_tdx_module_zero() {
        let tdx_module_identities = vec![TdxModuleIdentitiesBuilder::new().build()];
        let tee_tcb_svn = gen_tee_tcb_svn(1, 0);
        let tcb_info = TcbInfoV3 {
            tcb_info: TcbInfoV3Builder::new(false)
                .tdx_module(TdxModuleBuilder::new().build())
                .tdx_module_identities(tdx_module_identities)
                .build(),
            ..Default::default()
        };
        match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
            Ok((status, _, _, _)) => {
                assert_eq!(status, TdxModuleTcbValidationStatus::Ok);
            }
            Err(e) => panic!("error: {}", e),
        }
    }

    #[test]
    fn test_check_tdx_module_tcb_status_tdx_module_mismatch() {
        let tee_tcb_svn = gen_tee_tcb_svn(1, 1);
        let tcb_info = TcbInfoV3 {
            tcb_info: TcbInfoV3Builder::new(false)
                .tdx_module(TdxModuleBuilder::new().build())
                .build(),
            ..Default::default()
        };
        match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
            Ok((status, _, _, _)) => {
                assert_eq!(status, TdxModuleTcbValidationStatus::TdxModuleMismatch);
            }
            Err(e) => panic!("error: {}", e),
        }
    }

    #[test]
    fn test_check_tdx_module_tcb_status() {
        let tdx_module_identities = vec![TdxModuleIdentitiesBuilder::new()
            .id(2)
            .tcb_levels(vec![
                TdxModuleIdentitiesTcbLevelItemBuilder::new()
                    .tcb(TdxModuleIdentitiesTcbLevel { isvsvn: 2 })
                    .tcb_status(TdxModuleTcbStatus::UpToDate.to_string().as_ref())
                    .build(),
                TdxModuleIdentitiesTcbLevelItemBuilder::new()
                    .tcb(TdxModuleIdentitiesTcbLevel { isvsvn: 1 })
                    .advisory_ids(&["INTEL-SA-00001"])
                    .tcb_status(TdxModuleTcbStatus::OutOfDate.to_string().as_ref())
                    .build(),
            ])
            .build()];
        {
            let tee_tcb_svn = gen_tee_tcb_svn(1, 2);
            let tcb_info = TcbInfoV3 {
                tcb_info: TcbInfoV3Builder::new(false)
                    .tdx_module(TdxModuleBuilder::new().build())
                    .tdx_module_identities(tdx_module_identities.clone())
                    .build(),
                ..Default::default()
            };
            match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
                Ok((status, advisory_ids, _, _)) => {
                    assert_eq!(status, TdxModuleTcbValidationStatus::TcbOutOfDate);
                    assert_eq!(advisory_ids, vec!["INTEL-SA-00001"]);
                }
                Err(e) => panic!("error: {}", e),
            }
        }
        {
            let tee_tcb_svn = gen_tee_tcb_svn(2, 2);
            let tcb_info = TcbInfoV3 {
                tcb_info: TcbInfoV3Builder::new(false)
                    .tdx_module(TdxModuleBuilder::new().build())
                    .tdx_module_identities(tdx_module_identities.clone())
                    .build(),
                ..Default::default()
            };
            match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
                Ok((status, advisory_ids, _, _)) => {
                    assert_eq!(status, TdxModuleTcbValidationStatus::Ok);
                    assert!(advisory_ids.is_empty());
                }
                Err(e) => panic!("error: {}", e),
            }
        }
        {
            let tee_tcb_svn = gen_tee_tcb_svn(3, 2);
            let tcb_info = TcbInfoV3 {
                tcb_info: TcbInfoV3Builder::new(false)
                    .tdx_module(TdxModuleBuilder::new().build())
                    .tdx_module_identities(tdx_module_identities.clone())
                    .build(),
                ..Default::default()
            };
            match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
                Ok((status, advisory_ids, _, _)) => {
                    assert_eq!(status, TdxModuleTcbValidationStatus::Ok);
                    assert!(advisory_ids.is_empty());
                }
                Err(e) => panic!("error: {}", e),
            }
        }
        {
            let tee_tcb_svn = gen_tee_tcb_svn(1, 1);
            let tcb_info = TcbInfoV3 {
                tcb_info: TcbInfoV3Builder::new(false)
                    .tdx_module(TdxModuleBuilder::new().build())
                    .tdx_module_identities(tdx_module_identities)
                    .build(),
                ..Default::default()
            };
            match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
                Ok((status, _, _, _)) => {
                    assert_eq!(status, TdxModuleTcbValidationStatus::TcbNotSupported);
                }
                Err(e) => panic!("error: {}", e),
            }
        }
    }

    #[test]
    fn test_check_tdx_module_tcb_status_large_tdx_module_version() {
        let tdx_module_identities = vec![TdxModuleIdentitiesBuilder::new()
            .id(u8::MAX)
            .tcb_levels(vec![
                TdxModuleIdentitiesTcbLevelItemBuilder::new()
                    .tcb(TdxModuleIdentitiesTcbLevel { isvsvn: 2 })
                    .tcb_status(TdxModuleTcbStatus::UpToDate.to_string().as_ref())
                    .build(),
                TdxModuleIdentitiesTcbLevelItemBuilder::new()
                    .tcb(TdxModuleIdentitiesTcbLevel { isvsvn: 1 })
                    .advisory_ids(&["INTEL-SA-00001"])
                    .tcb_status(TdxModuleTcbStatus::OutOfDate.to_string().as_ref())
                    .build(),
            ])
            .build()];

        let tee_tcb_svn = gen_tee_tcb_svn(1, u8::MAX);
        let tcb_info = TcbInfoV3 {
            tcb_info: TcbInfoV3Builder::new(false)
                .tdx_module(TdxModuleBuilder::new().build())
                .tdx_module_identities(tdx_module_identities)
                .build(),
            ..Default::default()
        };
        match check_tdx_module_tcb_status(&tee_tcb_svn, &tcb_info) {
            Ok((status, advisory_ids, _, _)) => {
                assert_eq!(status, TdxModuleTcbValidationStatus::TcbOutOfDate);
                assert_eq!(advisory_ids, vec!["INTEL-SA-00001"]);
            }
            Err(e) => panic!("error: {}", e),
        }
    }

    fn gen_tee_tcb_svn(tdx_module_isv_svn: u8, tdx_module_version: u8) -> [u8; 16] {
        let mut tee_tcb_svn = [0; 16];
        tee_tcb_svn[0] = tdx_module_isv_svn;
        tee_tcb_svn[1] = tdx_module_version;
        tee_tcb_svn
    }
}
