use anyhow::{bail, Context};

use crate::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use crate::types::tcbinfo::TcbInfoV3;
use crate::types::ValidityIntersection;
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::{Result, X509Certificate};

pub fn validate_tcbinfov3(
    tee_type: u32,
    tcbinfov3: &TcbInfoV3,
    tcb_signing_cert: &X509Certificate,
    current_time: u64,
) -> Result<ValidityIntersection> {
    // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L96
    if tcbinfov3.tcb_info.version != 3 {
        bail!("Invalid TCB Info Version");
    } else if tee_type == SGX_TEE_TYPE {
        if tcbinfov3.tcb_info.id != "SGX" {
            bail!("Invalid TCB Info ID for SGX TEE Type");
        }
    } else if tee_type == TDX_TEE_TYPE {
        if tcbinfov3.tcb_info.id != "TDX" {
            bail!("Invalid TCB Info ID for TDX TEE Type");
        }
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    }

    // signature is a hex string, we'll convert it to bytes
    // we assume that the signature is a P256 ECDSA signature
    let tcbinfov3_signature_bytes = hex::decode(&tcbinfov3.signature)?;

    // verify that the tcb_info_root is signed by the root cert
    let tcbinfov3_signature_data = serde_json::to_vec(&tcbinfov3.tcb_info)?;
    verify_p256_signature_bytes(
        &tcbinfov3_signature_data,
        &tcbinfov3_signature_bytes,
        tcb_signing_cert.public_key().subject_public_key.as_ref(),
    )
    .context("TCB Info signature is invalid")?;

    let issue_date_seconds = tcbinfov3.tcb_info.issue_date()?.timestamp().try_into()?;
    let next_update_seconds = tcbinfov3.tcb_info.next_update()?.timestamp().try_into()?;

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        bail!(
            "TCB Info is not valid for the current time: {} < {} < {}",
            issue_date_seconds,
            current_time,
            next_update_seconds
        );
    }

    Ok(ValidityIntersection {
        not_before_max: issue_date_seconds,
        not_after_min: next_update_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::tests::gen_tcb_info_v3;
    use dcap_collaterals::{
        certs::{gen_sgx_intel_root_ca, gen_tcb_signing_ca, Validity},
        utils::{gen_key, to_certificate, unix_timestamp_to_rfc3339},
    };

    #[test]
    fn test_tcb_info_v3() {
        let root_pkey = gen_key();
        let root_cert =
            gen_sgx_intel_root_ca(&root_pkey, Validity::new_with_duration(1730000000, 1000))
                .unwrap();
        let tcb_signing_pkey = gen_key();
        let tcb_signing_cert = gen_tcb_signing_ca(
            &root_cert,
            &root_pkey,
            &tcb_signing_pkey,
            Validity::new_with_duration(1730000000, 1000),
        )
        .unwrap();

        let tcb_info = {
            let mut tcb_info = serde_json::from_slice::<TcbInfoV3>(
                include_bytes!("../../../../data/v3/tcbinfov3_00906ED50000.json").as_slice(),
            )
            .unwrap()
            .tcb_info;
            tcb_info.issue_date = unix_timestamp_to_rfc3339(1740000000);
            tcb_info.next_update = unix_timestamp_to_rfc3339(1740000000 + 1000);
            gen_tcb_info_v3(&tcb_signing_pkey, tcb_info).unwrap()
        };

        let res = validate_tcbinfov3(
            SGX_TEE_TYPE,
            &tcb_info,
            &to_certificate(&tcb_signing_cert.to_der().unwrap()).unwrap(),
            1740000000,
        );
        assert!(res.is_ok(), "{:?}", res);
        let validity = res.unwrap();
        // The validity should reflect the issue date and next update date of the TCB Info
        assert_eq!(validity.not_before_max, 1740000000);
        assert_eq!(validity.not_after_min, 1740000000 + 1000);

        assert!(
            validate_tcbinfov3(
                SGX_TEE_TYPE,
                &tcb_info,
                &to_certificate(&tcb_signing_cert.to_der().unwrap()).unwrap(),
                1740000000 - 1,
            )
            .is_err(),
            "TCB Info should be invalid before issue date"
        );
    }
}
