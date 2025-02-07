use anyhow::{bail, Context};

use crate::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use crate::types::{
    enclave_identity::EnclaveIdentityV2, EnclaveIdentityV2TcbStatus, ValidityIntersection,
};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::{Result, X509Certificate};

/// Validates a QE identity v2 against the TCB signing certificate
pub fn validate_qe_identityv2(
    tee_type: u32,
    qe_identityv2: &EnclaveIdentityV2,
    tcb_signing_pubkey: &X509Certificate,
) -> Result<ValidityIntersection> {
    // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271
    if qe_identityv2.enclave_identity.version != 2 {
        bail!("Invalid Enclave Identity Version");
    } else if tee_type == SGX_TEE_TYPE {
        if qe_identityv2.enclave_identity.id != "QE" {
            bail!("Invalid Enclave Identity ID for SGX TEE Type");
        }
    } else if tee_type == TDX_TEE_TYPE {
        if qe_identityv2.enclave_identity.id != "TD_QE" {
            bail!("Invalid Enclave Identity ID for TDX TEE Type");
        }
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    }

    // signature is a hex string, we'll convert it to bytes
    // we assume that the signature is a P256 ECDSA signature
    let qe_identityv2_signature_bytes = hex::decode(&qe_identityv2.signature)?;
    // verify that the enclave_identity_root is signed by the root cert
    let qe_identityv2_signature_data = serde_json::to_vec(&qe_identityv2.enclave_identity)?;

    verify_p256_signature_bytes(
        &qe_identityv2_signature_data,
        &qe_identityv2_signature_bytes,
        tcb_signing_pubkey.public_key().subject_public_key.as_ref(),
    )
    .context("QE identity signature is invalid")?;

    let issue_date_seconds = qe_identityv2
        .enclave_identity
        .issue_date()?
        .timestamp()
        .try_into()?;
    let next_update_seconds = qe_identityv2
        .enclave_identity
        .next_update()?
        .timestamp()
        .try_into()?;

    Ok(ValidityIntersection {
        not_before_max: issue_date_seconds,
        not_after_min: next_update_seconds,
    })
}

pub fn get_qe_tcbstatus(
    qe_report_isv_svn: u16,
    qeidentityv2: &EnclaveIdentityV2,
) -> Result<(EnclaveIdentityV2TcbStatus, Vec<String>)> {
    for tcb_level in qeidentityv2.enclave_identity.tcb_levels.iter() {
        if tcb_level.tcb.isvsvn <= qe_report_isv_svn {
            return Ok((
                EnclaveIdentityV2TcbStatus::from_str(&tcb_level.tcb_status)?,
                tcb_level.advisory_ids.clone().unwrap_or_default(),
            ));
        }
    }
    bail!(
        "No TCB level found for QE report ISV SVN {}",
        qe_report_isv_svn
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        constants::SGX_TEE_TYPE,
        utils::{enclave_identity::validate_qe_identityv2, tests::gen_enclave_identity},
    };
    use dcap_collaterals::{
        certs::{gen_sgx_intel_root_ca, gen_tcb_signing_ca, Validity},
        utils::{gen_key, to_certificate, unix_timestamp_to_rfc3339},
    };

    #[test]
    fn test_validate_enclave_identity() {
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

        let enclave_identity = {
            let mut id = serde_json::from_slice::<EnclaveIdentityV2>(
                include_bytes!("../../../../data/v3/qeidentityv2.json").as_slice(),
            )
            .unwrap()
            .enclave_identity;
            id.issue_date = unix_timestamp_to_rfc3339(1740000000);
            id.next_update = unix_timestamp_to_rfc3339(1740000000 + 1000);
            gen_enclave_identity(&tcb_signing_pkey, id).unwrap()
        };

        let res = validate_qe_identityv2(
            SGX_TEE_TYPE,
            &enclave_identity,
            &to_certificate(&tcb_signing_cert.to_der().unwrap()).unwrap(),
        );
        assert!(res.is_ok(), "{:?}", res);
        let validity = res.unwrap();

        // The validity should reflect the issue date and next update date of the QE identity
        assert_eq!(validity.not_before_max, 1740000000);
        assert_eq!(validity.not_after_min, 1740000000 + 1000);
    }
}
