use anyhow::{bail, Context};

use crate::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use crate::types::{
    enclave_identity::EnclaveIdentityV2, EnclaveIdentityV2TcbStatus, ValidityIntersection,
};
use crate::utils::crypto::verify_p256_signature_bytes;
use crate::{Result, X509Certificate};

/// validate_qe_identityv2 validates a QE identity v2 against the TCB signing certificate
pub fn validate_qe_identityv2(
    tee_type: u32,
    qe_identityv2: &EnclaveIdentityV2,
    tcb_signing_pubkey: &X509Certificate,
    current_time: u64,
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

    // check that the current time is between the issue_date and next_update_date
    if current_time < issue_date_seconds || current_time > next_update_seconds {
        bail!(
            "Enclave identity is not valid for the current time: {} < {} < {}",
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
