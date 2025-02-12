use crate::crypto::verify_p256_signature_bytes;
use crate::verifier::ValidityIntersection;
use crate::Result;
use anyhow::{bail, Context};
use core::str::FromStr;
use dcap_types::enclave_identity::EnclaveIdentityV2TcbLevelItem;
use dcap_types::{enclave_identity::EnclaveIdentityV2, EnclaveIdentityV2TcbStatus};
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use x509_parser::prelude::X509Certificate;

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
    qeidentityv2_tcb_levels: &[EnclaveIdentityV2TcbLevelItem],
) -> Result<(EnclaveIdentityV2TcbStatus, Vec<String>)> {
    for tcb_level in qeidentityv2_tcb_levels {
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
    use crate::tests::gen_enclave_identity;
    use dcap_collaterals::{
        certs::{gen_sgx_intel_root_ca, gen_tcb_signing_ca, Validity},
        utils::{gen_key, parse_cert_der, unix_timestamp_to_rfc3339},
    };
    use serde_json::json;

    #[test]
    fn test_validate_enclave_identity_v2() {
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
                include_bytes!("../../../data/v3/qeidentityv2.json").as_slice(),
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
            &parse_cert_der(&tcb_signing_cert.to_der().unwrap()).unwrap(),
        );
        assert!(res.is_ok(), "{:?}", res);
        let validity = res.unwrap();

        // The validity should reflect the issue date and next update date of the QE identity
        assert_eq!(validity.not_before_max, 1740000000);
        assert_eq!(validity.not_after_min, 1740000000 + 1000);
    }

    #[test]
    fn test_get_qe_tcbstatus() {
        let tcb_levels: Vec<EnclaveIdentityV2TcbLevelItem> = serde_json::from_value(json!([
            {
              "tcb": {
                "isvsvn": 8
              },
              "tcbDate": "2023-08-09T00:00:00Z",
              "tcbStatus": "UpToDate"
            },
            {
                "tcb": {
                  "isvsvn": 6
                },
                "tcbDate": "2022-08-09T00:00:00Z",
                "tcbStatus": "OutOfDate",
            },
            {
                "tcb": {
                  "isvsvn": 5
                },
                "tcbDate": "2021-08-09T00:00:00Z",
                "tcbStatus": "Revoked",
                "advisoryIDs": ["INTEL-SA-00615"]
            }
        ]))
        .unwrap();

        let (status, advisory_ids) = get_qe_tcbstatus(9, &tcb_levels).unwrap();
        assert_eq!(status, EnclaveIdentityV2TcbStatus::UpToDate);
        assert!(advisory_ids.is_empty());

        let (status, advisory_ids) = get_qe_tcbstatus(8, &tcb_levels).unwrap();
        assert_eq!(status, EnclaveIdentityV2TcbStatus::UpToDate);
        assert!(advisory_ids.is_empty());

        let (status, advisory_ids) = get_qe_tcbstatus(7, &tcb_levels).unwrap();
        assert_eq!(status, EnclaveIdentityV2TcbStatus::OutOfDate);
        assert!(advisory_ids.is_empty());

        let (status, advisory_ids) = get_qe_tcbstatus(5, &tcb_levels).unwrap();
        assert_eq!(status, EnclaveIdentityV2TcbStatus::Revoked);
        assert_eq!(advisory_ids, vec!["INTEL-SA-00615"]);

        let res = get_qe_tcbstatus(4, &tcb_levels);
        assert!(res.is_err(), "{:?}", res);
    }
}
