use crate::crl::IntelSgxCrls;
use crate::crypto::verify_p256_signature_bytes;
use crate::verifier::ValidityIntersection;
use crate::Result;
use anyhow::{bail, Context};
use dcap_types::tcbinfo::TcbInfoV3;
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use x509_parser::prelude::X509Certificate;

use crate::cert::{get_x509_issuer_cn, get_x509_subject_cn, verify_certificate};

/**
 * Validate the TCB Signing Certificate with the Root Certificate
 *
 * - the issuer of the TCB Signing Certificate must be the subject of the Root Certificate
 * - verify that the TCB Signing Certificate is signed by the Root Certificate
 * - check that the TCB Signing Certificate is not revoked by the Intel SGX CRLs
 *
 * Returns:
 * - The intersection of the validity periods of the TCB Signing Certificate and the Root Certificate
 *
 * Assumptions:
 * - `intel_sgx_root_cert` is not revoked and valid
 * - The crls of `intel_crls` are valid
 */
pub fn validate_tcb_signing_certificate(
    tcb_signing_cert: &X509Certificate,
    intel_sgx_root_cert: &X509Certificate,
    intel_crls: &IntelSgxCrls,
) -> Result<ValidityIntersection> {
    if get_x509_subject_cn(tcb_signing_cert) != "Intel SGX TCB Signing" {
        bail!("Invalid TCB Signing Cert Subject");
    } else if get_x509_issuer_cn(tcb_signing_cert) != get_x509_subject_cn(intel_sgx_root_cert) {
        bail!("TCB Signing Cert and Root Cert do not match");
    }
    // check that the tcb signing cert is signed by the root cert
    verify_certificate(&tcb_signing_cert, &intel_sgx_root_cert)
        .context("Invalid TCB Signing Cert")?;
    // check that the tcb signing cert is not revoked by the `self.sgx_root_ca_crl` CRL
    if intel_crls.is_cert_revoked(&tcb_signing_cert)? {
        bail!("TCB Signing Cert revoked");
    }

    let validity = ValidityIntersection::try_from(&tcb_signing_cert.validity)?
        .with_certificate(&intel_sgx_root_cert.validity)?;
    Ok(validity)
}

/**
 * Validate the TCB Info V3 structure
 *
 * - Verify that the TCB Info V3 structure is signed by the TCB Signing Cert
 * - Check that the TCB Info V3 structure is valid for the current time
 * - Return the validity periods of the TCB Info V3 structure
 */
pub fn validate_tcbinfov3(
    tee_type: u32,
    tcbinfov3: &TcbInfoV3,
    tcb_signing_cert: &X509Certificate,
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

    Ok(ValidityIntersection {
        not_before_max: tcbinfov3.tcb_info.issue_date()?.timestamp().try_into()?,
        not_after_min: tcbinfov3.tcb_info.next_update()?.timestamp().try_into()?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::gen_tcb_info_v3;
    use dcap_collaterals::{
        certs::{
            gen_crl_der, gen_pck_cert_ca, gen_pck_certchain, gen_root_ca, gen_sgx_intel_root_ca,
            gen_tcb_certchain, gen_tcb_signing_ca, PckCa, Validity,
        },
        sgx_extensions::SgxExtensionsBuilder,
        utils::{gen_key, parse_cert_der, unix_timestamp_to_rfc3339},
    };
    use x509_parser::prelude::{CertificateRevocationList, FromDer};

    #[test]
    fn test_tcb_signing_cert_validation() {
        let root_ca = gen_root_ca(Validity::long_duration().into(), None).unwrap();
        let root_ca_crl = root_ca.crl.to_der().unwrap();
        let sgx_extensions = SgxExtensionsBuilder::new().build();
        let pck_certchain = gen_pck_certchain(
            &root_ca,
            PckCa::Processor,
            &sgx_extensions,
            Validity::new_with_duration(1730000001, 1000).into(),
            None,
            None,
        )
        .unwrap();
        let pck_ca_crl = pck_certchain.pck_cert_crl.to_der().unwrap();

        let crls = IntelSgxCrls::new(
            CertificateRevocationList::from_der(root_ca_crl.as_ref())
                .unwrap()
                .1,
            CertificateRevocationList::from_der(pck_ca_crl.as_ref())
                .unwrap()
                .1,
        )
        .unwrap();

        let tcb_certchain = gen_tcb_certchain(
            &root_ca,
            Validity::new_with_duration(1730000000, 1000).into(),
        )
        .unwrap();

        {
            let res = validate_tcb_signing_certificate(
                &parse_cert_der(&tcb_certchain.cert.to_der().unwrap()).unwrap(),
                &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                &crls,
            );
            assert!(res.is_ok(), "{:?}", res);
            let validity = res.unwrap();
            assert_eq!(validity.not_before_max, 1730000000);
            assert_eq!(validity.not_after_min, 1730001000);
        }
        {
            let root_ca_crl = gen_crl_der(
                &root_ca.cert,
                &root_ca.key,
                &[tcb_certchain.cert.clone()],
                None,
            )
            .unwrap();
            let crls = IntelSgxCrls::new(
                CertificateRevocationList::from_der(root_ca_crl.as_ref())
                    .unwrap()
                    .1,
                CertificateRevocationList::from_der(pck_ca_crl.as_ref())
                    .unwrap()
                    .1,
            )
            .unwrap();
            let res = validate_tcb_signing_certificate(
                &parse_cert_der(&tcb_certchain.cert.to_der().unwrap()).unwrap(),
                &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                &crls,
            );
            assert!(res.is_err(), "{:?}", res);
            if let Err(e) = res {
                assert_eq!(e.to_string(), "TCB Signing Cert revoked");
            }
        }
        {
            let pck_ca_crl = gen_crl_der(
                &pck_certchain.pck_cert_ca,
                &pck_certchain.pck_cert_ca_key,
                &[tcb_certchain.cert.clone()],
                None,
            )
            .unwrap();
            let crls = IntelSgxCrls::new(
                CertificateRevocationList::from_der(root_ca_crl.as_ref())
                    .unwrap()
                    .1,
                CertificateRevocationList::from_der(pck_ca_crl.as_ref())
                    .unwrap()
                    .1,
            )
            .unwrap();
            let res = validate_tcb_signing_certificate(
                &parse_cert_der(&tcb_certchain.cert.to_der().unwrap()).unwrap(),
                &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                &crls,
            );
            assert!(res.is_ok(), "{:?}", res);
        }
        {
            let invalid_tcb_signing_cert = gen_pck_cert_ca(
                PckCa::Processor,
                &root_ca.cert,
                &root_ca.key,
                &tcb_certchain.key,
                Validity::new_with_duration(1730000000, 1000),
            )
            .unwrap();
            let res = validate_tcb_signing_certificate(
                &parse_cert_der(&invalid_tcb_signing_cert.to_der().unwrap()).unwrap(),
                &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                &crls,
            );
            assert!(res.is_err(), "{:?}", res);
        }
    }

    #[test]
    fn test_tcb_info_v3_validation() {
        let root_key = gen_key();
        let root_cert =
            gen_sgx_intel_root_ca(&root_key, Validity::new_with_duration(1730000000, 1000))
                .unwrap();
        let tcb_signing_pkey = gen_key();
        let tcb_signing_cert = gen_tcb_signing_ca(
            &root_cert,
            &root_key,
            &tcb_signing_pkey,
            Validity::new_with_duration(1730000000, 1000),
        )
        .unwrap();

        let tcb_info = {
            let mut tcb_info = serde_json::from_slice::<TcbInfoV3>(
                include_bytes!("../../../data/v3/tcbinfov3_00906ED50000.json").as_slice(),
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
            &parse_cert_der(&tcb_signing_cert.to_der().unwrap()).unwrap(),
        );
        assert!(res.is_ok(), "{:?}", res);
        let validity = res.unwrap();
        // The validity should reflect the issue date and next update date of the TCB Info
        assert_eq!(validity.not_before_max, 1740000000);
        assert_eq!(validity.not_after_min, 1740000000 + 1000);
    }
}
