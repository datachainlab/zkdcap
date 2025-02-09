use anyhow::{bail, Context};
use x509_parser::certificate::X509Certificate;

use crate::cert::{get_x509_issuer_cn, get_x509_subject_cn, verify_certchain_signature};
use crate::crl::IntelSgxCrls;
use crate::verifier::ValidityIntersection;
use crate::Result;

/**
 * Validate the PCK certificate
 *
 * - check if the `pck_leaf_cert` is a PCK cert and `pck_issuer_cert` is a PCK CA cert
 * - verify that the cert chain(pck_leaf_cert, pck_issuer_cert, intel_sgx_root_cert) signatures are valid
 * - check if the `pck_leaf_cert` and `pck_issuer_cert` are not revoked
 *
 * Returns:
 * - The intersection of the validity periods of the pcak_leaf_cert, pck_issuer_cert and intel_sgx_root_cert
 *
 * Assumptions:
 * - `intel_sgx_root_cert` is not revoked and valid
 * - The crls of `intel_crls` are valid
 */
pub fn validate_pck_cert<'a>(
    pck_leaf_cert: &X509Certificate<'a>,
    pck_issuer_cert: &X509Certificate<'a>,
    intel_sgx_root_cert: &X509Certificate<'_>,
    intel_crls: &IntelSgxCrls,
) -> Result<ValidityIntersection> {
    let pck_subject_cn = get_x509_subject_cn(&pck_leaf_cert);
    let pck_issuer_cn = get_x509_issuer_cn(&pck_leaf_cert);

    if pck_subject_cn != "Intel SGX PCK Certificate" {
        bail!("PCK Leaf Cert is not a PCK Cert");
    } else if pck_issuer_cn != "Intel SGX PCK Processor CA"
        && pck_issuer_cn != "Intel SGX PCK Platform CA"
    {
        bail!("PCK Issuer Cert is not a PCK CA Cert");
    }

    // we'll check what kind of cert is it, and validate the appropriate CRL
    if pck_issuer_cn != get_x509_subject_cn(&pck_issuer_cert) {
        bail!("PCK Leaf Cert and Issuer Cert do not match");
    } else if get_x509_issuer_cn(&pck_issuer_cert) != get_x509_subject_cn(intel_sgx_root_cert) {
        bail!("PCK Issuer Cert and Root Cert do not match");
    }

    // verify that the cert chain signatures are valid
    verify_certchain_signature(&[&pck_leaf_cert, &pck_issuer_cert], intel_sgx_root_cert)
        .context("Invalid PCK Chain")?;

    if intel_crls.is_cert_revoked(pck_leaf_cert)? {
        bail!("PCK cert is revoked: {:?}", pck_leaf_cert);
    } else if intel_crls.is_cert_revoked(pck_issuer_cert)? {
        bail!("PCK CA cert is revoked: {:?}", pck_issuer_cert);
    }

    let validity = ValidityIntersection::try_from(&pck_leaf_cert.validity)?
        .with_certificate(&pck_issuer_cert.validity)?
        .with_certificate(&intel_sgx_root_cert.validity)?;

    Ok(validity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        certs::{
            gen_crl_der, gen_pck_cert, gen_pck_cert_ca, gen_sgx_intel_root_ca, PckCa, Validity,
        },
        utils::{gen_key, to_certificate},
    };
    use x509_parser::prelude::{CertificateRevocationList, FromDer};

    #[test]
    fn test_validate_pck_cert() {
        let root_key = gen_key();
        let root_cert =
            gen_sgx_intel_root_ca(&root_key, Validity::new(1524607999, 2524607999)).unwrap();
        let pck_cert_processor_key = gen_key();
        let pck_cert_processor_cert = gen_pck_cert_ca(
            PckCa::Processor,
            &root_cert,
            &root_key,
            &pck_cert_processor_key,
            Validity::new(1524607999, 2524607999),
        )
        .unwrap();
        let pck_cert_key = gen_key();
        let pck_cert = gen_pck_cert(
            &pck_cert_processor_cert,
            &pck_cert_processor_key,
            &pck_cert_key,
            Validity::new(1524607999, 2524607999),
        )
        .unwrap();

        let root_ca_crl = gen_crl_der(&root_cert, &root_key, Default::default()).unwrap();
        let pck_ca_crl = gen_crl_der(
            &pck_cert_processor_cert,
            &pck_cert_processor_key,
            Default::default(),
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

        let pck_cert_der = pck_cert.to_der().unwrap();
        let pck_cert_processor_cert_der = pck_cert_processor_cert.to_der().unwrap();
        let root_cert_der = root_cert.to_der().unwrap();

        {
            let res = validate_pck_cert(
                &to_certificate(&pck_cert_der).unwrap(),
                &to_certificate(&pck_cert_processor_cert_der).unwrap(),
                &to_certificate(&root_cert_der).unwrap(),
                &crls,
            );
            assert!(res.is_ok(), "{:?}", res);
        }
        {
            let root_ca_crl = gen_crl_der(&root_cert, &root_key, Default::default()).unwrap();
            let pck_ca_crl = gen_crl_der(
                &pck_cert_processor_cert,
                &pck_cert_processor_key,
                &[pck_cert.clone()],
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

            let res = validate_pck_cert(
                &to_certificate(&pck_cert_der).unwrap(),
                &to_certificate(&pck_cert_processor_cert_der).unwrap(),
                &to_certificate(&root_cert_der).unwrap(),
                &crls,
            );
            assert!(res.is_err(), "{:?}", res);
            if let Err(e) = res {
                assert!(e.to_string().starts_with("PCK cert is revoked"));
            }
        }
        {
            let root_ca_crl =
                gen_crl_der(&root_cert, &root_key, &[pck_cert_processor_cert.clone()]).unwrap();
            let pck_ca_crl = gen_crl_der(
                &pck_cert_processor_cert,
                &pck_cert_processor_key,
                Default::default(),
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

            let res = validate_pck_cert(
                &to_certificate(&pck_cert_der).unwrap(),
                &to_certificate(&pck_cert_processor_cert_der).unwrap(),
                &to_certificate(&root_cert_der).unwrap(),
                &crls,
            );
            assert!(res.is_err(), "{:?}", res);
            if let Err(e) = res {
                assert!(e.to_string().starts_with("PCK CA cert is revoked"));
            }
        }
    }
}
