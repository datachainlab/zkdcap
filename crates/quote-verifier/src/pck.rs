use crate::cert::{get_x509_issuer_cn, get_x509_subject_cn, verify_certchain_signature};
use crate::crl::IntelSgxCrls;
use crate::verifier::ValidityIntersection;
use crate::Result;
use anyhow::{bail, Context};
use x509_parser::certificate::X509Certificate;

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
        certs::{gen_crl_der, gen_pck_certchain, gen_root_ca, PckCa},
        sgx_extensions::SgxExtensionsBuilder,
        utils::parse_cert_der,
    };
    use x509_parser::prelude::{CertificateRevocationList, FromDer};

    #[test]
    fn test_validate_pck_cert() {
        let root_ca = gen_root_ca(None, None).unwrap();
        let root_ca_crl = root_ca.crl.to_der().unwrap();
        let sgx_extensions = SgxExtensionsBuilder::new().build();
        let pck_certchains = vec![
            gen_pck_certchain(
                &root_ca,
                PckCa::Processor,
                &sgx_extensions,
                None,
                None,
                None,
            )
            .unwrap(),
            gen_pck_certchain(&root_ca, PckCa::Platform, &sgx_extensions, None, None, None)
                .unwrap(),
        ];
        for pck_certchain in pck_certchains {
            let pck_ca_crl = pck_certchain.pck_cert_crl.to_der().unwrap();
            {
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
                    &parse_cert_der(&pck_certchain.pck_cert.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&pck_certchain.pck_cert_ca.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                    &crls,
                );
                assert!(res.is_ok(), "{:?}", res);
            }

            {
                let pck_ca_crl = gen_crl_der(
                    &pck_certchain.pck_cert_ca,
                    &pck_certchain.pck_cert_ca_key,
                    &[pck_certchain.pck_cert.clone()],
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

                let res = validate_pck_cert(
                    &parse_cert_der(&pck_certchain.pck_cert.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&pck_certchain.pck_cert_ca.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                    &crls,
                );
                assert!(res.is_err(), "{:?}", res);
                if let Err(e) = res {
                    assert!(e.to_string().starts_with("PCK cert is revoked"));
                }
            }
            {
                let root_ca_crl = gen_crl_der(
                    &root_ca.cert,
                    &root_ca.key,
                    &[pck_certchain.pck_cert_ca.clone()],
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

                let res = validate_pck_cert(
                    &parse_cert_der(&pck_certchain.pck_cert.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&pck_certchain.pck_cert_ca.to_der().unwrap()).unwrap(),
                    &parse_cert_der(&root_ca.cert.to_der().unwrap()).unwrap(),
                    &crls,
                );
                assert!(res.is_err(), "{:?}", res);
                if let Err(e) = res {
                    assert!(e.to_string().starts_with("PCK CA cert is revoked"));
                }
            }
        }
    }
}
