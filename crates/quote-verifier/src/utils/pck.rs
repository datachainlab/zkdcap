use anyhow::{bail, Context};
use x509_parser::certificate::X509Certificate;

use crate::types::crl::IntelSgxCrls;
use crate::types::ValidityIntersection;
use crate::utils::cert::{
    get_x509_issuer_cn, get_x509_subject_cn, verify_certchain_signature, verify_crl_signature,
};
use crate::Result;

/// do the following checks:
/// - verify that the cert chain signatures are valid
/// - verify that `sgx_pck_crl` is signed by the PCK Platform/Processor CA cert
/// - check that the certificates used in the certchain are not revoked
pub fn verify_pck_certchain<'a>(
    pck_leaf_cert: &X509Certificate<'a>,
    pck_issuer_cert: &X509Certificate<'a>,
    intel_sgx_root_cert: &X509Certificate<'_>,
    intel_crls: &IntelSgxCrls,
) -> Result<ValidityIntersection> {
    // we'll check what kind of cert is it, and validate the appropriate CRL
    if get_x509_issuer_cn(&pck_leaf_cert) != get_x509_subject_cn(&pck_issuer_cert) {
        bail!("PCK Leaf Cert and Issuer Cert do not match");
    }

    // verify that the cert chain signatures are valid
    verify_certchain_signature(&[&pck_leaf_cert, &pck_issuer_cert], intel_sgx_root_cert)
        .context("Invalid PCK Chain")?;

    // check that `sgx_pck_crl` is signed by the PCK Platform/Processor CA cert
    verify_crl_signature(&intel_crls.sgx_pck_crl, &pck_issuer_cert)
        .context("Invalid PCK Issuer CRL")?;

    // checks that the certificates used in the certchain are not revoked
    for cert in [&pck_leaf_cert, &pck_issuer_cert] {
        if intel_crls.is_cert_revoked(cert)? {
            bail!("Certificate is revoked: {:?}", cert);
        }
    }

    let validity = ValidityIntersection::try_from(&pck_leaf_cert.validity)?
        .with_certificate(&pck_issuer_cert.validity)?;

    Ok(validity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        certs::{gen_crl, gen_pck_cert, gen_pck_cert_ca, gen_sgx_intel_root_ca, PckCa, Validity},
        utils::{gen_key, to_certificate},
    };
    use x509_parser::prelude::{CertificateRevocationList, FromDer};

    #[test]
    fn test_verify_pck_certchain() {
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

        let root_ca_crl = gen_crl(&root_cert, &root_key, Default::default()).unwrap();
        let pck_ca_crl = gen_crl(
            &pck_cert_processor_cert,
            &pck_cert_processor_key,
            Default::default(),
        )
        .unwrap();

        let pck_cert_der = pck_cert.to_der().unwrap();
        let pck_cert_processor_cert_der = pck_cert_processor_cert.to_der().unwrap();
        let root_cert_der = root_cert.to_der().unwrap();

        let res = verify_pck_certchain(
            &to_certificate(&pck_cert_der).unwrap(),
            &to_certificate(&pck_cert_processor_cert_der).unwrap(),
            &to_certificate(&root_cert_der).unwrap(),
            &IntelSgxCrls::new(
                CertificateRevocationList::from_der(root_ca_crl.to_der().unwrap().as_ref())
                    .unwrap()
                    .1,
                CertificateRevocationList::from_der(pck_ca_crl.to_der().unwrap().as_ref())
                    .unwrap()
                    .1,
            )
            .unwrap(),
        );
        assert!(res.is_ok(), "{:?}", res);
    }
}
