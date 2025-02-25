use crate::{verifier::ValidityIntersection, Result};
use anyhow::{bail, Context};
use dcap_types::cert::{SGX_PCK_PLATFORM_CA_CN, SGX_PCK_PROCESSOR_CA_CN, SGX_ROOT_CA_CN};
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

/// The type of CRL
#[derive(Debug, PartialEq, Eq)]
pub enum CrlType {
    /// Intel SGX Root CA CRL. Issued by "Intel SGX Root CA"
    SgxRootCa,
    /// Intel SGX PCK Processor CA CRL. Issued by "Intel SGX PCK Processor CA"
    SgxPckProcessor,
    /// Intel SGX PCK Platform CA CRL. Issued by "Intel SGX PCK Platform CA"
    SgxPckPlatform,
}

/// The CRLs issued by Intel SGX Root CA and Intel SGX PCK CA (Processor/Platform)
#[derive(Debug)]
pub struct IntelSgxCrls<'a> {
    /// The CRL issued by Intel SGX Root CA
    pub sgx_root_ca_crl: CertificateRevocationList<'a>,
    /// The CRL issued by Intel SGX PCK CA (Processor/Platform)
    pub sgx_pck_crl: CertificateRevocationList<'a>,
    /// The type of the CRL issued by Intel SGX PCK CA (Processor/Platform)
    pub sgx_pck_crl_type: CrlType,
}

impl<'a> IntelSgxCrls<'a> {
    /// Create a new Intel SGX CRLs
    /// We assume that the signature of the CRLs are already verified
    ///
    /// # Arguments
    /// - `sgx_root_ca_crl`: The CRL issued by Intel SGX Root CA.
    /// - `sgx_pck_crl`: The CRL issued by Intel SGX PCK CA (Processor/Platform)
    pub fn new(
        sgx_root_ca_crl: CertificateRevocationList<'a>,
        sgx_pck_crl: CertificateRevocationList<'a>,
    ) -> crate::Result<Self> {
        let sgx_root_ca_crl_type = get_crl_type_from_crl(&sgx_root_ca_crl)?;
        if sgx_root_ca_crl_type != CrlType::SgxRootCa {
            bail!(
                "Expected CRL type {:?}, got {:?}",
                CrlType::SgxRootCa,
                sgx_root_ca_crl_type
            );
        }
        let sgx_pck_crl_type = get_crl_type_from_crl(&sgx_pck_crl)?;
        match sgx_pck_crl_type {
            CrlType::SgxPckProcessor | CrlType::SgxPckPlatform => Ok(Self {
                sgx_root_ca_crl,
                sgx_pck_crl,
                sgx_pck_crl_type,
            }),
            t => bail!(
                "Expected CRL type {:?} or {:?}, got {:?}",
                CrlType::SgxPckProcessor,
                CrlType::SgxPckPlatform,
                t
            ),
        }
    }

    /// Check if the certificate is revoked
    /// We assume that the signature of the CRLs are already verified and the certificate is valid and the CRLs are valid in the current time
    ///
    /// # Arguments
    /// - `cert`: The certificate to check if it is revoked
    pub fn is_cert_revoked(&self, cert: &X509Certificate) -> Result<bool> {
        let crl = match get_crl_type_from_cert(cert)? {
            CrlType::SgxRootCa => &self.sgx_root_ca_crl,
            CrlType::SgxPckProcessor => {
                if self.sgx_pck_crl_type != CrlType::SgxPckProcessor {
                    bail!(
                        "CRL type mismatch: expected {:?}, got {:?}",
                        CrlType::SgxPckProcessor,
                        self.sgx_pck_crl_type
                    );
                }
                &self.sgx_pck_crl
            }
            CrlType::SgxPckPlatform => {
                if self.sgx_pck_crl_type != CrlType::SgxPckPlatform {
                    bail!(
                        "CRL type mismatch: expected {:?}, got {:?}",
                        CrlType::SgxPckPlatform,
                        self.sgx_pck_crl_type
                    );
                }
                &self.sgx_pck_crl
            }
        };
        // check if the cert is revoked given the crl
        // NOTE: We assume that the each revoked certificate entry's `revocation_date` is older than or equal to the `last_update` of the CRL
        // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/PckParser/CrlStore.cpp#L130
        Ok(crl
            .iter_revoked_certificates()
            .any(|entry| entry.user_certificate == cert.tbs_certificate.serial))
    }

    /// Check the validity of the CRLs in the current time
    ///
    /// # Arguments
    /// - `current_time`: The current time in seconds since UNIX epoch
    ///
    /// # Returns
    /// - The intersection of the validity periods of the CRLs
    pub fn check_validity(&self, current_time: u64) -> Result<ValidityIntersection> {
        let mut max_last_update = u64::MIN;
        let mut min_next_update = u64::MAX;
        for crl in [&self.sgx_root_ca_crl, &self.sgx_pck_crl] {
            let last_update = crl.last_update().timestamp().try_into()?;
            if last_update > max_last_update {
                if current_time < last_update {
                    bail!(
                        "CRL last_update is in the future: last_update={} current_time={}",
                        last_update,
                        current_time
                    );
                }
                max_last_update = last_update;
            }
            if let Some(next_update) = crl.next_update().map(|t| t.timestamp()) {
                let next_update = next_update.try_into()?;
                if next_update < min_next_update {
                    if current_time > next_update {
                        bail!(
                            "CRL next_update is in the past: next_update={} current_time={}",
                            next_update,
                            current_time
                        );
                    }
                    min_next_update = next_update;
                }
            }
        }
        Ok(ValidityIntersection {
            not_before_max: max_last_update,
            not_after_min: min_next_update,
        })
    }
}

/// Get the CRL type of the certificate
/// We assume that the issuer of the certificate issues the only one type of CRL
/// ref. p.5 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>
fn get_crl_type_from_cert(cert: &X509Certificate) -> Result<CrlType> {
    let issuer_cn = cert
        .issuer()
        .iter_common_name()
        .next()
        .context("No common name in the issuer")?
        .as_str()?;
    get_crl_type_from_issuer_cn(issuer_cn)
}

/// Get the type of the CRL from the issuer common name of the CRL
/// We assume that the issuer of the crl issues the only one type of CRL
/// ref. p.5 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>
fn get_crl_type_from_crl(crl: &CertificateRevocationList) -> Result<CrlType> {
    get_crl_type_from_issuer_cn(
        crl.issuer()
            .iter_common_name()
            .next()
            .context("No common name in the issuer")?
            .as_str()?,
    )
}

/// Get the type of the CRL from the issuer common name
fn get_crl_type_from_issuer_cn(issuer: &str) -> Result<CrlType> {
    if issuer == SGX_ROOT_CA_CN {
        Ok(CrlType::SgxRootCa)
    } else if issuer == SGX_PCK_PROCESSOR_CA_CN {
        Ok(CrlType::SgxPckProcessor)
    } else if issuer == SGX_PCK_PLATFORM_CA_CN {
        Ok(CrlType::SgxPckPlatform)
    } else {
        bail!("Unknown CRL issuer: {}", issuer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::collateral::QvCollateral;
    use dcap_collaterals::{
        certs::{gen_pck_certchain, gen_root_ca, PckCa},
        sgx_extensions::SgxExtensionsBuilder,
    };
    use x509_parser::prelude::FromDer;

    #[test]
    fn test_intel_sgx_crls() {
        let root_ca = gen_root_ca(None, None).unwrap();
        for ca_type in [PckCa::Processor, PckCa::Platform] {
            let pck_certchain = gen_pck_certchain(
                &root_ca,
                ca_type,
                &SgxExtensionsBuilder::new().build(),
                None,
                None,
                None,
            )
            .unwrap();

            // Test the case where the type of the given CRLs are correct
            {
                let collateral = QvCollateral {
                    sgx_intel_root_ca_crl_der: root_ca.crl.to_der().unwrap(),
                    sgx_pck_crl_der: pck_certchain.pck_cert_crl.to_der().unwrap(),
                    ..Default::default()
                };

                // Error - Root CA CRL and PCK Platform CRL
                let res = IntelSgxCrls::new(
                    collateral.get_sgx_pck_crl().unwrap(),
                    collateral.get_sgx_pck_crl().unwrap(),
                );
                assert!(res.is_err(), "{:?}", res.ok());

                // Error - Root CA CRL and Root CA CRL
                let res = IntelSgxCrls::new(
                    collateral.get_sgx_intel_root_ca_crl().unwrap(),
                    collateral.get_sgx_intel_root_ca_crl().unwrap(),
                );
                assert!(res.is_err(), "{:?}", res.ok());

                // OK - Root CA CRL and PCK Processor CRL
                let res = IntelSgxCrls::new(
                    collateral.get_sgx_intel_root_ca_crl().unwrap(),
                    collateral.get_sgx_pck_crl().unwrap(),
                );
                assert!(res.is_ok(), "{:?}", res.err());
                let crls = res.unwrap();
                assert_eq!(
                    crls.sgx_pck_crl_type,
                    if ca_type == PckCa::Processor {
                        CrlType::SgxPckProcessor
                    } else {
                        CrlType::SgxPckPlatform
                    }
                );
                let pck_cert_der = pck_certchain.pck_cert.to_der().unwrap();
                let (_, pck_cert) = X509Certificate::from_der(pck_cert_der.as_ref()).unwrap();
                let res = crls.is_cert_revoked(&pck_cert);
                assert!(res.is_ok(), "{:?}", res.err());
                assert!(!res.unwrap(), "PCK cert should not be revoked");
            }

            // Test the case where the PCK cert is revoked
            {
                let pck_certchain2 = pck_certchain.gen_new_pck_cert(true);
                let collateral = QvCollateral {
                    sgx_intel_root_ca_crl_der: root_ca.crl.to_der().unwrap(),
                    sgx_pck_crl_der: pck_certchain2.pck_cert_crl.to_der().unwrap(),
                    ..Default::default()
                };
                let res = IntelSgxCrls::new(
                    collateral.get_sgx_intel_root_ca_crl().unwrap(),
                    collateral.get_sgx_pck_crl().unwrap(),
                );
                assert!(res.is_ok(), "{:?}", res.err());
                let crls = res.unwrap();
                let pck_cert_der = pck_certchain.pck_cert.to_der().unwrap();
                let (_, pck_cert) = X509Certificate::from_der(pck_cert_der.as_ref()).unwrap();
                let res = crls.is_cert_revoked(&pck_cert);
                assert!(res.is_ok(), "{:?}", res.err());
                assert!(res.unwrap(), "PCK cert should be revoked");
            }

            // Test the case where the PCK CA cert is revoked
            {
                let root_ca2 = root_ca
                    .with_new_crl(vec![pck_certchain.pck_cert_ca.clone()])
                    .unwrap();
                let collateral = QvCollateral {
                    sgx_intel_root_ca_crl_der: root_ca2.crl.to_der().unwrap(),
                    sgx_pck_crl_der: pck_certchain.pck_cert_crl.to_der().unwrap(),
                    ..Default::default()
                };
                let res = IntelSgxCrls::new(
                    collateral.get_sgx_intel_root_ca_crl().unwrap(),
                    collateral.get_sgx_pck_crl().unwrap(),
                );
                assert!(res.is_ok(), "{:?}", res.err());
                let crls = res.unwrap();
                let pck_cert_ca_der = pck_certchain.pck_cert_ca.to_der().unwrap();
                let (_, pck_cert_ca) = X509Certificate::from_der(pck_cert_ca_der.as_ref()).unwrap();
                let res = crls.is_cert_revoked(&pck_cert_ca);
                assert!(res.is_ok(), "{:?}", res.err());
                assert!(res.unwrap(), "PCK CA cert should be revoked");
            }
        }
    }
}
