use crate::cert::get_crl_uri;
use crate::{verifier::ValidityIntersection, Result};
use anyhow::bail;
use x509_parser::{certificate::X509Certificate, revocation_list::CertificateRevocationList};

#[derive(Debug, PartialEq, Eq)]
pub enum CrlType {
    SgxRootCa,
    SgxPckProcessor,
    SgxPckPlatform,
}

#[derive(Debug)]
pub struct IntelSgxCrls<'a> {
    pub sgx_root_ca_crl: CertificateRevocationList<'a>,
    pub sgx_pck_crl: CertificateRevocationList<'a>,
    pub sgx_pck_crl_type: CrlType,
}

impl<'a> IntelSgxCrls<'a> {
    pub fn new(
        sgx_root_ca_crl: CertificateRevocationList<'a>,
        sgx_pck_crl: CertificateRevocationList<'a>,
    ) -> crate::Result<Self> {
        let sgx_root_ca_crl_type =
            get_crl_type_from_issuer_cn(get_crl_issuer_cn(&sgx_root_ca_crl)?)?;
        if sgx_root_ca_crl_type != CrlType::SgxRootCa {
            bail!("Unexpected CRL issuer: {:?}", sgx_root_ca_crl_type);
        }
        let sgx_pck_crl_type = get_crl_type_from_issuer_cn(get_crl_issuer_cn(&sgx_pck_crl)?)?;
        match sgx_pck_crl_type {
            CrlType::SgxPckProcessor | CrlType::SgxPckPlatform => Ok(Self {
                sgx_root_ca_crl,
                sgx_pck_crl,
                sgx_pck_crl_type,
            }),
            t => bail!("Unexpected CRL issuer: {:?}", t),
        }
    }

    pub fn is_cert_revoked(&self, cert: &X509Certificate) -> Result<bool> {
        let crl = match get_crl_type(cert) {
            Some(CrlType::SgxRootCa) => &self.sgx_root_ca_crl,
            Some(CrlType::SgxPckProcessor) => {
                if self.sgx_pck_crl_type != CrlType::SgxPckProcessor {
                    bail!(
                        "CRL type mismatch: expected {:?}, got {:?}",
                        CrlType::SgxPckProcessor,
                        self.sgx_pck_crl_type
                    );
                }
                &self.sgx_pck_crl
            }
            Some(CrlType::SgxPckPlatform) => {
                if self.sgx_pck_crl_type != CrlType::SgxPckPlatform {
                    bail!(
                        "CRL type mismatch: expected {:?}, got {:?}",
                        CrlType::SgxPckPlatform,
                        self.sgx_pck_crl_type
                    );
                }
                &self.sgx_pck_crl
            }
            None => bail!("Unknown CRL URI"),
        };
        // check if the cert is revoked given the crl
        Ok(crl
            .iter_revoked_certificates()
            .any(|entry| entry.user_certificate == cert.tbs_certificate.serial))
    }

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

/// Get the CRL type based on the CRL URI
fn get_crl_type(cert: &X509Certificate) -> Option<CrlType> {
    let crl_uri = get_crl_uri(cert)?;
    if crl_uri.contains("https://certificates.trustedservices.intel.com/IntelSGXRootCA.der") {
        Some(CrlType::SgxRootCa)
    } else if crl_uri
        .contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=processor")
        || crl_uri.contains(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=processor",
        )
    {
        Some(CrlType::SgxPckProcessor)
    } else if crl_uri
        .contains("https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform")
        || crl_uri.contains(
            "https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform",
        )
    {
        Some(CrlType::SgxPckPlatform)
    } else {
        None
    }
}

fn get_crl_type_from_issuer_cn(issuer: &str) -> Result<CrlType> {
    match issuer {
        "Intel SGX Root CA" => Ok(CrlType::SgxRootCa),
        "Intel SGX PCK Processor CA" => Ok(CrlType::SgxPckProcessor),
        "Intel SGX PCK Platform CA" => Ok(CrlType::SgxPckPlatform),
        _ => bail!("Unknown CRL issuer: {}", issuer),
    }
}

fn get_crl_issuer_cn<'a>(crl: &'a CertificateRevocationList) -> Result<&'a str> {
    Ok(crl.issuer().iter_common_name().next().unwrap().as_str()?)
}
