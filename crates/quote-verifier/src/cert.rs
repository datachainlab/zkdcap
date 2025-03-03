use crate::crypto::verify_p256_signature_der;
use anyhow::bail;
use core::str::FromStr;
use dcap_types::cert::{SgxExtensionTcbLevel, SgxExtensions};
use dcap_types::tcb_info::{TcbComponent, TcbInfoV3};
use dcap_types::TcbInfoV3TcbStatus;
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use x509_parser::prelude::*;

/// Parse a PEM-encoded certificate chain into a vector of `X509Certificate`.
pub fn parse_certchain(pem_certs: &[Pem]) -> crate::Result<Vec<X509Certificate>> {
    Ok(pem_certs
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<_, _>>()?)
}

/// Verifies the signature of a certificate using the public key of the signer certificate.
pub fn verify_certificate(
    cert: &X509Certificate,
    signer_cert: &X509Certificate,
) -> crate::Result<()> {
    let data = cert.tbs_certificate.as_ref();
    let signature = cert.signature_value.as_ref();
    let public_key = signer_cert.public_key().subject_public_key.as_ref();
    if cert.issuer() != signer_cert.subject() {
        bail!("Issuer does not match signer");
    }
    verify_p256_signature_der(data, signature, public_key)
}

/// Verifies the signature of a CRL using the public key of the signer certificate and checks that the issuer matches.
pub fn verify_crl_signature(
    crl: &CertificateRevocationList,
    signer_cert: &X509Certificate,
) -> crate::Result<()> {
    // verifies that the crl is valid
    let data = crl.tbs_cert_list.as_ref();
    let signature = crl.signature_value.as_ref();
    let public_key = signer_cert.public_key().subject_public_key.as_ref();
    if crl.issuer() != signer_cert.subject() {
        bail!("Issuer does not match signer");
    }
    verify_p256_signature_der(data, signature, public_key)
}

/// verify_certchain_signature just verify that the certchain signature matches, any other checks will be done by the caller
pub fn verify_certchain_signature(
    certs: &[&X509Certificate],
    root_cert: &X509Certificate,
) -> crate::Result<()> {
    // verify that the cert chain is valid
    let mut iter = certs.iter();
    let mut prev_cert = iter.next().unwrap();
    for cert in iter {
        // verify that the previous cert signed the current cert
        verify_certificate(prev_cert, cert)?;
        prev_cert = cert;
    }
    // verify that the root cert signed the last cert
    verify_certificate(prev_cert, root_cert)
}

/// Get the Subject Common Name (CN) from a certificate.
pub fn get_x509_subject_cn(cert: &X509Certificate) -> String {
    let subject = cert.subject();
    let cn = subject.iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
}

/// Get the Issuer Common Name (CN) from a certificate.
pub fn get_x509_issuer_cn(cert: &X509Certificate) -> String {
    let issuer = cert.issuer();
    let cn = issuer.iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
}

/// Get the TCB status of the SGX and TDX corresponding to the given SVN from the TCB Info V3.
/// This function returns the TCB status of the SGX and TDX, and the advisory IDs.
/// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181>
///
/// # Arguments
/// * `tee_type` - The type of TEE (SGX or TDX)
/// * `tee_tcb_svn` - The TCB SVN of the TEE (only for TDX)
/// * `sgx_extensions` - The SGX Extensions from the PCK Certificate
/// * `tcb_info_v3` - The TCB Info V3
/// # Returns
/// * `(sgx_tcb_status, tdx_tcb_status, advisory_ids)` - The TCB status of the SGX and TDX, and the advisory IDs
pub fn get_sgx_tdx_tcb_status_v3(
    tee_type: u32,
    tee_tcb_svn: Option<[u8; 16]>,
    sgx_extensions: &SgxExtensions,
    tcb_info_v3: &TcbInfoV3,
) -> crate::Result<(TcbInfoV3TcbStatus, Option<TcbInfoV3TcbStatus>, Vec<String>)> {
    if tee_type == SGX_TEE_TYPE {
        if tcb_info_v3.tcb_info.id != "SGX" {
            bail!("Invalid TCB Info ID for SGX TEE Type");
        } else if tee_tcb_svn.is_some() {
            bail!("SGX TCB SVN is not needed");
        }
    } else if tee_type == TDX_TEE_TYPE {
        if tcb_info_v3.tcb_info.id != "TDX" {
            bail!("Invalid TCB Info ID for TDX TEE Type");
        } else if tee_tcb_svn.is_none() {
            bail!("TDX TCB SVN is missing");
        }
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    }

    if sgx_extensions.fmspc != tcb_info_v3.tcb_info.fmspc()? {
        // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L117
        bail!(
            "FMSPC does not match: {:x?} != {:x?}",
            sgx_extensions.fmspc,
            tcb_info_v3.tcb_info.fmspc()?
        );
    } else if sgx_extensions.pceid != tcb_info_v3.tcb_info.pce_id()? {
        // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L124
        bail!(
            "PCE ID does not match: {:x?} != {:x?}",
            sgx_extensions.pceid,
            tcb_info_v3.tcb_info.pce_id()?
        );
    }

    let mut sgx_tcb_status: Option<TcbInfoV3TcbStatus> = None;
    let tcb = &sgx_extensions.tcb;
    let extension_pcesvn = tcb.pcesvn;

    for tcb_level in tcb_info_v3.tcb_info.tcb_levels.iter() {
        if sgx_tcb_status.is_none()
            && match_sgxtcbcomp(tcb, &tcb_level.tcb.sgxtcbcomponents)
            && extension_pcesvn >= tcb_level.tcb.pcesvn
        {
            sgx_tcb_status = Some(TcbInfoV3TcbStatus::from_str(tcb_level.tcb_status.as_str())?);
            if tee_type == SGX_TEE_TYPE {
                return Ok((
                    sgx_tcb_status.unwrap(),
                    None,
                    tcb_level.advisory_ids.clone().unwrap_or_default(),
                ));
            }
        }

        if tee_type == TDX_TEE_TYPE && sgx_tcb_status.is_some() {
            let tdxtcbcomponents = match &tcb_level.tcb.tdxtcbcomponents {
                Some(cmps) => cmps,
                None => bail!("TDX TCB Components are missing"),
            };
            let ok = match_tdxtcbcomp(&tee_tcb_svn.unwrap(), tdxtcbcomponents);
            if ok {
                return Ok((
                    sgx_tcb_status.unwrap(),
                    Some(TcbInfoV3TcbStatus::from_str(tcb_level.tcb_status.as_str())?),
                    tcb_level.advisory_ids.clone().unwrap_or_default(),
                ));
            }
        }
    }
    if let Some(status) = sgx_tcb_status {
        Ok((status, None, vec![]))
    } else {
        bail!("SGX TCB Level has not been found");
    }
}

/// Merge two vectors of advisory ids into one vector
/// This function will remove any duplicates
pub fn merge_advisory_ids(advisory_ids: Vec<String>, advisory_ids2: Vec<String>) -> Vec<String> {
    let mut ids = advisory_ids
        .into_iter()
        .chain(advisory_ids2)
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn match_sgxtcbcomp(tcb: &SgxExtensionTcbLevel, sgxtcbcomponents: &[TcbComponent; 16]) -> bool {
    // ref. https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-sgx-v4
    //      https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-tdx-v4
    // 3-a. Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16) with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level. If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, go to 3.b, otherwise move to the next item on TCB Levels list.
    tcb.sgxtcbcompsvns()
        .into_iter()
        .zip(sgxtcbcomponents.iter())
        .all(|(ext, tcb)| ext >= tcb.svn)
}

fn match_tdxtcbcomp(tee_tcb_svn: &[u8; 16], tdxtcbcomponents: &[TcbComponent; 16]) -> bool {
    // ref. https://api.portal.trustedservices.intel.com/content/documentation.html#pcs-tcb-info-tdx-v4
    // 3-c. Compare SVNs in TEE TCB SVN array retrieved from TD Report in Quote (from index 0 to 15 if TEE TCB SVN at index 1 is set to 0, or from index 2 to 15 otherwise) with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level. If all TEE TCB SVNs in the TD Report are greater or equal to the corresponding values in TCB Level, read tcbStatus assigned to this TCB level. Otherwise, move to the next item on TCB Levels list.
    let start_index = if tee_tcb_svn[1] > 0 { 2 } else { 0 };
    tee_tcb_svn[start_index..]
        .iter()
        .zip(tdxtcbcomponents[start_index..].iter())
        .all(|(tee, tcb)| *tee >= tcb.svn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_types::utils::{parse_crl_der, parse_x509_der};

    #[test]
    fn test_root_crl_verify() {
        let intel_sgx_root_ca = parse_x509_der(include_bytes!(
            "../data/Intel_SGX_Provisioning_Certification_RootCA.cer"
        ))
        .unwrap();
        let intel_sgx_root_ca_crl =
            parse_crl_der(include_bytes!("../data/intel_root_ca_crl.der")).unwrap();

        assert!(verify_crl_signature(&intel_sgx_root_ca_crl, &intel_sgx_root_ca).is_ok());
    }
}
