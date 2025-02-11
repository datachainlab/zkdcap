use anyhow::bail;
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::*;

use crate::crypto::verify_p256_signature_der;
use dcap_types::cert::{SgxExtensionTcbLevel, SgxExtensions};
use dcap_types::tcbinfo::{TcbComponent, TcbInfoV3};
use dcap_types::TcbInfoV3TcbStatus;
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};

pub fn parse_certchain<'a>(pem_certs: &'a [Pem]) -> crate::Result<Vec<X509Certificate<'a>>> {
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

// verify_certchain_signature just verify that the certchain signature matches, any other checks will be done by the caller
pub fn verify_certchain_signature<'a, 'b>(
    certs: &[&X509Certificate<'a>],
    root_cert: &X509Certificate<'b>,
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

pub fn get_x509_subject_cn(cert: &X509Certificate) -> String {
    let subject = cert.subject();
    let cn = subject.iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
}

pub fn get_x509_issuer_cn(cert: &X509Certificate) -> String {
    let issuer = cert.issuer();
    let cn = issuer.iter_common_name().next().unwrap();
    cn.as_str().unwrap().to_string()
}

pub fn get_crl_uri(cert: &X509Certificate) -> Option<String> {
    let crl_ext = cert
        .get_extension_unique(&OID_X509_EXT_CRL_DISTRIBUTION_POINTS)
        .unwrap()
        .unwrap();
    let crl_uri = match crl_ext.parsed_extension() {
        ParsedExtension::CRLDistributionPoints(crls) => {
            match &crls.iter().next().unwrap().distribution_point {
                Some(DistributionPointName::FullName(uri)) => {
                    let uri = &uri[0];
                    match uri {
                        GeneralName::URI(uri) => Some(uri.to_string()),
                        _ => None,
                    }
                }
                _ => None,
            }
        }
        _ => {
            unreachable!();
        }
    };
    crl_uri
}

/// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181
pub fn get_sgx_tdx_fmspc_tcbstatus_v3(
    tee_type: u32,
    tee_tcb_svn: Option<[u8; 16]>,
    // SGX Extensions from the PCK Certificate
    sgx_extensions: &SgxExtensions,
    tcbinfov3: &TcbInfoV3,
) -> crate::Result<(TcbInfoV3TcbStatus, Option<TcbInfoV3TcbStatus>, Vec<String>)> {
    let is_tdx = tee_type == TDX_TEE_TYPE && tcbinfov3.tcb_info.id == "TDX";
    if !is_tdx {
        // check if tee_type and tcb_info.id are consistent
        assert!(tee_type == SGX_TEE_TYPE && tcbinfov3.tcb_info.id == "SGX");
    }

    let is_tdx = if tee_type == SGX_TEE_TYPE {
        false
    } else if tee_type == TDX_TEE_TYPE {
        if tee_tcb_svn.is_none() {
            bail!("TDX TCB SVN is missing");
        }
        true
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    };

    // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L117
    if sgx_extensions.fmspc != tcbinfov3.tcb_info.fmspc()? {
        bail!(
            "FMSPC does not match: {:x?} != {:x?}",
            sgx_extensions.fmspc,
            tcbinfov3.tcb_info.fmspc()?
        );
    } else if sgx_extensions.pceid != tcbinfov3.tcb_info.pce_id()? {
        bail!(
            "PCE ID does not match: {:x?} != {:x?}",
            sgx_extensions.pceid,
            tcbinfov3.tcb_info.pce_id()?
        );
    }

    let mut sgx_tcb_status: Option<TcbInfoV3TcbStatus> = None;
    let tcb = &sgx_extensions.tcb;
    let extension_pcesvn = tcb.pcesvn;

    for tcb_level in tcbinfov3.tcb_info.tcb_levels.iter() {
        if sgx_tcb_status.is_none() {
            if match_sgxtcbcomp(tcb, &tcb_level.tcb.sgxtcbcomponents)
                && extension_pcesvn >= tcb_level.tcb.pcesvn
            {
                sgx_tcb_status = Some(TcbInfoV3TcbStatus::from_str(tcb_level.tcb_status.as_str())?);
                if !is_tdx {
                    return Ok((
                        sgx_tcb_status.unwrap(),
                        None,
                        tcb_level.advisory_ids.clone().unwrap_or_default(),
                    ));
                }
            }
        }
        if is_tdx && sgx_tcb_status.is_some() {
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

fn match_sgxtcbcomp(tcb: &SgxExtensionTcbLevel, sgxtcbcomponents: &[TcbComponent; 16]) -> bool {
    // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16) with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
    // If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, then return true.
    // Otherwise, return false.
    tcb.sgxtcbcompsvns()
        .into_iter()
        .zip(sgxtcbcomponents.iter())
        .all(|(ext, tcb)| ext >= tcb.svn)
}

fn match_tdxtcbcomp(tee_tcb_svn: &[u8; 16], tdxtcbcomponents: &[TcbComponent; 16]) -> bool {
    // Compare all of the TDX TCB Comp SVNs retrieved from the TDX Quote (from 01 to 16) with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level.
    // If all TDX TCB Comp SVNs in the quote are greater or equal to the corresponding values in TCB Level, then return true.
    // Otherwise, return false.
    tee_tcb_svn
        .iter()
        .zip(tdxtcbcomponents.iter())
        .all(|(tee, tcb)| *tee >= tcb.svn)
}

/// Merge two vectors of advisory ids into one vector
/// This function will remove any duplicates
pub fn merge_advisory_ids(advisory_ids: Vec<String>, advisory_ids2: Vec<String>) -> Vec<String> {
    let mut ids = advisory_ids
        .into_iter()
        .chain(advisory_ids2.into_iter())
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}
