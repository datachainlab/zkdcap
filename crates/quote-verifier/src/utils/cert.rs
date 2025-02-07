use anyhow::bail;
use x509_parser::oid_registry::asn1_rs::{
    oid, Boolean, Enumerated, FromDer, Integer, OctetString, Oid, Sequence,
};
use x509_parser::oid_registry::OID_X509_EXT_CRL_DISTRIBUTION_POINTS;
use x509_parser::prelude::*;

use crate::constants::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use crate::types::cert::{PckPlatformConfiguration, SgxExtensionTcbLevel, SgxExtensions};
use crate::types::tcbinfo::{TcbComponent, TcbInfoV3};
use crate::types::TcbInfoV3TcbStatus;
use crate::utils::crypto::verify_p256_signature_der;

pub fn pem_to_der(pem_bytes: &[u8]) -> Result<Vec<u8>, PEMError> {
    // convert from raw pem bytes to pem objects
    let pems = parse_pem(pem_bytes)?;
    // convert from pem objects to der bytes
    // to make it more optimize, we'll read get all the lengths of the der bytes
    // and then allocate the buffer once
    let der_bytes_len: usize = pems.iter().map(|pem| pem.contents.len()).sum();
    let mut der_bytes = Vec::with_capacity(der_bytes_len);
    for pem in pems {
        der_bytes.extend_from_slice(&pem.contents);
    }
    Ok(der_bytes)
}

pub fn parse_pem(raw_bytes: &[u8]) -> Result<Vec<Pem>, PEMError> {
    Pem::iter_from_buffer(raw_bytes).collect()
}

pub fn parse_crl_der<'a>(raw_bytes: &'a [u8]) -> crate::Result<CertificateRevocationList<'a>> {
    let (_, crl) = CertificateRevocationList::from_der(raw_bytes)?;
    Ok(crl)
}

pub fn parse_x509_der<'a>(raw_bytes: &'a [u8]) -> crate::Result<X509Certificate<'a>> {
    let (_, cert) = X509Certificate::from_der(raw_bytes)?;
    Ok(cert)
}

pub fn parse_x509_der_multi<'a>(raw_bytes: &'a [u8]) -> crate::Result<Vec<X509Certificate<'a>>> {
    let mut certs = Vec::new();
    let mut i = raw_bytes;
    while i.len() > 0 {
        let (j, cert) = X509Certificate::from_der(i)?;
        certs.push(cert);
        i = j;
    }
    Ok(certs)
}

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

pub fn get_asn1_uint64<'a>(bytes: &'a [u8], oid_str: &str) -> (&'a [u8], u64) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_int) = Integer::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_int.as_u64().unwrap())
}

pub fn get_asn1_bytes<'a>(bytes: &'a [u8], oid_str: &str) -> (&'a [u8], Vec<u8>) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_bytes) = OctetString::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_bytes.into_cow().to_vec())
}

pub fn extract_sgx_extensions<'a>(cert: &'a X509Certificate<'a>) -> SgxExtensions {
    // https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

    // <SGX Extensions OID>:
    //     <PPID OID>: <PPID value>
    //     <TCB OID>:
    //          <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
    //          <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
    //          …
    //          <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
    //          <PCESVN OID>: <PCESVN value>
    //          <CPUSVN OID>: <CPUSVN value>
    //     <PCE-ID OID>: <PCE-ID value>
    //     <FMSPC OID>: <FMSPC value>
    //     <SGX Type OID>: <SGX Type value>
    //     <PlatformInstanceID OID>: <PlatformInstanceID value>
    //     <Configuration OID>:
    //          <Dynamic Platform OID>: <Dynamic Platform flag value>
    //          <Cached Keys OID>: <Cached Keys flag value>
    //          <SMT Enabled OID>: <SMT Enabled flag value>

    // SGX Extensions       | 1.2.840.113741.1.13.1      | mandatory | ASN.1 Sequence
    // PPID                 | 1.2.840.113741.1.13.1.1    | mandatory | ASN.1 Octet String
    // TCB                  | 1.2.840.113741.1.13.1.2    | mandatory | ASN.1 Sequence
    // SGX TCB Comp01 SVN   | 1.2.840.113741.1.13.1.2.1  | mandatory | ASN.1 Integer
    // SGX TCB Comp02 SVN   | 1.2.840.113741.1.13.1.2.2  | mandatory | ASN.1 Integer
    // ...
    // SGX TCB Comp16 SVN   | 1.2.840.113741.1.13.1.2.16 | mandatory | ASN.1 Integer
    // PCESVN               | 1.2.840.113741.1.13.1.2.17 | mandatory | ASN.1 Integer
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Integer
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    // we'll process the sgx extensions here...
    let mut i = sgx_extensions.content.as_ref();

    // let's define the required information to create the SgxExtensions struct
    let mut ppid = [0; 16];
    let mut tcb = SgxExtensionTcbLevel {
        sgxtcbcomp01svn: 0,
        sgxtcbcomp02svn: 0,
        sgxtcbcomp03svn: 0,
        sgxtcbcomp04svn: 0,
        sgxtcbcomp05svn: 0,
        sgxtcbcomp06svn: 0,
        sgxtcbcomp07svn: 0,
        sgxtcbcomp08svn: 0,
        sgxtcbcomp09svn: 0,
        sgxtcbcomp10svn: 0,
        sgxtcbcomp11svn: 0,
        sgxtcbcomp12svn: 0,
        sgxtcbcomp13svn: 0,
        sgxtcbcomp14svn: 0,
        sgxtcbcomp15svn: 0,
        sgxtcbcomp16svn: 0,
        pcesvn: 0,
        cpusvn: [0; 16],
    };
    let mut pceid = [0; 2];
    let mut fmspc = [0; 6];
    let mut sgx_type = 0;
    let mut platform_instance_id: Option<[u8; 16]> = None;
    let mut configuration: Option<PckPlatformConfiguration> = None;

    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.1" => {
                let (k, ppid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                ppid.copy_from_slice(ppid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.2" => {
                let (k, tcb_sequence) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                // iterate through from 1 - 18
                let (k, sgxtcbcomp01svn) =
                    get_asn1_uint64(tcb_sequence.content.as_ref(), "1.2.840.113741.1.13.1.2.1");
                let (k, sgxtcbcomp02svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.2");
                let (k, sgxtcbcomp03svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.3");
                let (k, sgxtcbcomp04svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.4");
                let (k, sgxtcbcomp05svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.5");
                let (k, sgxtcbcomp06svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.6");
                let (k, sgxtcbcomp07svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.7");
                let (k, sgxtcbcomp08svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.8");
                let (k, sgxtcbcomp09svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.9");
                let (k, sgxtcbcomp10svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.10");
                let (k, sgxtcbcomp11svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.11");
                let (k, sgxtcbcomp12svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.12");
                let (k, sgxtcbcomp13svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.13");
                let (k, sgxtcbcomp14svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.14");
                let (k, sgxtcbcomp15svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.15");
                let (k, sgxtcbcomp16svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.16");
                let (k, pcesvn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.17");
                let (k, cpusvn) = get_asn1_bytes(k, "1.2.840.113741.1.13.1.2.18");

                assert_eq!(k.len(), 0);
                // copy the bytes into the tcb struct
                tcb.sgxtcbcomp01svn = sgxtcbcomp01svn as u8;
                tcb.sgxtcbcomp02svn = sgxtcbcomp02svn as u8;
                tcb.sgxtcbcomp03svn = sgxtcbcomp03svn as u8;
                tcb.sgxtcbcomp04svn = sgxtcbcomp04svn as u8;
                tcb.sgxtcbcomp05svn = sgxtcbcomp05svn as u8;
                tcb.sgxtcbcomp06svn = sgxtcbcomp06svn as u8;
                tcb.sgxtcbcomp07svn = sgxtcbcomp07svn as u8;
                tcb.sgxtcbcomp08svn = sgxtcbcomp08svn as u8;
                tcb.sgxtcbcomp09svn = sgxtcbcomp09svn as u8;
                tcb.sgxtcbcomp10svn = sgxtcbcomp10svn as u8;
                tcb.sgxtcbcomp11svn = sgxtcbcomp11svn as u8;
                tcb.sgxtcbcomp12svn = sgxtcbcomp12svn as u8;
                tcb.sgxtcbcomp13svn = sgxtcbcomp13svn as u8;
                tcb.sgxtcbcomp14svn = sgxtcbcomp14svn as u8;
                tcb.sgxtcbcomp15svn = sgxtcbcomp15svn as u8;
                tcb.sgxtcbcomp16svn = sgxtcbcomp16svn as u8;
                tcb.pcesvn = pcesvn as u16;
                tcb.cpusvn.copy_from_slice(cpusvn.as_ref());
            }
            "1.2.840.113741.1.13.1.3" => {
                let (k, pceid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                pceid.copy_from_slice(pceid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.5" => {
                let (k, sgx_type_enum) = Enumerated::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                sgx_type = sgx_type_enum.0;
            }
            "1.2.840.113741.1.13.1.6" => {
                let (k, platform_instance_id_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut temp = [0; 16];
                temp.copy_from_slice(platform_instance_id_bytes.as_ref());
                platform_instance_id = Some(temp);
            }
            "1.2.840.113741.1.13.1.7" => {
                let (k, configuration_seq) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut configuration_temp = PckPlatformConfiguration {
                    dynamic_platform: None,
                    cached_keys: None,
                    smt_enabled: None,
                };
                // iterate through from 1 - 3, note that some of them might be optional.
                let mut k = configuration_seq.content.as_ref();
                while k.len() > 0 {
                    let (l, asn1_seq) = Sequence::from_der(k).unwrap();
                    k = l;
                    let (l, current_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
                    match current_oid.to_id_string().as_str() {
                        "1.2.840.113741.1.13.1.7.1" => {
                            let (l, dynamic_platform_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.dynamic_platform =
                                Some(dynamic_platform_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.2" => {
                            let (l, cached_keys_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.cached_keys = Some(cached_keys_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.3" => {
                            let (l, smt_enabled_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.smt_enabled = Some(smt_enabled_bool.bool());
                        }
                        _ => {
                            unreachable!("Unknown OID: {}", current_oid.to_id_string());
                        }
                    }
                }
                // done parsing...
                configuration = Some(configuration_temp);
            }
            _ => {
                unreachable!("Unknown OID: {}", current_oid.to_id_string());
            }
        }
    }

    SgxExtensions {
        ppid,
        tcb,
        pceid,
        fmspc,
        sgx_type,
        platform_instance_id,
        configuration,
    }
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
    if sgx_extensions.fmspc.as_slice() != hex::decode(&tcbinfov3.tcb_info.fmspc)? {
        bail!("FMSpc does not match");
    } else if sgx_extensions.pceid.as_slice() != hex::decode(&tcbinfov3.tcb_info.pce_id)? {
        bail!("PCEID does not match");
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

fn match_sgxtcbcomp(tcb: &SgxExtensionTcbLevel, sgxtcbcomponents: &[TcbComponent]) -> bool {
    let extension_tcbcomponents = extension_to_tcbcomponents(tcb);
    // Compare all of the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate (from 01 to 16) with the corresponding values of SVNs in sgxtcbcomponents array of TCB Level.
    // If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, then return true.
    // Otherwise, return false.
    extension_tcbcomponents
        .iter()
        .zip(sgxtcbcomponents.iter())
        .all(|(ext, tcb)| ext.svn >= tcb.svn)
}

fn match_tdxtcbcomp(tee_tcb_svn: &[u8; 16], tdxtcbcomponents: &[TcbComponent]) -> bool {
    // Compare all of the TDX TCB Comp SVNs retrieved from the TDX Quote (from 01 to 16) with the corresponding values of SVNs in tdxtcbcomponents array of TCB Level.
    // If all TDX TCB Comp SVNs in the quote are greater or equal to the corresponding values in TCB Level, then return true.
    // Otherwise, return false.
    tee_tcb_svn
        .iter()
        .zip(tdxtcbcomponents.iter())
        .all(|(tee, tcb)| *tee >= tcb.svn)
}

fn extension_to_tcbcomponents(extension: &SgxExtensionTcbLevel) -> Vec<TcbComponent> {
    let mut tcbcomponents = Vec::with_capacity(16);
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp01svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp02svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp03svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp04svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp05svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp06svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp07svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp08svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp09svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp10svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp11svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp12svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp13svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp14svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp15svn,
        category: None,
        type_: None,
    });
    tcbcomponents.push(TcbComponent {
        svn: extension.sgxtcbcomp16svn,
        category: None,
        type_: None,
    });

    tcbcomponents
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
