use crate::crypto::verify_p256_signature_der;
use anyhow::bail;
use core::ops::{BitAnd, BitOr, Deref};
use core::str::FromStr;
use dcap_types::cert::{SgxExtensionTcbLevel, SgxExtensions};
use dcap_types::tcb_info::{TcbComponent, TcbInfoV3};
use dcap_types::TcbInfoV3TcbStatus;
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use x509_parser::prelude::*;

pub const KU_NONE: KeyUsageFlags = KeyUsageFlags(0);
pub const KU_DIGITAL_SIGNATURE: KeyUsageFlags = KeyUsageFlags(1);
pub const KU_NON_REPUDIATION: KeyUsageFlags = KeyUsageFlags(1 << 1);
pub const KU_KEY_ENCIPHERMENT: KeyUsageFlags = KeyUsageFlags(1 << 2);
pub const KU_DATA_ENCIPHERMENT: KeyUsageFlags = KeyUsageFlags(1 << 3);
pub const KU_KEY_AGREEMENT: KeyUsageFlags = KeyUsageFlags(1 << 4);
pub const KU_KEY_CERT_SIGN: KeyUsageFlags = KeyUsageFlags(1 << 5);
pub const KU_CRL_SIGN: KeyUsageFlags = KeyUsageFlags(1 << 6);
pub const KU_ENCIPHER_ONLY: KeyUsageFlags = KeyUsageFlags(1 << 7);
pub const KU_DECIPHER_ONLY: KeyUsageFlags = KeyUsageFlags(1 << 8);

/// KeyUsageFlags is a bitmask of Key Usage flags.
///
/// Each flag corresponds to a specific key usage as defined in RFC 5280.
/// ref. <https://datatracker.ietf.org/doc/html/rfc5280#section-4.2.1.3>
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct KeyUsageFlags(pub u16);

impl Deref for KeyUsageFlags {
    type Target = u16;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl BitOr for KeyUsageFlags {
    type Output = KeyUsageFlags;

    fn bitor(self, rhs: KeyUsageFlags) -> Self::Output {
        KeyUsageFlags(self.0 | rhs.0)
    }
}

impl BitAnd for KeyUsageFlags {
    type Output = KeyUsageFlags;

    fn bitand(self, rhs: KeyUsageFlags) -> Self::Output {
        KeyUsageFlags(self.0 & rhs.0)
    }
}

/// Parse a PEM-encoded certificate chain into a vector of `X509Certificate`.
pub fn parse_certchain(pem_certs: &[Pem]) -> crate::Result<Vec<X509Certificate>> {
    Ok(pem_certs
        .iter()
        .map(|pem| pem.parse_x509())
        .collect::<Result<_, _>>()?)
}

/// Verifies the signature of a certificate using the public key of the signer certificate.
pub fn verify_certificate_signature(
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
    if certs.is_empty() {
        bail!("Empty certificate chain");
    }
    // verify that the cert chain is valid
    let mut iter = certs.iter();
    let mut prev_cert = iter.next().unwrap();
    for cert in iter {
        // verify that the previous cert signed the current cert
        verify_certificate_signature(prev_cert, cert)?;
        prev_cert = cert;
    }
    // verify that the root cert signed the last cert
    verify_certificate_signature(prev_cert, root_cert)
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

/// Get the TCB status and advisory IDs of the SGX or TDX corresponding to the given SVN from the TCB Info V3.
///
/// This function returns:
/// - For SGX: SGX TCB status and associated advisory IDs.
/// - For TDX: SGX TCB status (matched by SGX components) and TDX TCB status (matched by TDX components) with advisory IDs associated only to the matched TDX TCB level.
///
/// Reference implementation:
/// <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L129-L181>
///
/// # Arguments
/// * `tee_type` - The type of TEE (SGX or TDX)
/// * `tee_tcb_svn` - The TCB SVN of the TEE (only for TDX, must be None for SGX)
/// * `sgx_extensions` - The SGX Extensions from the PCK Certificate
/// * `tcb_info_v3` - The TCB Info V3
///
/// # Returns
/// * `(sgx_tcb_status, tdx_tcb_status, advisory_ids)`:
///   - `sgx_tcb_status`: SGX TCB status based on matching SGX components.
///   - `tdx_tcb_status`: Optional TDX TCB status based on matching TDX components (only set for TDX).
///   - `advisory_ids`: Advisory IDs associated with the matched TCB level.
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
            bail!("SGX TCB SVN should be None for SGX TEE Type");
        }
    } else if tee_type == TDX_TEE_TYPE {
        if tcb_info_v3.tcb_info.id != "TDX" {
            bail!("Invalid TCB Info ID for TDX TEE Type");
        } else if tee_tcb_svn.is_none() {
            bail!("TDX TCB SVN is required for TDX TEE Type");
        }
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    }

    if sgx_extensions.fmspc != tcb_info_v3.tcb_info.fmspc()? {
        bail!(
            "FMSPC mismatch: {:x?} != {:x?}",
            sgx_extensions.fmspc,
            tcb_info_v3.tcb_info.fmspc()?
        );
    } else if sgx_extensions.pceid != tcb_info_v3.tcb_info.pce_id()? {
        bail!(
            "PCE ID mismatch: {:x?} != {:x?}",
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
                // Return advisory IDs associated with matched SGX TCB level
                return Ok((
                    sgx_tcb_status.unwrap(),
                    None,
                    tcb_level.advisory_ids.clone().unwrap_or_default(),
                ));
            }
        }

        if tee_type == TDX_TEE_TYPE && sgx_tcb_status.is_some() {
            let tdxtcbcomponents = tcb_level
                .tcb
                .tdxtcbcomponents
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("TDX TCB Components missing"))?;

            if match_tdxtcbcomp(&tee_tcb_svn.unwrap(), tdxtcbcomponents) {
                // Return advisory IDs associated with matched TDX TCB level
                return Ok((
                    sgx_tcb_status.unwrap(),
                    Some(TcbInfoV3TcbStatus::from_str(tcb_level.tcb_status.as_str())?),
                    tcb_level.advisory_ids.clone().unwrap_or_default(),
                ));
            }
        }
    }

    if let Some(status) = sgx_tcb_status {
        // SGX matched, but TDX did not match any level, thus no advisory IDs
        Ok((status, None, vec![]))
    } else {
        bail!("No matching SGX TCB Level found");
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

/// Validates the critical `KeyUsage` and `BasicConstraints` extensions of an X.509 certificate.
///
/// This function ensures that the certificate includes both `KeyUsage` and `BasicConstraints`
/// extensions marked as critical, and that their values match the expected ones.
///
/// - For `KeyUsage`, it checks that all bits specified in `expected_ku` are present in the certificate's `KeyUsage`.
///   Additional bits set in the certificate are allowed and not rejected.
/// - For `BasicConstraints`, it checks that the `ca` flag and the `path_len_constraint` match exactly.
///
/// # Arguments
/// * `cert` - The X.509 certificate to validate.
/// * `expected_ca` - Whether the certificate is expected to be a CA.
/// * `expected_pathlen` - The expected `pathLenConstraint` value (if any).
/// * `expected_ku` - The expected combination of `KeyUsage` bits that must be present.
///
/// # Errors
/// Returns an error if:
/// - A required extension is missing,
/// - A known critical extension does not match the expected values,
/// - An unknown critical extension is present.
pub(crate) fn validate_cert_extensions(
    cert: &X509Certificate,
    expected_ca: bool,
    expected_pathlen: Option<u32>,
    expected_ku: KeyUsageFlags,
) -> crate::Result<()> {
    let mut ku_validated = false;
    let mut bc_validated = false;
    for ext in cert.extensions().iter().filter(|ext| ext.critical) {
        match ext.parsed_extension() {
            ParsedExtension::KeyUsage(ku) => {
                // check that all expected bits are set
                if ku.flags & expected_ku.0 != expected_ku.0 {
                    bail!(
                        "Certificate Key Usage mismatch: expected={:b}, actual={:b}",
                        expected_ku.0,
                        ku.flags
                    );
                }
                ku_validated = true;
            }
            ParsedExtension::BasicConstraints(bc) => {
                if bc.ca != expected_ca || bc.path_len_constraint != expected_pathlen {
                    bail!(
                        "Certificate Basic Constraints mismatch: ca={}, pathlen={:?}",
                        expected_ca,
                        expected_pathlen
                    );
                }
                bc_validated = true;
            }
            _ => bail!("Unknown critical extension: {}", ext.oid),
        }
    }
    if !ku_validated {
        bail!("Missing critical Key Usage extension");
    }
    if !bc_validated {
        bail!("Missing critical Basic Constraints extension");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        certs::{build_x509_name, gen_skid, Validity},
        openssl::x509::X509,
        utils::gen_key,
    };
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

    #[test]
    fn test_validate_cert_extensions() {
        use x509_parser::prelude::FromDer;

        // OK: Valid certificate: leaf cert with expected KU and basic constraints
        {
            let cert = gen_cert(false, None, KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION);
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res = validate_cert_extensions(
                &cert,
                false,
                None,
                KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION,
            );
            assert!(res.is_ok(), "valid cert should pass: {:?}", res);
        }

        // Failed: Missing Key Usage bit (non_repudiation is missing)
        {
            let cert = gen_cert(false, None, KU_DIGITAL_SIGNATURE); // only digital_signature
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res = validate_cert_extensions(
                &cert,
                false,
                None,
                KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION,
            );
            assert!(res.is_err(), "missing KU bit should fail");
        }

        // Failed: Mismatched BasicConstraints CA flag (expected false, actual true)
        {
            let cert = gen_cert(true, None, KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION); // CA = true
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res = validate_cert_extensions(
                &cert,
                false,
                None,
                KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION,
            );
            assert!(res.is_err(), "CA mismatch should fail");
        }

        // OK: Mismatched BasicConstraints path length
        {
            let cert = gen_cert(true, Some(1), KU_KEY_CERT_SIGN | KU_CRL_SIGN);
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res = validate_cert_extensions(
                &cert,
                true,
                Some(0), // expected pathlen: 0, actual: 1
                KU_KEY_CERT_SIGN | KU_CRL_SIGN,
            );
            assert!(res.is_err(), "pathlen mismatch should fail");
        }

        // Failed: Missing Key Usage extension entirely (critical extension missing)
        {
            let cert = gen_cert(false, None, KU_NONE); // no KeyUsage
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res = validate_cert_extensions(&cert, false, None, KU_DIGITAL_SIGNATURE);
            assert!(res.is_err(), "missing KeyUsage extension should fail");
        }

        // OK: Valid CA certificate with correct KeyUsage and BasicConstraints
        {
            let cert = gen_cert(true, Some(0), KU_KEY_CERT_SIGN | KU_CRL_SIGN);
            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            let res =
                validate_cert_extensions(&cert, true, Some(0), KU_KEY_CERT_SIGN | KU_CRL_SIGN);
            assert!(res.is_ok(), "valid CA cert should pass");
        }

        // OK: Valid certificate with extra KeyUsage bits
        {
            // Expected: digital_signature + non_repudiation
            // Extra   : key_encipherment + key_agreement
            let cert = gen_cert(
                false,
                None,
                KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION | KU_KEY_ENCIPHERMENT | KU_KEY_AGREEMENT,
            );

            let der = cert.to_der().unwrap();
            let (_, cert) = X509Certificate::from_der(&der).unwrap();

            // We only require digital_signature and non_repudiation to be present.
            let res = validate_cert_extensions(
                &cert,
                false,
                None,
                KU_DIGITAL_SIGNATURE | KU_NON_REPUDIATION,
            );

            assert!(
                res.is_ok(),
                "cert with extra KeyUsage bits should still pass validation"
            );
        }
    }

    fn gen_cert(ca: bool, path_len: Option<u32>, ku: KeyUsageFlags) -> X509 {
        use dcap_collaterals::openssl::x509::extension::{BasicConstraints, KeyUsage};
        use dcap_collaterals::openssl::{
            asn1::Asn1Integer, bn::BigNum, hash::MessageDigest, x509::X509Builder,
        };

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap(); // X.509 v3

        let serial = BigNum::from_u32(1).unwrap(); // Dummy serial
        let serial = Asn1Integer::from_bn(&serial).unwrap();
        builder.set_serial_number(&serial).unwrap();

        builder
            .set_not_before(&Validity::long_duration().not_before())
            .unwrap();
        builder
            .set_not_after(&Validity::long_duration().not_after())
            .unwrap();

        let pkey = gen_key();
        builder.set_pubkey(&pkey).unwrap();

        let name = build_x509_name("Test CA").unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.append_extension(gen_skid(&pkey)).unwrap();

        // Key Usage extension
        let mut key_usage = KeyUsage::new();
        if ku != KU_NONE {
            key_usage.critical();
            if ku & KU_DIGITAL_SIGNATURE != KU_NONE {
                key_usage.digital_signature();
            }
            if ku & KU_NON_REPUDIATION != KU_NONE {
                key_usage.non_repudiation();
            }
            if ku & KU_KEY_ENCIPHERMENT != KU_NONE {
                key_usage.key_encipherment();
            }
            if ku & KU_DATA_ENCIPHERMENT != KU_NONE {
                key_usage.data_encipherment();
            }
            if ku & KU_KEY_AGREEMENT != KU_NONE {
                key_usage.key_agreement();
            }
            if ku & KU_KEY_CERT_SIGN != KU_NONE {
                key_usage.key_cert_sign();
            }
            if ku & KU_CRL_SIGN != KU_NONE {
                key_usage.crl_sign();
            }
            if ku & KU_ENCIPHER_ONLY != KU_NONE {
                key_usage.encipher_only();
            }
            if ku & KU_DECIPHER_ONLY != KU_NONE {
                key_usage.decipher_only();
            }

            builder
                .append_extension(key_usage.build().unwrap())
                .unwrap();
        }

        // Basic Constraints extension
        let mut bc = BasicConstraints::new();
        bc.critical();
        if ca {
            bc.ca();
        }
        if let Some(plc) = path_len {
            bc.pathlen(plc);
        }
        builder.append_extension(bc.build().unwrap()).unwrap();

        builder.sign(&pkey, MessageDigest::sha256()).unwrap();
        builder.build()
    }
}
