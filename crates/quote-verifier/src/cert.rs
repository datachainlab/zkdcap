use crate::crypto::verify_p256_signature_der;
use anyhow::{anyhow, bail};
use core::ops::{BitAnd, BitOr, Deref};
use core::str::FromStr;
use dcap_types::cert::{
    SgxExtensionTcbLevel, SgxExtensions, INTEL_SGX_COUNTRY_NAME, INTEL_SGX_LOCALITY_NAME,
    INTEL_SGX_ORGANIZATION_NAME, INTEL_SGX_PCK_CERT_COMMON_NAME,
    INTEL_SGX_PCK_PLATFORM_CA_COMMON_NAME, INTEL_SGX_PCK_PROCESSOR_CA_COMMON_NAME,
    INTEL_SGX_ROOT_CA_COMMON_NAME, INTEL_SGX_STATE_OR_PROVINCE_NAME,
    INTEL_SGX_TCB_SIGNING_COMMON_NAME,
};
use dcap_types::tcb_info::{TcbComponent, TcbInfoV3};
use dcap_types::TcbInfoV3TcbStatus;
use dcap_types::{SGX_TEE_TYPE, TDX_TEE_TYPE};
use x509_parser::oid_registry::{
    OID_X509_COMMON_NAME, OID_X509_COUNTRY_NAME, OID_X509_LOCALITY_NAME,
    OID_X509_ORGANIZATION_NAME, OID_X509_STATE_OR_PROVINCE_NAME,
};
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

/// Checks if the given X.509 name matches the SGX Root CA DN.
///
/// The expected DN is "CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
///
/// # Returns
/// - `Ok(true)` if the DN structure and all attribute values match the expected DN.
/// - `Ok(false)` if the DN structure is valid but the Common Name (CN) does not match the expected value.
/// - `Err(_)` if the DN is malformed or contains unexpected attributes (e.g., missing or out of order).
pub fn is_sgx_root_ca_dn(name: &X509Name) -> crate::Result<bool> {
    is_valid_intel_sgx_dn(name, INTEL_SGX_ROOT_CA_COMMON_NAME)
}

/// Checks if the given X.509 name matches the SGX TCB Signing Cert DN.
///
/// The expected DN is "CN=Intel SGX TCB Signing, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
///
/// # Returns
/// - `Ok(true)` if the DN structure and all attribute values match the expected DN.
/// - `Ok(false)` if the DN structure is valid but the Common Name (CN) does not match the expected value.
/// - `Err(_)` if the DN is malformed or contains unexpected attributes (e.g., missing or out of order).
pub fn is_sgx_tcb_signing_cert_dn(name: &X509Name) -> crate::Result<bool> {
    is_valid_intel_sgx_dn(name, INTEL_SGX_TCB_SIGNING_COMMON_NAME)
}

/// Checks if the given X.509 name matches the SGX PCK Processor CA DN.
///
/// The expected DN is "CN=Intel SGX PCK Processor CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
///
/// # Returns
/// - `Ok(true)` if the DN structure and all attribute values match the expected DN.
/// - `Ok(false)` if the DN structure is valid but the Common Name (CN) does not match the expected value.
/// - `Err(_)` if the DN is malformed or contains unexpected attributes (e.g., missing or out of order).
pub fn is_sgx_pck_processor_ca_dn(name: &X509Name) -> crate::Result<bool> {
    is_valid_intel_sgx_dn(name, INTEL_SGX_PCK_PROCESSOR_CA_COMMON_NAME)
}

/// Checks if the given X.509 name matches the SGX PCK Platform CA DN.
///
/// The expected DN is "CN=Intel SGX PCK Platform CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
///
/// # Returns
/// - `Ok(true)` if the DN structure and all attribute values match the expected DN.
/// - `Ok(false)` if the DN structure is valid but the Common Name (CN) does not match the expected value.
/// - `Err(_)` if the DN is malformed or contains unexpected attributes (e.g., missing or out of order).
pub fn is_sgx_pck_platform_ca_dn(name: &X509Name) -> crate::Result<bool> {
    is_valid_intel_sgx_dn(name, INTEL_SGX_PCK_PLATFORM_CA_COMMON_NAME)
}

/// Checks if the given X.509 name matches the SGX PCK Cert DN.
///
/// The expected DN is "CN=Intel SGX PCK Certificate, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
///
/// # Returns
/// - `Ok(true)` if the DN structure and all attribute values match the expected DN.
/// - `Ok(false)` if the DN structure is valid but the Common Name (CN) does not match the expected value.
/// - `Err(_)` if the DN is malformed or contains unexpected attributes (e.g., missing or out of order).
pub fn is_sgx_pck_cert_dn(name: &X509Name) -> crate::Result<bool> {
    is_valid_intel_sgx_dn(name, INTEL_SGX_PCK_CERT_COMMON_NAME)
}

/// Verifies that the given X.509 DN matches the expected Intel SGX DN structure and values.
///
/// This function checks that the DN has exactly five RDN attributes in the expected order:
/// - Common Name (CN)
/// - Organization Name (O)
/// - Locality Name (L)
/// - State or Province Name (ST)
/// - Country Name (C)
///
/// All attributes except CN must match known Intel SGX values. The CN is compared to `expected_cn`.
///
/// # Returns
/// - `Ok(true)` if all attribute values match, including the CN.
/// - `Ok(false)` if the DN structure is correct but the CN does not match `expected_cn`.
/// - `Err(_)` if the DN is malformed (e.g., missing attributes, extra attributes, or unexpected OIDs).
fn is_valid_intel_sgx_dn(name: &X509Name, expected_cn: &str) -> crate::Result<bool> {
    let mut iter = name.iter_attributes();
    let cn = iter.next().ok_or(anyhow!("CN attribute not found"))?;
    if cn.attr_type() != &OID_X509_COMMON_NAME {
        bail!(
            "Expected CN attribute, found: {:?}",
            cn.attr_type().as_bytes()
        );
    }
    let o = iter.next().ok_or(anyhow!("O attribute not found"))?;
    if o.attr_type() != &OID_X509_ORGANIZATION_NAME {
        bail!(
            "Expected O attribute, found: {:?}",
            o.attr_type().as_bytes()
        );
    }
    if o.as_str()? != INTEL_SGX_ORGANIZATION_NAME {
        bail!("Unexpected O: {}", o.as_str().unwrap());
    }
    let l = iter.next().ok_or(anyhow!("L attribute not found"))?;
    if l.attr_type() != &OID_X509_LOCALITY_NAME {
        bail!(
            "Expected L attribute, found: {:?}",
            l.attr_type().as_bytes()
        );
    }
    if l.as_str()? != INTEL_SGX_LOCALITY_NAME {
        bail!("Unexpected L: {}", l.as_str().unwrap());
    }
    let st = iter.next().ok_or(anyhow!("ST attribute not found"))?;
    if st.attr_type() != &OID_X509_STATE_OR_PROVINCE_NAME {
        bail!(
            "Expected ST attribute, found: {:?}",
            st.attr_type().as_bytes()
        );
    }
    if st.as_str()? != INTEL_SGX_STATE_OR_PROVINCE_NAME {
        bail!("Unexpected ST: {}", st.as_str().unwrap());
    }
    let c = iter.next().ok_or(anyhow!("C attribute not found"))?;
    if c.attr_type() != &OID_X509_COUNTRY_NAME {
        bail!(
            "Expected C attribute, found: {:?}",
            c.attr_type().as_bytes()
        );
    }
    if c.as_str()? != INTEL_SGX_COUNTRY_NAME {
        bail!("Unexpected C: {}", c.as_str().unwrap());
    }
    if iter.next().is_some() {
        bail!("Unexpected attributes found in DN");
    }
    Ok(cn.as_str()? == expected_cn)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        certs::{build_x509_name, build_x509_name_with_values, gen_skid, Validity},
        openssl::x509::X509,
        utils::gen_key,
    };
    use dcap_types::utils::{parse_crl_der, parse_x509_der};

    /// "CN=Intel SGX Root CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
    const SGX_ROOT_CA_DN_DER: &[u8] = &[
        48, 104, 49, 26, 48, 24, 6, 3, 85, 4, 3, 12, 17, 73, 110, 116, 101, 108, 32, 83, 71, 88,
        32, 82, 111, 111, 116, 32, 67, 65, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12, 17, 73, 110, 116,
        101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49, 20, 48, 18, 6, 3,
        85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11, 48, 9, 6, 3, 85,
        4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83,
    ];
    /// "CN=Intel SGX TCB Signing, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
    const SGX_TCB_SIGNING_CERT_DN_DER: &[u8] = &[
        48, 108, 49, 30, 48, 28, 6, 3, 85, 4, 3, 12, 21, 73, 110, 116, 101, 108, 32, 83, 71, 88,
        32, 84, 67, 66, 32, 83, 105, 103, 110, 105, 110, 103, 49, 26, 48, 24, 6, 3, 85, 4, 10, 12,
        17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105, 111, 110, 49,
        20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97, 114, 97, 49, 11,
        48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19, 2, 85, 83,
    ];
    /// "CN=Intel SGX PCK Processor CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
    const SGX_PCK_PROCESSOR_CA_DN_DER: &[u8] = &[
        48, 113, 49, 35, 48, 33, 6, 3, 85, 4, 3, 12, 26, 73, 110, 116, 101, 108, 32, 83, 71, 88,
        32, 80, 67, 75, 32, 80, 114, 111, 99, 101, 115, 115, 111, 114, 32, 67, 65, 49, 26, 48, 24,
        6, 3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116,
        105, 111, 110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108,
        97, 114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6,
        19, 2, 85, 83,
    ];
    /// "CN=Intel SGX PCK Platform CA, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
    const SGX_PCK_PLATFORM_CA_DN_DER: &[u8] = &[
        48, 112, 49, 34, 48, 32, 6, 3, 85, 4, 3, 12, 25, 73, 110, 116, 101, 108, 32, 83, 71, 88,
        32, 80, 67, 75, 32, 80, 108, 97, 116, 102, 111, 114, 109, 32, 67, 65, 49, 26, 48, 24, 6, 3,
        85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116, 105,
        111, 110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108, 97,
        114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6, 19,
        2, 85, 83,
    ];
    /// "CN=Intel SGX PCK Certificate, O=Intel Corporation, L=Santa Clara, ST=CA, C=US"
    const SGX_PCK_CERT_DN_DER: &[u8] = &[
        48, 112, 49, 34, 48, 32, 6, 3, 85, 4, 3, 12, 25, 73, 110, 116, 101, 108, 32, 83, 71, 88,
        32, 80, 67, 75, 32, 67, 101, 114, 116, 105, 102, 105, 99, 97, 116, 101, 49, 26, 48, 24, 6,
        3, 85, 4, 10, 12, 17, 73, 110, 116, 101, 108, 32, 67, 111, 114, 112, 111, 114, 97, 116,
        105, 111, 110, 49, 20, 48, 18, 6, 3, 85, 4, 7, 12, 11, 83, 97, 110, 116, 97, 32, 67, 108,
        97, 114, 97, 49, 11, 48, 9, 6, 3, 85, 4, 8, 12, 2, 67, 65, 49, 11, 48, 9, 6, 3, 85, 4, 6,
        19, 2, 85, 83,
    ];

    #[test]
    fn test_sgx_cert_x509_name_validation() {
        let (_, name) = X509Name::from_der(SGX_ROOT_CA_DN_DER).unwrap();
        let res = is_sgx_root_ca_dn(&name);
        assert!(res.is_ok(), "Failed to validate SGX Root CA DN: {:?}", res);
        assert!(res.unwrap(), "SGX Root CA DN validation failed");
        let (_, name) = X509Name::from_der(SGX_TCB_SIGNING_CERT_DN_DER).unwrap();
        let res = is_sgx_tcb_signing_cert_dn(&name);
        assert!(
            res.is_ok(),
            "Failed to validate SGX TCB Signing Cert DN: {:?}",
            res
        );
        assert!(res.unwrap(), "SGX TCB Signing Cert DN validation failed");
        let (_, name) = X509Name::from_der(SGX_PCK_PROCESSOR_CA_DN_DER).unwrap();
        let res = is_sgx_pck_processor_ca_dn(&name);
        assert!(
            res.is_ok(),
            "Failed to validate SGX PCK Processor CA DN: {:?}",
            res
        );
        assert!(res.unwrap(), "SGX PCK Processor CA DN validation failed");
        let (_, name) = X509Name::from_der(SGX_PCK_PLATFORM_CA_DN_DER).unwrap();
        let res = is_sgx_pck_platform_ca_dn(&name);
        assert!(
            res.is_ok(),
            "Failed to validate SGX PCK Platform CA DN: {:?}",
            res
        );
        assert!(res.unwrap(), "SGX PCK Platform CA DN validation failed");
        let (_, name) = X509Name::from_der(SGX_PCK_CERT_DN_DER).unwrap();
        let res = is_sgx_pck_cert_dn(&name);
        assert!(res.is_ok(), "Failed to validate SGX PCK Cert DN: {:?}", res);
        assert!(res.unwrap(), "SGX PCK Cert DN validation failed");
    }

    #[test]
    fn test_sgx_cert_x509_name_validation_fail() {
        {
            let name_der = build_x509_name_with_values(
                "Invalid Common Name",
                INTEL_SGX_ORGANIZATION_NAME,
                INTEL_SGX_LOCALITY_NAME,
                INTEL_SGX_STATE_OR_PROVINCE_NAME,
                INTEL_SGX_COUNTRY_NAME,
            )
            .unwrap()
            .to_der()
            .unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(res.is_ok(), "Failed to validate SGX Root CA DN: {:?}", res);
            assert!(!res.unwrap(), "SGX Root CA DN validation should fail");
        }
        {
            let name_der = build_x509_name_with_values(
                INTEL_SGX_ROOT_CA_COMMON_NAME,
                "Invalid Org",
                INTEL_SGX_LOCALITY_NAME,
                INTEL_SGX_STATE_OR_PROVINCE_NAME,
                INTEL_SGX_COUNTRY_NAME,
            )
            .unwrap()
            .to_der()
            .unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            let name_der = build_x509_name_with_values(
                INTEL_SGX_ROOT_CA_COMMON_NAME,
                INTEL_SGX_ORGANIZATION_NAME,
                "Invalid Locality",
                INTEL_SGX_STATE_OR_PROVINCE_NAME,
                INTEL_SGX_COUNTRY_NAME,
            )
            .unwrap()
            .to_der()
            .unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            let name_der = build_x509_name_with_values(
                INTEL_SGX_ROOT_CA_COMMON_NAME,
                INTEL_SGX_ORGANIZATION_NAME,
                INTEL_SGX_LOCALITY_NAME,
                "Invalid State",
                INTEL_SGX_COUNTRY_NAME,
            )
            .unwrap()
            .to_der()
            .unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            let name_der = build_x509_name_with_values(
                INTEL_SGX_ROOT_CA_COMMON_NAME,
                INTEL_SGX_ORGANIZATION_NAME,
                INTEL_SGX_LOCALITY_NAME,
                INTEL_SGX_STATE_OR_PROVINCE_NAME,
                "XX",
            )
            .unwrap()
            .to_der()
            .unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            // each attribute is valid, but the order is unexpected
            let mut builder = dcap_collaterals::openssl::x509::X509Name::builder().unwrap();
            builder
                .append_entry_by_text("O", INTEL_SGX_ORGANIZATION_NAME)
                .unwrap();
            builder
                .append_entry_by_text("CN", INTEL_SGX_ROOT_CA_COMMON_NAME)
                .unwrap();
            builder
                .append_entry_by_text("L", INTEL_SGX_LOCALITY_NAME)
                .unwrap();
            builder
                .append_entry_by_text("ST", INTEL_SGX_STATE_OR_PROVINCE_NAME)
                .unwrap();
            builder
                .append_entry_by_text("C", INTEL_SGX_COUNTRY_NAME)
                .unwrap();
            let name_der = builder.build().to_der().unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            // each attribute is valid, but the number of attributes is unexpected
            let mut builder = dcap_collaterals::openssl::x509::X509Name::builder().unwrap();
            builder
                .append_entry_by_text("CN", INTEL_SGX_ROOT_CA_COMMON_NAME)
                .unwrap();
            builder
                .append_entry_by_text("O", INTEL_SGX_ORGANIZATION_NAME)
                .unwrap();
            builder
                .append_entry_by_text("L", INTEL_SGX_LOCALITY_NAME)
                .unwrap();
            builder
                .append_entry_by_text("ST", INTEL_SGX_STATE_OR_PROVINCE_NAME)
                .unwrap();
            let name_der = builder.build().to_der().unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
        {
            // additional attribute is present
            let mut builder = dcap_collaterals::openssl::x509::X509Name::builder().unwrap();
            builder
                .append_entry_by_text("CN", INTEL_SGX_ROOT_CA_COMMON_NAME)
                .unwrap();
            builder
                .append_entry_by_text("O", INTEL_SGX_ORGANIZATION_NAME)
                .unwrap();
            builder
                .append_entry_by_text("L", INTEL_SGX_LOCALITY_NAME)
                .unwrap();
            builder
                .append_entry_by_text("ST", INTEL_SGX_STATE_OR_PROVINCE_NAME)
                .unwrap();
            builder
                .append_entry_by_text("C", INTEL_SGX_COUNTRY_NAME)
                .unwrap();
            // invalid attribute
            builder.append_entry_by_text("OU", "SGX").unwrap();
            let name_der = builder.build().to_der().unwrap();
            let (_, name) = X509Name::from_der(&name_der).unwrap();
            let res = is_sgx_root_ca_dn(&name);
            assert!(
                res.is_err(),
                "Should fail to validate SGX Root CA DN: {:?}",
                res
            );
        }
    }

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
