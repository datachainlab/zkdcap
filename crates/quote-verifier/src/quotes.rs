pub mod version_3;
pub mod version_4;

use crate::cert::{parse_certchain, verify_crl_signature};
use crate::collateral::QvCollateral;
use crate::crl::IntelSgxCrls;
use crate::crypto::{sha256sum, verify_p256_signature_bytes};
use crate::enclave_identity::{get_qe_tcb_status, validate_qe_identityv2};
use crate::pck::validate_pck_cert;
use crate::sgx_extensions::extract_sgx_extensions;
use crate::tcb_info::{validate_tcb_info_v3, validate_tcb_signing_certificate};
use crate::verifier::{QuoteVerificationOutput, Validity};
use crate::Result;
use anyhow::{bail, Context};
use dcap_types::cert::SgxExtensions;
use dcap_types::enclave_identity::EnclaveIdentityV2;
use dcap_types::quotes::{
    body::{EnclaveReport, QuoteBody},
    CertData, Quote, QuoteHeader,
};
use dcap_types::tcb_info::TcbInfo;
use dcap_types::utils::parse_pem;
use dcap_types::EnclaveIdentityV2TcbStatus;
use version_3::verify_quote_v3;
use version_4::verify_quote_v4;
use x509_parser::certificate::X509Certificate;

/// Verify the quote with the given collateral data and return the verification output.
///
/// Our verifier's verification logic is based on
/// <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationApp/src/AppCore/AppCore.cpp#L81>.
///
/// However, our verifier returns an error instead of an output if the result corresponds the status is not defined in `Status`(e.g., `STATUS_TCB_NOT_SUPPORTED`).
///
/// # Arguments
/// * `quote` - The quote to be verified.
/// * `collateral` - The collateral data to be used for verification.
/// * `current_time` - The current time in seconds since the Unix epoch.
/// # Returns
/// * The verification result.
pub fn verify_quote(
    quote: &Quote,
    collateral: &QvCollateral,
    current_time: u64,
) -> Result<QuoteVerificationOutput> {
    match quote {
        Quote::V3(quote) => verify_quote_v3(quote, collateral, current_time),
        Quote::V4(quote) => verify_quote_v4(quote, collateral, current_time),
    }
}

/// The TCB info of the QE
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QeTcb {
    pub tcb_evaluation_data_number: u32,
    pub tcb_status: EnclaveIdentityV2TcbStatus,
    pub advisory_ids: Vec<String>,
}

/// Verify the quote and return the TCB info of the QE, SGX extensions from the PCK leaf certificate, TCB info of the platform, and the validity intersection of all collaterals
///
/// # Arguments
///
/// * `quote_header` - The header of the quote
/// * `quote_body` - The body of the quote
/// * `ecdsa_attestation_signature` - The ECDSA signature of the quote using the attestation key
/// * `ecdsa_attestation_pubkey` - The ECDSA public key of the attestation key. This is the public key of the attestation key that signed the quote.
/// * `qe_report` - The QE report containing the hash of the attestation key and QE auth data as the report data
/// * `qe_report_signature` - The signature of the QE report using the PCK
/// * `qe_auth_data` - The QE auth data
/// * `qe_cert_data` - The QE certificate data. The cert data type must be 5.
/// * `collateral` - The QV collateral data. `collaterals.intel_root_ca` is Root of Trust in the verification process
/// * `current_time` - The current time in seconds.
///
/// # Returns
///
/// * A tuple containing:
/// * The TCB info of the QE
/// * The SGX extensions from the PCK leaf certificate
/// * The TCB info of the platform
/// * The validity intersection of all collaterals
#[allow(clippy::too_many_arguments)]
fn verify_quote_common(
    quote_header: &QuoteHeader,
    quote_body: &QuoteBody,
    ecdsa_attestation_signature: &[u8; 64],
    ecdsa_attestation_pubkey: &[u8; 64],
    qe_report: &EnclaveReport,
    qe_report_signature: &[u8; 64],
    qe_auth_data: &[u8],
    qe_cert_data: &CertData,
    collateral: &QvCollateral,
    current_time: u64,
) -> Result<(QeTcb, SgxExtensions, TcbInfo, Validity)> {
    // get the certchain embedded in the ecda quote signature data
    // this can be one of 5 types, and we only support type 5
    // https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/aa239d25a437a28f3f4de92c38f5b6809faac842/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_3.h#L63C4-L63C112
    if qe_cert_data.cert_data_type != 5 {
        bail!("QE Cert Type must be 5");
    }
    let certchain_pems = parse_pem(&qe_cert_data.cert_data)?;
    let (pck_leaf_cert, pck_issuer_cert) = {
        let mut certchain = parse_certchain(&certchain_pems)?;
        // certchain in the cert_data whose type is 5 should have 3 certificates:
        // PCK leaf, PCK issuer, and Root CA
        if certchain.len() != 3 {
            bail!("Invalid Certchain length");
        }
        // extract the leaf and issuer certificates, but ignore the root cert as we already have it
        (certchain.remove(0), certchain.remove(0))
    };

    let intel_sgx_root_cert = collateral.get_sgx_intel_root_ca()?;
    let intel_crls = {
        let sgx_root_ca_crl = collateral.get_sgx_intel_root_ca_crl()?;
        let pck_crl = collateral.get_sgx_pck_crl()?;

        // check that `sgx_root_ca_crl` is signed by the root cert
        verify_crl_signature(&sgx_root_ca_crl, &intel_sgx_root_cert)
            .context("Invalid Root CA CRL")?;
        // check that `pck_crl` is signed by the PCK Issuer cert
        verify_crl_signature(&pck_crl, &pck_issuer_cert).context("Invalid PCK Issuer CRL")?;

        IntelSgxCrls::new(sgx_root_ca_crl, pck_crl)?
    };
    let validity = intel_crls.check_validity(current_time)?;

    // check that root cert is not revoked
    if intel_crls.is_cert_revoked(&intel_sgx_root_cert)? {
        bail!("Root CA Cert revoked");
    }

    let validity = validate_pck_cert(
        &pck_leaf_cert,
        &pck_issuer_cert,
        &intel_sgx_root_cert,
        &intel_crls,
    )?
    .with_other(validity);

    let tcb_signing_cert = collateral.get_sgx_tcb_signing()?;
    let validity =
        validate_tcb_signing_certificate(&tcb_signing_cert, &intel_sgx_root_cert, &intel_crls)?
            .validate_or_error(current_time)
            .context("TCB Signing Cert is not valid")?
            .with_other(validity);

    // validate TCB Info
    let (validity, tcb_info) = {
        let tcb_info_v3 = collateral.get_tcb_info_v3()?;
        let tcb_validity =
            validate_tcb_info_v3(quote_header.tee_type, &tcb_info_v3, &tcb_signing_cert)?
                .validate_or_error(current_time)
                .context("TCBInfo is not valid")?;
        (validity.with_other(tcb_validity), TcbInfo::V3(tcb_info_v3))
    };

    // validate QEIdentity
    let (validity, qe_identity_v2) = {
        let qe_identity_v2 = collateral.get_qe_identity_v2()?;
        let qe_validity =
            validate_qe_identityv2(quote_header.tee_type, &qe_identity_v2, &tcb_signing_cert)?
                .validate_or_error(current_time)
                .context("QEIdentity is not valid")?;
        (validity.with_other(qe_validity), qe_identity_v2)
    };

    // validate QE Report and Quote Body
    let qe_tcb = verify_qe_report(
        qe_report,
        ecdsa_attestation_pubkey,
        qe_auth_data,
        &qe_identity_v2,
        &pck_leaf_cert,
        qe_report_signature,
    )?;
    verify_quote_attestation(
        quote_header,
        quote_body,
        ecdsa_attestation_pubkey,
        ecdsa_attestation_signature,
    )
    .context("Invalid quote attestation")?;
    let pck_cert_sgx_extensions = extract_sgx_extensions(&pck_leaf_cert)?;

    if !validity.validate() {
        bail!("Validity intersection provided from collaterals is invalid");
    } else if !validity.validate_time(current_time) {
        bail!(
            "certificates are expired: validity={} current_time={}",
            validity,
            current_time
        );
    }

    Ok((qe_tcb, pck_cert_sgx_extensions, tcb_info, validity.into()))
}

/// Verify the QE Report and return the TCB Status and Advisory IDs
///
/// ref.
/// - <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L221>
/// - <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L230>
/// - <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47>
///
/// do the following checks:
/// - ensure that `ecdsa_attestation_key` and `qe_auth_data` are valid against the `qe_report.report_data`
/// - validate the `qe_report` against the `qe_identity_v2`
/// - verify the signature for `qe_report` data using the `pck_leaf_cert` public key
/// - determine the TCB Status based on the `qe_report.isv_svn` and `qe_identity_v2`
fn verify_qe_report(
    qe_report: &EnclaveReport,
    ecdsa_attestation_pubkey: &[u8; 64],
    qe_auth_data: &[u8],
    qe_identity_v2: &EnclaveIdentityV2,
    pck_leaf_cert: &X509Certificate,
    qe_report_signature: &[u8; 64],
) -> Result<QeTcb> {
    // validate QEReport then get TCB Status
    if !validate_qe_report_data(
        &qe_report.report_data,
        ecdsa_attestation_pubkey,
        qe_auth_data,
    ) {
        bail!("QE Report Data is incorrect");
    }
    validate_qe_report(qe_report, qe_identity_v2)
        .context("QE Report values do not match with the provided QEIdentity")?;

    // verify the signature for qe report data
    verify_p256_signature_bytes(
        qe_report.to_bytes().as_slice(),
        qe_report_signature,
        pck_leaf_cert.public_key().subject_public_key.as_ref(),
    )
    .context("Invalid QE Report Signature")?;

    let (tcb_status, advisory_ids) = get_qe_tcb_status(
        qe_report.isv_svn,
        &qe_identity_v2.enclave_identity.tcb_levels,
    )?;

    // NOTE: The reference implementation converts `TcbStatus` to `Status`, but the conversion does not give any additional information and is therefore omitted in our implementation.
    // The following points are the conversion rules in the reference implementation:
    //
    // 1. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L93
    // `tcb_status` is converted to the following status:
    // UpToDate => STATUS_OK
    // Revoked => STATUS_SGX_ENCLAVE_REPORT_ISVSVN_REVOKED
    // OutOfDate => STATUS_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
    //
    // 2. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L286
    // The above three statuses are fallthrough to the default case, so there is no status conversion here.

    Ok(QeTcb {
        tcb_evaluation_data_number: qe_identity_v2.enclave_identity.tcb_evaluation_data_number,
        tcb_status,
        advisory_ids,
    })
}

/// Verify the attestation signature for the quote (header + body) using the attestation public key
fn verify_quote_attestation(
    quote_header: &QuoteHeader,
    quote_body: &QuoteBody,
    ecdsa_attestation_pubkey: &[u8; 64],
    ecdsa_attestation_signature: &[u8; 64],
) -> Result<()> {
    // verify the signature for attestation body
    let mut data = quote_header.to_bytes().to_vec();
    match quote_body {
        QuoteBody::SGXQuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
        QuoteBody::TD10QuoteBody(body) => data.extend_from_slice(&body.to_bytes()),
    };

    // 0x04 is the prefix for uncompressed P-256 public key
    let mut prefixed_pub_key = [4; 65];
    prefixed_pub_key[1..65].copy_from_slice(ecdsa_attestation_pubkey);
    verify_p256_signature_bytes(&data, ecdsa_attestation_signature, &prefixed_pub_key)
}

/// Validate the QE Report against the QEIdentity
///
/// ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/812e0fa140a284b772b2d8b08583c761e23ec3b3/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47
fn validate_qe_report(
    enclave_report: &EnclaveReport,
    qe_identity_v2: &EnclaveIdentityV2,
) -> Result<()> {
    let miscselect_mask = qe_identity_v2.enclave_identity.miscselect_mask()?;
    let miscselect = qe_identity_v2.enclave_identity.miscselect()?;

    if (enclave_report.misc_select() & miscselect_mask) != miscselect {
        bail!(
            "Enclave MiscSelect does not match: {:x} != {:x}",
            enclave_report.misc_select(),
            miscselect
        );
    }

    let attributes = qe_identity_v2.enclave_identity.attributes()?;
    let attributes_mask = qe_identity_v2.enclave_identity.attributes_mask()?;
    let masked_enclave_attributes = enclave_report
        .attributes
        .iter()
        .zip(attributes_mask.iter())
        .map(|(a, m)| a & m)
        .collect::<Vec<u8>>();
    if masked_enclave_attributes != attributes {
        bail!(
            "Enclave Attributes does not match: {:x?} != {:x?}",
            masked_enclave_attributes,
            attributes
        );
    }

    if enclave_report.mrsigner != qe_identity_v2.enclave_identity.mrsigner()? {
        bail!(
            "Enclave MrSigner does not match: {:x?} != {:x?}",
            enclave_report.mrsigner,
            qe_identity_v2.enclave_identity.mrsigner()?
        );
    }

    if enclave_report.isv_prod_id != qe_identity_v2.enclave_identity.isvprodid {
        bail!(
            "Enclave ISVProdID does not match: {:x} != {:x}",
            enclave_report.isv_prod_id,
            qe_identity_v2.enclave_identity.isvprodid
        );
    }

    Ok(())
}

/// validate the ecdsa attestation key and qe auth data against the report data
fn validate_qe_report_data(
    report_data: &[u8],
    ecdsa_attestation_key: &[u8],
    qe_auth_data: &[u8],
) -> bool {
    let mut verification_data = Vec::new();
    verification_data.extend_from_slice(ecdsa_attestation_key);
    verification_data.extend_from_slice(qe_auth_data);
    let mut recomputed_report_data = [0u8; 64];
    recomputed_report_data[..32].copy_from_slice(&sha256sum(&verification_data));
    recomputed_report_data == report_data
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        quote::sign_isv_enclave_report,
        utils::{gen_key, p256_prvkey_to_pubkey_bytes},
    };

    #[test]
    fn test_verify_quote_attestation() {
        let header = QuoteHeader::default();
        let body = QuoteBody::SGXQuoteBody(EnclaveReport::default());
        let attestation_key = gen_key();
        let sig = sign_isv_enclave_report(&attestation_key, &header, &body).unwrap();
        let pubkey = p256_prvkey_to_pubkey_bytes(&attestation_key).unwrap();
        let res = verify_quote_attestation(&header, &body, &pubkey, &sig);
        assert!(res.is_ok(), "Failed to verify quote attestation: {:?}", res);
    }
}
