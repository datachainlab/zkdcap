pub mod version_3;
pub mod version_4;

use crate::cert::{parse_certchain, verify_crl_signature};
use crate::collaterals::IntelCollateral;
use crate::crl::IntelSgxCrls;
use crate::crypto::sha256sum;
use crate::crypto::verify_p256_signature_bytes;
use crate::enclave_identity::get_qe_tcb_status;
use crate::enclave_identity::validate_qe_identityv2;
use crate::pck::validate_pck_cert;
use crate::sgx_extensions::extract_sgx_extensions;
use crate::tcbinfo::validate_tcb_signing_certificate;
use crate::tcbinfo::validate_tcbinfov3;
use crate::verifier::ValidityIntersection;
use crate::Result;
use anyhow::{bail, Context};
use dcap_types::cert::SgxExtensions;
use dcap_types::enclave_identity::EnclaveIdentityV2;
use dcap_types::quotes::{
    body::{EnclaveReport, QuoteBody},
    CertData, QuoteHeader,
};
use dcap_types::tcbinfo::TcbInfo;
use dcap_types::utils::parse_pem;
use dcap_types::{EnclaveIdentityV2TcbStatus, Status, TcbInfoV3TcbStatus};
use dcap_types::{ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID};
use x509_parser::certificate::X509Certificate;

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
/// * `collaterals` - The Intel collateral data. `collaterals.intel_root_ca` is Root of Trust in the verification process
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
    collaterals: &IntelCollateral,
    current_time: u64,
) -> Result<(QeTcb, SgxExtensions, TcbInfo, ValidityIntersection)> {
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

    let intel_sgx_root_cert = collaterals.get_sgx_intel_root_ca()?;
    let intel_crls = {
        let sgx_root_ca_crl = collaterals.get_sgx_intel_root_ca_crl()?;
        let pck_crl = collaterals.get_sgx_pck_crl()?;

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

    let tcb_signing_cert = collaterals.get_sgx_tcb_signing()?;
    let validity =
        validate_tcb_signing_certificate(&tcb_signing_cert, &intel_sgx_root_cert, &intel_crls)?
            .validate_or_error(current_time)
            .context("TCB Signing Cert is not valid")?
            .with_other(validity);

    // validate tcbinfo
    let (validity, tcb_info) = {
        let tcb_info_v3 = collaterals.get_tcbinfov3()?;
        let tcb_validity =
            validate_tcbinfov3(quote_header.tee_type, &tcb_info_v3, &tcb_signing_cert)?
                .validate_or_error(current_time)
                .context("TCBInfo is not valid")?;
        (validity.with_other(tcb_validity), TcbInfo::V3(tcb_info_v3))
    };

    // validate QEIdentity
    let (validity, qeidentityv2) = {
        let qeidentityv2 = collaterals.get_qeidentityv2()?;
        let qe_validity =
            validate_qe_identityv2(quote_header.tee_type, &qeidentityv2, &tcb_signing_cert)?
                .validate_or_error(current_time)
                .context("QEIdentity is not valid")?;
        (validity.with_other(qe_validity), qeidentityv2)
    };

    // validate QE Report and Quote Body
    let qe_tcb = verify_qe_report(
        qe_report,
        ecdsa_attestation_pubkey,
        qe_auth_data,
        &qeidentityv2,
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

    Ok((qe_tcb, pck_cert_sgx_extensions, tcb_info, validity))
}

fn check_quote_header(quote_header: &QuoteHeader, expected_quote_version: u16) -> Result<()> {
    if quote_header.version != expected_quote_version {
        bail!("Invalid Quote Version");
    } else if quote_header.att_key_type != ECDSA_256_WITH_P256_CURVE {
        bail!("Invalid att_key_type");
    } else if quote_header.qe_vendor_id != INTEL_QE_VENDOR_ID {
        bail!("Invalid qe_vendor_id");
    } else {
        Ok(())
    }
}
/// Verify the QE Report and return the TCB Status and Advisory IDs
///
/// ref. <https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/29bd3b0a3b46c1159907d656b45f378f97e7e686/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47>
/// do the following checks:
/// - ensure that `ecdsa_attestation_key` and `qe_auth_data` are valid against the `qe_report.report_data`
/// - validate the `qe_report` against the `qeidentityv2`
/// - verify the signature for `qe_report` data using the `pck_leaf_cert` public key
/// - determine the TCB Status based on the `qe_report.isv_svn` and `qeidentityv2`
fn verify_qe_report(
    qe_report: &EnclaveReport,
    ecdsa_attestation_pubkey: &[u8; 64],
    qe_auth_data: &[u8],
    qeidentityv2: &EnclaveIdentityV2,
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
    validate_qe_report(qe_report, qeidentityv2)
        .context("QE Report values do not match with the provided QEIdentity")?;

    // verify the signature for qe report data
    verify_p256_signature_bytes(
        qe_report.to_bytes().as_slice(),
        qe_report_signature,
        pck_leaf_cert.public_key().subject_public_key.as_ref(),
    )
    .context("Invalid QE Report Signature")?;

    // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/29bd3b0a3b46c1159907d656b45f378f97e7e686/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L92
    // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L286
    let (tcb_status, advisory_ids) =
        get_qe_tcb_status(qe_report.isv_svn, &qeidentityv2.enclave_identity.tcb_levels)?;

    Ok(QeTcb {
        tcb_evaluation_data_number: qeidentityv2.enclave_identity.tcb_evaluation_data_number,
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
/// ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/29bd3b0a3b46c1159907d656b45f378f97e7e686/Src/AttestationLibrary/src/Verifiers/EnclaveReportVerifier.cpp#L47
fn validate_qe_report(
    enclave_report: &EnclaveReport,
    qeidentityv2: &EnclaveIdentityV2,
) -> Result<()> {
    let miscselect_mask = qeidentityv2.enclave_identity.miscselect_mask()?;
    let miscselect = qeidentityv2.enclave_identity.miscselect()?;

    if (enclave_report.misc_select() & miscselect_mask) != miscselect {
        bail!(
            "Enclave MiscSelect does not match: {:x} != {:x}",
            enclave_report.misc_select(),
            miscselect
        );
    }

    let attributes = qeidentityv2.enclave_identity.attributes()?;
    let attributes_mask = qeidentityv2.enclave_identity.attributes_mask()?;
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

    if enclave_report.mrsigner != qeidentityv2.enclave_identity.mrsigner()? {
        bail!(
            "Enclave MrSigner does not match: {:x?} != {:x?}",
            enclave_report.mrsigner,
            qeidentityv2.enclave_identity.mrsigner()?
        );
    }

    if enclave_report.isv_prod_id != qeidentityv2.enclave_identity.isvprodid {
        bail!(
            "Enclave ISVProdID does not match: {:x} != {:x}",
            enclave_report.isv_prod_id,
            qeidentityv2.enclave_identity.isvprodid
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

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/16b7291a7a86e486fdfcf1dfb4be885c0cc00b4e/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L271-L312
fn converge_tcb_status_with_qe_tcb(
    tcb_status: TcbInfoV3TcbStatus,
    qe_tcb_status: EnclaveIdentityV2TcbStatus,
) -> Status {
    match qe_tcb_status {
        EnclaveIdentityV2TcbStatus::OutOfDate => {
            if tcb_status == TcbInfoV3TcbStatus::UpToDate
                || tcb_status == TcbInfoV3TcbStatus::SWHardeningNeeded
            {
                return Status::TcbOutOfDate;
            } else if tcb_status == TcbInfoV3TcbStatus::ConfigurationNeeded
                || tcb_status == TcbInfoV3TcbStatus::ConfigurationAndSWHardeningNeeded
            {
                return Status::TcbOutOfDateConfigurationNeeded;
            }
        }
        EnclaveIdentityV2TcbStatus::Revoked => return Status::TcbRevoked,
        EnclaveIdentityV2TcbStatus::UpToDate => {}
    }

    // https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/26f9641ff62377637af5e2989ab154d807cc3b0e/Src/AttestationLibrary/src/Verifiers/Checks/TcbLevelCheck.cpp#L109
    // switch (tcbLevelStatus)
    // {
    //     case STATUS_TCB_TD_RELAUNCH_ADVISED:
    //     case STATUS_TCB_TD_RELAUNCH_ADVISED_CONFIGURATION_NEEDED:
    //     case STATUS_TCB_OUT_OF_DATE:
    //     case STATUS_TCB_REVOKED:
    //     case STATUS_TCB_CONFIGURATION_NEEDED:
    //     case STATUS_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
    //     case STATUS_TCB_SW_HARDENING_NEEDED:
    //     case STATUS_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
    //     case STATUS_TCB_NOT_SUPPORTED:
    //     case STATUS_OK:
    //         return tcbLevelStatus;
    //     default:
    //         /// 4.1.2.4.17.5
    //         return STATUS_TCB_UNRECOGNIZED_STATUS;
    // }
    match tcb_status {
        TcbInfoV3TcbStatus::UpToDate => Status::Ok,
        TcbInfoV3TcbStatus::SWHardeningNeeded => Status::TcbSwHardenningNeeded,
        TcbInfoV3TcbStatus::ConfigurationNeeded => Status::TcbConfigurationNeeded,
        TcbInfoV3TcbStatus::ConfigurationAndSWHardeningNeeded => {
            Status::TcbConfigurationAndSwHardenningNeeded
        }
        TcbInfoV3TcbStatus::OutOfDate => Status::TcbOutOfDate,
        TcbInfoV3TcbStatus::OutOfDateConfigurationNeeded => Status::TcbOutOfDateConfigurationNeeded,
        TcbInfoV3TcbStatus::Revoked => Status::TcbRevoked,
    }
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
