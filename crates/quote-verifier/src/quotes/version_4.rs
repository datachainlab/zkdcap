use super::{
    check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb, Result,
};
use crate::{
    cert::{get_sgx_tdx_fmspc_tcbstatus_v3, merge_advisory_ids},
    collaterals::IntelCollateral,
    crypto::sha256sum,
    tdx_module::{converge_tcb_status_with_tdx_module_tcb, get_tdx_module_identity_and_tcb},
    verifier::VerifiedOutput,
    VERIFIER_VERSION,
};
use anyhow::{bail, Context};
use dcap_types::{
    quotes::{body::QuoteBody, version_4::QuoteV4, CertDataType},
    tcbinfo::TcbInfo,
    TcbInfoV3TcbStatus, TdxModuleTcbValidationStatus, SGX_TEE_TYPE,
};

pub fn verify_quote_dcapv4(
    quote: &QuoteV4,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> Result<VerifiedOutput> {
    check_quote_header(&quote.header, 4).context("invalid quote header")?;

    // we'll now proceed to verify the qe
    let qe_cert_data_v4 = &quote.signature.qe_cert_data;

    // right now we just handle type 6, which contains the QEReport, QEReportSignature, QEAuthData and another CertData
    let qe_report_cert_data = if let CertDataType::QeReportCertData(qe_report_cert_data) =
        qe_cert_data_v4.get_cert_data()?
    {
        qe_report_cert_data
    } else {
        bail!(
            "unsupported cert data type: {}",
            qe_cert_data_v4.cert_data_type
        );
    };

    let (qe_tcb_status, qe_advisory_ids, sgx_extensions, tcb_info, validity) =
        common_verify_and_fetch_tcb(
            &quote.header,
            &quote.quote_body,
            &quote.signature.quote_signature,
            &quote.signature.ecdsa_attestation_key,
            &qe_report_cert_data.qe_report,
            &qe_report_cert_data.qe_report_signature,
            &qe_report_cert_data.qe_auth_data.data,
            &qe_report_cert_data.qe_cert_data,
            collaterals,
            current_time,
        )?;

    if !validity.validate_time(current_time) {
        bail!(
            "certificates are expired: validity={} current_time={}",
            validity,
            current_time
        );
    }
    let TcbInfo::V3(tcb_info_v3) = tcb_info;
    let (quote_tdx_body, tee_tcb_svn) = if let QuoteBody::TD10QuoteBody(body) = &quote.quote_body {
        (Some(body), body.tee_tcb_svn)
    } else {
        // SGX does not produce tee_tcb_svns
        (None, [0; 16])
    };

    // check TCB level

    let tee_type = quote.header.tee_type;
    let (sgx_tcb_status, tdx_tcb_status, tcb_advisory_ids) =
        get_sgx_tdx_fmspc_tcbstatus_v3(tee_type, Some(tee_tcb_svn), &sgx_extensions, &tcb_info_v3)?;

    let mut advisory_ids = merge_advisory_ids(tcb_advisory_ids, qe_advisory_ids);
    let mut tcb_status: TcbInfoV3TcbStatus;
    if quote.header.tee_type == SGX_TEE_TYPE {
        tcb_status = sgx_tcb_status;
    } else {
        tcb_status = tdx_tcb_status.context("TDX TCB Status not found")?;

        // Fetch TDXModule TCB and TDXModule Identity
        let (
            tdx_module_tcb_status,
            tdx_module_advisory_ids,
            tdx_module_mrsigner,
            tdx_module_attributes,
        ) = get_tdx_module_identity_and_tcb(&tee_tcb_svn, &tcb_info_v3)?;
        if tdx_module_tcb_status == TdxModuleTcbValidationStatus::TcbNotSupported
            || tdx_module_tcb_status == TdxModuleTcbValidationStatus::TdxModuleMismatch
        {
            // NOTE: early return - modify from the original
            bail!("TDX Module TCB not supported or out of date");
        }

        // check TDX module
        let (tdx_report_mrsigner, tdx_report_attributes) = if let Some(tdx_body) = quote_tdx_body {
            (tdx_body.mrsignerseam, tdx_body.seam_attributes)
        } else {
            unreachable!();
        };

        // TODO check if these validations are correct
        let mr_signer_matched = tdx_module_mrsigner == tdx_report_mrsigner;
        let attributes_matched = tdx_module_attributes == tdx_report_attributes;
        if !mr_signer_matched || !attributes_matched {
            bail!("TDX module values mismatch");
        }

        tcb_status = converge_tcb_status_with_tdx_module_tcb(tcb_status, tdx_module_tcb_status);
        advisory_ids = merge_advisory_ids(advisory_ids, tdx_module_advisory_ids);
    }

    Ok(VerifiedOutput {
        version: VERIFIER_VERSION,
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status: converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status),
        fmspc: sgx_extensions.fmspc,
        sgx_intel_root_ca_hash: sha256sum(collaterals.sgx_intel_root_ca_der.as_ref()),
        validity,
        quote_body: quote.quote_body,
        advisory_ids,
    })
}
