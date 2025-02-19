use super::{check_quote_header, converge_tcb_status_with_qe_tcb, verify_quote_common, Result};
use crate::{
    cert::{get_sgx_tdx_tcb_status_v3, merge_advisory_ids},
    collaterals::IntelCollateral,
    crypto::sha256sum,
    tdx_module::{check_tdx_module_tcb_status, converge_tcb_status_with_tdx_module_tcb},
    verifier::QuoteVerificationOutput,
    VERIFIER_VERSION,
};
use anyhow::{bail, Context};
use core::cmp::min;
use dcap_types::{
    quotes::{body::QuoteBody, version_4::QuoteV4, CertDataType},
    tcbinfo::TcbInfo,
    TdxModuleTcbValidationStatus, SGX_TEE_TYPE, TDX_TEE_TYPE,
};

/// Verify the given DCAP quote v4 and return the verification output.
///
/// # Arguments
/// - `quote`: The quote to be verified
/// - `collaterals`: The collateral data to be used for verification
/// - `current_time`: The current time in seconds since the Unix epoch
pub fn verify_quote_v4(
    quote: &QuoteV4,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> Result<QuoteVerificationOutput> {
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

    let (qe_tcb, sgx_extensions, tcb_info, validity) = verify_quote_common(
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

    let TcbInfo::V3(tcb_info_v3) = tcb_info;
    let (quote_tdx_body, tee_tcb_svn) = if let QuoteBody::TD10QuoteBody(body) = &quote.quote_body {
        (Some(body), Some(body.tee_tcb_svn))
    } else {
        // SGX does not produce tee_tcb_svn
        (None, None)
    };

    let tee_type = quote.header.tee_type;
    let (sgx_tcb_status, tdx_tcb_status, tcb_advisory_ids) =
        get_sgx_tdx_tcb_status_v3(tee_type, tee_tcb_svn, &sgx_extensions, &tcb_info_v3)?;

    let advisory_ids = merge_advisory_ids(tcb_advisory_ids, qe_tcb.advisory_ids);

    let (tcb_status, advisory_ids) = if tee_type == TDX_TEE_TYPE {
        let tdx_tcb_status = tdx_tcb_status.context("TDX TCB Status not found")?;

        // Fetch TDXModule TCB and TDXModule Identity
        let (
            tdx_module_tcb_status,
            tdx_module_advisory_ids,
            tdx_module_mrsigner,
            tdx_module_attributes,
        ) = check_tdx_module_tcb_status(&tee_tcb_svn.unwrap_or_default(), &tcb_info_v3)?;
        if tdx_module_tcb_status == TdxModuleTcbValidationStatus::TcbNotSupported
            || tdx_module_tcb_status == TdxModuleTcbValidationStatus::TdxModuleMismatch
        {
            // NOTE: early return - different from the original code
            bail!("TDX Module TCB not supported or out of date");
        }

        // check TDX module
        let (tdx_report_mrsigner, tdx_report_attributes) = quote_tdx_body
            .map(|tdx_body| (tdx_body.mrsignerseam, tdx_body.seam_attributes))
            .context("TDX Quote Body not found")?;

        // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L181
        if tdx_module_mrsigner != tdx_report_mrsigner {
            bail!("TDX module mrsigner mismatch");
        }
        // ref. https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/QuoteVerifier.cpp#L200
        if tdx_module_attributes != tdx_report_attributes {
            bail!("TDX module attributes mismatch");
        }

        (
            converge_tcb_status_with_tdx_module_tcb(tdx_tcb_status, tdx_module_tcb_status),
            merge_advisory_ids(advisory_ids, tdx_module_advisory_ids),
        )
    } else if tee_type == SGX_TEE_TYPE {
        (sgx_tcb_status, advisory_ids)
    } else {
        bail!("Unsupported TEE type: {}", tee_type);
    };

    Ok(QuoteVerificationOutput {
        version: VERIFIER_VERSION,
        quote_version: quote.header.version,
        tee_type,
        tcb_status: converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb.tcb_status),
        min_tcb_evaluation_data_number: min(
            qe_tcb.tcb_evaluation_data_number,
            tcb_info_v3.tcb_info.tcb_evaluation_data_number,
        ),
        fmspc: sgx_extensions.fmspc,
        sgx_intel_root_ca_hash: sha256sum(collaterals.sgx_intel_root_ca_der.as_ref()),
        validity,
        quote_body: quote.quote_body,
        advisory_ids,
    })
}
