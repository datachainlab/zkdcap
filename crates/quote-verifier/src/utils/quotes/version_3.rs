use super::{
    check_quote_header, common_verify_and_fetch_tcb, converge_tcb_status_with_qe_tcb, Result,
};
use crate::constants::VERIFIER_VERSION;
use crate::types::quotes::{body::QuoteBody, version_3::QuoteV3};
use crate::types::{collaterals::IntelCollateral, tcbinfo::TcbInfo, VerifiedOutput};
use crate::utils::cert::{get_sgx_tdx_fmspc_tcbstatus_v3, merge_advisory_ids};
use crate::utils::hash::keccak256sum;
use anyhow::{bail, Context};

pub fn verify_quote_dcapv3(
    quote: &QuoteV3,
    collaterals: &IntelCollateral,
    current_time: u64,
) -> Result<VerifiedOutput> {
    check_quote_header(&quote.header, 3).context("invalid quote header")?;

    let quote_body = QuoteBody::SGXQuoteBody(quote.isv_enclave_report);
    let ((qe_tcb_status, qe_advisory_ids), sgx_extensions, tcb_info, validity) =
        common_verify_and_fetch_tcb(
            &quote.header,
            &quote_body,
            &quote.signature.isv_enclave_report_signature,
            &quote.signature.ecdsa_attestation_key,
            &quote.signature.qe_report,
            &quote.signature.qe_report_signature,
            &quote.signature.qe_auth_data.data,
            &quote.signature.qe_cert_data,
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
    let (tcb_status, _, tcb_advisory_ids) =
        get_sgx_tdx_fmspc_tcbstatus_v3(quote.header.tee_type, None, &sgx_extensions, &tcb_info_v3)?;

    Ok(VerifiedOutput {
        version: VERIFIER_VERSION,
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status: converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb_status),
        fmspc: sgx_extensions.fmspc,
        sgx_intel_root_ca_hash: keccak256sum(collaterals.sgx_intel_root_ca_der.as_ref()),
        validity,
        quote_body,
        advisory_ids: merge_advisory_ids(tcb_advisory_ids, qe_advisory_ids),
    })
}
