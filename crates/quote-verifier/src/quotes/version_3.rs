use super::{check_quote_header, converge_tcb_status_with_qe_tcb, verify_quote_common, Result};
use crate::{
    cert::{get_sgx_tdx_fmspc_tcbstatus_v3, merge_advisory_ids},
    collaterals::IntelCollateral,
    crypto::keccak256sum,
    verifier::QuoteVerificationOutput,
    VERIFIER_VERSION,
};
use anyhow::Context;
use core::cmp::min;
use dcap_types::{
    quotes::{body::QuoteBody, version_3::QuoteV3},
    tcbinfo::TcbInfo,
};

/// Verify the given DCAP quote v3 and return the verification output.
///
/// # Arguments
/// - `quote`: The quote to be verified
/// - `collateral`: The collateral data to be used for verification
/// - `current_time`: The current time in seconds since the Unix epoch
pub fn verify_quote_v3(
    quote: &QuoteV3,
    collateral: &IntelCollateral,
    current_time: u64,
) -> Result<QuoteVerificationOutput> {
    check_quote_header(&quote.header, 3).context("invalid quote header")?;

    let quote_body = QuoteBody::SGXQuoteBody(quote.isv_enclave_report);
    let (qe_status, sgx_extensions, tcb_info, validity) = verify_quote_common(
        &quote.header,
        &quote_body,
        &quote.signature.isv_enclave_report_signature,
        &quote.signature.ecdsa_attestation_key,
        &quote.signature.qe_report,
        &quote.signature.qe_report_signature,
        &quote.signature.qe_auth_data.data,
        &quote.signature.qe_cert_data,
        collateral,
        current_time,
    )?;
    let TcbInfo::V3(tcb_info_v3) = tcb_info;
    let (tcb_status, _, tcb_advisory_ids) =
        get_sgx_tdx_fmspc_tcbstatus_v3(quote.header.tee_type, None, &sgx_extensions, &tcb_info_v3)?;

    Ok(QuoteVerificationOutput {
        version: VERIFIER_VERSION,
        quote_version: quote.header.version,
        tee_type: quote.header.tee_type,
        tcb_status: converge_tcb_status_with_qe_tcb(tcb_status, qe_status.tcb_status),
        min_tcb_evaluation_data_number: min(
            qe_status.tcb_evaluation_data_number,
            tcb_info_v3.tcb_info.tcb_evaluation_data_number,
        ),
        fmspc: sgx_extensions.fmspc,
        sgx_intel_root_ca_hash: keccak256sum(collateral.sgx_intel_root_ca_der.as_ref()),
        validity,
        quote_body,
        advisory_ids: merge_advisory_ids(tcb_advisory_ids, qe_status.advisory_ids),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::{
        certs::{gen_pck_certchain, gen_root_ca, gen_tcb_certchain, PckCa},
        enclave_identity::{EnclaveIdentityId, EnclaveIdentityV2Builder},
        enclave_report::{build_qe_auth_data, build_qe_report_data, EnclaveReportBuilder},
        quote::{build_qe_cert_data, gen_quote_v3, sign_qe_report, QuoteHeaderBuilder},
        sgx_extensions::SgxExtensionsBuilder,
        tcbinfo::{TcbInfoV3Builder, TcbInfoV3TcbLevelBuilder, TcbInfoV3TcbLevelItemBuilder},
        utils::{gen_key, p256_prvkey_to_pubkey_bytes},
    };
    use dcap_types::cert::SgxExtensionTcbLevel;
    use serde_json::json;

    #[test]
    fn test_verify_quote_dcapv3() {
        let root_ca = gen_root_ca(None, None).unwrap();
        let root_ca_crl = root_ca.crl.to_der().unwrap();
        let tcb_certchain = gen_tcb_certchain(&root_ca, None).unwrap();
        let sgx_extensions = SgxExtensionsBuilder::new()
            .fmspc([0, 96, 106, 0, 0, 0])
            .tcb(SgxExtensionTcbLevel::new(
                &[12, 12, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                13,
                Default::default(),
            ))
            .build();
        let pck_certchain = gen_pck_certchain(
            &root_ca,
            PckCa::Processor,
            &sgx_extensions,
            None,
            None,
            None,
        )
        .unwrap();
        let pck_ca_crl = pck_certchain.pck_cert_crl.to_der().unwrap();

        let quote_header = QuoteHeaderBuilder::new_v3().sgx_tee_type().build();
        let isv_enclave_report = EnclaveReportBuilder::new().build();

        let attestation_key = gen_key();

        let qe_cert_data = build_qe_cert_data(
            &pck_certchain.pck_cert,
            &pck_certchain.pck_cert_ca,
            &root_ca.cert,
        );

        let qe_report = EnclaveReportBuilder::new()
            .isv_svn(8)
            .report_data(build_qe_report_data(
                &p256_prvkey_to_pubkey_bytes(&attestation_key).unwrap(),
                build_qe_auth_data(0),
            ))
            .build();

        let qe_report_signature = sign_qe_report(&pck_certchain.pck_cert_key, &qe_report);

        let quote = gen_quote_v3(
            &attestation_key,
            &quote_header,
            isv_enclave_report,
            qe_cert_data,
            qe_report,
            qe_report_signature,
        )
        .unwrap();

        let target_tcb_levels = vec![TcbInfoV3TcbLevelItemBuilder::new(
            TcbInfoV3TcbLevelBuilder::new()
                .pcesvn(sgx_extensions.tcb.pcesvn)
                .sgxtcbcomponents(&sgx_extensions.tcb.sgxtcbcompsvns())
                .build(),
        )
        .tcb_status("SWHardeningNeeded")
        .tcb_date_str("2024-03-13T00:00:00Z")
        .advisory_ids(&["INTEL-SA-00334", "INTEL-SA-00615"])
        .build()];

        // fmspc and tcb_levels must be consistent with the sgx extensions in the pck cert
        let tcb_info = TcbInfoV3Builder::new(true)
            .fmspc([0, 96, 106, 0, 0, 0])
            .tcb_evaluation_data_number(2)
            .tcb_levels(target_tcb_levels)
            .build_and_sign(&tcb_certchain.key)
            .unwrap();

        let qe_identity = EnclaveIdentityV2Builder::new(EnclaveIdentityId::QE)
            .tcb_evaluation_data_number(1)
            .tcb_levels_json(json!([
            {
              "tcb": {
                "isvsvn": qe_report.isv_svn
              },
              "tcbDate": "2023-08-09T00:00:00Z",
              "tcbStatus": "UpToDate"
            }
            ]))
            .build_and_sign(&tcb_certchain.key)
            .unwrap();

        let collateral = IntelCollateral {
            tcbinfo_bytes: serde_json::to_vec(&tcb_info).unwrap(),
            qeidentity_bytes: serde_json::to_vec(&qe_identity).unwrap(),
            sgx_intel_root_ca_der: root_ca.cert.to_der().unwrap(),
            sgx_tcb_signing_der: tcb_certchain.cert.to_der().unwrap(),
            sgx_intel_root_ca_crl_der: root_ca_crl,
            sgx_pck_crl_der: pck_ca_crl,
        };

        let current_time = 1730000000;
        let res = verify_quote_v3(&quote, &collateral, current_time);
        assert!(res.is_ok(), "{:?}", res);
        let output = res.unwrap();
        assert_eq!(output.min_tcb_evaluation_data_number, 1);
    }
}
