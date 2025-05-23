use super::{verify_quote_common, Result};
use crate::{
    cert::{get_sgx_tdx_tcb_status_v3, merge_advisory_ids},
    collateral::QvCollateral,
    crypto::keccak256sum,
    verifier::{QuoteVerificationOutput, Status, QV_OUTPUT_VERSION},
};
use anyhow::{bail, Context};
use core::cmp::min;
use dcap_types::{
    quotes::{body::QuoteBody, version_3::QuoteV3, QuoteHeader},
    tcb_info::TcbInfo,
    ECDSA_256_WITH_P256_CURVE, INTEL_QE_VENDOR_ID, QUOTE_FORMAT_V3, SGX_TEE_TYPE,
};

/// Verify the given DCAP quote v3 and return the verification output.
///
/// Please also refer to the documentation of `verify_quote` for more details.
///
/// # Arguments
/// - `quote`: The quote to be verified
/// - `collateral`: The collateral data to be used for verification
/// - `current_time`: The current time in seconds since the Unix epoch
pub fn verify_quote_v3(
    quote: &QuoteV3,
    collateral: &QvCollateral,
    current_time: u64,
) -> Result<QuoteVerificationOutput> {
    validate_quote_header_v3(&quote.header).context("invalid quote header")?;

    let quote_body = QuoteBody::SGXQuoteBody(quote.isv_enclave_report);
    let (qe_tcb, sgx_extensions, tcb_info, validity) = verify_quote_common(
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
        get_sgx_tdx_tcb_status_v3(quote.header.tee_type, None, &sgx_extensions, &tcb_info_v3)?;
    let advisory_ids = merge_advisory_ids(tcb_advisory_ids, qe_tcb.advisory_ids);

    Ok(QuoteVerificationOutput {
        version: QV_OUTPUT_VERSION,
        quote_version: QUOTE_FORMAT_V3,
        tee_type: quote.header.tee_type,
        status: Status::converge_tcb_status_with_qe_tcb(tcb_status, qe_tcb.tcb_status),
        min_tcb_evaluation_data_number: min(
            qe_tcb.tcb_evaluation_data_number,
            tcb_info_v3.tcb_info.tcb_evaluation_data_number,
        ),
        fmspc: sgx_extensions.fmspc,
        sgx_intel_root_ca_hash: keccak256sum(collateral.sgx_intel_root_ca_der.as_ref()),
        validity,
        quote_body,
        advisory_ids,
    })
}

fn validate_quote_header_v3(quote_header: &QuoteHeader) -> Result<()> {
    if quote_header.version != QUOTE_FORMAT_V3 {
        bail!("Invalid Quote Version");
    } else if quote_header.tee_type != SGX_TEE_TYPE {
        bail!("Invalid TEE Type");
    } else if quote_header.att_key_type != ECDSA_256_WITH_P256_CURVE {
        bail!("Invalid att_key_type");
    } else if quote_header.qe_vendor_id != INTEL_QE_VENDOR_ID {
        bail!("Invalid qe_vendor_id");
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quotes::verify_quote;
    use dcap_collaterals::{
        certs::{gen_pck_certchain, gen_root_ca, gen_tcb_certchain, PckCa},
        enclave_identity::{EnclaveIdentityId, EnclaveIdentityV2Builder},
        enclave_report::{build_qe_auth_data, build_qe_report_data, EnclaveReportBuilder},
        quote::{build_qe_cert_data, gen_quote_v3, sign_qe_report, QuoteHeaderBuilder},
        sgx_extensions::SgxExtensionsBuilder,
        tcb_info::{TcbInfoV3Builder, TcbInfoV3TcbLevelBuilder, TcbInfoV3TcbLevelItemBuilder},
        utils::{gen_key, p256_prvkey_to_pubkey_bytes},
    };
    use dcap_types::{cert::SgxExtensionTcbLevel, utils::pem_to_der};
    use serde_json::json;

    #[test]
    fn test_verify_quote_v3_intel() {
        let collaterals = QvCollateral {
            tcb_info_json: include_str!("../../data/tcbinfov3_00906ED50000.json").to_string(),
            qe_identity_json: include_str!("../../data/qeidentityv2_sgx.json").to_string(),
            sgx_intel_root_ca_der: include_bytes!(
                "../../data/Intel_SGX_Provisioning_Certification_RootCA.cer"
            )
            .to_vec(),
            sgx_tcb_signing_der: pem_to_der(include_bytes!("../../data/tcb_signing_cert.pem"))
                .unwrap(),
            sgx_intel_root_ca_crl_der: include_bytes!("../../data/intel_root_ca_crl.der").to_vec(),
            sgx_pck_crl_der: include_bytes!("../../data/pck_processor_crl.der").to_vec(),
        };

        let dcap_quote_bytes = hex::decode("03000200000000000a001000939a7233f79c4ca9940a0db3957f0607b5fe5d7f613d2d40b066b320879bd14d0000000015150b07ff800e000000000000000000000000000000000000000000000000000000000000000000000000000000000005000000000000000700000000000000dca1a1841ab2e3fa7025c1d175d2c947df760b3baa4a9a0f30f4fd05718fcfe3000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000013a5883f5ffebfa210a8c2f6f8b8e3b7c7fd88dc70000000000000000000000000000000000000000000000000000000000000000000000000000000000000044100000fcb1fb4fe78441afe6c05e6d4591d923e3d10a237f4568013c5bbbe2a30a4cc5f50d71facf9da5e27635687c0c07d19aeb72a3d6375e1c96e5643f7e620601c04b1526520dd11db5efc9504fa42d048e37ba38c90c8873e7c62f72e86794797bcf8586b9e5c10d0866a95331548da898ae0adf78e428128324151ee558cfc71215150b07ff800e00000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000070000000000000096b347a64e5a045e27369c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e400000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017b0dc79c3dc5ff39b3f67346eef41f1ecd63e0a5259a9102eaace1f0aca06ec00000000000000000000000000000000000000000000000000000000000000005ebe66d69491408b1c5948a56b7209b932051148415b68ca371d91ffa4e83e81408e877ac580c5f848a22c849fa4334221695eb4567de369757b949fe086ba7b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500dc0d00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949456a544343424453674177494241674956414a34674a3835554b6b7a613873504a4847676e4f4b6d5451426e754d416f4743437147534d343942414d430a4d484578497a416842674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a4165467730794e5441784d6a41784d444d7a4e4446614677307a4d6a41784d6a41784d444d7a0a4e4446614d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675132567964476c6d61574e6864475578476a415942674e560a42416f4d45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b470a413155454341774351304578437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741450a516a537877644d662b2b3578645553717478343769335952633970504a475434304642774e306e5335557a43314233524b63544875514c3135796b357a4c766c0a5535707a7563552f2b6d674a4e6f55774b6e784942364f434171677767674b6b4d42384741315564497751594d426141464e446f71747031312f6b75535265590a504873555a644456386c6c4e4d477747413155644877526c4d474d77596142666f463247573268306448427a4f693876595842704c6e527964584e305a57527a0a5a584a3261574e6c63793570626e526c6243356a62323076633264344c324e6c636e52705a6d6c6a5958527062323476646a517663474e7259334a7350324e680a5058427962324e6c63334e7663695a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464f7632356e4f67634c754f693644424b3037470a4d4f5161315a53494d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949423141594a4b6f5a496876684e0a415130424249494278544343416345774867594b4b6f5a496876684e41513042415151514459697469663748386e4277566732482b38504f476a4343415751470a43697147534962345451454e41514977676746554d42414743797147534962345451454e41514942416745564d42414743797147534962345451454e415149430a416745564d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745454d42414743797147534962340a5451454e41514946416745424d42454743797147534962345451454e41514947416749416744415142677371686b69472b4530424451454342774942446a41510a42677371686b69472b45304244514543434149424144415142677371686b69472b45304244514543435149424144415142677371686b69472b453042445145430a436749424144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69470a2b45304244514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b4530424451454344774942414441510a42677371686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b453042445145430a4567515146525543424147414467414141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b4530420a44514545424159416b473756414141774477594b4b6f5a496876684e4151304242516f424144414b42676771686b6a4f5051514441674e4841444245416942750a6846786c7379536f4a373479392f374665436c6679522b544d4a626c43696663364e577538637466424149674c524f6e50584138636d3864577061716f4679680a467559567237396f696f584e63395354677857573332633d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436d444343416a36674177494241674956414e446f71747031312f6b7553526559504873555a644456386c6c4e4d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484578497a41680a42674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b4442464a626e526c0a6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e420a4d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424c39712b4e4d7032494f670a74646c31626b2f75575a352b5447516d38614369387a373866732b664b435133642b75447a586e56544154325a68444369667949754a77764e33774e427039690a484253534d4a4d4a72424f6a6762737767626777487759445652306a42426777466f4155496d554d316c71644e496e7a6737535655723951477a6b6e427177770a556759445652306642457377535442486f45576751345a426148523063484d364c79396a5a584a3061575a70593246305a584d7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253394a626e526c62464e4857464a76623352445153356b5a584977485159445652304f42425945464e446f0a71747031312f6b7553526559504873555a644456386c6c4e4d41344741315564447745422f77514541774942426a415342674e5648524d4241663845434441470a4151482f416745414d416f4743437147534d343942414d43413067414d4555434951434a6754627456714f795a316d336a716941584d365159613672357357530a34792f4737793875494a4778647749675271507642534b7a7a516167424c517135733541373070646f6961524a387a2f3075447a344e675639316b3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00").unwrap();
        let res = QuoteV3::from_bytes(&dcap_quote_bytes);
        assert!(res.is_ok(), "failed to parse quotev3: {:?}", res.err());
        let (dcap_quote, _) = res.unwrap();
        let res = verify_quote_v3(&dcap_quote, &collaterals, 1737458686);
        assert!(res.is_ok(), "verification failed: {:?}", res.err());
        let verified_output = res.unwrap();
        assert_eq!(verified_output.quote_version, 3);
        assert_eq!(verified_output.tee_type, 0);
        assert_eq!(verified_output.status, Status::TcbSwHardenningNeeded);
        assert_eq!(verified_output.fmspc, [0x00, 0x90, 0x6E, 0xD5, 0x00, 0x00]);
        assert_eq!(
            verified_output.sgx_intel_root_ca_hash,
            keccak256sum(collaterals.sgx_intel_root_ca_der.as_ref())
        );
        assert_eq!(
            verified_output.advisory_ids,
            vec!["INTEL-SA-00334", "INTEL-SA-00615"]
        );
        assert!(
            verified_output.validity.validate(),
            "validity intersection failed"
        );
        assert_eq!(
            verified_output.validity.not_before, 1737456351,
            "invalid `not_before_max`"
        );
        assert_eq!(
            verified_output.validity.not_after, 1740048100,
            "invalid `not_after_min`"
        );
        let bz = verified_output.to_bytes();
        let res = QuoteVerificationOutput::from_bytes(&bz);
        assert!(
            res.is_ok(),
            "failed to parse verified output: {:?}",
            res.err()
        );
        let vo = res.unwrap();
        assert_eq!(verified_output, vo);
    }

    #[test]
    fn test_verify_quote_v3() {
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

        let collateral = QvCollateral {
            tcb_info_json: serde_json::to_string(&tcb_info).unwrap(),
            qe_identity_json: serde_json::to_string(&qe_identity).unwrap(),
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

        let res = verify_quote(&quote.into(), &collateral, current_time);
        assert!(res.is_ok(), "{:?}", res);
    }
}
