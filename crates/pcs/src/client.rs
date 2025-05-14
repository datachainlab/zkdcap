use anyhow::{anyhow, bail, Error};
use dcap_quote_verifier::cert::{
    is_sgx_pck_platform_ca_dn, is_sgx_pck_processor_ca_dn, parse_certchain,
};
use dcap_quote_verifier::collateral::QvCollateral;
use dcap_quote_verifier::sgx_extensions::extract_sgx_extensions;
use dcap_types::quotes::CertData;
use dcap_types::utils::{parse_pem, pem_to_der};
use log::*;

/// The URL of the Provisioning Certification Service (PCS).
pub const INTEL_SGX_PCS_URL: &str = "https://api.trustedservices.intel.com";
/// The URL of the Intel SGX Certificates Service.
pub const INTEL_SGX_CERTS_URL: &str = "https://certificates.trustedservices.intel.com";

/// PCSClient is a client for the Provisioning Certification Service (PCS) or Provisioning Certification Caching Service (PCCS).
#[derive(Debug)]
pub struct PCSClient {
    /// The URL of the Provisioning Certification Service (PCS) or Provisioning Certification Caching Service (PCCS).
    pcs_or_pccs_url: String,
    /// The URL of the Intel SGX Certificates Service.
    certs_service_url: String,
    /// The target TCB evaluation data number. If None, the latest TCB evaluation data will be used.
    target_tcb_evaluation_data_number: Option<u32>,
}

impl Default for PCSClient {
    /// Default PCSClient uses Intel's PCS and Certificates Service URLs.
    fn default() -> Self {
        PCSClient::new(INTEL_SGX_PCS_URL, INTEL_SGX_CERTS_URL, None)
    }
}

impl PCSClient {
    /// Create a new PCSClient.
    ///
    /// # Arguments
    /// * `pcs_or_pccs_url` - The URL of the Provisioning Certification Service (PCS) or Provisioning Certification Caching Service (PCCS).
    /// * `certs_service_url` - The URL of the Intel SGX Certificates Service.
    /// * `target_tcb_evaluation_data_number` - The target TCB evaluation data number. If None, the latest TCB evaluation data will be used.
    pub fn new(
        pcs_or_pccs_url: &str,
        certs_service_url: &str,
        target_tcb_evaluation_data_number: Option<u32>,
    ) -> Self {
        PCSClient {
            pcs_or_pccs_url: pcs_or_pccs_url.trim_end_matches('/').to_string(),
            certs_service_url: certs_service_url.trim_end_matches('/').to_string(),
            target_tcb_evaluation_data_number,
        }
    }

    /// Get the collateral required for verifying a DCAP quote.
    ///
    /// # Arguments
    /// * `qe_cert_data` - The certificate data of the QE that generated the quote to be verified. The certificate data type must be 5.
    pub fn get_collateral(
        &self,
        is_sgx: bool,
        qe_cert_data: &CertData,
    ) -> Result<QvCollateral, Error> {
        let pcs_url = self.pcs_or_pccs_url.as_str();
        let certs_service_url = self.certs_service_url.as_str();
        let base_url = if is_sgx {
            format!("{pcs_url}/sgx/certification/v4")
        } else {
            format!("{pcs_url}/tdx/certification/v4")
        };
        if qe_cert_data.cert_data_type != 5 {
            bail!("QE Cert Type must be 5".to_string());
        }
        let certchain_pems = parse_pem(&qe_cert_data.cert_data)
            .map_err(|e| anyhow!("cannot parse QE cert chain: {}", e))?;

        let certchain = parse_certchain(&certchain_pems)
            .map_err(|e| anyhow!("cannot parse QE cert chain: {}", e))?;
        if certchain.len() != 3 {
            bail!("QE Cert chain must have 3 certs".to_string());
        }

        // get the pck certificate
        let pck_cert = &certchain[0];
        let pck_cert_issuer = &certchain[1];

        // get the SGX extension
        let sgx_extensions = extract_sgx_extensions(pck_cert)
            .map_err(|e| anyhow!("cannot extract SGX extensions: {}", e))?;

        let tcb_evaludation_policy = self.tcb_evaludation_policy();

        // get the TCB info of the platform
        let (tcb_info_json, sgx_tcb_signing_der) = {
            let fmspc = hex::encode_upper(sgx_extensions.fmspc);
            let res = http_get(format!(
                "{base_url}/tcb?fmspc={fmspc}&{tcb_evaludation_policy}"
            ))?;
            let issuer_chain =
                extract_raw_certs(get_header(&res, "TCB-Info-Issuer-Chain")?.as_bytes())?;
            (res.text()?, issuer_chain[0].clone())
        };

        // get the QE identity
        let qe_identity_json =
            http_get(format!("{base_url}/qe/identity?{tcb_evaludation_policy}"))?.text()?;

        let pck_crl_url = if is_sgx_pck_platform_ca_dn(pck_cert_issuer.subject())? {
            format!("{pcs_url}/sgx/certification/v4/pckcrl?ca=platform&encoding=der")
        } else if is_sgx_pck_processor_ca_dn(pck_cert_issuer.subject())? {
            format!("{pcs_url}/sgx/certification/v4/pckcrl?ca=processor&encoding=der")
        } else {
            bail!("unknown PCK issuer");
        };

        let sgx_pck_crl_der = http_get(pck_crl_url)?.bytes()?.to_vec();

        let sgx_root_cert_der = http_get(format!(
            "{certs_service_url}/Intel_SGX_Provisioning_Certification_RootCA.cer"
        ))?
        .bytes()?
        .to_vec();

        let sgx_intel_root_ca_crl_der =
            http_get(format!("{certs_service_url}/IntelSGXRootCA.der"))?
                .bytes()?
                .to_vec();

        Ok(QvCollateral {
            tcb_info_json,
            qe_identity_json,
            sgx_intel_root_ca_der: sgx_root_cert_der,
            sgx_tcb_signing_der,
            sgx_intel_root_ca_crl_der,
            sgx_pck_crl_der,
        })
    }

    /// Get the PCK certificate.
    ///
    /// # Arguments
    /// * `encrypted_ppid` - The PPID encrypted with PPIDEK.
    /// * `cpusvn` - The CPUSVN value.
    /// * `pcesvn` - The PCESVN value.
    /// * `pceid` - The PCE-ID value.
    /// # Returns
    /// * The PCK certificate and the PCK issuer certificate.
    pub fn get_pck_certchain(
        &self,
        encrypted_ppid: &[u8; 384],
        cpusvn: &[u8; 16],
        pcesvn: u16,
        pceid: u16,
    ) -> Result<PckCertResponse, Error> {
        let pcs_url = self.pcs_or_pccs_url.as_str();
        let base_url = format!("{pcs_url}/sgx/certification/v4/pckcert");
        let res = reqwest::blocking::Client::new()
            .get(&base_url)
            .query(&[
                ("encrypted_ppid", hex::encode(encrypted_ppid)),
                ("cpusvn", hex::encode(cpusvn)),
                ("pcesvn", hex::encode(pcesvn.to_le_bytes())),
                ("pceid", hex::encode(pceid.to_le_bytes())),
            ])
            .send()
            .map_err(|e| anyhow!("cannot get {}: {}", base_url, e))?;
        if !res.status().is_success() {
            bail!("invalid http status: {}", res.status());
        }
        Ok(PckCertResponse {
            fmspc: hex::decode(get_header(&res, "SGX-FMSPC")?)?
                .try_into()
                .map_err(|e| anyhow!("cannot convert to array: {:?}", e))?,
            pck_ca_type: get_header(&res, "SGX-PCK-Certificate-CA-Type")?,
            pck_cert_issuer_der: extract_raw_certs(
                get_header(&res, "SGX-PCK-Certificate-Issuer-Chain")?.as_bytes(),
            )?[1]
                .clone(),
            pck_cert_der: pem_to_der(
                res.bytes()
                    .map_err(|e| anyhow!("cannot get bytes: {}", e))?
                    .to_vec()
                    .as_ref(),
            )?,
        })
    }

    fn tcb_evaludation_policy(&self) -> String {
        if let Some(target_tcb_evaluation_data_number) = self.target_tcb_evaluation_data_number {
            format!("tcbEvaluationDataNumber={target_tcb_evaluation_data_number}")
        } else {
            "update=early".to_string()
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PckCertResponse {
    pub pck_cert_der: Vec<u8>,
    pub pck_cert_issuer_der: Vec<u8>,
    pub fmspc: [u8; 6],
    pub pck_ca_type: String,
}

fn get_header(res: &reqwest::blocking::Response, name: &str) -> Result<String, Error> {
    let value = res
        .headers()
        .get(name)
        .ok_or_else(|| anyhow!("missing header: {}", name))?
        .to_str()
        .map_err(|e| anyhow!("invalid header value: {}", e))?;
    let value =
        urlencoding::decode(value).map_err(|e| anyhow!("cannot decode header value: {}", e))?;
    Ok(value.into_owned())
}

fn extract_raw_certs(cert_chain: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    Ok(pem::parse_many(cert_chain)
        .map_err(|e| anyhow!("cannot parse PEM: {}", e))?
        .iter()
        .map(|i| i.contents().to_vec())
        .collect())
}

fn http_get(url: String) -> Result<reqwest::blocking::Response, Error> {
    debug!("get collateral from {}", url);
    let res = reqwest::blocking::get(&url).map_err(|e| anyhow!("cannot get {}: {}", url, e))?;
    if !res.status().is_success() {
        bail!("invalid http status: {}", res.status());
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_collateral_sgx() {
        let qe_cert_data_bz = hex::decode("0500dc0d00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949456a544343424453674177494241674956414a34674a3835554b6b7a613873504a4847676e4f4b6d5451426e754d416f4743437147534d343942414d430a4d484578497a416842674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a4165467730794e5441784d6a41784d444d7a4e4446614677307a4d6a41784d6a41784d444d7a0a4e4446614d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675132567964476c6d61574e6864475578476a415942674e560a42416f4d45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b470a413155454341774351304578437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741450a516a537877644d662b2b3578645553717478343769335952633970504a475434304642774e306e5335557a43314233524b63544875514c3135796b357a4c766c0a5535707a7563552f2b6d674a4e6f55774b6e784942364f434171677767674b6b4d42384741315564497751594d426141464e446f71747031312f6b75535265590a504873555a644456386c6c4e4d477747413155644877526c4d474d77596142666f463247573268306448427a4f693876595842704c6e527964584e305a57527a0a5a584a3261574e6c63793570626e526c6243356a62323076633264344c324e6c636e52705a6d6c6a5958527062323476646a517663474e7259334a7350324e680a5058427962324e6c63334e7663695a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464f7632356e4f67634c754f693644424b3037470a4d4f5161315a53494d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949423141594a4b6f5a496876684e0a415130424249494278544343416345774867594b4b6f5a496876684e41513042415151514459697469663748386e4277566732482b38504f476a4343415751470a43697147534962345451454e41514977676746554d42414743797147534962345451454e41514942416745564d42414743797147534962345451454e415149430a416745564d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745454d42414743797147534962340a5451454e41514946416745424d42454743797147534962345451454e41514947416749416744415142677371686b69472b4530424451454342774942446a41510a42677371686b69472b45304244514543434149424144415142677371686b69472b45304244514543435149424144415142677371686b69472b453042445145430a436749424144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69470a2b45304244514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b4530424451454344774942414441510a42677371686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b453042445145430a4567515146525543424147414467414141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b4530420a44514545424159416b473756414141774477594b4b6f5a496876684e4151304242516f424144414b42676771686b6a4f5051514441674e4841444245416942750a6846786c7379536f4a373479392f374665436c6679522b544d4a626c43696663364e577538637466424149674c524f6e50584138636d3864577061716f4679680a467559567237396f696f584e63395354677857573332633d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436d444343416a36674177494241674956414e446f71747031312f6b7553526559504873555a644456386c6c4e4d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484578497a41680a42674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b4442464a626e526c0a6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e420a4d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424c39712b4e4d7032494f670a74646c31626b2f75575a352b5447516d38614369387a373866732b664b435133642b75447a586e56544154325a68444369667949754a77764e33774e427039690a484253534d4a4d4a72424f6a6762737767626777487759445652306a42426777466f4155496d554d316c71644e496e7a6737535655723951477a6b6e427177770a556759445652306642457377535442486f45576751345a426148523063484d364c79396a5a584a3061575a70593246305a584d7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253394a626e526c62464e4857464a76623352445153356b5a584977485159445652304f42425945464e446f0a71747031312f6b7553526559504873555a644456386c6c4e4d41344741315564447745422f77514541774942426a415342674e5648524d4241663845434441470a4151482f416745414d416f4743437147534d343942414d43413067414d4555434951434a6754627456714f795a316d336a716941584d365159613672357357530a34792f4737793875494a4778647749675271507642534b7a7a516167424c517135733541373070646f6961524a387a2f3075447a344e675639316b3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00").unwrap();
        let cert_data = CertData::from_bytes(&qe_cert_data_bz).unwrap();
        let client = PCSClient::default();
        let res = client.get_collateral(true, &cert_data);
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn get_pck_cert() {
        let encrypted_ppid = hex::decode("500ddb99c48fe783f9fa0f380757787f48da3807d9d9b04f72bbc4ef7421a1418caeaf5483703568ea7be76ed21e0bd40fffd109b366e58101b8e9fd33c35354caaf5105d45e7f48c6ecca02e81cc86a2b174de4c78b08790d00523f07ab7312b19c0ebf5bf108d21d1410c9bd0c54c3687af21c30a123f12cbea2834eb5046b3447eb539bb18e91298709fc4f923ed2f6e3974487f0529c4c6a9fd28bb283ff958bb9f918506f54e7750be4aa8fde198be7beda22ef91bebfb88731d8e64681a0e6fbd44534a30028170ec6e3fe7df37abc1ec0621137ad298caf0acb5c52439bf85c6a9c1795f889937a23f3ada145dab50011005d0b1e5fec879deeee1041e04d2abfa843e037762002767aff46462dcaf3b6f601ab921758c6a4ea45ede1325cbfb00999598fcd19f5321fb110d20d7574a7e6efa67409a87c062b80db377e7fc22a0f833a20c26e976f44ca45b234c1aedd3a55ee365a1eab489f7e7b5e3ecdd631529660d6d4b6c67e7a753de5d38128cc167a632b5fc0a55b7e009d96").unwrap();
        let cpusvn = hex::decode("15150b07ff800e000000000000000000").unwrap();
        let pcesvn = u16::from_le_bytes(hex::decode("1000").unwrap().try_into().unwrap());
        let pceid = u16::from_le_bytes(hex::decode("0000").unwrap().try_into().unwrap());
        let client = PCSClient::default();
        let res = client.get_pck_certchain(
            &encrypted_ppid.try_into().unwrap(),
            &cpusvn.try_into().unwrap(),
            pcesvn,
            pceid,
        );
        assert!(res.is_ok(), "{:?}", res);
        let res = res.unwrap();
        assert_eq!(res.pck_ca_type, "processor");
        assert_eq!(res.fmspc, [0, 144, 110, 213, 0, 0]);
    }
}
