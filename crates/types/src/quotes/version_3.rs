use super::{body::EnclaveReport, CertData, QeAuthData, QuoteHeader};
use crate::{Result, ENCLAVE_REPORT_LEN, QUOTE_FORMAT_V3, QUOTE_HEADER_LEN};
use anyhow::{anyhow, bail};

const SIGNATURE_DATA_SIZE_OFFSET: usize = QUOTE_HEADER_LEN + ENCLAVE_REPORT_LEN;
const SIGNATURE_DATA_SIZE_LEN: usize = 4;
const SIGNATURE_DATA_OFFSET: usize =
    QUOTE_HEADER_LEN + ENCLAVE_REPORT_LEN + SIGNATURE_DATA_SIZE_LEN;

/// Quote structure for DCAP version 3.
/// The structure is defined in the Intel SGX ECDSA Quote Library Reference.
/// ref. <https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/Intel_SGX_ECDSA_QuoteLibReference_DCAP_API.pdf>
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteV3 {
    /// Header of Quote data structure. This field is transparent (the user knows
    /// its internal structure). Rest of the Quote data structure can be
    /// treated as opaque (hidden from the user).
    pub header: QuoteHeader,
    /// Report of the attested ISV Enclave.
    /// The CPUSVN and ISVSVN is the TCB when the quote is generated.
    /// The REPORT.ReportData is defined by the ISV but should provide quote replay
    /// protection if required.
    pub isv_enclave_report: EnclaveReport,
    /// Size of the Quote Signature Data structure in bytes.
    /// Variable-length data containing the signature and supporting data.
    /// E.g. ECDSA 256-bit Quote Signature Data Structure (SgxQuoteSignatureData)
    /// The size of the signature data structure in bytes.
    pub signature_len: u32,
    /// The signature data structure is a variable-length data structure that contains the signature and supporting data.
    /// E.g. ECDSA 256-bit Quote Signature Data Structure (SgxQuoteSignatureData)
    pub signature: QuoteSignatureDataV3,
}

impl QuoteV3 {
    /// Parse a QuoteV3 from a byte slice.
    ///
    /// # Arguments
    /// - `raw_bytes`: A byte slice containing the QuoteV3 data.
    ///
    /// # Returns
    /// - A tuple containing the parsed QuoteV3 and the number of bytes consumed.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<(Self, usize)> {
        if raw_bytes.len() < SIGNATURE_DATA_OFFSET {
            bail!("Invalid Quote v3 length: header");
        }
        let header = QuoteHeader::from_bytes(&raw_bytes[..QUOTE_HEADER_LEN])?;
        if header.version != QUOTE_FORMAT_V3 {
            bail!(
                "Invalid Quote version: expected {}, got {}",
                QUOTE_FORMAT_V3,
                header.version
            );
        }
        let isv_enclave_report =
            EnclaveReport::from_bytes(&raw_bytes[QUOTE_HEADER_LEN..SIGNATURE_DATA_SIZE_OFFSET])?;
        let signature_len = u32::from_le_bytes([
            raw_bytes[SIGNATURE_DATA_SIZE_OFFSET],
            raw_bytes[SIGNATURE_DATA_SIZE_OFFSET + 1],
            raw_bytes[SIGNATURE_DATA_SIZE_OFFSET + 2],
            raw_bytes[SIGNATURE_DATA_SIZE_OFFSET + 3],
        ]);
        if raw_bytes.len() < SIGNATURE_DATA_OFFSET + signature_len as usize {
            bail!("Invalid Quote v3 length: signature data");
        }
        let quote_end_offset = SIGNATURE_DATA_OFFSET + signature_len as usize;
        let signature =
            QuoteSignatureDataV3::from_bytes(&raw_bytes[SIGNATURE_DATA_OFFSET..quote_end_offset])?;

        Ok((
            QuoteV3 {
                header,
                isv_enclave_report,
                signature_len,
                signature,
            },
            quote_end_offset,
        ))
    }

    /// Serialize a QuoteV3 to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.extend_from_slice(&self.header.to_bytes());
        raw_bytes.extend_from_slice(&self.isv_enclave_report.to_bytes());
        raw_bytes.extend_from_slice(&self.signature_len.to_le_bytes());
        raw_bytes.extend_from_slice(&self.signature.to_bytes());
        raw_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuoteSignatureDataV3 {
    pub isv_enclave_report_signature: [u8; 64], // ECDSA signature, the r component followed by the s component, 2 x 32 bytes.
    pub ecdsa_attestation_key: [u8; 64], // EC KT-I Public Key, the x-coordinate followed by the y-coordinate
    // (on the RFC 6090 P-256 curve), 2 x 32 bytes.
    pub qe_report: EnclaveReport,
    pub qe_report_signature: [u8; 64],
    pub qe_auth_data: QeAuthData,
    pub qe_cert_data: CertData,
}

impl QuoteSignatureDataV3 {
    /// Parse a QuoteSignatureDataV3 from a byte slice.
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<QuoteSignatureDataV3> {
        let len = raw_bytes.len();
        if len < 576 {
            return Err(anyhow!("QuoteSignatureDataV3 data is too short"));
        }
        let mut isv_enclave_report_signature = [0u8; 64];
        let mut ecdsa_attestation_key = [0u8; 64];
        let mut qe_report_signature = [0u8; 64];

        isv_enclave_report_signature.copy_from_slice(&raw_bytes[0..64]);
        ecdsa_attestation_key.copy_from_slice(&raw_bytes[64..128]);
        let qe_report = EnclaveReport::from_bytes(&raw_bytes[128..512])?;
        qe_report_signature.copy_from_slice(&raw_bytes[512..576]);
        let qe_auth_data = QeAuthData::from_bytes(&raw_bytes[576..])?;
        let qe_cert_data_start = 576 + 2 + qe_auth_data.size as usize;
        let qe_cert_data = CertData::from_bytes(&raw_bytes[qe_cert_data_start..])?;

        Ok(QuoteSignatureDataV3 {
            isv_enclave_report_signature,
            ecdsa_attestation_key,
            qe_report,
            qe_report_signature,
            qe_auth_data,
            qe_cert_data,
        })
    }

    /// Serialize a QuoteSignatureDataV3 to a byte vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut raw_bytes = Vec::new();
        raw_bytes.extend_from_slice(&self.isv_enclave_report_signature);
        raw_bytes.extend_from_slice(&self.ecdsa_attestation_key);
        raw_bytes.extend_from_slice(&self.qe_report.to_bytes());
        raw_bytes.extend_from_slice(&self.qe_report_signature);
        raw_bytes.extend_from_slice(&self.qe_auth_data.to_bytes());
        raw_bytes.extend_from_slice(&self.qe_cert_data.to_bytes());

        raw_bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        quotes::{
            body::tests::enclave_report_strategy,
            tests::{cert_data_strategy, qe_auth_data_strategy, quote_header_strategy},
            Quote,
        },
        SGX_TEE_TYPE,
    };
    use proptest::{collection::vec, prelude::*};

    const RAW_QUOTE_V3: &str = "03000200000000000a001000939a7233f79c4ca9940a0db3957f0607b5fe5d7f613d2d40b066b320879bd14d0000000015150b07ff800e00000000000000000000000000000000000000000000000000000000000000000000000000000000000500000000000000070000000000000026ae825ffce1cf9dcdf682614f4d36704e7bca087bbb5264aca9301d7824cec8000000000000000000000000000000000000000000000000000000000000000083d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001af6363621e462319c2bfa15d4b510dfa7911fb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000004810000013071751574162fbeffae9ac9904957bfbce0fd82ddddfc3f4b2d191e387a4149d8645435f2bcdc5383b67c4883461808eb7ae956cd531eb051211dd8badece64b1526520dd11db5efc9504fa42d048e37ba38c90c8873e7c62f72e86794797bcf8586b9e5c10d0866a95331548da898ae0adf78e428128324151ee558cfc71215150b07ff800e00000000000000000000000000000000000000000000000000000000000000000000000000000000001500000000000000070000000000000096b347a64e5a045e27369c26e6dcda51fd7c850e9b3a3a79e718f43261dee1e400000000000000000000000000000000000000000000000000000000000000008c4f5775d796503e96137f77c68a829a0056ac8ded70140b081b094490c57bff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001000a0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000017b0dc79c3dc5ff39b3f67346eef41f1ecd63e0a5259a9102eaace1f0aca06ec00000000000000000000000000000000000000000000000000000000000000005ebe66d69491408b1c5948a56b7209b932051148415b68ca371d91ffa4e83e81408e877ac580c5f848a22c849fa4334221695eb4567de369757b949fe086ba7b2000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f0500e00d00002d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949456a7a4343424453674177494241674956414a34674a3835554b6b7a613873504a4847676e4f4b6d5451426e754d416f4743437147534d343942414d430a4d484578497a416842674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b0a4442464a626e526c6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e560a4241674d416b4e424d517377435159445651514745774a56557a4165467730794e5441794d5445774e5445314d7a56614677307a4d6a41794d5445774e5445310a4d7a56614d484178496a416742674e5642414d4d47556c756447567349464e4857434251513073675132567964476c6d61574e6864475578476a415942674e560a42416f4d45556c756447567349454e76636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b470a413155454341774351304578437a414a42674e5642415954416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a304441516344516741450a516a537877644d662b2b3578645553717478343769335952633970504a475434304642774e306e5335557a43314233524b63544875514c3135796b357a4c766c0a5535707a7563552f2b6d674a4e6f55774b6e784942364f434171677767674b6b4d42384741315564497751594d426141464e446f71747031312f6b75535265590a504873555a644456386c6c4e4d477747413155644877526c4d474d77596142666f463247573268306448427a4f693876595842704c6e527964584e305a57527a0a5a584a3261574e6c63793570626e526c6243356a62323076633264344c324e6c636e52705a6d6c6a5958527062323476646a517663474e7259334a7350324e680a5058427962324e6c63334e7663695a6c626d4e765a476c755a7a316b5a584977485159445652304f42425945464f7632356e4f67634c754f693644424b3037470a4d4f5161315a53494d41344741315564447745422f775145417749477744414d42674e5648524d4241663845416a41414d4949423141594a4b6f5a496876684e0a415130424249494278544343416345774867594b4b6f5a496876684e41513042415151514459697469663748386e4277566732482b38504f476a4343415751470a43697147534962345451454e41514977676746554d42414743797147534962345451454e41514942416745564d42414743797147534962345451454e415149430a416745564d42414743797147534962345451454e41514944416745434d42414743797147534962345451454e41514945416745454d42414743797147534962340a5451454e41514946416745424d42454743797147534962345451454e41514947416749416744415142677371686b69472b4530424451454342774942446a41510a42677371686b69472b45304244514543434149424144415142677371686b69472b45304244514543435149424144415142677371686b69472b453042445145430a436749424144415142677371686b69472b45304244514543437749424144415142677371686b69472b45304244514543444149424144415142677371686b69470a2b45304244514543445149424144415142677371686b69472b45304244514543446749424144415142677371686b69472b4530424451454344774942414441510a42677371686b69472b45304244514543454149424144415142677371686b69472b45304244514543455149424454416642677371686b69472b453042445145430a4567515146525543424147414467414141414141414141414144415142676f71686b69472b45304244514544424149414144415542676f71686b69472b4530420a44514545424159416b473756414141774477594b4b6f5a496876684e4151304242516f424144414b42676771686b6a4f5051514441674e4a41444247416945410a2b43376a5847346167716359346d6b41692f4e6f65382f7a2f2b7a7a7178505a484e696537587168314e30434951446d785a54487365646e64616c4b6865646c0a48306972697a44336943696a435a546a2f3673757443627874673d3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436d444343416a36674177494241674956414e446f71747031312f6b7553526559504873555a644456386c6c4e4d416f4743437147534d343942414d430a4d476778476a415942674e5642414d4d45556c756447567349464e48574342536232393049454e424d526f77474159445651514b4442464a626e526c624342440a62334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e424d5173770a435159445651514745774a56557a4165467730784f4441314d6a45784d4455774d5442614677307a4d7a41314d6a45784d4455774d5442614d484578497a41680a42674e5642414d4d476b6c756447567349464e48574342515130736755484a765932567a6332397949454e424d526f77474159445651514b4442464a626e526c0a6243424462334a7762334a6864476c76626a45554d424947413155454277774c553246756447456751327868636d4578437a414a42674e564241674d416b4e420a4d517377435159445651514745774a56557a425a4d424d4742797147534d34394167454743437147534d34394177454841304941424c39712b4e4d7032494f670a74646c31626b2f75575a352b5447516d38614369387a373866732b664b435133642b75447a586e56544154325a68444369667949754a77764e33774e427039690a484253534d4a4d4a72424f6a6762737767626777487759445652306a42426777466f4155496d554d316c71644e496e7a6737535655723951477a6b6e427177770a556759445652306642457377535442486f45576751345a426148523063484d364c79396a5a584a3061575a70593246305a584d7564484a316333526c5a484e6c0a636e5a705932567a4c6d6c75644756734c6d4e766253394a626e526c62464e4857464a76623352445153356b5a584977485159445652304f42425945464e446f0a71747031312f6b7553526559504873555a644456386c6c4e4d41344741315564447745422f77514541774942426a415342674e5648524d4241663845434441470a4151482f416745414d416f4743437147534d343942414d43413067414d4555434951434a6754627456714f795a316d336a716941584d365159613672357357530a34792f4737793875494a4778647749675271507642534b7a7a516167424c517135733541373070646f6961524a387a2f3075447a344e675639316b3d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a2d2d2d2d2d424547494e2043455254494649434154452d2d2d2d2d0a4d4949436a7a4343416a53674177494241674955496d554d316c71644e496e7a6737535655723951477a6b6e42717777436759494b6f5a497a6a3045417749770a614445614d4267474131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e760a636e4276636d4630615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a0a42674e5642415954416c56544d423458445445344d4455794d5445774e4455784d466f58445451354d54497a4d54497a4e546b314f566f77614445614d4267470a4131554541777752535735305a5777675530645949464a766233516751304578476a415942674e5642416f4d45556c756447567349454e76636e4276636d46300a615739754d5251774567594456515148444174545957353059534244624746795954454c4d416b47413155454341774351304578437a414a42674e56424159540a416c56544d466b77457759484b6f5a497a6a3043415159494b6f5a497a6a3044415163445167414543366e45774d4449595a4f6a2f69505773437a61454b69370a314f694f534c52466857476a626e42564a66566e6b59347533496a6b4459594c304d784f346d717379596a6c42616c54565978465032734a424b357a6c4b4f420a757a43427544416642674e5648534d4547444157674251695a517a575770303069664f44744a5653763141624f5363477244425342674e5648523845537a424a0a4d45656752614244686b466f64485277637a6f764c324e6c636e52705a6d6c6a5958526c63793530636e567a6447566b63325679646d6c6a5a584d75615735300a5a577775593239744c306c756447567355306459556d397664454e424c6d526c636a416442674e564851344546675155496d554d316c71644e496e7a673753560a55723951477a6b6e4271777744675944565230504151482f42415144416745474d42494741315564457745422f7751494d4159424166384341514577436759490a4b6f5a497a6a3045417749445351417752674968414f572f35516b522b533943695344634e6f6f774c7550524c735747662f59693747535839344267775477670a41694541344a306c72486f4d732b586f356f2f7358364f39515778485241765a55474f6452513763767152586171493d0a2d2d2d2d2d454e442043455254494649434154452d2d2d2d2d0a00";

    #[test]
    fn test_quote_v3() {
        let raw_bytes = hex::decode(RAW_QUOTE_V3).unwrap();
        let (quote, consumed) = QuoteV3::from_bytes(&raw_bytes).unwrap();
        assert_eq!(consumed, raw_bytes.len());
        assert_eq!(quote.header.version, 3);
        let serialized_quote = quote.to_bytes();
        assert_eq!(raw_bytes.to_vec(), serialized_quote);

        let (quote, consumed) = Quote::from_bytes(&raw_bytes).unwrap();
        assert_eq!(consumed, raw_bytes.len());
        let serialized_quote2 = quote.to_bytes();
        assert_eq!(raw_bytes.to_vec(), serialized_quote2);
        assert_eq!(serialized_quote, serialized_quote2);
    }

    proptest! {
        #[test]
        fn test_quote_signature_data_v3_roundtrip(quote_signature_data_v3 in quote_signature_data_v3_strategy()) {
            let raw_bytes = quote_signature_data_v3.to_bytes();
            let parsed_quote_signature_data_v3 = QuoteSignatureDataV3::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(quote_signature_data_v3, parsed_quote_signature_data_v3);
        }

        #[test]
        fn test_quote_v3_roundtrip(quote_v3 in quote_v3_strategy()) {
            let raw_bytes = quote_v3.to_bytes();
            let (parsed_quote_v3, consumed) = QuoteV3::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(consumed, raw_bytes.len());
            prop_assert_eq!(&quote_v3, &parsed_quote_v3);
            let (quote, consumed) = Quote::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(consumed, raw_bytes.len());
            prop_assert_eq!(&quote, &Quote::V3(quote_v3));
            let serialized_quote = quote.to_bytes();
            prop_assert_eq!(raw_bytes, serialized_quote);
        }
    }

    pub(crate) fn quote_v3_strategy() -> impl Strategy<Value = QuoteV3> {
        (
            quote_header_strategy(Some(QUOTE_FORMAT_V3), Some(SGX_TEE_TYPE)),
            enclave_report_strategy(),
            quote_signature_data_v3_strategy(),
        )
            .prop_map(|(header, isv_enclave_report, signature)| QuoteV3 {
                header,
                isv_enclave_report,
                signature_len: signature.to_bytes().len() as u32,
                signature,
            })
    }

    pub(crate) fn quote_signature_data_v3_strategy() -> impl Strategy<Value = QuoteSignatureDataV3>
    {
        (
            vec(any::<u8>(), 64),
            vec(any::<u8>(), 64),
            enclave_report_strategy(),
        )
            .prop_flat_map(
                |(isv_enclave_report_signature, ecdsa_attestation_key, qe_report)| {
                    (
                        Just(isv_enclave_report_signature),
                        Just(ecdsa_attestation_key),
                        Just(qe_report),
                        vec(any::<u8>(), 64),
                        qe_auth_data_strategy(1024),
                        cert_data_strategy(1024),
                    )
                },
            )
            .prop_map(
                |(
                    isv_enclave_report_signature,
                    ecdsa_attestation_key,
                    qe_report,
                    qe_report_signature,
                    qe_auth_data,
                    qe_cert_data,
                )| QuoteSignatureDataV3 {
                    isv_enclave_report_signature: isv_enclave_report_signature
                        .as_slice()
                        .try_into()
                        .unwrap(),
                    ecdsa_attestation_key: ecdsa_attestation_key.as_slice().try_into().unwrap(),
                    qe_report,
                    qe_report_signature: qe_report_signature.as_slice().try_into().unwrap(),
                    qe_auth_data,
                    qe_cert_data,
                },
            )
    }
}
