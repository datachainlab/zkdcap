use serde::{Deserialize, Serialize};
use x509_parser::{
    der_parser::{
        asn1_rs::{Boolean, Enumerated, Integer, OctetString, Sequence},
        oid, Oid,
    },
    prelude::{FromDer, X509Certificate},
};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SgxExtensionTcbLevel {
    pub sgxtcbcomp01svn: u8,
    pub sgxtcbcomp02svn: u8,
    pub sgxtcbcomp03svn: u8,
    pub sgxtcbcomp04svn: u8,
    pub sgxtcbcomp05svn: u8,
    pub sgxtcbcomp06svn: u8,
    pub sgxtcbcomp07svn: u8,
    pub sgxtcbcomp08svn: u8,
    pub sgxtcbcomp09svn: u8,
    pub sgxtcbcomp10svn: u8,
    pub sgxtcbcomp11svn: u8,
    pub sgxtcbcomp12svn: u8,
    pub sgxtcbcomp13svn: u8,
    pub sgxtcbcomp14svn: u8,
    pub sgxtcbcomp15svn: u8,
    pub sgxtcbcomp16svn: u8,
    pub pcesvn: u16,
    pub cpusvn: [u8; 16],
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SgxExtensions {
    pub ppid: [u8; 16],
    pub tcb: SgxExtensionTcbLevel,
    pub pceid: [u8; 2],
    pub fmspc: [u8; 6],
    pub sgx_type: u32,
    pub platform_instance_id: Option<[u8; 16]>,
    pub configuration: Option<PckPlatformConfiguration>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PckPlatformConfiguration {
    pub dynamic_platform: Option<bool>,
    pub cached_keys: Option<bool>,
    pub smt_enabled: Option<bool>,
}

pub fn extract_sgx_extensions<'a>(cert: &'a X509Certificate<'a>) -> SgxExtensions {
    // https://download.01.org/intel-sgx/sgx-dcap/1.20/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

    // <SGX Extensions OID>:
    //     <PPID OID>: <PPID value>
    //     <TCB OID>:
    //          <SGX TCB Comp01 SVN OID>: <SGX TCB Comp01 SVN value>
    //          <SGX TCB Comp02 SVN OID>: <SGX TCB Comp02 SVN value>
    //          …
    //          <SGX TCB Comp16 SVN OID>: <SGX TCB Comp16 SVN value>
    //          <PCESVN OID>: <PCESVN value>
    //          <CPUSVN OID>: <CPUSVN value>
    //     <PCE-ID OID>: <PCE-ID value>
    //     <FMSPC OID>: <FMSPC value>
    //     <SGX Type OID>: <SGX Type value>
    //     <PlatformInstanceID OID>: <PlatformInstanceID value>
    //     <Configuration OID>:
    //          <Dynamic Platform OID>: <Dynamic Platform flag value>
    //          <Cached Keys OID>: <Cached Keys flag value>
    //          <SMT Enabled OID>: <SMT Enabled flag value>

    // SGX Extensions       | 1.2.840.113741.1.13.1      | mandatory | ASN.1 Sequence
    // PPID                 | 1.2.840.113741.1.13.1.1    | mandatory | ASN.1 Octet String
    // TCB                  | 1.2.840.113741.1.13.1.2    | mandatory | ASN.1 Sequence
    // SGX TCB Comp01 SVN   | 1.2.840.113741.1.13.1.2.1  | mandatory | ASN.1 Integer
    // SGX TCB Comp02 SVN   | 1.2.840.113741.1.13.1.2.2  | mandatory | ASN.1 Integer
    // ...
    // SGX TCB Comp16 SVN   | 1.2.840.113741.1.13.1.2.16 | mandatory | ASN.1 Integer
    // PCESVN               | 1.2.840.113741.1.13.1.2.17 | mandatory | ASN.1 Integer
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Integer
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    let sgx_extensions_bytes = cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))
        .unwrap()
        .unwrap()
        .value;

    let (_, sgx_extensions) = Sequence::from_der(sgx_extensions_bytes).unwrap();

    // we'll process the sgx extensions here...
    let mut i = sgx_extensions.content.as_ref();

    // let's define the required information to create the SgxExtensions struct
    let mut ppid = [0; 16];
    let mut tcb = SgxExtensionTcbLevel {
        sgxtcbcomp01svn: 0,
        sgxtcbcomp02svn: 0,
        sgxtcbcomp03svn: 0,
        sgxtcbcomp04svn: 0,
        sgxtcbcomp05svn: 0,
        sgxtcbcomp06svn: 0,
        sgxtcbcomp07svn: 0,
        sgxtcbcomp08svn: 0,
        sgxtcbcomp09svn: 0,
        sgxtcbcomp10svn: 0,
        sgxtcbcomp11svn: 0,
        sgxtcbcomp12svn: 0,
        sgxtcbcomp13svn: 0,
        sgxtcbcomp14svn: 0,
        sgxtcbcomp15svn: 0,
        sgxtcbcomp16svn: 0,
        pcesvn: 0,
        cpusvn: [0; 16],
    };
    let mut pceid = [0; 2];
    let mut fmspc = [0; 6];
    let mut sgx_type = 0;
    let mut platform_instance_id: Option<[u8; 16]> = None;
    let mut configuration: Option<PckPlatformConfiguration> = None;

    while i.len() > 0 {
        let (j, current_sequence) = Sequence::from_der(i).unwrap();
        i = j;
        let (j, current_oid) = Oid::from_der(current_sequence.content.as_ref()).unwrap();
        match current_oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.1" => {
                let (k, ppid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                ppid.copy_from_slice(ppid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.2" => {
                let (k, tcb_sequence) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                // iterate through from 1 - 18
                let (k, sgxtcbcomp01svn) =
                    get_asn1_uint64(tcb_sequence.content.as_ref(), "1.2.840.113741.1.13.1.2.1");
                let (k, sgxtcbcomp02svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.2");
                let (k, sgxtcbcomp03svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.3");
                let (k, sgxtcbcomp04svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.4");
                let (k, sgxtcbcomp05svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.5");
                let (k, sgxtcbcomp06svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.6");
                let (k, sgxtcbcomp07svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.7");
                let (k, sgxtcbcomp08svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.8");
                let (k, sgxtcbcomp09svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.9");
                let (k, sgxtcbcomp10svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.10");
                let (k, sgxtcbcomp11svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.11");
                let (k, sgxtcbcomp12svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.12");
                let (k, sgxtcbcomp13svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.13");
                let (k, sgxtcbcomp14svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.14");
                let (k, sgxtcbcomp15svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.15");
                let (k, sgxtcbcomp16svn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.16");
                let (k, pcesvn) = get_asn1_uint64(k, "1.2.840.113741.1.13.1.2.17");
                let (k, cpusvn) = get_asn1_bytes(k, "1.2.840.113741.1.13.1.2.18");

                assert_eq!(k.len(), 0);
                // copy the bytes into the tcb struct
                tcb.sgxtcbcomp01svn = sgxtcbcomp01svn as u8;
                tcb.sgxtcbcomp02svn = sgxtcbcomp02svn as u8;
                tcb.sgxtcbcomp03svn = sgxtcbcomp03svn as u8;
                tcb.sgxtcbcomp04svn = sgxtcbcomp04svn as u8;
                tcb.sgxtcbcomp05svn = sgxtcbcomp05svn as u8;
                tcb.sgxtcbcomp06svn = sgxtcbcomp06svn as u8;
                tcb.sgxtcbcomp07svn = sgxtcbcomp07svn as u8;
                tcb.sgxtcbcomp08svn = sgxtcbcomp08svn as u8;
                tcb.sgxtcbcomp09svn = sgxtcbcomp09svn as u8;
                tcb.sgxtcbcomp10svn = sgxtcbcomp10svn as u8;
                tcb.sgxtcbcomp11svn = sgxtcbcomp11svn as u8;
                tcb.sgxtcbcomp12svn = sgxtcbcomp12svn as u8;
                tcb.sgxtcbcomp13svn = sgxtcbcomp13svn as u8;
                tcb.sgxtcbcomp14svn = sgxtcbcomp14svn as u8;
                tcb.sgxtcbcomp15svn = sgxtcbcomp15svn as u8;
                tcb.sgxtcbcomp16svn = sgxtcbcomp16svn as u8;
                tcb.pcesvn = pcesvn as u16;
                tcb.cpusvn.copy_from_slice(cpusvn.as_ref());
            }
            "1.2.840.113741.1.13.1.3" => {
                let (k, pceid_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                pceid.copy_from_slice(pceid_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.4" => {
                let (k, fmspc_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                fmspc.copy_from_slice(fmspc_bytes.as_ref());
            }
            "1.2.840.113741.1.13.1.5" => {
                let (k, sgx_type_enum) = Enumerated::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                sgx_type = sgx_type_enum.0;
            }
            "1.2.840.113741.1.13.1.6" => {
                let (k, platform_instance_id_bytes) = OctetString::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut temp = [0; 16];
                temp.copy_from_slice(platform_instance_id_bytes.as_ref());
                platform_instance_id = Some(temp);
            }
            "1.2.840.113741.1.13.1.7" => {
                let (k, configuration_seq) = Sequence::from_der(j).unwrap();
                assert_eq!(k.len(), 0);
                let mut configuration_temp = PckPlatformConfiguration {
                    dynamic_platform: None,
                    cached_keys: None,
                    smt_enabled: None,
                };
                // iterate through from 1 - 3, note that some of them might be optional.
                let mut k = configuration_seq.content.as_ref();
                while k.len() > 0 {
                    let (l, asn1_seq) = Sequence::from_der(k).unwrap();
                    k = l;
                    let (l, current_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
                    match current_oid.to_id_string().as_str() {
                        "1.2.840.113741.1.13.1.7.1" => {
                            let (l, dynamic_platform_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.dynamic_platform =
                                Some(dynamic_platform_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.2" => {
                            let (l, cached_keys_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.cached_keys = Some(cached_keys_bool.bool());
                        }
                        "1.2.840.113741.1.13.1.7.3" => {
                            let (l, smt_enabled_bool) = Boolean::from_der(l).unwrap();
                            assert_eq!(l.len(), 0);
                            configuration_temp.smt_enabled = Some(smt_enabled_bool.bool());
                        }
                        _ => {
                            unreachable!("Unknown OID: {}", current_oid.to_id_string());
                        }
                    }
                }
                // done parsing...
                configuration = Some(configuration_temp);
            }
            _ => {
                unreachable!("Unknown OID: {}", current_oid.to_id_string());
            }
        }
    }

    SgxExtensions {
        ppid,
        tcb,
        pceid,
        fmspc,
        sgx_type,
        platform_instance_id,
        configuration,
    }
}

fn get_asn1_uint64<'a>(bytes: &'a [u8], oid_str: &str) -> (&'a [u8], u64) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_int) = Integer::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_int.as_u64().unwrap())
}

fn get_asn1_bytes<'a>(bytes: &'a [u8], oid_str: &str) -> (&'a [u8], Vec<u8>) {
    let (k, asn1_seq) = Sequence::from_der(bytes).unwrap();
    let (l, asn1_oid) = Oid::from_der(asn1_seq.content.as_ref()).unwrap();
    assert!(oid_str.eq(&asn1_oid.to_id_string()));
    let (l, asn1_bytes) = OctetString::from_der(l).unwrap();
    assert_eq!(l.len(), 0);
    (k, asn1_bytes.into_cow().to_vec())
}
