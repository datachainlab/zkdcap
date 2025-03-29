use crate::Result;
use anyhow::{anyhow, Context};
use dcap_types::cert::{PckPlatformConfiguration, SgxExtensionTcbLevel, SgxExtensions};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Boolean, Enumerated, Integer, OctetString, Sequence};
use x509_parser::der_parser::{oid, Oid};
use x509_parser::prelude::FromDer;

/// Extract the SGX Extensions from the given PCK certificate
///
/// ref. p.11-14 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>
///
/// # Arguments
/// - `pck_cert`: The PCK certificate from which to extract the SGX Extensions
pub fn extract_sgx_extensions(pck_cert: &X509Certificate<'_>) -> Result<SgxExtensions> {
    let sgx_extensions_bytes = pck_cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))?
        .context("SGX Extensions not found")?
        .value;
    parse_sgx_extensions(sgx_extensions_bytes)
}

/// Parse the SGX Extensions from the DER-encoded bytes
///
/// ref. p.11-14 <https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf>
///
/// # Arguments
/// - `sgx_extensions_bytes`: The DER-encoded bytes of the SGX Extensions
pub fn parse_sgx_extensions(sgx_extensions_bytes: &[u8]) -> Result<SgxExtensions> {
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
    // CPUSVN               | 1.2.840.113741.1.13.1.2.18 | mandatory | ASN.1 Octet String
    // PCE-ID               | 1.2.840.113741.1.13.1.3    | mandatory | ASN.1 Octet String
    // FMSPC                | 1.2.840.113741.1.13.1.4    | mandatory | ASN.1 Octet String
    // SGX Type             | 1.2.840.113741.1.13.1.5    | mandatory | ASN.1 Enumerated
    // Platform Instance ID | 1.2.840.113741.1.13.1.6    | optional  | ASN.1 Octet String
    // Configuration        | 1.2.840.113741.1.13.1.7    | optional  | ASN.1 Sequence
    // Dynamic Platform     | 1.2.840.113741.1.13.1.7.1  | optional  | ASN.1 Boolean
    // Cached Keys          | 1.2.840.113741.1.13.1.7.2  | optional  | ASN.1 Boolean
    // SMT Enabled          | 1.2.840.113741.1.13.1.7.3  | optional  | ASN.1 Boolean

    // Parse the outer SGX Extensions sequence.
    let (rest, outer_seq) = Sequence::from_der(sgx_extensions_bytes)
        .map_err(|e| anyhow!("Failed to parse SGX Extensions outer sequence: {:?}", e))?;
    if !rest.is_empty() {
        return Err(anyhow!("Extra data after SGX Extensions outer sequence"));
    }
    let mut remaining = outer_seq.content.as_ref();

    // Initialize optional fields.
    let mut ppid: Option<[u8; 16]> = None;
    let mut tcb: Option<SgxExtensionTcbLevel> = None;
    let mut pceid: Option<[u8; 2]> = None;
    let mut fmspc: Option<[u8; 6]> = None;
    let mut sgx_type: Option<u32> = None;
    let mut platform_instance_id: Option<[u8; 16]> = None;
    let mut configuration: Option<PckPlatformConfiguration> = None;

    // Iterate over each field in the outer sequence.
    while !remaining.is_empty() {
        let (rem, item) = Sequence::from_der(remaining)
            .map_err(|e| anyhow!("Failed to parse SGX extension item: {:?}", e))?;
        remaining = rem;

        // Parse the OID for the current item.
        let (value, oid) = Oid::from_der(item.content.as_ref())
            .map_err(|e| anyhow!("Failed to parse OID in SGX extension item: {:?}", e))?;

        match oid.to_id_string().as_str() {
            "1.2.840.113741.1.13.1.1" => {
                // PPID (OctetString)
                if ppid.is_some() {
                    return Err(anyhow!("Duplicate PPID field in SGX Extensions"));
                }
                let (rest, octet) = OctetString::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse PPID OctetString: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after PPID OctetString"));
                }
                let octets = octet.as_ref();
                if octets.len() != 16 {
                    return Err(anyhow!(
                        "Invalid PPID length: expected 16, got {}",
                        octets.len()
                    ));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(octets);
                ppid = Some(arr);
            }
            "1.2.840.113741.1.13.1.2" => {
                // TCB (Sequence)
                if tcb.is_some() {
                    return Err(anyhow!("Duplicate TCB field in SGX Extensions"));
                }
                let (rest, tcb_seq) = Sequence::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse TCB sequence: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after TCB sequence"));
                }
                tcb = Some(parse_tcb_level(tcb_seq.content.as_ref())?);
            }
            "1.2.840.113741.1.13.1.3" => {
                // PCE-ID (OctetString)
                if pceid.is_some() {
                    return Err(anyhow!("Duplicate PCE-ID field in SGX Extensions"));
                }
                let (rest, octet) = OctetString::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse PCE-ID OctetString: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after PCE-ID OctetString"));
                }
                let octets = octet.as_ref();
                if octets.len() != 2 {
                    return Err(anyhow!(
                        "Invalid PCE-ID length: expected 2, got {}",
                        octets.len()
                    ));
                }
                let mut arr = [0u8; 2];
                arr.copy_from_slice(octets);
                pceid = Some(arr);
            }
            "1.2.840.113741.1.13.1.4" => {
                // FMSPC (OctetString)
                if fmspc.is_some() {
                    return Err(anyhow!("Duplicate FMSPC field in SGX Extensions"));
                }
                let (rest, octet) = OctetString::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse FMSPC OctetString: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after FMSPC OctetString"));
                }
                let octets = octet.as_ref();
                if octets.len() != 6 {
                    return Err(anyhow!(
                        "Invalid FMSPC length: expected 6, got {}",
                        octets.len()
                    ));
                }
                let mut arr = [0u8; 6];
                arr.copy_from_slice(octets);
                fmspc = Some(arr);
            }
            "1.2.840.113741.1.13.1.5" => {
                // SGX Type (Enumerated)
                if sgx_type.is_some() {
                    return Err(anyhow!("Duplicate SGX Type field in SGX Extensions"));
                }
                let (rest, enumerated) = Enumerated::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse SGX Type Enumerated: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after SGX Type Enumerated"));
                }
                sgx_type = Some(enumerated.0);
            }
            "1.2.840.113741.1.13.1.6" => {
                // Platform Instance ID (OctetString, Optional)
                if platform_instance_id.is_some() {
                    return Err(anyhow!(
                        "Duplicate Platform Instance ID field in SGX Extensions"
                    ));
                }
                let (rest, octet) = OctetString::from_der(value).map_err(|e| {
                    anyhow!("Failed to parse Platform Instance ID OctetString: {:?}", e)
                })?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after Platform Instance ID OctetString"));
                }
                let octets = octet.as_ref();
                if octets.len() != 16 {
                    return Err(anyhow!(
                        "Invalid Platform Instance ID length: expected 16, got {}",
                        octets.len()
                    ));
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(octets);
                platform_instance_id = Some(arr);
            }
            "1.2.840.113741.1.13.1.7" => {
                // Configuration (Sequence, Optional)
                if configuration.is_some() {
                    return Err(anyhow!("Duplicate Configuration field in SGX Extensions"));
                }
                let (rest, config_seq) = Sequence::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse Configuration sequence: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after Configuration sequence"));
                }
                configuration = Some(parse_configuration(config_seq.content.as_ref())?);
            }
            other => {
                return Err(anyhow!("Unknown SGX extension OID encountered: {}", other));
            }
        }
    }

    // Verify that all mandatory fields were present.
    let ppid = ppid.ok_or_else(|| anyhow!("Missing PPID field in SGX Extensions"))?;
    let tcb = tcb.ok_or_else(|| anyhow!("Missing TCB field in SGX Extensions"))?;
    let pceid = pceid.ok_or_else(|| anyhow!("Missing PCE-ID field in SGX Extensions"))?;
    let fmspc = fmspc.ok_or_else(|| anyhow!("Missing FMSPC field in SGX Extensions"))?;
    let sgx_type = sgx_type.ok_or_else(|| anyhow!("Missing SGX Type field in SGX Extensions"))?;

    Ok(SgxExtensions {
        ppid,
        tcb,
        pceid,
        fmspc,
        sgx_type,
        platform_instance_id,
        configuration,
    })
}

/// Parses an ASN.1 field (a SEQUENCE containing an OID and an Integer) and returns the u8 value.
fn parse_asn1_field_u8<'a>(input: &'a [u8], expected_oid: &'a str) -> Result<(&'a [u8], u8)> {
    parse_asn1_field_integer(input, expected_oid, |i| {
        i.as_u8()
            .map_err(|_| anyhow!("Integer value out of range for u8"))
    })
}

/// Parses an ASN.1 field (a SEQUENCE containing an OID and an Integer) and returns the u16 value.
fn parse_asn1_field_u16<'a>(input: &'a [u8], expected_oid: &'a str) -> Result<(&'a [u8], u16)> {
    parse_asn1_field_integer(input, expected_oid, |i| {
        i.as_u16()
            .map_err(|_| anyhow!("Integer value out of range for u16"))
    })
}

/// Parses an ASN.1 field (a SEQUENCE containing an OID and an Integer) and returns the integer value.
/// It verifies that the OID matches the expected value.
fn parse_asn1_field_integer<'a, T, F>(
    input: &'a [u8],
    expected_oid: &str,
    f: F,
) -> Result<(&'a [u8], T)>
where
    F: FnOnce(Integer) -> Result<T>,
{
    let (remaining, seq) = Sequence::from_der(input).map_err(|e| {
        anyhow!(
            "Failed to parse sequence for field {}: {:?}",
            expected_oid,
            e
        )
    })?;
    let (value, oid) = Oid::from_der(seq.content.as_ref())
        .map_err(|e| anyhow!("Failed to parse OID for field {}: {:?}", expected_oid, e))?;
    if oid.to_id_string() != expected_oid {
        return Err(anyhow!(
            "Unexpected OID: expected {}, got {}",
            expected_oid,
            oid.to_id_string()
        ));
    }
    let (rest, integer) = Integer::from_der(value).map_err(|e| {
        anyhow!(
            "Failed to parse integer for field {}: {:?}",
            expected_oid,
            e
        )
    })?;
    if !rest.is_empty() {
        return Err(anyhow!(
            "Extra data after integer for field {}",
            expected_oid
        ));
    }
    Ok((remaining, f(integer)?))
}

/// Parses an ASN.1 field (a SEQUENCE containing an OID and an OctetString) and returns the bytes.
fn parse_asn1_field_octets<'a>(
    input: &'a [u8],
    expected_oid: &'a str,
) -> Result<(&'a [u8], Vec<u8>)> {
    let (remaining, seq) = Sequence::from_der(input).map_err(|e| {
        anyhow!(
            "Failed to parse sequence for field {}: {:?}",
            expected_oid,
            e
        )
    })?;
    let (value, oid) = Oid::from_der(seq.content.as_ref())
        .map_err(|e| anyhow!("Failed to parse OID for field {}: {:?}", expected_oid, e))?;
    if oid.to_id_string() != expected_oid {
        return Err(anyhow!(
            "Unexpected OID: expected {}, got {}",
            expected_oid,
            oid.to_id_string()
        ));
    }
    let (rest, octet) = OctetString::from_der(value).map_err(|e| {
        anyhow!(
            "Failed to parse OctetString for field {}: {:?}",
            expected_oid,
            e
        )
    })?;
    if !rest.is_empty() {
        return Err(anyhow!(
            "Extra data after OctetString for field {}",
            expected_oid
        ));
    }
    Ok((remaining, octet.as_ref().to_vec()))
}

/// Parses the TCB level fields from the given input bytes.
fn parse_tcb_level(input: &[u8]) -> Result<SgxExtensionTcbLevel> {
    let mut rem = input;

    let (r, sgxtcbcomp01svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.1")?;
    rem = r;
    let (r, sgxtcbcomp02svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.2")?;
    rem = r;
    let (r, sgxtcbcomp03svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.3")?;
    rem = r;
    let (r, sgxtcbcomp04svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.4")?;
    rem = r;
    let (r, sgxtcbcomp05svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.5")?;
    rem = r;
    let (r, sgxtcbcomp06svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.6")?;
    rem = r;
    let (r, sgxtcbcomp07svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.7")?;
    rem = r;
    let (r, sgxtcbcomp08svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.8")?;
    rem = r;
    let (r, sgxtcbcomp09svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.9")?;
    rem = r;
    let (r, sgxtcbcomp10svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.10")?;
    rem = r;
    let (r, sgxtcbcomp11svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.11")?;
    rem = r;
    let (r, sgxtcbcomp12svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.12")?;
    rem = r;
    let (r, sgxtcbcomp13svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.13")?;
    rem = r;
    let (r, sgxtcbcomp14svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.14")?;
    rem = r;
    let (r, sgxtcbcomp15svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.15")?;
    rem = r;
    let (r, sgxtcbcomp16svn) = parse_asn1_field_u8(rem, "1.2.840.113741.1.13.1.2.16")?;
    rem = r;
    let (r, pcesvn) = parse_asn1_field_u16(rem, "1.2.840.113741.1.13.1.2.17")?;
    rem = r;
    let (r, cpusvn_vec) = parse_asn1_field_octets(rem, "1.2.840.113741.1.13.1.2.18")?;
    rem = r;

    if !rem.is_empty() {
        return Err(anyhow!("Extra data after parsing TCB fields"));
    }
    if cpusvn_vec.len() != 16 {
        return Err(anyhow!(
            "Invalid CPUSVN length: expected 16, got {}",
            cpusvn_vec.len()
        ));
    }
    let mut cpusvn = [0u8; 16];
    cpusvn.copy_from_slice(&cpusvn_vec);

    Ok(SgxExtensionTcbLevel {
        sgxtcbcomp01svn,
        sgxtcbcomp02svn,
        sgxtcbcomp03svn,
        sgxtcbcomp04svn,
        sgxtcbcomp05svn,
        sgxtcbcomp06svn,
        sgxtcbcomp07svn,
        sgxtcbcomp08svn,
        sgxtcbcomp09svn,
        sgxtcbcomp10svn,
        sgxtcbcomp11svn,
        sgxtcbcomp12svn,
        sgxtcbcomp13svn,
        sgxtcbcomp14svn,
        sgxtcbcomp15svn,
        sgxtcbcomp16svn,
        pcesvn,
        cpusvn,
    })
}

/// Parses the Configuration field which is a sequence of optional Boolean items.
fn parse_configuration(input: &[u8]) -> Result<PckPlatformConfiguration> {
    let mut rem = input;
    let mut dynamic_platform = None;
    let mut cached_keys = None;
    let mut smt_enabled = None;

    // Parse each item (each item is a SEQUENCE with an OID and a Boolean)
    while !rem.is_empty() {
        let (r, seq_item) = Sequence::from_der(rem)
            .map_err(|e| anyhow!("Failed to parse configuration item: {:?}", e))?;
        rem = r;
        let content = seq_item.content.as_ref();
        let (value, oid) = Oid::from_der(content)
            .map_err(|e| anyhow!("Failed to parse OID in configuration item: {:?}", e))?;
        let field_oid = oid.to_id_string();
        let (rest, boolean) = Boolean::from_der(value).map_err(|e| {
            anyhow!(
                "Failed to parse Boolean for configuration field {}: {:?}",
                field_oid,
                e
            )
        })?;
        if !rest.is_empty() {
            return Err(anyhow!(
                "Extra data after Boolean for configuration field {}",
                field_oid
            ));
        }
        match field_oid.as_str() {
            "1.2.840.113741.1.13.1.7.1" => dynamic_platform = Some(boolean.bool()),
            "1.2.840.113741.1.13.1.7.2" => cached_keys = Some(boolean.bool()),
            "1.2.840.113741.1.13.1.7.3" => smt_enabled = Some(boolean.bool()),
            other => return Err(anyhow!("Unknown configuration field OID: {}", other)),
        }
    }
    Ok(PckPlatformConfiguration {
        dynamic_platform,
        cached_keys,
        smt_enabled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use dcap_collaterals::sgx_extensions::sgx_extensions_to_bytes;

    #[test]
    fn test_extract_sgx_extensions_processor() {
        let extension_bytes = hex::decode("308201C1301E060A2A864886F84D010D010104100D88AD89FEC7F27070560D87FBC3CE1A30820164060A2A864886F84D010D0102308201543010060B2A864886F84D010D0102010201153010060B2A864886F84D010D0102020201153010060B2A864886F84D010D0102030201023010060B2A864886F84D010D0102040201043010060B2A864886F84D010D0102050201013011060B2A864886F84D010D010206020200803010060B2A864886F84D010D01020702010E3010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D01021102010D301F060B2A864886F84D010D01021204101515020401800E0000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600906ED50000300F060A2A864886F84D010D01050A0100").unwrap();
        let res = parse_sgx_extensions(&extension_bytes);
        assert!(res.is_ok(), "{:?}", res);

        let extensions = res.unwrap();
        assert_eq!(extensions.sgx_type, 0);
        assert_eq!(
            extensions.tcb.sgxtcbcompsvns(), // 16 elements
            [21, 21, 2, 4, 1, 128, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            extensions.ppid,
            [13, 136, 173, 137, 254, 199, 242, 112, 112, 86, 13, 135, 251, 195, 206, 26]
        );
        assert_eq!(extensions.fmspc, [0, 144, 110, 213, 0, 0]);
        assert_eq!(extensions.pceid, [0, 0]);
        assert_eq!(extensions.tcb.pcesvn, 13);
        assert_eq!(
            extensions.tcb.cpusvn,
            [21, 21, 2, 4, 1, 128, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(extensions.configuration.is_none());
        let bytes = sgx_extensions_to_bytes(&extensions).unwrap();
        assert_eq!(extension_bytes, bytes);
    }

    #[test]
    fn test_extract_sgx_extensions_platform() {
        let extension_bytes = hex::decode("30820228301E060A2A864886F84D010D0101041025F8E1DA4FE822D04F0FF15025931F4930820165060A2A864886F84D010D0102308201553010060B2A864886F84D010D01020102010C3010060B2A864886F84D010D01020202010C3010060B2A864886F84D010D0102030201033010060B2A864886F84D010D0102040201033011060B2A864886F84D010D010205020200FF3011060B2A864886F84D010D010206020200FF3010060B2A864886F84D010D0102070201013010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D01021102010D301F060B2A864886F84D010D01021204100C0C0303FFFF010000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600606A000000300F060A2A864886F84D010D01050A0101301E060A2A864886F84D010D010604101135C40890AEDF44EB6E02D58424229E3044060A2A864886F84D010D010730363010060B2A864886F84D010D0107010101FF3010060B2A864886F84D010D0107020101003010060B2A864886F84D010D010703010100").unwrap();
        let res = parse_sgx_extensions(&extension_bytes);
        assert!(res.is_ok(), "{:?}", res);

        let extensions = res.unwrap();
        let bytes = sgx_extensions_to_bytes(&extensions).unwrap();
        assert_eq!(extension_bytes, bytes);

        assert_eq!(extensions.sgx_type, 1);
        assert_eq!(
            extensions.tcb.sgxtcbcompsvns(), // 16 elements
            [12, 12, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            extensions.ppid,
            [37, 248, 225, 218, 79, 232, 34, 208, 79, 15, 241, 80, 37, 147, 31, 73]
        );
        assert_eq!(extensions.fmspc, [0, 96, 106, 0, 0, 0]);
        assert_eq!(extensions.pceid, [0, 0]);
        assert_eq!(extensions.tcb.pcesvn, 13);
        assert_eq!(
            extensions.tcb.cpusvn,
            [12, 12, 3, 3, 255, 255, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(extensions.configuration.is_some());
        let configuration = extensions.configuration.unwrap();
        assert!(configuration.dynamic_platform.is_some());
        assert!(configuration.cached_keys.is_some());
        assert!(configuration.smt_enabled.is_some());
    }
}
