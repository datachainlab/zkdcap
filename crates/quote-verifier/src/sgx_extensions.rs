use crate::Result;
use anyhow::{anyhow, Context};
use dcap_types::cert::{PckPlatformConfiguration, SgxExtensionTcbLevel, SgxExtensions};
use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Boolean, Enumerated, Integer, OctetString, Sequence};
use x509_parser::der_parser::{oid, Oid};
use x509_parser::prelude::FromDer;

pub fn extract_sgx_extensions<'a>(pck_cert: &'a X509Certificate<'a>) -> Result<SgxExtensions> {
    let sgx_extensions_bytes = pck_cert
        .get_extension_unique(&oid!(1.2.840 .113741 .1 .13 .1))?
        .context("SGX Extensions not found")?
        .value;
    parse_sgx_extensions(sgx_extensions_bytes)
}

/// Parse the SGX Extensions from the DER-encoded bytes and returns an `SgxExtensions` structure.
pub fn parse_sgx_extensions<'a>(sgx_extensions_bytes: &'a [u8]) -> Result<SgxExtensions> {
    // p.11-14 https://download.01.org/intel-sgx/sgx-dcap/1.22/linux/docs/SGX_PCK_Certificate_CRL_Spec-1.4.pdf

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
                let (rest, tcb_seq) = Sequence::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse TCB sequence: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after TCB sequence"));
                }
                tcb = Some(parse_tcb_level(tcb_seq.content.as_ref())?);
            }
            "1.2.840.113741.1.13.1.3" => {
                // PCE-ID (OctetString)
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
                let (rest, enumerated) = Enumerated::from_der(value)
                    .map_err(|e| anyhow!("Failed to parse SGX Type Enumerated: {:?}", e))?;
                if !rest.is_empty() {
                    return Err(anyhow!("Extra data after SGX Type Enumerated"));
                }
                sgx_type = Some(enumerated.0);
            }
            "1.2.840.113741.1.13.1.6" => {
                // Platform Instance ID (OctetString, Optional)
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

/// Parses an ASN.1 field (a SEQUENCE containing an OID and an Integer) and returns the integer value.
/// It verifies that the OID matches the expected value.
fn parse_asn1_field_uint<'a>(input: &'a [u8], expected_oid: &'a str) -> Result<(&'a [u8], u64)> {
    let (remaining, seq) = Sequence::from_der(input).map_err(|e| {
        anyhow!(
            "Failed to parse sequence for field {}: {:?}",
            expected_oid,
            e
        )
    })?;
    let content = seq.content.as_ref();
    let (value, oid) = Oid::from_der(content)
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
    let i = integer
        .as_u64()
        .context("Failed to convert integer to u64")?;
    Ok((remaining, i))
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

    let (r, comp01) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.1")?;
    rem = r;
    let (r, comp02) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.2")?;
    rem = r;
    let (r, comp03) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.3")?;
    rem = r;
    let (r, comp04) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.4")?;
    rem = r;
    let (r, comp05) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.5")?;
    rem = r;
    let (r, comp06) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.6")?;
    rem = r;
    let (r, comp07) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.7")?;
    rem = r;
    let (r, comp08) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.8")?;
    rem = r;
    let (r, comp09) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.9")?;
    rem = r;
    let (r, comp10) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.10")?;
    rem = r;
    let (r, comp11) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.11")?;
    rem = r;
    let (r, comp12) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.12")?;
    rem = r;
    let (r, comp13) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.13")?;
    rem = r;
    let (r, comp14) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.14")?;
    rem = r;
    let (r, comp15) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.15")?;
    rem = r;
    let (r, comp16) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.16")?;
    rem = r;
    let (r, pcesvn) = parse_asn1_field_uint(rem, "1.2.840.113741.1.13.1.2.17")?;
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
        sgxtcbcomp01svn: comp01 as u8,
        sgxtcbcomp02svn: comp02 as u8,
        sgxtcbcomp03svn: comp03 as u8,
        sgxtcbcomp04svn: comp04 as u8,
        sgxtcbcomp05svn: comp05 as u8,
        sgxtcbcomp06svn: comp06 as u8,
        sgxtcbcomp07svn: comp07 as u8,
        sgxtcbcomp08svn: comp08 as u8,
        sgxtcbcomp09svn: comp09 as u8,
        sgxtcbcomp10svn: comp10 as u8,
        sgxtcbcomp11svn: comp11 as u8,
        sgxtcbcomp12svn: comp12 as u8,
        sgxtcbcomp13svn: comp13 as u8,
        sgxtcbcomp14svn: comp14 as u8,
        sgxtcbcomp15svn: comp15 as u8,
        sgxtcbcomp16svn: comp16 as u8,
        pcesvn: pcesvn as u16,
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
        let extension_bytes = hex::decode("308201C0301E060A2A864886F84D010D010104100000000000000000000000000000000030820163060A2A864886F84D010D0102308201533010060B2A864886F84D010D0102010201003010060B2A864886F84D010D0102020201003010060B2A864886F84D010D0102030201003010060B2A864886F84D010D0102040201003010060B2A864886F84D010D0102050201003010060B2A864886F84D010D0102060201003010060B2A864886F84D010D0102070201003010060B2A864886F84D010D0102080201003010060B2A864886F84D010D0102090201003010060B2A864886F84D010D01020A0201003010060B2A864886F84D010D01020B0201003010060B2A864886F84D010D01020C0201003010060B2A864886F84D010D01020D0201003010060B2A864886F84D010D01020E0201003010060B2A864886F84D010D01020F0201003010060B2A864886F84D010D0102100201003010060B2A864886F84D010D010211020100301F060B2A864886F84D010D0102120410000000000000000000000000000000003010060A2A864886F84D010D0103040200003014060A2A864886F84D010D0104040600606A000000300F060A2A864886F84D010D01050A0100").unwrap();
        let res = parse_sgx_extensions(&extension_bytes);
        assert!(res.is_ok(), "{:?}", res);

        let extensions = res.unwrap();
        let bytes = sgx_extensions_to_bytes(&extensions).unwrap();
        assert_eq!(extension_bytes, bytes);
        assert_eq!(extensions.sgx_type, 0);
        assert!(extensions.configuration.is_none());
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
        assert!(extensions.configuration.is_some());
        let configuration = extensions.configuration.unwrap();
        assert!(configuration.dynamic_platform.is_some());
        assert!(configuration.cached_keys.is_some());
        assert!(configuration.smt_enabled.is_some());
    }
}
