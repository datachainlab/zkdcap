use anyhow::{anyhow, Result};
use dcap_types::cert::{PckPlatformConfiguration, SgxExtensionTcbLevel, SgxExtensions};
use std::str::FromStr;
use x509_parser::der_parser::asn1_rs::{Boolean, Enumerated, Integer, OctetString, ToDer};
use x509_parser::der_parser::Oid;

pub struct SgxExtensionsBuilder {
    obj: SgxExtensions,
}

impl SgxExtensionsBuilder {
    pub fn new() -> Self {
        Self {
            obj: Default::default(),
        }
    }

    pub fn ppid(self, ppid: [u8; 16]) -> Self {
        Self {
            obj: SgxExtensions { ppid, ..self.obj },
        }
    }

    pub fn tcb(self, tcb: SgxExtensionTcbLevel) -> Self {
        Self {
            obj: SgxExtensions { tcb, ..self.obj },
        }
    }

    pub fn pceid(self, pceid: [u8; 2]) -> Self {
        Self {
            obj: SgxExtensions { pceid, ..self.obj },
        }
    }

    pub fn fmspc(self, fmspc: [u8; 6]) -> Self {
        Self {
            obj: SgxExtensions { fmspc, ..self.obj },
        }
    }

    pub fn sgx_type(self, sgx_type: u32) -> Self {
        Self {
            obj: SgxExtensions {
                sgx_type,
                ..self.obj
            },
        }
    }

    pub fn platform_instance_id(self, platform_instance_id: [u8; 16]) -> Self {
        Self {
            obj: SgxExtensions {
                platform_instance_id: Some(platform_instance_id),
                ..self.obj
            },
        }
    }

    pub fn configuration(self, configuration: PckPlatformConfiguration) -> Self {
        Self {
            obj: SgxExtensions {
                configuration: Some(configuration),
                ..self.obj
            },
        }
    }

    pub fn build(self) -> SgxExtensions {
        self.obj
    }
}

/// Generates the DER-encoded SGX Extensions bytes from the provided `SgxExtensions` structure.
pub fn sgx_extensions_to_bytes(extensions: &SgxExtensions) -> Result<Vec<u8>> {
    let mut items = Vec::new();

    // 1. PPID (OID: 1.2.840.113741.1.13.1.1) - Mandatory
    set_asn1_bytes(&mut items, "1.2.840.113741.1.13.1.1", &extensions.ppid)?;

    // 2. TCB (OID: 1.2.840.113741.1.13.1.2) - Mandatory
    // TCB is a sequence containing multiple fields (SGX TCB CompXX SVN, PCESVN, CPUSVN)
    let mut tcb_items = Vec::new();
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.1",
        extensions.tcb.sgxtcbcomp01svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.2",
        extensions.tcb.sgxtcbcomp02svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.3",
        extensions.tcb.sgxtcbcomp03svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.4",
        extensions.tcb.sgxtcbcomp04svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.5",
        extensions.tcb.sgxtcbcomp05svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.6",
        extensions.tcb.sgxtcbcomp06svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.7",
        extensions.tcb.sgxtcbcomp07svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.8",
        extensions.tcb.sgxtcbcomp08svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.9",
        extensions.tcb.sgxtcbcomp09svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.10",
        extensions.tcb.sgxtcbcomp10svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.11",
        extensions.tcb.sgxtcbcomp11svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.12",
        extensions.tcb.sgxtcbcomp12svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.13",
        extensions.tcb.sgxtcbcomp13svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.14",
        extensions.tcb.sgxtcbcomp14svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.15",
        extensions.tcb.sgxtcbcomp15svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.16",
        extensions.tcb.sgxtcbcomp16svn as u64,
    )?;
    set_asn1_uint64(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.17",
        extensions.tcb.pcesvn as u64,
    )?;
    set_asn1_bytes(
        &mut tcb_items,
        "1.2.840.113741.1.13.1.2.18",
        &extensions.tcb.cpusvn,
    )?;
    // Wrap the TCB items in a DER sequence.
    let tcb_der = encode_der_sequence(&tcb_items);
    // Add the TCB field with its OID.
    set_asn1_item(&mut items, "1.2.840.113741.1.13.1.2", tcb_der)?;

    // 3. PCE-ID (OID: 1.2.840.113741.1.13.1.3) - Mandatory
    set_asn1_bytes(&mut items, "1.2.840.113741.1.13.1.3", &extensions.pceid)?;

    // 4. FMSPC (OID: 1.2.840.113741.1.13.1.4) - Mandatory
    set_asn1_bytes(&mut items, "1.2.840.113741.1.13.1.4", &extensions.fmspc)?;

    // 5. SGX Type (OID: 1.2.840.113741.1.13.1.5) - Mandatory
    set_asn1_enumerated(&mut items, "1.2.840.113741.1.13.1.5", extensions.sgx_type)?;

    // 6. Platform Instance ID (OID: 1.2.840.113741.1.13.1.6) - Optional
    if let Some(pid) = &extensions.platform_instance_id {
        set_asn1_bytes(&mut items, "1.2.840.113741.1.13.1.6", pid)?;
    }

    // 7. Configuration (OID: 1.2.840.113741.1.13.1.7) - Optional
    if let Some(conf) = &extensions.configuration {
        let mut conf_items = Vec::new();
        if let Some(dynamic_platform) = conf.dynamic_platform {
            set_asn1_boolean(
                &mut conf_items,
                "1.2.840.113741.1.13.1.7.1",
                dynamic_platform,
            )?;
        }
        if let Some(cached_keys) = conf.cached_keys {
            set_asn1_boolean(&mut conf_items, "1.2.840.113741.1.13.1.7.2", cached_keys)?;
        }
        if let Some(smt_enabled) = conf.smt_enabled {
            set_asn1_boolean(&mut conf_items, "1.2.840.113741.1.13.1.7.3", smt_enabled)?;
        }
        let conf_der = encode_der_sequence(&conf_items);
        set_asn1_item(&mut items, "1.2.840.113741.1.13.1.7", conf_der)?;
    }

    // Wrap all items in a DER sequence for SGX Extensions.
    let sgx_extensions_der = encode_der_sequence(&items);
    Ok(sgx_extensions_der)
}

/// Encodes the given content as a DER sequence.
fn encode_der_sequence(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    // DER Sequence tag (0x30)
    out.push(0x30);
    let len = content.len();
    if len < 128 {
        out.push(len as u8);
    } else {
        // For lengths >= 128, use the long form encoding.
        let mut len_bytes = Vec::new();
        let mut n = len;
        while n > 0 {
            len_bytes.push((n & 0xFF) as u8);
            n >>= 8;
        }
        len_bytes.reverse();
        out.push(0x80 | (len_bytes.len() as u8));
        out.extend_from_slice(&len_bytes);
    }
    out.extend_from_slice(content);
    out
}

/// Adds an ASN.1 item (OID and DER-encoded value) to the provided byte vector.
fn set_asn1_item(bytes: &mut Vec<u8>, oid_str: &str, der_value: Vec<u8>) -> Result<()> {
    // Encode the target OID.
    let oid = Oid::from_str(oid_str).map_err(|e| anyhow!("Invalid OID: {:?}", e))?;
    let oid_der = oid
        .to_der_vec()
        .map_err(|e| anyhow!("OID DER encoding error: {:?}", e))?;

    let mut item_content = Vec::new();
    item_content.extend_from_slice(&oid_der);
    item_content.extend_from_slice(&der_value);
    // Wrap the content in a DER sequence.
    let item = encode_der_sequence(&item_content);
    bytes.extend_from_slice(&item);
    Ok(())
}

/// Encodes a u64 as an ASN.1 Integer with the given OID.
fn set_asn1_uint64(bytes: &mut Vec<u8>, oid_str: &str, value: u64) -> Result<()> {
    let der_int = Integer::from(value)
        .to_der_vec()
        .map_err(|e| anyhow!("Integer DER encoding error: {:?}", e))?;
    set_asn1_item(bytes, oid_str, der_int)
}

/// Encodes a byte slice as an ASN.1 OctetString with the given OID.
fn set_asn1_bytes(bytes: &mut Vec<u8>, oid_str: &str, value: &[u8]) -> Result<()> {
    let der_oct = OctetString::from(value)
        .to_der_vec()
        .map_err(|e| anyhow!("OctetString DER encoding error: {:?}", e))?;
    set_asn1_item(bytes, oid_str, der_oct)
}

/// Encodes a u32 as an ASN.1 Enumerated with the given OID.
fn set_asn1_enumerated(bytes: &mut Vec<u8>, oid_str: &str, value: u32) -> Result<()> {
    let der_enum = Enumerated(value)
        .to_der_vec()
        .map_err(|e| anyhow!("Enumerated DER encoding error: {:?}", e))?;
    set_asn1_item(bytes, oid_str, der_enum)
}

/// Encodes a bool as an ASN.1 Boolean with the given OID.
fn set_asn1_boolean(bytes: &mut Vec<u8>, oid_str: &str, value: bool) -> Result<()> {
    let der_bool = if value { Boolean::TRUE } else { Boolean::FALSE }
        .to_der_vec()
        .map_err(|e| anyhow!("Boolean DER encoding error: {:?}", e))?;
    set_asn1_item(bytes, oid_str, der_bool)
}
