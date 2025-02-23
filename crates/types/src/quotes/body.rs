use anyhow::bail;

use crate::{Result, ENCLAVE_REPORT_LEN};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum QuoteBody {
    /// QE3
    SGXQuoteBody(EnclaveReport),
    /// QE4
    TD10QuoteBody(TD10ReportBody),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnclaveReport {
    /// Security Version of the CPU (raw value) [16 bytes]
    pub cpu_svn: [u8; 16],
    /// SSA Frame extended feature set. [4 bytes]
    /// Reports what SECS.MISCSELECT settings are used in the enclave. You can limit the
    /// allowed MISCSELECT settings in the sigstruct using MISCSELECT/MISCMASK.
    pub misc_select: [u8; 4],
    /// Reserved for future use - 0 [28 bytes]
    pub reserved_1: [u8; 28],
    /// Set of flags describing attributes of the enclave. [16 bytes]
    /// Reports what SECS.ATTRIBUTES settings are used in the enclave. The ISV can limit what
    /// SECS.ATTRIBUTES can be used when loading the enclave through parameters to the SGX Signtool.
    /// The Signtool will produce a SIGSTRUCT with ATTRIBUTES and ATTRIBUTESMASK
    /// which determine allowed ATTRIBUTES.
    /// - For each SIGSTRUCT.ATTRIBUTESMASK bit that is set, then corresponding bit in the
    ///   SECS.ATTRIBUTES must match the same bit in SIGSTRUCT.ATTRIBUTES.
    pub attributes: [u8; 16],
    /// Measurement of the enclave. [32 bytes]
    /// The MRENCLAVE value is the SHA256 hash of the ENCLAVEHASH field in the SIGSTRUCT.
    pub mrenclave: [u8; 32],
    /// Reserved for future use - 0 [32 bytes]
    pub reserved_2: [u8; 32],
    /// Measurement of the enclave signer. [32 bytes]
    /// The MRSIGNER value is the SHA256 hash of the MODULUS field in the SIGSTRUCT.
    pub mrsigner: [u8; 32],
    /// Reserved for future use - 0 [96 bytes]
    pub reserved_3: [u8; 96],
    /// Product ID of the enclave. [2 bytes]
    /// The ISV should configure a unique ISVProdID for each product which may
    /// want to share sealed data between enclaves signed with a specific MRSIGNER. The ISV
    /// may want to supply different data to identical enclaves signed for different products.
    pub isv_prod_id: u16,
    /// Security Version of the enclave [2 bytes]
    pub isv_svn: u16,
    /// Reserved for future use - 0 [60 bytes]
    pub reserved_4: [u8; 60],
    /// Additional report data. [64 bytes]
    /// The enclave is free to provide 64 bytes of custom data to the REPORT.
    /// This can be used to provide specific data from the enclave or it can be used to hold
    /// a hash of a larger block of data which is provided with the quote.
    /// The verification of the quote signature confirms the integrity of the
    /// report data (and the rest of the REPORT body).
    pub report_data: [u8; 64],
}

impl EnclaveReport {
    /// Parse raw bytes into EnclaveReport
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<EnclaveReport> {
        if raw_bytes.len() != ENCLAVE_REPORT_LEN {
            bail!("Invalid length of bytes for EnclaveReport");
        }
        let mut obj = EnclaveReport {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            reserved_1: [0; 28],
            attributes: [0; 16],
            mrenclave: [0; 32],
            reserved_2: [0; 32],
            mrsigner: [0; 32],
            reserved_3: [0; 96],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved_4: [0; 60],
            report_data: [0; 64],
        };

        // parse raw bytes into obj
        obj.cpu_svn.copy_from_slice(&raw_bytes[0..16]);
        obj.misc_select.copy_from_slice(&raw_bytes[16..20]);
        obj.reserved_1.copy_from_slice(&raw_bytes[20..48]);
        obj.attributes.copy_from_slice(&raw_bytes[48..64]);
        obj.mrenclave.copy_from_slice(&raw_bytes[64..96]);
        obj.reserved_2.copy_from_slice(&raw_bytes[96..128]);
        obj.mrsigner.copy_from_slice(&raw_bytes[128..160]);
        obj.reserved_3.copy_from_slice(&raw_bytes[160..256]);
        obj.isv_prod_id = u16::from_le_bytes([raw_bytes[256], raw_bytes[257]]);
        obj.isv_svn = u16::from_le_bytes([raw_bytes[258], raw_bytes[259]]);
        obj.reserved_4.copy_from_slice(&raw_bytes[260..320]);
        obj.report_data.copy_from_slice(&raw_bytes[320..384]);

        Ok(obj)
    }

    /// Convert EnclaveReport into raw bytes
    pub fn to_bytes(&self) -> [u8; 384] {
        // convert the struct into raw bytes
        let mut raw_bytes = [0; 384];
        // copy the fields into the raw bytes
        raw_bytes[0..16].copy_from_slice(&self.cpu_svn);
        raw_bytes[16..20].copy_from_slice(&self.misc_select);
        raw_bytes[20..48].copy_from_slice(&self.reserved_1);
        raw_bytes[48..64].copy_from_slice(&self.attributes);
        raw_bytes[64..96].copy_from_slice(&self.mrenclave);
        raw_bytes[96..128].copy_from_slice(&self.reserved_2);
        raw_bytes[128..160].copy_from_slice(&self.mrsigner);
        raw_bytes[160..256].copy_from_slice(&self.reserved_3);
        raw_bytes[256..258].copy_from_slice(&self.isv_prod_id.to_le_bytes());
        raw_bytes[258..260].copy_from_slice(&self.isv_svn.to_le_bytes());
        raw_bytes[260..320].copy_from_slice(&self.reserved_4);
        raw_bytes[320..384].copy_from_slice(&self.report_data);

        raw_bytes
    }

    /// Get the misc_select field as a u32
    pub fn misc_select(&self) -> u32 {
        u32::from_le_bytes(self.misc_select)
    }
}

impl Default for EnclaveReport {
    fn default() -> Self {
        EnclaveReport {
            cpu_svn: [0; 16],
            misc_select: [0; 4],
            reserved_1: [0; 28],
            attributes: [0; 16],
            mrenclave: [0; 32],
            reserved_2: [0; 32],
            mrsigner: [0; 32],
            reserved_3: [0; 96],
            isv_prod_id: 0,
            isv_svn: 0,
            reserved_4: [0; 60],
            report_data: [0; 64],
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct TD10ReportBody {
    /// Describes the TCB of TDX. [16 bytes]
    /// Each byte of the TEE_TCB_SVN field corresponds to a component of the `TCBInfo.TCBLevels.tcb.tdxtcbcomponents.svn` array.
    pub tee_tcb_svn: [u8; 16],
    /// Measurement of the TDX Module. [48 bytes]
    pub mrseam: [u8; 48],
    /// Measurement of the TDX Module. [48 bytes]
    pub mrsignerseam: [u8; 48],
    /// Zero for Intel TDX Module [8 bytes]
    pub seam_attributes: u64,
    /// Must be zero for TDX 1.0 [8 bytes]
    pub td_attributes: u64,
    /// TD Attributes [8 bytes]
    /// \[0:7\]    : (TUD) TD Under Debug flags.
    ///            If any of the bits in this group are set to 1, the TD is untrusted.
    ///            \[0\]     - (DEBUG) Defines whether the TD runs in TD debug mode (set to 1) or not (set to 0).
    ///                      In TD debug mode, the CPU state and private memory are accessible by the host VMM.
    ///            \[1:7\]   - (RESERVED) Reserved for future TUD flags, must be 0.
    /// \[8:31]   : (SEC) Attributes that may impact the security of the TD
    ///            \[8:27\]  - (RESERVED) Reserved for future SEC flags, must be 0.
    ///            \[28\]    - (SEPT_VE_DISABLE) Disable EPT violation conversion to #VE on TD access of PENDING pages
    ///            \[29\]    - (RESERVED) Reserved for future SEC flags, must be 0.
    ///            \[30\]    - (PKS) TD is allowed to use Supervisor Protection Keys.
    ///            \[31\]    - (KL) TD is allowed to use Key Locker.
    /// \[32:63]  : (OTHER) Attributes that do not impact the security of the TD
    ///            \[32:62\] - (RESERVED) Reserved for future OTHER flags, must be 0.
    ///            \[63\]    - (PERFMON) TD is allowed to use Perfmon and PERF_METRICS capabilities.
    pub xfam: u64,
    /// (SHA384) Measurement of the initial contents of the TD. [48 bytes]
    pub mrtd: [u8; 48],
    /// Software-defined ID for non-owner-defined configuration of the TD, e.g., runtime or OS configuration. [48 bytes]
    pub mrconfigid: [u8; 48],
    /// Software-defined ID for the TD’s owner [48 bytes]
    pub mrowner: [u8; 48],
    /// Software-defined ID for owner-defined configuration of the TD, e.g., specific to the workload rather than the runtime or OS. [48 bytes]
    pub mrownerconfig: [u8; 48],
    /// (SHA384) Root of Trust for Measurement (RTM) for the TD. [48 bytes]
    pub rtmr0: [u8; 48],
    /// (SHA384) Root of Trust for Measurement (RTM) for the TD. [48 bytes]
    pub rtmr1: [u8; 48],
    /// (SHA384) Root of Trust for Measurement (RTM) for the TD. [48 bytes]
    pub rtmr2: [u8; 48],
    /// (SHA384) Root of Trust for Measurement (RTM) for the TD. [48 bytes]
    pub rtmr3: [u8; 48],
    /// Additional report data. [64 bytes]
    /// The TD is free to provide 64 bytes of custom data to the REPORT.
    /// This can be used to provide specific data from the TD or it can be used to hold a hash of a larger block of data which is provided with the quote.
    /// Note that the signature of a TD Quote covers the REPORTDATA field. As a result, the integrity is protected with a key rooted in an Intel CA.
    pub report_data: [u8; 64],
}

impl TD10ReportBody {
    /// Parse raw bytes into TD10ReportBody
    pub fn from_bytes(raw_bytes: &[u8]) -> Result<Self> {
        if raw_bytes.len() != 584 {
            bail!("Invalid length of bytes for TD10ReportBody");
        }

        // copy the bytes into the struct
        let mut tee_tcb_svn = [0; 16];
        tee_tcb_svn.copy_from_slice(&raw_bytes[0..16]);
        let mut mrseam = [0; 48];
        mrseam.copy_from_slice(&raw_bytes[16..64]);
        let mut mrsignerseam = [0; 48];
        mrsignerseam.copy_from_slice(&raw_bytes[64..112]);
        let seam_attributes = u64::from_le_bytes([
            raw_bytes[112],
            raw_bytes[113],
            raw_bytes[114],
            raw_bytes[115],
            raw_bytes[116],
            raw_bytes[117],
            raw_bytes[118],
            raw_bytes[119],
        ]);
        let td_attributes = u64::from_le_bytes([
            raw_bytes[120],
            raw_bytes[121],
            raw_bytes[122],
            raw_bytes[123],
            raw_bytes[124],
            raw_bytes[125],
            raw_bytes[126],
            raw_bytes[127],
        ]);
        let xfam = u64::from_le_bytes([
            raw_bytes[128],
            raw_bytes[129],
            raw_bytes[130],
            raw_bytes[131],
            raw_bytes[132],
            raw_bytes[133],
            raw_bytes[134],
            raw_bytes[135],
        ]);
        let mut mrtd = [0; 48];
        mrtd.copy_from_slice(&raw_bytes[136..184]);
        let mut mrconfigid = [0; 48];
        mrconfigid.copy_from_slice(&raw_bytes[184..232]);
        let mut mrowner = [0; 48];
        mrowner.copy_from_slice(&raw_bytes[232..280]);
        let mut mrownerconfig = [0; 48];
        mrownerconfig.copy_from_slice(&raw_bytes[280..328]);
        let mut rtmr0 = [0; 48];
        rtmr0.copy_from_slice(&raw_bytes[328..376]);
        let mut rtmr1 = [0; 48];
        rtmr1.copy_from_slice(&raw_bytes[376..424]);
        let mut rtmr2 = [0; 48];
        rtmr2.copy_from_slice(&raw_bytes[424..472]);
        let mut rtmr3 = [0; 48];
        rtmr3.copy_from_slice(&raw_bytes[472..520]);
        let mut report_data = [0; 64];
        report_data.copy_from_slice(&raw_bytes[520..584]);

        Ok(TD10ReportBody {
            tee_tcb_svn,
            mrseam,
            mrsignerseam,
            seam_attributes,
            td_attributes,
            xfam,
            mrtd,
            mrconfigid,
            mrowner,
            mrownerconfig,
            rtmr0,
            rtmr1,
            rtmr2,
            rtmr3,
            report_data,
        })
    }

    /// Convert TD10ReportBody into raw bytes
    pub fn to_bytes(&self) -> [u8; 584] {
        let mut raw_bytes = [0; 584];
        raw_bytes[0..16].copy_from_slice(&self.tee_tcb_svn);
        raw_bytes[16..64].copy_from_slice(&self.mrseam);
        raw_bytes[64..112].copy_from_slice(&self.mrsignerseam);
        raw_bytes[112..120].copy_from_slice(&self.seam_attributes.to_le_bytes());
        raw_bytes[120..128].copy_from_slice(&self.td_attributes.to_le_bytes());
        raw_bytes[128..136].copy_from_slice(&self.xfam.to_le_bytes());
        raw_bytes[136..184].copy_from_slice(&self.mrtd);
        raw_bytes[184..232].copy_from_slice(&self.mrconfigid);
        raw_bytes[232..280].copy_from_slice(&self.mrowner);
        raw_bytes[280..328].copy_from_slice(&self.mrownerconfig);
        raw_bytes[328..376].copy_from_slice(&self.rtmr0);
        raw_bytes[376..424].copy_from_slice(&self.rtmr1);
        raw_bytes[424..472].copy_from_slice(&self.rtmr2);
        raw_bytes[472..520].copy_from_slice(&self.rtmr3);
        raw_bytes[520..584].copy_from_slice(&self.report_data);

        raw_bytes
    }
}

impl Default for TD10ReportBody {
    fn default() -> Self {
        TD10ReportBody {
            tee_tcb_svn: [0; 16],
            mrseam: [0; 48],
            mrsignerseam: [0; 48],
            seam_attributes: 0,
            td_attributes: 0,
            xfam: 0,
            mrtd: [0; 48],
            mrconfigid: [0; 48],
            mrowner: [0; 48],
            mrownerconfig: [0; 48],
            rtmr0: [0; 48],
            rtmr1: [0; 48],
            rtmr2: [0; 48],
            rtmr3: [0; 48],
            report_data: [0; 64],
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_enclave_report_roundtrip(report in enclave_report_strategy()) {
            let raw_bytes = report.to_bytes();
            let parsed_report = EnclaveReport::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(parsed_report, report);
        }

        #[test]
        fn test_td10_report_body_roundtrip(body in td10_report_body_strategy()) {
            let raw_bytes = body.to_bytes();
            let parsed_body = TD10ReportBody::from_bytes(&raw_bytes).unwrap();
            prop_assert_eq!(parsed_body, body);
        }
    }

    // proptest strategy for EnclaveReport
    pub(crate) fn enclave_report_strategy() -> impl Strategy<Value = EnclaveReport> {
        (
            any::<[u8; 16]>(),
            any::<[u8; 4]>(),
            any::<[u8; 28]>(),
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 96]>(),
            any::<u16>(),
            any::<u16>(),
            any::<[u8; 60]>(),
            any::<[u8; 64]>(),
        )
            .prop_map(
                |(
                    cpu_svn,
                    misc_select,
                    reserved_1,
                    attributes,
                    mrenclave,
                    reserved_2,
                    mrsigner,
                    reserved_3,
                    isv_prod_id,
                    isv_svn,
                    reserved_4,
                    report_data,
                )| EnclaveReport {
                    cpu_svn,
                    misc_select,
                    reserved_1,
                    attributes,
                    mrenclave,
                    reserved_2,
                    mrsigner,
                    reserved_3,
                    isv_prod_id,
                    isv_svn,
                    reserved_4,
                    report_data,
                },
            )
    }

    // proptest strategy for TD10ReportBody
    pub(crate) fn td10_report_body_strategy() -> impl Strategy<Value = TD10ReportBody> {
        (
            (
                any::<[u8; 16]>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
                any::<u64>(),
                any::<u64>(),
                any::<u64>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
                any::<[u8; 48]>(),
            ),
            (any::<[u8; 48]>(), any::<[u8; 48]>(), any::<[u8; 64]>()),
        )
            .prop_map(
                |(
                    (
                        tee_tcb_svn,
                        mrseam,
                        mrsignerseam,
                        seam_attributes,
                        td_attributes,
                        xfam,
                        mrtd,
                        mrconfigid,
                        mrowner,
                        mrownerconfig,
                        rtmr0,
                        rtmr1,
                    ),
                    (rtmr2, rtmr3, report_data),
                )| TD10ReportBody {
                    tee_tcb_svn,
                    mrseam,
                    mrsignerseam,
                    seam_attributes,
                    td_attributes,
                    xfam,
                    mrtd,
                    mrconfigid,
                    mrowner,
                    mrownerconfig,
                    rtmr0,
                    rtmr1,
                    rtmr2,
                    rtmr3,
                    report_data,
                },
            )
    }
}
