use serde::{Deserialize, Serialize};

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

impl SgxExtensionTcbLevel {
    pub fn new(sgxtcbcompsvns: &[u8; 16], pcesvn: u16, cpusvn: [u8; 16]) -> Self {
        Self {
            sgxtcbcomp01svn: sgxtcbcompsvns[0],
            sgxtcbcomp02svn: sgxtcbcompsvns[1],
            sgxtcbcomp03svn: sgxtcbcompsvns[2],
            sgxtcbcomp04svn: sgxtcbcompsvns[3],
            sgxtcbcomp05svn: sgxtcbcompsvns[4],
            sgxtcbcomp06svn: sgxtcbcompsvns[5],
            sgxtcbcomp07svn: sgxtcbcompsvns[6],
            sgxtcbcomp08svn: sgxtcbcompsvns[7],
            sgxtcbcomp09svn: sgxtcbcompsvns[8],
            sgxtcbcomp10svn: sgxtcbcompsvns[9],
            sgxtcbcomp11svn: sgxtcbcompsvns[10],
            sgxtcbcomp12svn: sgxtcbcompsvns[11],
            sgxtcbcomp13svn: sgxtcbcompsvns[12],
            sgxtcbcomp14svn: sgxtcbcompsvns[13],
            sgxtcbcomp15svn: sgxtcbcompsvns[14],
            sgxtcbcomp16svn: sgxtcbcompsvns[15],
            pcesvn,
            cpusvn,
        }
    }

    pub fn sgxtcbcompsvns(&self) -> [u8; 16] {
        [
            self.sgxtcbcomp01svn,
            self.sgxtcbcomp02svn,
            self.sgxtcbcomp03svn,
            self.sgxtcbcomp04svn,
            self.sgxtcbcomp05svn,
            self.sgxtcbcomp06svn,
            self.sgxtcbcomp07svn,
            self.sgxtcbcomp08svn,
            self.sgxtcbcomp09svn,
            self.sgxtcbcomp10svn,
            self.sgxtcbcomp11svn,
            self.sgxtcbcomp12svn,
            self.sgxtcbcomp13svn,
            self.sgxtcbcomp14svn,
            self.sgxtcbcomp15svn,
            self.sgxtcbcomp16svn,
        ]
    }
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
