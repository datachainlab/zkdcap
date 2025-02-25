use risc0_binfmt::compute_image_id;
use risc0_build::{embed_method_metadata_with_options, DockerOptionsBuilder, GuestOptionsBuilder};
use std::{collections::HashMap, env, fs::File, io::Write};

fn main() {
    println!("cargo:rerun-if-env-changed=ZKDCAP_RISC0_BUILD");
    match env::var("ZKDCAP_RISC0_BUILD") {
        Ok(v) if v == "1" => {
            println!("debug: ZKDCAP_RISC0_BUILD is set");
        }
        _ => {
            println!("debug: ZKDCAP_RISC0_BUILD is not set");
            return;
        }
    }

    // Builds can be made deterministic, and thereby reproducible, by using Docker to build the
    // guest.
    let use_docker = DockerOptionsBuilder::default()
        .root_dir("../../")
        .build()
        .unwrap();

    let guest_options = GuestOptionsBuilder::default()
        .use_docker(use_docker)
        .build()
        .unwrap();

    // Generate Rust source files for the methods crate.
    let guests = embed_method_metadata_with_options(HashMap::from([("guests", guest_options)]));

    if guests.len() != 1 {
        panic!("expected exactly one guest, found {}", guests.len());
    };
    let elf_value = std::fs::read(guests[0].path.to_string()).unwrap();
    let image_id = compute_image_id(&elf_value).unwrap();
    let image_id_words = image_id.as_words().to_vec();
    let image_id_str = image_id.to_string();
    let mut elf_file = File::create("./artifacts/dcap-quote-verifier").unwrap();
    elf_file.write_all(&elf_value).unwrap();
    let mut methods_file = File::create("./src/methods.rs").unwrap();
    methods_file
        .write_all(
            format!(
                r##"
pub const DCAP_QUOTE_VERIFIER_ID: [u32; 8] = {image_id_words:?};
pub const DCAP_QUOTE_VERIFIER_ID_STR: &str = "{image_id_str}";
pub const DCAP_QUOTE_VERIFIER_ELF: &[u8] = include_bytes!("../artifacts/dcap-quote-verifier");
"##
            )
            .as_bytes(),
        )
        .unwrap();
}
