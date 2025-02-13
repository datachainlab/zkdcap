use risc0_binfmt::compute_image_id;
use risc0_build::{embed_method_metadata_with_options, DockerOptions, GuestOptions};
use std::{
    collections::HashMap,
    fs::File,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};

fn main() {
    // Builds can be made deterministic, and thereby reproducible, by using Docker to build the
    // guest.
    let use_docker = Some(DockerOptions {
        root_dir: Some("../../".into()),
    });

    // Generate Rust source files for the methods crate.
    let guests = embed_method_metadata_with_options(HashMap::from([(
        "guests",
        GuestOptions {
            features: Vec::new(),
            use_docker,
        },
    )]));

    if guests.len() != 1 {
        panic!("expected exactly one guest, found {}", guests.len());
    };
    let elf_path = get_correct_elf_path(&PathBuf::from_str(&guests[0].path).unwrap());
    let elf_value = std::fs::read(&elf_path).unwrap();
    let image_id = compute_image_id(&elf_value).unwrap().as_words().to_vec();
    let mut elf_file = File::create("./artifacts/dcap-quote-verifier").unwrap();
    elf_file.write_all(&elf_value).unwrap();
    let mut methods_file = File::create("./src/methods.rs").unwrap();
    methods_file
        .write_all(
            format!(
                r##"
pub const DCAP_QUOTE_VERIFIER_ID: [u32; 8] = {image_id:?};
pub const DCAP_QUOTE_VERIFIER_ELF: &[u8] = include_bytes!("../artifacts/dcap-quote-verifier");
"##
            )
            .as_bytes(),
        )
        .unwrap();
}

fn get_correct_elf_path(elf_path: &Path) -> String {
    elf_path
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("target/riscv-guest/riscv32im-risc0-zkvm-elf/docker/guests/dcap_quote_verifier")
        .as_path()
        .to_str()
        .unwrap()
        .to_string()
}
