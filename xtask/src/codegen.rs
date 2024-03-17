use aya_tool::generate::InputFile;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
  let dir = PathBuf::from("xdp-udp-echors/src");
  let names: Vec<&str> = vec!["ethhdr", "ipv4hdr", "udphdr"];
  let bindings = aya_tool::generate(
    InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
    &names, &[],
  )?;
  let mut out = File::create(dir.join("bindings.rs"))?;
  write!(out, "{}", bindings)?;
  Ok(())
}
