// reference: https://github.com/yukinakanaka/aya-lab/blob/main/tail-calls/xtask/src/build.rs

use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::build_ebpf::{build_ebpf, Architecture, Options as BuiltOptions};

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    #[clap(long)]
    pub release: bool,
}

fn build_project(opts: &Options) -> Result<(), anyhow::Error> {
    let mut args = vec!["build"];
    if opts.release {
        args.push("--release");
    }
    let status = Command::new("cargo")
        .args(&args)
        .status()
        .expect("failed to build userspace");

    assert!(status.success());
    Ok(())
}

pub fn build(opts: Options) -> Result<(), anyhow::Error> {
    build_ebpf(BuiltOptions {
        target: opts.bpf_target,
        release: opts.release,
    })
    .context("Error while building eBPF program")?;
    build_project(&opts).context("Error while building userspace application")?;
    Ok(())
}
