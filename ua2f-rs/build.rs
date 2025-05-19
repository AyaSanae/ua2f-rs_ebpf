// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use anyhow::{Context as _, anyhow};
use aya_build::cargo_metadata;

fn main() -> anyhow::Result<()> {
    #[cfg(target_arch = "aarch64")]
    {
        // libxdp and libbpf are required for linking.
        // You should set `rustc-link-search` to specify the search path for these libraries.
        println!("cargo:rustc-link-search=/usr/local/lib");
        println!("cargo:rustc-link-lib=xdp");
        println!("cargo:rustc-link-lib=bpf");
        println!("cargo:rustc-link-lib=elf");
        println!("cargo:rustc-link-lib=z");
    }

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "ua2f-rs-ebpf")
        .ok_or_else(|| anyhow!("ua2f-rs-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package])
}
