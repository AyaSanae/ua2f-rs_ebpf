// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashSet, net::Ipv4Addr, os::unix::io::AsRawFd, panic, process::Command,
    time::Duration,
};

use anyhow::{Context, anyhow};
use aya::maps::Array;
use aya_log::EbpfLogger;
use clap::Parser;
use ipnet::Ipv4Net;
use libc::atexit;
use log::{info, warn};
use tokio::{signal, time::interval};
use ua2f_rs::{
    RX_VETH, TX_VETH, af_xdp::af_xdp_init, config::create_or_read_config, ebpf::*,
    get_count_packets, modify::process_packet,
};
use ua2f_rs_common::EbpfError;

#[derive(Parser)]
#[command(name = "ua2f-rs")]
#[command(author, version, about)]
struct Opt {
    #[clap(short, long)]
    iface: Option<String>,
    #[clap(short, long)]
    config: Option<String>,
    #[clap(long)]
    ttl: Option<u8>,
    #[clap(long)]
    verbose: Option<bool>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    if !unsafe { libc::getuid() == 0 || libc::geteuid() == 0 } {
        anyhow::bail!("This program must be run as root");
    }
    if opt.verbose.is_some() {
        unsafe { std::env::set_var("RUST_LOG", "info") };
    }
    env_logger::init();

    let file_config = create_or_read_config()?;

    let attach_iface = match &opt.iface {
        Some(iface) => iface.clone(),
        None => file_config.attach_iface.clone(),
    };

    let ttl = match &opt.ttl {
        Some(user_ttl) => *user_ttl,
        None => file_config.ttl,
    };

    let attach_ifindex = get_ifindex(&attach_iface)?;

    let mut filter_ip = HashSet::new();
    let mut filter_ip_cidr = HashSet::new();
    for ip in &file_config.filter_ip {
        if ip.contains("/") {
            let net: Ipv4Net = ip.parse().map_err(|e| anyhow!("{}: {}", e, ip))?;
            filter_ip_cidr.insert(net);
        } else {
            let ip: Ipv4Addr = ip.parse().map_err(|e| anyhow!("{}: {}", e, ip))?;
            filter_ip.insert(ip);
        }
    }

    if !file_config.filter_ip.is_empty() {
        info!("filter_ip: {:?}", file_config.filter_ip);
    }

    unsafe {
        atexit(del_veth);
    }
    panic::set_hook(Box::new(|_| unsafe {
        atexit(del_veth);
    }));

    let ua2f_veth_tx_ifindex = create_veth()?;

    let af_xdp = af_xdp_init(RX_VETH)?;
    let xsk_fd = (*af_xdp.rx.fd()).as_raw_fd();

    let (mut tc_bpf, mut xdp_bpf) =
        ebpf_init(xsk_fd, ua2f_veth_tx_ifindex, filter_ip, filter_ip_cidr, ttl)?;
    if let Err(e) = EbpfLogger::init(&mut tc_bpf) {
        warn!("failed to initialize TC eBPF logger: {}", e);
    }

    if let Err(e) = EbpfLogger::init(&mut xdp_bpf) {
        warn!("failed to initialize XDP eBPF logger: {}", e);
    }

    ebpf_up(&mut xdp_bpf, &mut tc_bpf, &attach_iface)?;

    println!("Initialization Complete! Running...");

    let mut process_packet_handle =
        tokio::spawn(async move { process_packet(attach_ifindex, af_xdp) });
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(1800));
        let xdp_count: Array<_, u64> =
            Array::try_from(xdp_bpf.map_mut("HTTP_PACKET_COUNT").unwrap()).unwrap();

        loop {
            interval.tick().await;
            println!(
                "Count of http packets: {} And Count of modified packets with User-Agent: {}",
                xdp_count.get(&0, 0).unwrap(),
                get_count_packets()
            );
        }
    });

    tokio::select! {
        res = &mut process_packet_handle  => {
            match res{
                Ok(inner_result) => {
                inner_result.map_err(|e| anyhow!("Packet processing error: {}", e))
            },
                Err(e) => Err(anyhow!("failed to precess packet: {}",e)),
            }

    },
        res = catching_bpf_error("ERR_RINGBUF", &tc_bpf) => {
            match res {
                Ok(ebpf_err) => match ebpf_err {
                    EbpfError::GetIfIndexErr => Err(anyhow!("[TC ebpf]: Unable to get {} ifindex!",TX_VETH)),
                    EbpfError::RedirectErr => Err(anyhow!("[TC ebpf]: packet redirect Error!")),
                    EbpfError::GetUserTTLErr => Err(anyhow!("[TC ebpf]: Failed to get user ttl !")),
                },
                Err(e) => Err(e),
            }
        },
        _ = signal::ctrl_c() => {
            info!("Received Ctrl+C, Exiting...");
             std::process::exit(1);
        },
    }
}

fn create_veth() -> Result<u32, anyhow::Error> {
    Command::new("ip")
        .args([
            "link", "add", TX_VETH, "type", "veth", "peer", "name", RX_VETH,
        ])
        .status()
        .context("Failed to create veth")?;
    Command::new("ip")
        .args(["link", "set", "dev", TX_VETH, "up"])
        .status()
        .context(format! {"Failed to set up {}",TX_VETH})?;

    Command::new("ip")
        .args(["link", "set", "dev", RX_VETH, "up"])
        .status()
        .context(format! {"Failed to set up {}",RX_VETH})?;

    get_ifindex(TX_VETH)
}

extern "C" fn del_veth() {
    let _ = Command::new("ip")
        .args(["link", "delete", RX_VETH])
        .status();
}
