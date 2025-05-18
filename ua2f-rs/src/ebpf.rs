// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    collections::HashSet,
    net::Ipv4Addr,
    os::{fd::RawFd, unix::io::AsRawFd},
};

use anyhow::{Context, anyhow};
use aya::{
    Ebpf,
    maps::{Array, HashMap, LpmTrie, RingBuf, XskMap, lpm_trie::Key},
    programs::{SchedClassifier, TcAttachType, Xdp, XdpFlags, tc},
};
use ipnet::Ipv4Net;
use log::info;
use pnet::datalink;
use tokio::io::unix::AsyncFd;
use ua2f_rs_common::{EbpfError, RX_VETH};

pub fn ebpf_init(
    xsk_fd: RawFd,
    tc_redirect_ifindex: u32,
    filter_ip: HashSet<Ipv4Addr>,
    filter_ip_cidr: HashSet<Ipv4Net>,
    ttl: u8,
) -> Result<(Ebpf, Ebpf), anyhow::Error> {
    let mut tc_bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/tc_ebpf"
    )))?;

    info!("TC: redirect ifindex:{tc_redirect_ifindex} pass to TC ebpf program");
    let mut ifindex_list: Array<_, u32> = Array::try_from(tc_bpf.map_mut("IFINDEX").unwrap())?;
    ifindex_list.set(0, tc_redirect_ifindex, 0)?;

    info!("TC: pass TTL:{ttl} to TC ebpf program");
    let mut user_ttl: Array<_, u8> = Array::try_from(tc_bpf.map_mut("USER_TTL").unwrap())?;
    user_ttl.set(0, ttl, 0)?;

    info!("TC: pass filter_list to TC ebpf program");
    let mut filter_map: HashMap<_, u32, u32> =
        HashMap::try_from(tc_bpf.map_mut("FILTER_LIST").unwrap())?;
    for ip in filter_ip {
        let ip: u32 = ip.to_bits();
        filter_map.insert(ip.to_be(), 0, 0)?;
    }

    let mut trie = LpmTrie::try_from(tc_bpf.map_mut("FILTER_LIST_CIDR").unwrap())?;
    for ip_cidr in filter_ip_cidr {
        let key = Key::new(
            ip_cidr.prefix_len() as u32,
            u32::from(ip_cidr.addr()).to_be(),
        );
        trie.insert(&key, 1, 0)?;
    }

    let mut xdp_bpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/xdp_ebpf"
    )))?;

    let mut xsk_map = XskMap::try_from(xdp_bpf.map_mut("XSKS_MAP").unwrap())?;
    xsk_map.set(0, xsk_fd, 0)?;

    let mut xdp_count: Array<_, u64> =
        Array::try_from(xdp_bpf.map_mut("HTTP_PACKET_COUNT").unwrap())?;
    xdp_count.set(0, 0, 0)?;

    Ok((tc_bpf, xdp_bpf))
}

pub fn ebpf_up(xdp: &mut Ebpf, tc: &mut Ebpf, attach_iface: &str) -> Result<(), anyhow::Error> {
    let _ = tc::qdisc_add_clsact(attach_iface);
    let program: &mut SchedClassifier = tc.program_mut("packet_filter").unwrap().try_into()?;
    program.load()?;
    info!("TC: Attach to {attach_iface}");
    program.attach(attach_iface, TcAttachType::Egress)?;
    info!("TC: start!");

    info!("XDP: Load");
    let program: &mut Xdp = xdp.program_mut("ua2f_veth_rx_filter").unwrap().try_into()?;
    program.load()?;
    info!("XDP: Start");
    program.attach(RX_VETH, XdpFlags::DRV_MODE)
    .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    Ok(())
}

pub fn get_ifindex(ifname: &str) -> Result<u32, anyhow::Error> {
    Ok(datalink::interfaces()
        .into_iter()
        .find(|iface| iface.name == ifname)
        .ok_or(anyhow!("Unable find {}", ifname))?
        .index)
}

pub async fn catching_bpf_error(ring_buf: &str, bpf: Ebpf) -> anyhow::Result<()> {
    let mut ring_buf = RingBuf::try_from(bpf.map(ring_buf).unwrap()).unwrap();
    let async_fd = AsyncFd::new(ring_buf.as_raw_fd())?;
    let _ = async_fd.readable().await?;

    loop {
        if let Some(e) = ring_buf.next() {
            if e.len() == std::mem::size_of::<EbpfError>() {
                let error = unsafe { std::ptr::read(e.as_ptr() as *const EbpfError) };
                return Err(error.into());
            } else {
                return Err(anyhow::anyhow!("Invalid EbpfError size in ring buffer"));
            }
        }
    }
}
