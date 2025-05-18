// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only
#![no_std]
#![no_main]
mod tc_lib;

use aya_ebpf::{
    bindings::TC_ACT_OK,
    helpers::r#gen::bpf_skb_change_head,
    macros::{classifier, map},
    maps::{Array, HashMap, LpmTrie, RingBuf, lpm_trie::Key},
    programs::TcContext,
};
use aya_log_ebpf::error;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
};
use tc_lib::{
    HTTP_METHOD_NAME_MIN_LENGTH, get_tcp_payload_info, is_http_method, redirect, set_ttl,
};
use ua2f_rs_common::{EbpfError, MetaData, USER_AGENT_SIZE};
#[map]
static FILTER_LIST: HashMap<u32, u32> = HashMap::with_max_entries(514, 0);
#[map]
static FILTER_LIST_CIDR: LpmTrie<u32, u32> = LpmTrie::with_max_entries(514, 0);
#[map]
static IFINDEX: Array<u32> = Array::with_max_entries(1, 0);
#[map]
static USER_TTL: Array<u8> = Array::with_max_entries(1, 0);
#[map]
static ERR_RINGBUF: RingBuf = RingBuf::with_byte_size(8, 0);

fn filter_ip(address: u32) -> bool {
    let key = Key::new(32, address);
    unsafe { FILTER_LIST_CIDR.get(&key).is_some() || FILTER_LIST.get(&address).is_some() }
}

#[classifier]
pub fn packet_filter(ctx: TcContext) -> i32 {
    let ifindex = match IFINDEX.get(0) {
        Some(ifindex) => *ifindex,
        None => {
            if let Some(mut entry) = ERR_RINGBUF.reserve::<EbpfError>(0) {
                entry.write(EbpfError::GetIfIndexErr);
                entry.submit(0);
            }
            114
        }
    };

    unsafe {
        let mark = (*ctx.skb.skb).mark;
        if mark == 0x114514 {
            return TC_ACT_OK;
        }
    }

    match try_filter(ctx, ifindex) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline]
fn try_filter(ctx: TcContext, ifindex: u32) -> Result<i32, ()> {
    let mut ctx = ctx;

    let ethhdr: EthHdr = ctx.load(0).map_err(|_| ())?;

    match ethhdr.ether_type {
        EtherType::Ipv4 => {}
        _ => return Err(()),
    }

    let ipv4hdr: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let destination = ipv4hdr.dst_addr().to_bits().to_be();
    if filter_ip(destination) {
        return Err(());
    };

    set_ttl(&mut ctx, ipv4hdr, &USER_TTL, &ERR_RINGBUF).map_err(|_| ())?;

    match ipv4hdr.proto {
        IpProto::Tcp => {}
        _ => return Ok(TC_ACT_OK),
    }

    let (tcp_payload_offset, tcp_payload_size) =
        get_tcp_payload_info(&ctx, ipv4hdr).map_err(|_| ())?;

    if tcp_payload_size < HTTP_METHOD_NAME_MIN_LENGTH + USER_AGENT_SIZE {
        return Err(());
    }

    let tcp_payload: [u8; 4] = ctx.load(tcp_payload_offset).map_err(|_| {})?;
    if !is_http_method(&tcp_payload) {
        return Err(());
    }

    let res =
        unsafe { bpf_skb_change_head(ctx.skb.skb, core::mem::size_of::<MetaData>() as u32, 0) };
    if res < 0 {
        error!(&ctx, "failed to adjust room!");
        return Err(());
    }

    let meta_data = MetaData {
        mark: 0x114514,
        ipv4hdr_len: (ipv4hdr.ihl() * 4),
        tcp_payload_offset: tcp_payload_offset as u16,
    };

    ctx.store(0, &meta_data, 0).map_err(|_| {
        error!(&ctx, "failed to adjust room!");
    })?;

    Ok(redirect(ifindex, &ERR_RINGBUF))
}
