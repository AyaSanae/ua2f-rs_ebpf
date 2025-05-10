// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use core::mem;

use aya_ebpf::{
    bindings::{TC_ACT_REDIRECT, TC_ACT_SHOT},
    cty::c_long,
    helpers::r#gen::bpf_redirect,
    maps::{Array, RingBuf},
    programs::TcContext,
};
use aya_log_ebpf::error;
use network_types::{eth::EthHdr, ip::Ipv4Hdr};
use ua2f_rs_common::EbpfError;

pub const HTTP_METHOD_NAME_MIN_LENGTH: usize = 3;
pub const TTL_OFFSET: usize = EthHdr::LEN + mem::offset_of!(Ipv4Hdr, ttl);
pub const IP_CSUM_OFFSET: usize = EthHdr::LEN + mem::offset_of!(Ipv4Hdr, check);

const TCPHDR_DATA_OFFSET: usize = 12;
#[inline]
pub fn get_tcp_payload_info(ctx: &TcContext, ipv4hdr: Ipv4Hdr) -> Result<(usize, usize), c_long> {
    let ipv4hdr_len = (ipv4hdr.ihl() * 4) as usize;

    let tcphdr_data_offset_location = EthHdr::LEN + ipv4hdr_len + TCPHDR_DATA_OFFSET;
    let tcphdr_data_offset: u8 = ctx.load(tcphdr_data_offset_location)?;
    let tcphdr_len = ((tcphdr_data_offset >> 4) * 4) as usize;

    let tcp_payload_offset = EthHdr::LEN + ipv4hdr_len + tcphdr_len;
    let tcp_payload_size = match ipv4hdr
        .total_len()
        .checked_sub(ipv4hdr_len as u16 + tcphdr_len as u16)
    {
        Some(size) => size,
        None => return Err(-1),
    };

    Ok((tcp_payload_offset, tcp_payload_size as usize))
}

#[inline]
pub fn is_http_method(payload: &[u8; 4]) -> bool {
    matches!(
        payload,
        b"GET " | b"POST" | b"HEAD" | b"PUT " | b"DELE" | b"OPTI" | b"PATC" | b"CONN" | b"TRAC"
    )
}

#[inline]
pub fn redirect(ifindex: u32, err_ringbuf: &RingBuf) -> i32 {
    let act_code = unsafe { bpf_redirect(ifindex, 0) };
    if act_code == TC_ACT_SHOT as i64 {
        if let Some(mut entry) = err_ringbuf.reserve::<EbpfError>(0) {
            entry.write(EbpfError::RedirectErr);
            entry.submit(0);
        }
        return TC_ACT_SHOT;
    }

    TC_ACT_REDIRECT
}

pub fn set_ttl(
    ctx: &mut TcContext,
    ipv4hdr: Ipv4Hdr,
    user_ttl: &Array<u8>,
    err_ringbuf: &RingBuf,
) -> Result<(), i64> {
    let original_ttl = ipv4hdr.ttl;
    let user_ttl = match user_ttl.get(0) {
        Some(user_ttl) => *user_ttl,
        None => {
            if let Some(mut entry) = err_ringbuf.reserve::<EbpfError>(0) {
                entry.write(EbpfError::GetUserTTLErr);
                entry.submit(0);
            }
            114
        }
    };
    if original_ttl != user_ttl {
        ctx.l3_csum_replace(
            IP_CSUM_OFFSET,
            original_ttl.to_be() as u64,
            user_ttl.to_be() as u64,
            2,
        )
        .inspect_err(|_| {
            error!(ctx, "failed to update l3 csum!");
        })?;

        ctx.store(TTL_OFFSET, &(user_ttl.to_be()), 0)
            .inspect_err(|_| {
                error!(ctx, "Failed to modify ttl");
            })?;
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
pub fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
