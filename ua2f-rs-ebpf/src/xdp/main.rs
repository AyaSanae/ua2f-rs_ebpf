// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only
#![no_std]
#![no_main]

mod xdp_lib;

use aya_ebpf::{
    bindings::xdp_action::{self, XDP_DROP, XDP_REDIRECT},
    macros::{map, xdp},
    maps::{Array, XskMap},
    programs::XdpContext,
};
use aya_log_ebpf::error;
use ua2f_rs_common::MetaData;
use xdp_lib::ptr_at;

#[map]
static XSKS_MAP: XskMap = XskMap::with_max_entries(1, 0);
#[map]
static HTTP_PACKET_COUNT: Array<u64> = Array::with_max_entries(1, 0);

#[xdp]
pub fn ua2f_veth_rx_filter(ctx: XdpContext) -> u32 {
    match unsafe { try_filter(ctx) } {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_DROP,
    }
}

unsafe fn try_filter(ctx: XdpContext) -> Result<u32, ()> {
    let meta_data: *const MetaData = ptr_at(&ctx, 0).map_err(|_| {
        error!(&ctx, "Failed to read meta_info");
    })?;
    let mark = unsafe { (*meta_data).mark };
    if mark != 0x114514 {
        // info!(&ctx, "XDP: DROP IT");
        return Err(());
    }

    let queue_id = unsafe { (*ctx.ctx).rx_queue_index };
    let res = XSKS_MAP.redirect(queue_id, 0).unwrap_or(XDP_DROP);
    if res == XDP_REDIRECT {
        unsafe {
            if let Some(count) = HTTP_PACKET_COUNT.get_ptr_mut(0) {
                *count += 1;
            }
        }
        return Ok(res);
    }

    error!(&ctx, "xdp: failed to redirect! error code:{}", res);
    Err(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
