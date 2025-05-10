// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use core::mem;

use aya_ebpf::programs::XdpContext;

#[inline(always)]
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}
