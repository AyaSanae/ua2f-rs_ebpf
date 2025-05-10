// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

#![no_std]

pub const USER_AGENT_SIZE: usize = 12; //"User-Agent: ".len()

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub enum EbpfError {
    RedirectErr,
    GetIfIndexErr,
    GetUserTTLErr,
}

#[repr(C, packed)]
pub struct MetaData {
    pub mark: u32,
    pub ipv4hdr_len: u8,
    pub tcp_payload_offset: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
