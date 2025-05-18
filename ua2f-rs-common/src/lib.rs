// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

#![no_std]

use core::{
    error::Error,
    fmt::{self, Display},
};

pub const USER_AGENT_SIZE: usize = 12; //"User-Agent: ".len()

pub const RX_VETH: &str = "ua2f_veth_rx";
pub const TX_VETH: &str = "ua2f_veth_tx";

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum EbpfError {
    RedirectErr,
    GetIfIndexErr,
    GetUserTTLErr,
}

impl Display for EbpfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EbpfError::RedirectErr => write!(f, "Failed to redirect packet to {RX_VETH}"),
            EbpfError::GetIfIndexErr => write!(f, "Failed to get attached ifindex!"),
            EbpfError::GetUserTTLErr => write!(f, "Failed to get user TTL value"),
        }
    }
}

impl Error for EbpfError {}

#[repr(C, packed)]
pub struct MetaData {
    pub mark: u32,
    pub ipv4hdr_len: u8,
    pub tcp_payload_offset: u16,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
