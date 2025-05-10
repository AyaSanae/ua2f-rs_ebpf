// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::ffi::CString;

use xsk_rs::{
    FillQueue, FrameDesc, RxQueue,
    config::{BindFlags, Interface, LibxdpFlags, QueueSize, SocketConfig, UmemConfig, XdpFlags},
    socket::Socket,
    umem::Umem,
};

pub struct AfXdp {
    pub rx: RxQueue,
    pub fill: FillQueue,
    pub umem: Umem,
    pub descs: Vec<FrameDesc>,
}

pub fn af_xdp_init(iface: &str) -> Result<AfXdp, anyhow::Error> {
    let umem_config = UmemConfig::default();
    let (umem, descs) = Umem::new(umem_config, 1024.try_into()?, false)?;

    let iface = Interface::new(CString::new(iface).unwrap());
    let queue_id = 0;

    let socket_config = SocketConfig::builder()
        .libxdp_flags(LibxdpFlags::XSK_LIBXDP_FLAGS_INHIBIT_PROG_LOAD)
        .rx_queue_size(QueueSize::new(1024).unwrap())
        .tx_queue_size(QueueSize::new(1024).unwrap())
        .xdp_flags(XdpFlags::empty())
        .bind_flags(BindFlags::empty())
        .build();

    let (_, rx, fq_and_cq) = unsafe { Socket::new(socket_config, &umem, &iface, queue_id)? };

    let (fill, _) = fq_and_cq.expect("FILL and COMPLETION queues required");
    Ok(AfXdp {
        rx,
        fill,
        umem,
        descs,
    })
}
