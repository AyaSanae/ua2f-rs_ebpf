// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    mem,
    ops::Add,
    os::fd::{AsFd, AsRawFd},
    ptr,
};

use anyhow::{Context, anyhow};
use libc::{AF_PACKET, ETH_P_IP, sockaddr, sockaddr_ll};
use network_types::eth::EthHdr;
use pnet::packet::{
    ipv4::Ipv4Packet,
    tcp::{self, MutableTcpPacket},
};
use socket2::{Domain, Socket, Type};
use ua2f_rs_common::{MetaData, USER_AGENT_SIZE};

use crate::{add_modify_count, af_xdp::AfXdp};

pub fn process_packet(attach_iface_ifindex: u32, af_xdp: AfXdp) -> Result<(), anyhow::Error> {
    let mut af_xdp = af_xdp;
    let (socket, addr) = socket_init(attach_iface_ifindex)?;

    unsafe {
        af_xdp.fill.produce(&af_xdp.descs);
    }

    loop {
        let pkts_recvd = unsafe { af_xdp.rx.poll_and_consume(&mut af_xdp.descs, 100)? };
        for recv_desc in af_xdp.descs.iter_mut().take(pkts_recvd) {
            let mut data = unsafe { af_xdp.umem.data_mut(recv_desc) };
            let data = data.contents_mut();
            let data = parse_packet_and_modify_ua(data)?;
            send_packet(&socket, &addr, data)?;
        }

        unsafe { af_xdp.fill.produce(&af_xdp.descs) };
    }
}

fn parse_packet_and_modify_ua(data: &mut [u8]) -> Result<&mut [u8], anyhow::Error> {
    let (meta_data, data) = match parse_packet_info(data) {
        Some(meta_and_packet_data) => meta_and_packet_data,
        None => {
            anyhow::bail!("Illegal packet size");
        }
    };

    if modify_ua(&mut data[meta_data.tcp_payload_offset as usize..]).is_err() {
        return Ok(data);
    }

    let (_, ip_tcp_slice) = data.split_at_mut(EthHdr::LEN);
    let (ipv4_slice, tcp_slice) = ip_tcp_slice.split_at_mut(meta_data.ipv4hdr_len as usize);
    let ipv4_packet =
        Ipv4Packet::new(ipv4_slice).context("Failed to create mutable IPV4 packet")?;
    let mut tcp_packet =
        MutableTcpPacket::new(tcp_slice).context("Failed to create mutable TCP packet")?;

    tcp_packet.set_checksum(0);
    let checksum = tcp::ipv4_checksum(
        &tcp_packet.to_immutable(),
        &ipv4_packet.get_source(),
        &ipv4_packet.get_destination(),
    );
    tcp_packet.set_checksum(checksum);

    add_modify_count();
    Ok(data)
}

fn parse_packet_info(data: &mut [u8]) -> Option<(MetaData, &mut [u8])> {
    if data.len() < std::mem::size_of::<MetaData>() {
        return None;
    }

    let (meta_data_bytes, remaining_data) = data.split_at_mut(std::mem::size_of::<MetaData>());
    let meta_data = unsafe { ptr::read(meta_data_bytes.as_ptr() as *const MetaData) };

    Some((meta_data, remaining_data))
}

fn modify_ua(tcp_payload: &mut [u8]) -> Result<(), anyhow::Error> {
    let ua_pos = tcp_payload
        .windows(USER_AGENT_SIZE)
        .position(|window| window.eq_ignore_ascii_case(b"User-Agent: "))
        .ok_or(anyhow!("Unable to find User-Agent"))?
        .add(USER_AGENT_SIZE);

    let ua_end = tcp_payload[ua_pos..]
        .iter()
        .position(|&b| b == b'\r')
        .ok_or(anyhow!("Unable to find Tail of User-Agent"))?;

    tcp_payload[ua_pos..ua_pos + ua_end].fill(b'F');

    Ok(())
}

fn send_packet(socket: &Socket, addr: &sockaddr_ll, packet: &[u8]) -> Result<(), anyhow::Error> {
    let sockaddr_ptr = addr as *const _ as *const sockaddr;
    let sockaddr_len = mem::size_of_val(addr) as u32;

    let sent = unsafe {
        libc::sendto(
            socket.as_fd().as_raw_fd(),
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            sockaddr_ptr,
            sockaddr_len,
        )
    };
    if sent < 0 {
        anyhow::bail!("Failed to send packet: {}", std::io::Error::last_os_error());
    }

    Ok(())
}

fn socket_init(attach_iface_ifindex: u32) -> Result<(Socket, sockaddr_ll), anyhow::Error> {
    let socket = Socket::new(Domain::PACKET, Type::RAW, None)?;
    socket.set_mark(0x114514)?;

    let mut addr: sockaddr_ll = unsafe { mem::zeroed() };
    addr.sll_family = AF_PACKET as u16;
    addr.sll_protocol = (ETH_P_IP as u16).to_be();
    addr.sll_ifindex = attach_iface_ifindex as i32;
    addr.sll_halen = 0;
    addr.sll_addr = [0u8; 8];

    Ok((socket, addr))
}
