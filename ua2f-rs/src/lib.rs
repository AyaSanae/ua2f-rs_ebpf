// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::sync::atomic::{AtomicU64, Ordering};

pub mod af_xdp;
pub mod config;
pub mod ebpf;
pub mod modify;

static MODIFY_COUNT: AtomicU64 = AtomicU64::new(0);

pub fn add_modify_count() {
    MODIFY_COUNT.fetch_add(1, Ordering::Relaxed);
}

pub fn get_count_packets() -> u64 {
    MODIFY_COUNT.load(Ordering::Relaxed)
}
