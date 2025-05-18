// SPDX-FileCopyrightText: 2025 AyaSanae
//
// SPDX-License-Identifier: GPL-3.0-only

use std::{
    fs::{self},
    path::PathBuf,
};

use anyhow::{Context, anyhow};
use dirs::home_dir;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub attach_iface: String,
    pub filter_ip: Vec<String>,
    pub count_interval: u64,
    pub ttl: u8,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            attach_iface: "eno1".to_string(),
            filter_ip: vec![],
            ttl: 64u8,
            count_interval: 1800,
        }
    }
}

pub fn create_or_read_config() -> Result<Config, anyhow::Error> {
    let config_path = get_config_path()?;
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create config directory at {parent:?}"))?;
    }

    match fs::read_to_string(&config_path) {
        Ok(content) => {
            toml::from_str(&content).map_err(|e| anyhow!("Failed to parse config file:\n \t{e}"))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let config = Config::default();
            let toml = toml::to_string(&config)
                .map_err(|e| anyhow!("Failed to serialize default config: {e}"))?;
            fs::write(&config_path, toml)
                .with_context(|| format!("Failed to write config file at {config_path:?}"))?;
            Ok(config)
        }
        Err(e) => Err(anyhow!("Failed to read config file: {}", e)),
    }
}

fn get_config_path() -> Result<PathBuf, anyhow::Error> {
    home_dir()
        .map(|mut path| {
            path.push(".config");
            path.push("ua2f_rs");
            path.push("config.toml");
            path
        })
        .ok_or_else(|| anyhow!("HOME dir not found"))
}
