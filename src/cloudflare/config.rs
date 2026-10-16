use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{ensure, Context};
use clap::Args;

#[derive(Args, Clone)]
pub struct CloudflareArgs {
    /// Enable direct Cloudflare custom IP list synchronization.
    #[arg(long, env = "CLOUDFLARE_ENABLED", default_value = "false")]
    pub cloudflare_enabled: bool,
    #[arg(long, env = "CLOUDFLARE_API_TOKEN", hide_env_values = true)]
    pub cloudflare_api_token: Option<String>,
    #[arg(long, env = "CLOUDFLARE_ACCOUNT_ID")]
    pub cloudflare_account_id: Option<String>,
    /// ID of an existing, dedicated custom IP list managed entirely by this bouncer.
    #[arg(long, env = "CLOUDFLARE_LIST_ID")]
    pub cloudflare_list_id: Option<String>,
    /// Writable persistent file; also used to prevent concurrent writers.
    #[arg(long, env = "CLOUDFLARE_STATE_PATH")]
    pub cloudflare_state_path: Option<PathBuf>,
    #[arg(long, env = "CLOUDFLARE_SYNC_INTERVAL_SECS", default_value = "60")]
    pub cloudflare_sync_interval_secs: u64,
    #[arg(
        long,
        env = "CLOUDFLARE_RECONCILE_INTERVAL_SECS",
        default_value = "3600"
    )]
    pub cloudflare_reconcile_interval_secs: u64,
    #[arg(long, env = "CLOUDFLARE_MAX_ITEMS", default_value = "10000")]
    pub cloudflare_max_items: usize,
}

impl Default for CloudflareArgs {
    fn default() -> Self {
        Self {
            cloudflare_enabled: false,
            cloudflare_api_token: None,
            cloudflare_account_id: None,
            cloudflare_list_id: None,
            cloudflare_state_path: None,
            cloudflare_sync_interval_secs: 60,
            cloudflare_reconcile_interval_secs: 3600,
            cloudflare_max_items: 10_000,
        }
    }
}

// Cli derives Debug. Never expose the token through that representation.
impl fmt::Debug for CloudflareArgs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CloudflareArgs")
            .field("enabled", &self.cloudflare_enabled)
            .finish_non_exhaustive()
    }
}

pub struct CloudflareConfig {
    pub(crate) api_token: String,
    pub(crate) account_id: String,
    pub(crate) list_id: String,
    pub(crate) state_path: PathBuf,
    pub(crate) sync_interval: Duration,
    pub(crate) reconcile_interval: Duration,
    pub(crate) max_items: usize,
}

impl CloudflareArgs {
    pub fn config(&self) -> anyhow::Result<Option<CloudflareConfig>> {
        if !self.cloudflare_enabled {
            return Ok(None);
        }
        let required = |value: &Option<String>, name| {
            value
                .as_ref()
                .filter(|value| !value.trim().is_empty())
                .cloned()
                .with_context(|| format!("{name} is required when CLOUDFLARE_ENABLED=true"))
        };
        let api_token = required(&self.cloudflare_api_token, "CLOUDFLARE_API_TOKEN")?;
        let account_id = required(&self.cloudflare_account_id, "CLOUDFLARE_ACCOUNT_ID")?;
        let list_id = required(&self.cloudflare_list_id, "CLOUDFLARE_LIST_ID")?;
        for (name, value) in [
            ("CLOUDFLARE_ACCOUNT_ID", &account_id),
            ("CLOUDFLARE_LIST_ID", &list_id),
        ] {
            ensure!(
                value.len() == 32 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
                "{name} must be a 32-character hexadecimal ID"
            );
        }
        let state_path = self.cloudflare_state_path.clone()
            .filter(|path| !path.as_os_str().is_empty() && path.file_name().is_some())
            .context("CLOUDFLARE_STATE_PATH must name a writable persistent file when CLOUDFLARE_ENABLED=true")?;
        ensure!(
            self.cloudflare_sync_interval_secs > 0,
            "CLOUDFLARE_SYNC_INTERVAL_SECS must be positive"
        );
        ensure!(
            self.cloudflare_reconcile_interval_secs > 0,
            "CLOUDFLARE_RECONCILE_INTERVAL_SECS must be positive"
        );
        ensure!(
            (1..=10_000).contains(&self.cloudflare_max_items),
            "CLOUDFLARE_MAX_ITEMS must be between 1 and 10000"
        );
        Ok(Some(CloudflareConfig {
            api_token,
            account_id,
            list_id,
            state_path,
            sync_interval: Duration::from_secs(self.cloudflare_sync_interval_secs),
            reconcile_interval: Duration::from_secs(self.cloudflare_reconcile_interval_secs),
            max_items: self.cloudflare_max_items,
        }))
    }
}
