use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use anyhow::{ensure, Context};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;

use super::CloudflareConfig;

pub(super) const QUOTA_WINDOW_SECS: u64 = 12 * 60 * 60;
const MAX_MODIFICATIONS: usize = 900_000;
const MAX_WRITE_REQUESTS: usize = 27_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Mutation {
    Add(Vec<IpNet>),
    Delete(Vec<IpNet>),
}

impl Mutation {
    pub fn len(&self) -> usize {
        match self {
            Self::Add(nets) | Self::Delete(nets) => nets.len(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Pending {
    pub operation_id: Option<String>,
    pub submitted_at: u64,
    pub mutation: Mutation,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Reservation {
    pub at: u64,
    pub modifications: usize,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct LocalState {
    version: u8,
    account_id: String,
    list_id: String,
    // New items have no ID until the next read. Refresh only when their ID is needed.
    pub items: BTreeMap<IpNet, Option<String>>,
    pub pending: Option<Pending>,
    pub cooldown_until: u64,
    pub reservations: VecDeque<Reservation>,
}

impl LocalState {
    fn new(config: &CloudflareConfig) -> Self {
        Self {
            version: 1,
            account_id: config.account_id.clone(),
            list_id: config.list_id.clone(),
            items: BTreeMap::new(),
            pending: None,
            cooldown_until: 0,
            reservations: VecDeque::new(),
        }
    }

    /// Reserve before sending, including uncertain/failed attempts, to avoid undercounting.
    pub fn reserve(&mut self, count: usize, now: u64) -> bool {
        self.reservations
            .retain(|entry| entry.at.saturating_add(QUOTA_WINDOW_SECS) > now);
        let modifications = self
            .reservations
            .iter()
            .map(|entry| entry.modifications)
            .sum::<usize>();
        if self.reservations.len() >= MAX_WRITE_REQUESTS
            || modifications.saturating_add(count) > MAX_MODIFICATIONS
        {
            self.cooldown_until = self
                .reservations
                .front()
                .map(|entry| entry.at.saturating_add(QUOTA_WINDOW_SECS))
                .unwrap_or(now + QUOTA_WINDOW_SECS);
            return false;
        }
        self.reservations.push_back(Reservation {
            at: now,
            modifications: count,
        });
        true
    }

    pub fn confirm(&mut self, mutation: &Mutation) {
        match mutation {
            Mutation::Add(nets) => {
                for net in nets {
                    self.items.entry(*net).or_insert(None);
                }
            }
            Mutation::Delete(nets) => {
                for net in nets {
                    self.items.remove(net);
                }
            }
        }
    }
}

pub(super) struct StateStore {
    path: PathBuf,
    // OS lock is released on crash; a stale lock file never prevents a restart.
    _lock: File,
}

fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

impl StateStore {
    pub async fn open(config: &CloudflareConfig) -> anyhow::Result<(Self, LocalState)> {
        tokio::fs::create_dir_all(parent(&config.state_path))
            .await
            .context("Cannot create Cloudflare state directory")?;
        let mut lock_path = config.state_path.as_os_str().to_owned();
        lock_path.push(".lock");
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(PathBuf::from(lock_path))
            .context("Cannot open Cloudflare state lock")?;
        lock.try_lock()
            .context("Cloudflare state is already locked by another bouncer")?;
        let state = match tokio::fs::read(&config.state_path).await {
            Ok(bytes) => serde_json::from_slice::<LocalState>(&bytes).context(
                "Cannot parse Cloudflare state file; restore a valid backup before restarting",
            )?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => LocalState::new(config),
            Err(error) => return Err(error).context("Cannot read Cloudflare state file"),
        };
        ensure!(state.version == 1 && state.account_id == config.account_id && state.list_id == config.list_id,
            "Cloudflare state belongs to a different account/list or version; use a separate CLOUDFLARE_STATE_PATH");
        let store = Self {
            path: config.state_path.clone(),
            _lock: lock,
        };
        store.save(&state).await?;
        Ok((store, state))
    }

    pub async fn save(&self, state: &LocalState) -> anyhow::Result<()> {
        let mut temp_path = self.path.as_os_str().to_owned();
        temp_path.push(".tmp");
        let temp_path = PathBuf::from(temp_path);
        let mut options = tokio::fs::OpenOptions::new();
        options.create(true).truncate(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&temp_path)
            .await
            .context("Cannot write Cloudflare state file")?;
        file.write_all(&serde_json::to_vec(state)?).await?;
        file.sync_all().await?;
        tokio::fs::rename(&temp_path, &self.path).await?;
        // Make the rename durable as well as the contents.
        #[cfg(unix)]
        tokio::fs::File::open(parent(&self.path))
            .await?
            .sync_all()
            .await?;
        Ok(())
    }
}
