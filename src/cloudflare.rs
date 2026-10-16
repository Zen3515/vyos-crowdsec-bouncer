//! Optional, local-only Cloudflare custom IP list synchronization.
//! No Workers, Pages, KV, rule provisioning, or secondary LAPI stream.
mod client;
mod config;
mod state;

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, ensure, Context};
use ipnet::IpNet;
use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;
use tokio::time::Instant;
use tracing::{error, info, warn};

use crate::blacklist::IpRangeMixed;
use crate::crowdsec_lapi::types::DecisionsIpRange;
use client::{now, ApiFailure, CloudflareClient};
use state::{LocalState, Mutation, Pending, StateStore};

pub use config::{CloudflareArgs, CloudflareConfig};

type Snapshot = Option<Arc<IpRangeMixed>>;

/// Latest complete desired state. A slow Cloudflare API never blocks the primary bouncer.
#[derive(Clone)]
pub struct DecisionPublisher(watch::Sender<Snapshot>);

impl DecisionPublisher {
    pub fn channel() -> (Self, watch::Receiver<Snapshot>) {
        let (sender, receiver) = watch::channel(None);
        (Self(sender), receiver)
    }

    pub fn publish_full(&self, blacklist: IpRangeMixed) {
        self.0.send_replace(Some(Arc::new(blacklist)));
    }

    pub fn publish_incremental(&self, decisions: &DecisionsIpRange) {
        self.0.send_modify(|snapshot| {
            if let Some(previous) = snapshot {
                *snapshot = Some(Arc::new(
                    previous.exclude(&decisions.deleted).merge(&decisions.new),
                ));
            }
        });
    }
}

#[derive(Deserialize)]
struct ListMetadata {
    kind: String,
    num_items: usize,
}

#[derive(Deserialize)]
struct ListItem {
    id: String,
    ip: String,
}

#[derive(Deserialize)]
struct Submitted {
    operation_id: String,
}

#[derive(Deserialize)]
struct Operation {
    status: String,
    error: Option<String>,
}

const BATCH_SIZE: usize = 1_000;
const AMBIGUOUS_WRITE_DELAY: u64 = 60;

pub struct CloudflareSync {
    config: CloudflareConfig,
    client: CloudflareClient,
    store: StateStore,
    state: LocalState,
    needs_refresh: bool,
    last_refresh: Option<Instant>,
    poll_interval: Duration,
}

fn parse_net(value: &str) -> anyhow::Result<IpNet> {
    Ok(value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .context("Invalid IP address in Cloudflare list")?
        .trunc())
}

/// Preserve exact coverage, splitting ranges that are wider than Cloudflare accepts.
fn candidates(blacklist: &IpRangeMixed) -> BTreeSet<IpNet> {
    let mut result = BTreeSet::new();
    for net in IpNet::aggregate(&blacklist.into_nets()) {
        let minimum_prefix = if net.addr().is_ipv4() { 8 } else { 12 };
        if net.prefix_len() < minimum_prefix {
            result.extend(
                net.subnets(minimum_prefix)
                    .expect("valid Cloudflare prefix"),
            );
        } else {
            result.insert(net.trunc());
        }
    }
    result
}

fn select_desired(
    candidates: &BTreeSet<IpNet>,
    actual: &BTreeMap<IpNet, Option<String>>,
    cap: usize,
) -> BTreeSet<IpNet> {
    // Retain already installed active entries first to avoid churning at capacity.
    let mut desired = actual
        .keys()
        .filter(|net| candidates.contains(net))
        .take(cap)
        .copied()
        .collect::<BTreeSet<_>>();
    for net in candidates {
        if desired.len() >= cap {
            break;
        }
        desired.insert(*net);
    }
    desired
}

impl CloudflareSync {
    pub async fn new(config: CloudflareConfig) -> anyhow::Result<Self> {
        let (store, state) = StateStore::open(&config).await?;
        let mut client = CloudflareClient::new(&config.api_token)?;
        client.cooldown_until = state.cooldown_until;
        Ok(Self {
            config,
            client,
            store,
            state,
            needs_refresh: true,
            last_refresh: None,
            poll_interval: Duration::from_secs(2),
        })
    }

    fn list_path(&self) -> String {
        format!(
            "accounts/{}/rules/lists/{}",
            self.config.account_id, self.config.list_id
        )
    }

    async fn refresh(&mut self) -> anyhow::Result<()> {
        let path = self.list_path();
        let metadata = self
            .client
            .request::<ListMetadata>(Method::GET, &path, &[], None)
            .await?
            .result
            .context("Cloudflare list metadata is missing")?;
        ensure!(
            metadata.kind == "ip",
            "CLOUDFLARE_LIST_ID must refer to a custom IP list"
        );
        ensure!(
            metadata.num_items <= 10_000,
            "Cloudflare list exceeds the supported free-plan capacity"
        );
        let mut items = BTreeMap::new();
        let mut cursor: Option<String> = None;
        let mut seen_cursors = HashSet::new();
        loop {
            let mut query = vec![("per_page", "500".to_string())];
            if let Some(cursor) = &cursor {
                query.push(("cursor", cursor.clone()));
            }
            let response = self
                .client
                .request::<Vec<ListItem>>(Method::GET, &format!("{path}/items"), &query, None)
                .await?;
            for item in response
                .result
                .context("Cloudflare list items are missing")?
            {
                ensure!(!item.id.is_empty(), "Cloudflare list item ID is missing");
                ensure!(
                    items.insert(parse_net(&item.ip)?, Some(item.id)).is_none(),
                    "Cloudflare list changed during pagination; retrying a fresh read"
                );
            }
            ensure!(
                items.len() <= 10_000,
                "Cloudflare list exceeds the supported free-plan capacity"
            );
            cursor = response
                .result_info
                .and_then(|info| info.cursors)
                .and_then(|cursors| cursors.after)
                .filter(|cursor| !cursor.is_empty());
            match &cursor {
                None => break,
                Some(cursor) => ensure!(
                    seen_cursors.insert(cursor.clone()),
                    "Cloudflare repeated a pagination cursor"
                ),
            }
        }
        ensure!(
            items.len() == metadata.num_items,
            "Cloudflare list changed or pagination was incomplete; retrying a fresh read"
        );
        self.state.items = items;
        self.store.save(&self.state).await?;
        self.needs_refresh = false;
        self.last_refresh = Some(Instant::now());
        info!(
            entry_count = self.state.items.len(),
            "Reconciled Cloudflare list state"
        );
        Ok(())
    }

    async fn finish_pending(&mut self) -> anyhow::Result<()> {
        let Some(pending) = &self.state.pending else {
            return Ok(());
        };
        let Some(id) = pending.operation_id.clone() else {
            // The process may have died after sending but before saving the operation ID.
            ensure!(
                now() >= pending.submitted_at.saturating_add(AMBIGUOUS_WRITE_DELAY),
                "Waiting before reconciling an ambiguous Cloudflare write"
            );
            self.state.pending = None;
            self.needs_refresh = true;
            self.store.save(&self.state).await?;
            return Ok(());
        };
        let path = format!(
            "accounts/{}/rules/lists/bulk_operations/{id}",
            self.config.account_id
        );
        for attempt in 0..6 {
            let response = self
                .client
                .request::<Operation>(Method::GET, &path, &[], None)
                .await;
            if let Err(error) = &response {
                if error
                    .downcast_ref::<ApiFailure>()
                    .is_some_and(|error| error.status == reqwest::StatusCode::NOT_FOUND)
                {
                    // Operation records may expire. Recover from actual list contents instead.
                    self.state
                        .pending
                        .as_mut()
                        .expect("pending operation exists")
                        .operation_id = None;
                    self.needs_refresh = true;
                    self.store.save(&self.state).await?;
                }
            }
            let operation = response?
                .result
                .context("Cloudflare bulk operation status is missing")?;
            match operation.status.as_str() {
                "completed" => {
                    let pending = self.state.pending.take().expect("pending operation exists");
                    self.state.confirm(&pending.mutation);
                    self.store.save(&self.state).await?;
                    return Ok(());
                }
                "failed" => {
                    self.state.pending = None;
                    self.needs_refresh = true;
                    self.store.save(&self.state).await?;
                    bail!("Cloudflare bulk operation failed: {:?}", operation.error);
                }
                "pending" | "running" => {
                    if attempt < 5 {
                        tokio::time::sleep(
                            (self.poll_interval * (1 << attempt)).min(Duration::from_secs(30)),
                        )
                        .await;
                    }
                }
                other => bail!("Unknown Cloudflare bulk operation status: {other}"),
            }
        }
        bail!("Cloudflare bulk operation is still pending; will resume polling next cycle")
    }

    async fn mutate(&mut self, mutation: Mutation) -> anyhow::Result<()> {
        let (method, body) = match &mutation {
            Mutation::Add(nets) => (
                Method::POST,
                json!(nets
                    .iter()
                    .map(|net| json!({"ip": net.to_string()}))
                    .collect::<Vec<_>>()),
            ),
            Mutation::Delete(nets) => {
                let ids =
                    nets.iter()
                        .map(|net| {
                            let id =
                                self.state.items.get(net).and_then(Option::as_ref).context(
                                    "Cloudflare item IDs need a refresh before deletion",
                                )?;
                            Ok(json!({"id": id}))
                        })
                        .collect::<anyhow::Result<Vec<_>>>()?;
                (Method::DELETE, json!({"items": ids}))
            }
        };
        if !self.state.reserve(mutation.len(), now()) {
            self.store.save(&self.state).await?;
            bail!(
                "Cloudflare local 12-hour write budget exhausted; updates deferred until {}",
                self.state.cooldown_until
            );
        }
        let count = mutation.len();
        self.state.pending = Some(Pending {
            operation_id: None,
            submitted_at: now(),
            mutation,
        });
        // Never write remotely without first durably recording intent and quota usage.
        self.store.save(&self.state).await?;
        let response = self
            .client
            .request::<Submitted>(
                method.clone(),
                &format!("{}/items", self.list_path()),
                &[],
                Some(body),
            )
            .await?;
        let operation_id = response
            .result
            .context("Cloudflare operation ID is missing")?
            .operation_id;
        ensure!(
            !operation_id.is_empty(),
            "Cloudflare returned an empty operation ID"
        );
        self.state
            .pending
            .as_mut()
            .expect("pending operation exists")
            .operation_id = Some(operation_id);
        self.store.save(&self.state).await?;
        self.finish_pending().await?;
        info!(action = %method, entry_count = count, "Updated Cloudflare list");
        Ok(())
    }

    async fn sync_once(&mut self, snapshot: &IpRangeMixed) -> anyhow::Result<()> {
        if now() < self.state.cooldown_until {
            return Ok(());
        }
        // Retry local persistence before any further network work after an I/O error.
        self.store.save(&self.state).await?;
        self.finish_pending().await?;
        if self.needs_refresh
            || self
                .last_refresh
                .is_none_or(|last| last.elapsed() >= self.config.reconcile_interval)
        {
            self.refresh().await?;
        }
        let candidates = candidates(snapshot);
        let mut desired = select_desired(&candidates, &self.state.items, self.config.max_items);
        if self
            .state
            .items
            .iter()
            .any(|(net, id)| !desired.contains(net) && id.is_none())
        {
            self.refresh().await?;
            desired = select_desired(&candidates, &self.state.items, self.config.max_items);
        }
        if candidates.len() > desired.len() {
            warn!(cap = self.config.max_items, skipped_entries = candidates.len() - desired.len(),
                "Cloudflare list capacity reached; retaining installed active entries before adding new bans");
        }
        let deleted = self
            .state
            .items
            .keys()
            .filter(|net| !desired.contains(net))
            .copied()
            .collect::<Vec<_>>();
        let added = desired
            .iter()
            .filter(|net| !self.state.items.contains_key(net))
            .copied()
            .collect::<Vec<_>>();
        // Expire stale bans first and free capacity before adding replacements.
        for batch in deleted.chunks(BATCH_SIZE) {
            self.mutate(Mutation::Delete(batch.to_vec())).await?;
        }
        for batch in added.chunks(BATCH_SIZE) {
            self.mutate(Mutation::Add(batch.to_vec())).await?;
        }
        Ok(())
    }

    pub async fn run(mut self, mut snapshots: watch::Receiver<Snapshot>) -> anyhow::Result<()> {
        info!("Starting optional Cloudflare custom IP list sync");
        // An unavailable LAPI must never turn an uninitialized snapshot into a list wipe.
        while snapshots.borrow().is_none() {
            if snapshots.changed().await.is_err() {
                return Ok(());
            }
        }
        let mut interval = tokio::time::interval(self.config.sync_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut failures: u32 = 0;
        loop {
            interval.tick().await;
            let snapshot = snapshots
                .borrow()
                .clone()
                .context("CrowdSec snapshot disappeared")?;
            if let Err(error) = self.tick(&snapshot, &mut failures).await {
                error!(
                    ?error,
                    "Cloudflare sync failed; primary bouncer continues and Cloudflare will retry"
                );
            }
        }
    }

    async fn tick(&mut self, snapshot: &IpRangeMixed, failures: &mut u32) -> anyhow::Result<()> {
        if now() < self.state.cooldown_until {
            return Ok(());
        }
        let result = self.sync_once(snapshot).await;
        if result.is_err() {
            self.needs_refresh = true;
            let delay = self
                .config
                .sync_interval
                .as_secs()
                .max(60)
                .saturating_mul(1 << (*failures).min(6))
                .min(3600);
            *failures = failures.saturating_add(1);
            self.state.cooldown_until = self.state.cooldown_until.max(now().saturating_add(delay));
        } else {
            *failures = 0;
        }
        self.state.cooldown_until = self.state.cooldown_until.max(self.client.cooldown_until);
        self.store.save(&self.state).await?;
        result
    }
}

#[cfg(test)]
mod tests;
