use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use ipnet::IpNet;
use tracing::{debug, error, info, instrument, warn};

use crate::blacklist::IpRangeMixed;
use crate::crowdsec_lapi::types::{DecisionsIpRange, DecisionsNets};
use crate::crowdsec_lapi::{CrowdsecLAPI, DecisionsOptions, DEFAULT_DECISION_ORIGINS};
use crate::utils::retry_backoff;
use crate::vyos_api::{update_firewall_nets, VyosApi};
use crate::App;

const FIREWALL_GROUP_MAX_ITEMS: usize = 15_000;
const RECONCILE_RETRIES: u64 = 10;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReconcileMode {
    Incremental,
    FullSync,
}

impl ReconcileMode {
    fn startup(self) -> bool {
        matches!(self, Self::FullSync)
    }

    fn is_full_sync(self) -> bool {
        matches!(self, Self::FullSync)
    }
}

#[derive(Debug)]
struct CappedUpdate {
    decisions: DecisionsNets,
    final_blacklist: IpRangeMixed,
}

#[instrument(level = "debug", skip(app), fields(group_name = %app.config.firewall_group))]
async fn retrieve_existing_networks(app: &App) -> Result<Vec<IpNet>, anyhow::Error> {
    let existing_networks = app
        .vyos
        .retrieve_firewall_network_groups(&app.config.firewall_group)
        .await?;

    let entry_count = existing_networks.data.len();
    debug!(
        group_name = app.config.firewall_group.as_str(),
        entry_count, "Loaded firewall group state from VyOS"
    );
    Ok(existing_networks.data)
}

#[instrument(level = "debug", skip(app), fields(group_name = %app.config.firewall_group))]
async fn retrieve_existing_blacklist(app: &App) -> Result<IpRangeMixed, anyhow::Error> {
    Ok(IpRangeMixed::from(retrieve_existing_networks(app).await?))
}

#[instrument(level = "debug", skip(app), fields(group_name = %app.config.firewall_group))]
pub async fn store_existing_blacklist(app: &App) -> Result<(), anyhow::Error> {
    let blacklist = retrieve_existing_blacklist(app).await?;
    app.blacklist.store(blacklist);
    Ok(())
}

fn build_capped_update(
    retained_blacklist: &IpRangeMixed,
    candidate_adds: IpRangeMixed,
    deleted: IpRangeMixed,
) -> CappedUpdate {
    let retained_count = retained_blacklist.net_count();

    if retained_count >= FIREWALL_GROUP_MAX_ITEMS {
        warn!(
            retained_entry_count = retained_count,
            cap = FIREWALL_GROUP_MAX_ITEMS,
            "Firewall group is at or above capacity; new CrowdSec bans will be skipped until entries are removed"
        );
    }

    let allowed_adds = FIREWALL_GROUP_MAX_ITEMS.saturating_sub(retained_count);
    let all_new_nets = candidate_adds.into_nets();
    let attempted_new_count = all_new_nets.len();
    let applied_new_count = attempted_new_count.min(allowed_adds);
    let skipped_adds = attempted_new_count.saturating_sub(applied_new_count);

    if skipped_adds > 0 {
        warn!(
            cap = FIREWALL_GROUP_MAX_ITEMS,
            retained_entry_count = retained_count,
            attempted_new_count,
            applied_new_count,
            skipped_new_count = skipped_adds,
            "CrowdSec bans were capped to avoid exceeding the VyOS firewall group limit"
        );
    }

    let applied_new = IpRangeMixed::from(
        all_new_nets
            .into_iter()
            .take(applied_new_count)
            .collect::<Vec<_>>(),
    );
    let final_blacklist = retained_blacklist.merge(&applied_new);

    CappedUpdate {
        decisions: DecisionsNets {
            new: applied_new.into_nets(),
            deleted: deleted.into_nets(),
        },
        final_blacklist,
    }
}

fn build_exact_full_sync_update(
    actual_nets: Vec<IpNet>,
    desired_blacklist: IpRangeMixed,
) -> CappedUpdate {
    let all_desired_nets = desired_blacklist.into_nets();
    let attempted_desired_count = all_desired_nets.len();
    let applied_desired_count = attempted_desired_count.min(FIREWALL_GROUP_MAX_ITEMS);
    let skipped_desired_count = attempted_desired_count.saturating_sub(applied_desired_count);

    if skipped_desired_count > 0 {
        warn!(
            cap = FIREWALL_GROUP_MAX_ITEMS,
            attempted_desired_count,
            applied_desired_count,
            skipped_desired_count,
            "CrowdSec bans were capped during full sync to avoid exceeding the VyOS firewall group limit"
        );
    }

    let desired_nets = all_desired_nets
        .into_iter()
        .take(applied_desired_count)
        .collect::<Vec<_>>();
    let actual_set = actual_nets.iter().cloned().collect::<HashSet<_>>();
    let desired_set = desired_nets.iter().cloned().collect::<HashSet<_>>();

    let deleted = actual_nets
        .into_iter()
        .filter(|net| !desired_set.contains(net))
        .collect::<Vec<_>>();
    let new = desired_nets
        .iter()
        .filter(|net| !actual_set.contains(*net))
        .cloned()
        .collect::<Vec<_>>();

    CappedUpdate {
        decisions: DecisionsNets { new, deleted },
        final_blacklist: IpRangeMixed::from(desired_nets),
    }
}

#[instrument(level = "info", skip(app, update), fields(mode = ?mode))]
async fn apply_update(
    app: &App,
    update: CappedUpdate,
    mode: ReconcileMode,
) -> Result<(), anyhow::Error> {
    let timeout = Some(Duration::from_secs(60 * 5));

    if update.decisions.is_empty() {
        info!("No firewall changes needed");
        if mode.is_full_sync() && app.config.vyos_save_config {
            if let Err(err) = app.vyos.save_config(timeout).await {
                app.pending_save.store(true, Ordering::SeqCst);
                return Err(err);
            }
            app.pending_save.store(false, Ordering::SeqCst);
        }
    } else {
        if let Err(err) = update_firewall_nets(
            &app.vyos,
            update.decisions.clone(),
            &app.config.firewall_group,
            timeout,
            app.config.vyos_save_config,
        )
        .await
        {
            if app.config.vyos_save_config {
                app.pending_save.store(true, Ordering::SeqCst);
            }
            return Err(err);
        }
        if app.config.vyos_save_config {
            app.pending_save.store(false, Ordering::SeqCst);
        }
    }

    app.blacklist.store(update.final_blacklist);
    Ok(())
}

#[instrument(
    level = "info",
    skip(app, decision_options),
    fields(
        startup = decision_options.startup,
        firewall_group = %app.config.firewall_group
    )
)]
pub async fn reconcile_decisions(
    app: &App,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    if decision_options.get_startup() {
        reconcile_full_sync(app, decision_options).await
    } else {
        reconcile_incremental(app, decision_options).await
    }
}

async fn reconcile_incremental(
    app: &App,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    info!("Fetching incremental decisions");

    let new_decisions = app.lapi.stream_decisions(decision_options).await?;

    let blacklist = app.blacklist.load();
    let decision_ips = DecisionsIpRange::from(new_decisions)
        .filter_new(&app.config.trusted_ips)
        .filter_new(blacklist.as_ref())
        .filter_deleted(blacklist.as_ref());
    let retained_blacklist = blacklist.as_ref().exclude(&decision_ips.deleted);

    let update = build_capped_update(&retained_blacklist, decision_ips.new, decision_ips.deleted);
    apply_update(app, update, ReconcileMode::Incremental).await
}

async fn reconcile_full_sync(
    app: &App,
    decision_options: &DecisionsOptions,
) -> Result<(), anyhow::Error> {
    info!("Reconciling full firewall group state");

    let actual_nets = retrieve_existing_networks(app).await?;
    let desired_decisions = app.lapi.stream_decisions(decision_options).await?;
    let desired_blacklist = DecisionsIpRange::from(desired_decisions)
        .new
        .exclude(&app.config.trusted_ips);

    let update = build_exact_full_sync_update(actual_nets, desired_blacklist);

    apply_update(app, update, ReconcileMode::FullSync).await
}

fn select_reconcile_mode(
    force_full_sync: bool,
    last_full_sync: Option<Instant>,
    full_sync_interval: Option<Duration>,
    now: Instant,
) -> ReconcileMode {
    if force_full_sync {
        return ReconcileMode::FullSync;
    }

    if let Some(interval) = full_sync_interval {
        if last_full_sync
            .map(|last| now.duration_since(last) >= interval)
            .unwrap_or(true)
        {
            return ReconcileMode::FullSync;
        }
    }

    ReconcileMode::Incremental
}

async fn reconcile_once(app: &App, mode: ReconcileMode) -> Result<(), anyhow::Error> {
    let decision_options = DecisionsOptions::new(&DEFAULT_DECISION_ORIGINS, mode.startup());
    reconcile_decisions(app, &decision_options).await
}

async fn reconcile_with_retries(
    app: &App,
    initial_mode: ReconcileMode,
) -> Result<ReconcileMode, anyhow::Error> {
    let mut mode = initial_mode;
    let mut current_retries = 0;

    loop {
        match reconcile_once(app, mode).await {
            Ok(()) => return Ok(mode),
            Err(err) if current_retries < RECONCILE_RETRIES => {
                current_retries += 1;
                error!(
                    ?err,
                    retry = current_retries,
                    previous_mode = ?mode,
                    next_mode = ?ReconcileMode::FullSync,
                    "Failed reconciliation iteration"
                );
                mode = ReconcileMode::FullSync;
                tokio::time::sleep(retry_backoff(current_retries, 1000)).await;
            }
            Err(err) => {
                error!(?err, "Ran out of reconciliation retries");
                return Err(err);
            }
        }
    }
}

pub async fn reconcile(app: App) -> Result<(), anyhow::Error> {
    info!("Starting main loop, fetching decisions...");
    let mut force_full_sync = true;
    let mut last_full_sync = None;

    loop {
        let mode = select_reconcile_mode(
            force_full_sync,
            last_full_sync,
            app.config.full_sync_interval,
            Instant::now(),
        );

        match reconcile_with_retries(&app, mode).await {
            Ok(completed_mode) => {
                force_full_sync = false;
                if completed_mode.is_full_sync() {
                    last_full_sync = Some(Instant::now());
                }
            }
            Err(err) => {
                error!(
                    ?err,
                    "Reconciliation failed after retries; next attempt will start with a full sync"
                );
                force_full_sync = true;
            }
        }

        tokio::time::sleep(app.config.update_period).await;
    }
}

#[cfg(test)]
mod tests {
    use crate::blacklist::IpRangeMixed;
    use crate::crowdsec_lapi::types::{CrowdsecAuth, Decision, DecisionsResponse, Scope};
    use crate::crowdsec_lapi::{CrowdsecLapiClient, DecisionsOptions};
    use crate::vyos_api::{VyosClient, VyosCommandResponse};
    use crate::Config;
    use ipnet::IpNet;

    use super::{
        reconcile_decisions, reconcile_with_retries, select_reconcile_mode, App, ReconcileMode,
        FIREWALL_GROUP_MAX_ITEMS,
    };
    use iprange::IpRange;
    use mockito::{Matcher, Mock, Server, ServerGuard};

    fn lapi_client(apikey: String, mock: &Server) -> CrowdsecLapiClient {
        let url = format!("http://{}", mock.host_with_port());
        CrowdsecLapiClient::new(
            url.parse().unwrap(),
            CrowdsecAuth::Apikey(apikey),
            std::time::Duration::from_secs(1),
        )
    }

    fn vyos_client(apikey: String, mock: &Server) -> VyosClient {
        let url = format!("http://{}", mock.host_with_port());
        VyosClient::new(url.parse().unwrap(), apikey)
    }

    fn mock_decision(value: &str) -> Decision {
        let scope = if value.contains('/') {
            Scope::Range
        } else {
            Scope::Ip
        };
        Decision {
            value: String::from(value),
            scope,
            ..Default::default()
        }
    }
    fn mock_decisions<'a>(
        cidrs_new: impl IntoIterator<Item = &'a str>,
        cidrs_delete: impl IntoIterator<Item = &'a str>,
    ) -> DecisionsResponse {
        DecisionsResponse {
            new: Some(cidrs_new.into_iter().map(mock_decision).collect()),
            deleted: Some(cidrs_delete.into_iter().map(mock_decision).collect()),
        }
    }

    fn mock_default_decision_stream(
        mock: &mut ServerGuard,
        apikey: &str,
        startup: bool,
        decisions: DecisionsResponse,
    ) -> Mock {
        mock.mock("GET", "/v1/decisions/stream")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded(String::from("startup"), startup.to_string()),
                Matcher::UrlEncoded(String::from("type"), String::from("ban")),
                Matcher::UrlEncoded(
                    String::from("origins"),
                    String::from("crowdsec,lists,cscli"),
                ),
                Matcher::UrlEncoded(String::from("scopes"), String::from("ip,range")),
                Matcher::UrlEncoded(String::from("dedup"), String::from("false")),
            ]))
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .expect(1)
            .create()
    }
    fn mock_save_command(mock: &mut ServerGuard) -> Mock {
        mock.mock("POST", "/config-file")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create()
    }

    fn mock_save_command_expect(mock: &mut ServerGuard, expect: usize) -> Mock {
        mock.mock("POST", "/config-file")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(expect)
            .create()
    }

    fn ipnets(values: &[&str]) -> Vec<IpNet> {
        values.iter().map(|value| value.parse().unwrap()).collect()
    }

    fn mock_retrieve_group(
        mock: &mut ServerGuard,
        ipv4_values: &[&str],
        ipv6_values: &[&str],
    ) -> Vec<Mock> {
        let ipv4 = ipnets(ipv4_values);
        let ipv6 = ipnets(ipv6_values);
        let mut mocks = Vec::new();

        mocks.push(
            mock.mock("POST", "/retrieve")
                .match_body(Matcher::AllOf(vec![
                    Matcher::Regex(r#""network-group""#.into()),
                    Matcher::Regex(r#""op":"exists""#.into()),
                ]))
                .with_body(format!(
                    r#"{{"success": true, "data": {}, "error": null}}"#,
                    !ipv4.is_empty()
                ))
                .with_status(200)
                .expect(1)
                .create(),
        );

        mocks.push(
            mock.mock("POST", "/retrieve")
                .match_body(Matcher::AllOf(vec![
                    Matcher::Regex(r#""network-group""#.into()),
                    Matcher::Regex(r#""op":"returnValues""#.into()),
                ]))
                .with_body(
                    serde_json::to_string(&VyosCommandResponse {
                        success: true,
                        data: ipv4,
                        error: None,
                    })
                    .unwrap(),
                )
                .with_status(200)
                .expect(if ipv4_values.is_empty() { 0 } else { 1 })
                .create(),
        );

        mocks.push(
            mock.mock("POST", "/retrieve")
                .match_body(Matcher::AllOf(vec![
                    Matcher::Regex(r#""ipv6-network-group""#.into()),
                    Matcher::Regex(r#""op":"exists""#.into()),
                ]))
                .with_body(format!(
                    r#"{{"success": true, "data": {}, "error": null}}"#,
                    !ipv6.is_empty()
                ))
                .with_status(200)
                .expect(1)
                .create(),
        );

        mocks.push(
            mock.mock("POST", "/retrieve")
                .match_body(Matcher::AllOf(vec![
                    Matcher::Regex(r#""ipv6-network-group""#.into()),
                    Matcher::Regex(r#""op":"returnValues""#.into()),
                ]))
                .with_body(
                    serde_json::to_string(&VyosCommandResponse {
                        success: true,
                        data: ipv6,
                        error: None,
                    })
                    .unwrap(),
                )
                .with_status(200)
                .expect(if ipv6_values.is_empty() { 0 } else { 1 })
                .create(),
        );

        mocks
    }
    struct TestApp {
        app: App,
        lapi_mock: ServerGuard,
        vyos_mock: ServerGuard,
    }
    async fn mock_app(apikey: &str) -> TestApp {
        let lapi_mock = Server::new_async().await;
        let vyos_mock = Server::new_async().await;
        let app = App {
            lapi: lapi_client(apikey.to_string(), &lapi_mock),
            vyos: vyos_client(apikey.to_string(), &vyos_mock),
            config: Config {
                firewall_group: String::from("group"),
                trusted_ips: IpRangeMixed::default(),
                update_period: std::time::Duration::from_secs(1),
                full_sync_interval: Some(std::time::Duration::from_secs(900)),
                vyos_save_config: true,
            },
            blacklist: crate::BlacklistCache::default(),
            pending_save: std::sync::atomic::AtomicBool::new(false),
        };

        TestApp {
            app,
            lapi_mock,
            vyos_mock,
        }
    }

    #[tokio::test]
    async fn iteration_sucessful() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let add_ips = ["127.0.0.1/32", "127.0.0.2", "junk"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve_exists = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"exists""#.into()))
            .with_body(r#"{"success": true, "data": true, "error": null}"#)
            .with_status(200)
            .expect(2)
            .create();
        let retrieve = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"returnValues""#.into()))
            .with_body(
                serde_json::to_string(&VyosCommandResponse {
                    success: true,
                    data: Vec::<()>::new(),
                    error: None,
                })
                .unwrap(),
            )
            .with_status(200)
            .expect(2)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);

        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };
        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve_exists.assert();
        retrieve.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(
                ["127.0.0.1/32", "127.0.0.2/32"]
                    .into_iter()
                    .map(|x| x.parse().unwrap())
            )
        );

        let next_decisions = mock_decisions(["127.0.0.3"], ["127.0.0.1"]);

        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&next_decisions).expect("valid json"))
            .with_status(200)
            .create();

        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);
        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4.clone(),
            IpRange::from_iter(["127.0.0.2/31"].into_iter().map(|x| x.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn no_update_if_present_in_cache() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let add_ips = ["127.0.0.1/32"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve_exists = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"exists""#.into()))
            .with_body(r#"{"success": true, "data": true, "error": null}"#)
            .with_status(200)
            .expect(2)
            .create();
        let retrieve = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"returnValues""#.into()))
            .with_body(
                serde_json::to_string(&VyosCommandResponse {
                    success: true,
                    data: add_ips,
                    error: None,
                })
                .unwrap(),
            )
            .with_status(200)
            .expect(2)
            .create();

        // No call to update firewall since all the decisions already exist
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(0)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);
        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve_exists.assert();
        retrieve.assert();
        config.assert();
        save.assert();
    }

    #[tokio::test]
    async fn no_update_for_whitelisted_nets() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;
        test_app.app.config.trusted_ips = vec!["127.0.0.1/32".parse().unwrap()].into();

        let add_ips = ["127.0.0.1/32"];
        let initial_decisions = mock_decisions(add_ips, []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();

        // No call to update firewall since the subnet is whitelisted
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(0)
            .create();
        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();
    }

    #[tokio::test]
    async fn startup_without_existing_firewall_group_is_ok() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let initial_decisions = mock_decisions([], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&initial_decisions).expect("valid json"))
            .with_status(200)
            .create();
        let retrieve_exists = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"exists""#.into()))
            .with_body(r#"{"success": true, "data": false, "error": null}"#)
            .with_status(200)
            .expect(2)
            .create();
        let retrieve_values = test_app
            .vyos_mock
            .mock("POST", "/retrieve")
            .match_body(Matcher::Regex(r#""op":"returnValues""#.into()))
            .with_status(200)
            .expect(0)
            .create();
        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(0)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);
        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        retrieve_exists.assert();
        retrieve_values.assert();
        config.assert();
        save.assert();
        assert!(test_app.app.blacklist.load().is_empty());
    }

    #[tokio::test]
    async fn caps_new_entries_at_firewall_group_limit() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let existing = (0..FIREWALL_GROUP_MAX_ITEMS)
            .map(|idx| -> IpNet {
                format!("10.{}.{}.1/32", idx / 256, idx % 256)
                    .parse()
                    .unwrap()
            })
            .collect::<Vec<_>>();
        test_app.app.blacklist.store(IpRangeMixed::from(existing));

        let decisions = mock_decisions(["203.0.113.1", "203.0.113.2"], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(0)
            .create();
        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        lapi_stream.assert();
        config.assert();

        let blacklist = test_app.app.blacklist.load();
        assert_eq!(blacklist.net_count(), FIREWALL_GROUP_MAX_ITEMS);
        assert!(!blacklist
            .into_nets()
            .iter()
            .any(|net| net.to_string() == "203.0.113.1/32" || net.to_string() == "203.0.113.2/32"));
    }

    #[tokio::test]
    async fn full_sync_prunes_stale_vyos_entries() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let retrieve_mocks = mock_retrieve_group(
            &mut test_app.vyos_mock,
            &["127.0.0.1/32", "127.0.0.2/32"],
            &[],
        );

        let decisions = mock_decisions(["127.0.0.2"], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .match_body(Matcher::Regex(r#"127\.0\.0\.1/32"#.into()))
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);

        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        for mock in retrieve_mocks {
            mock.assert();
        }
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(["127.0.0.2/32"].into_iter().map(|x| x.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn full_sync_deletes_exact_stale_vyos_entries_without_simplifying_them() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let retrieve_mocks = mock_retrieve_group(
            &mut test_app.vyos_mock,
            &["87.121.84.80/31", "87.121.84.82/31", "107.172.35.195/32"],
            &[],
        );

        let decisions = mock_decisions(["107.172.35.195"], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=true")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .match_body(Matcher::AllOf(vec![
                Matcher::Regex(r#"87\.121\.84\.80/31"#.into()),
                Matcher::Regex(r#"87\.121\.84\.82/31"#.into()),
            ]))
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);

        let decision_options = DecisionsOptions {
            startup: true,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_ok());
        for mock in retrieve_mocks {
            mock.assert();
        }
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(
                ["107.172.35.195/32"]
                    .into_iter()
                    .map(|x| x.parse().unwrap())
            )
        );
    }

    #[tokio::test]
    async fn configure_success_false_returns_error_and_keeps_cache() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let decisions = mock_decisions(["127.0.0.1"], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": false, "data": [], "error": "commit failed"}"#)
            .with_status(200)
            .expect(1)
            .create();
        let save = mock_save_command_expect(&mut test_app.vyos_mock, 0);

        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_err());
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert!(test_app.app.blacklist.load().is_empty());
        assert!(test_app
            .app
            .pending_save
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn save_success_false_returns_error_and_keeps_cache() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let decisions = mock_decisions(["127.0.0.1"], []);
        let lapi_stream = test_app
            .lapi_mock
            .mock("GET", "/v1/decisions/stream?startup=false")
            .match_header("x-api-key", apikey)
            .with_body(serde_json::to_vec(&decisions).expect("valid json"))
            .with_status(200)
            .create();

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();
        let save = test_app
            .vyos_mock
            .mock("POST", "/config-file")
            .with_body(r#"{"success": false, "data": [], "error": "save failed"}"#)
            .with_status(200)
            .expect(1)
            .create();

        let decision_options = DecisionsOptions {
            startup: false,
            ..Default::default()
        };

        let result = reconcile_decisions(&test_app.app, &decision_options).await;
        assert!(result.is_err());
        lapi_stream.assert();
        config.assert();
        save.assert();
        assert!(test_app.app.blacklist.load().is_empty());
        assert!(test_app
            .app
            .pending_save
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[tokio::test]
    async fn failed_incremental_retry_uses_full_sync() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let incremental_decisions = mock_decisions(["127.0.0.1"], []);
        let incremental_stream = mock_default_decision_stream(
            &mut test_app.lapi_mock,
            apikey,
            false,
            incremental_decisions,
        );

        let failed_config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": false, "data": [], "error": "commit failed"}"#)
            .with_status(200)
            .expect(1)
            .create();

        let retrieve_mocks = mock_retrieve_group(&mut test_app.vyos_mock, &[], &[]);

        let full_sync_decisions = mock_decisions(["127.0.0.1"], []);
        let full_sync_stream = mock_default_decision_stream(
            &mut test_app.lapi_mock,
            apikey,
            true,
            full_sync_decisions,
        );

        let successful_config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();
        let save = mock_save_command(&mut test_app.vyos_mock);

        let result = reconcile_with_retries(&test_app.app, ReconcileMode::Incremental).await;
        assert_eq!(result.unwrap(), ReconcileMode::FullSync);
        incremental_stream.assert();
        failed_config.assert();
        for mock in retrieve_mocks {
            mock.assert();
        }
        full_sync_stream.assert();
        successful_config.assert();
        save.assert();
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(["127.0.0.1/32"].into_iter().map(|x| x.parse().unwrap()))
        );
    }

    #[tokio::test]
    async fn save_failure_retry_saves_full_sync_without_config_changes() {
        let apikey = "test_key";
        let mut test_app = mock_app(apikey).await;

        let incremental_decisions = mock_decisions(["127.0.0.1"], []);
        let incremental_stream = mock_default_decision_stream(
            &mut test_app.lapi_mock,
            apikey,
            false,
            incremental_decisions,
        );

        let config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();
        let failed_save = test_app
            .vyos_mock
            .mock("POST", "/config-file")
            .with_body(r#"{"success": false, "data": [], "error": "save failed"}"#)
            .with_status(200)
            .expect(1)
            .create();

        let retrieve_mocks = mock_retrieve_group(&mut test_app.vyos_mock, &["127.0.0.1/32"], &[]);

        let full_sync_decisions = mock_decisions(["127.0.0.1"], []);
        let full_sync_stream = mock_default_decision_stream(
            &mut test_app.lapi_mock,
            apikey,
            true,
            full_sync_decisions,
        );

        let no_config = test_app
            .vyos_mock
            .mock("POST", "/configure")
            .with_status(200)
            .expect(0)
            .create();
        let successful_save = mock_save_command(&mut test_app.vyos_mock);

        let result = reconcile_with_retries(&test_app.app, ReconcileMode::Incremental).await;
        assert_eq!(result.unwrap(), ReconcileMode::FullSync);
        incremental_stream.assert();
        config.assert();
        failed_save.assert();
        for mock in retrieve_mocks {
            mock.assert();
        }
        full_sync_stream.assert();
        no_config.assert();
        successful_save.assert();
        assert!(!test_app
            .app
            .pending_save
            .load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(
            test_app.app.blacklist.load().v4,
            IpRange::from_iter(["127.0.0.1/32"].into_iter().map(|x| x.parse().unwrap()))
        );
    }

    #[test]
    fn selects_periodic_full_sync_when_due() {
        let now = std::time::Instant::now();
        let interval = std::time::Duration::from_secs(900);

        assert_eq!(
            select_reconcile_mode(true, Some(now), Some(interval), now),
            ReconcileMode::FullSync
        );
        assert_eq!(
            select_reconcile_mode(false, None, Some(interval), now),
            ReconcileMode::FullSync
        );
        assert_eq!(
            select_reconcile_mode(
                false,
                Some(now - std::time::Duration::from_secs(901)),
                Some(interval),
                now,
            ),
            ReconcileMode::FullSync
        );
        assert_eq!(
            select_reconcile_mode(
                false,
                Some(now - std::time::Duration::from_secs(899)),
                Some(interval),
                now,
            ),
            ReconcileMode::Incremental
        );
        assert_eq!(
            select_reconcile_mode(false, Some(now), None, now),
            ReconcileMode::Incremental
        );
    }
}
