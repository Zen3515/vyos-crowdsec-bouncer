use std::collections::BTreeSet;
use std::path::PathBuf;
use std::time::Duration;

use mockito::{Matcher, Mock, Server, ServerGuard};
use serde_json::{json, Value};

use super::client::now;
use super::state::{Mutation, Pending, Reservation, QUOTA_WINDOW_SECS};
use super::{
    candidates, select_desired, CloudflareArgs, CloudflareConfig, CloudflareSync, DecisionPublisher,
};
use crate::blacklist::IpRangeMixed;
use crate::crowdsec_lapi::types::DecisionsIpRange;

const ACCOUNT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const LIST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TempState(PathBuf);

impl TempState {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "cloudflare-bouncer-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )))
    }

    fn args(&self) -> CloudflareArgs {
        CloudflareArgs {
            cloudflare_enabled: true,
            cloudflare_api_token: Some("test-token".into()),
            cloudflare_account_id: Some(ACCOUNT.into()),
            cloudflare_list_id: Some(LIST.into()),
            cloudflare_state_path: Some(self.0.join("state.json")),
            ..Default::default()
        }
    }

    fn config(&self) -> CloudflareConfig {
        self.args().config().unwrap().unwrap()
    }
}

impl Drop for TempState {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn nets(values: &[&str]) -> IpRangeMixed {
    IpRangeMixed::from(
        values
            .iter()
            .map(|value| super::parse_net(value).unwrap())
            .collect::<Vec<_>>(),
    )
}

fn path(suffix: &str) -> String {
    format!("/accounts/{ACCOUNT}/rules/lists/{LIST}{suffix}")
}
fn operation_path(id: &str) -> String {
    format!("/accounts/{ACCOUNT}/rules/lists/bulk_operations/{id}")
}

async fn sync(temp: &TempState, server: &Server) -> CloudflareSync {
    let mut sync = CloudflareSync::new(temp.config()).await.unwrap();
    sync.client.base = format!("{}/", server.url()).parse().unwrap();
    sync.client.request_interval = Duration::ZERO;
    sync.poll_interval = Duration::ZERO;
    sync
}

fn envelope(result: Value) -> String {
    json!({"success": true, "result": result}).to_string()
}

fn read_state(server: &mut ServerGuard, items: &[(&str, &str)]) -> Vec<Mock> {
    vec![
        server
            .mock("GET", path("").as_str())
            .match_header("authorization", "Bearer test-token")
            .with_body(envelope(json!({"kind": "ip", "num_items": items.len()})))
            .expect(1)
            .create(),
        server
            .mock("GET", path("/items").as_str())
            .match_query(Matcher::UrlEncoded("per_page".into(), "500".into()))
            .with_body(envelope(json!(items
                .iter()
                .map(|(id, ip)| json!({"id": id, "ip": ip}))
                .collect::<Vec<_>>())))
            .expect(1)
            .create(),
    ]
}

fn completed(server: &mut ServerGuard, id: &str) -> Mock {
    server
        .mock("GET", operation_path(id).as_str())
        .with_body(envelope(json!({"status": "completed"})))
        .expect(1)
        .create()
}

fn mutation(server: &mut ServerGuard, method: &str, body: Value, id: &str) -> Mock {
    server
        .mock(method, path("/items").as_str())
        .match_body(Matcher::Json(body))
        .with_status(201)
        .with_body(envelope(json!({"operation_id": id})))
        .expect(1)
        .create()
}

#[test]
fn disabled_by_default_even_with_partial_or_invalid_configuration() {
    let args = CloudflareArgs {
        cloudflare_api_token: Some("test-token".into()),
        cloudflare_max_items: 0,
        ..Default::default()
    };
    assert!(args.config().unwrap().is_none());
    assert!(!format!("{args:?}").contains("test-token"));
}

#[test]
fn enabled_requires_complete_configuration_and_free_plan_cap() {
    let temp = TempState::new();
    let mut args = temp.args();
    args.cloudflare_api_token = None;
    assert!(args
        .config()
        .err()
        .unwrap()
        .to_string()
        .contains("CLOUDFLARE_API_TOKEN"));
    args = temp.args();
    args.cloudflare_state_path = None;
    assert!(args
        .config()
        .err()
        .unwrap()
        .to_string()
        .contains("CLOUDFLARE_STATE_PATH"));
    args = temp.args();
    args.cloudflare_max_items = 10_001;
    assert!(args.config().is_err());
    args = temp.args();
    args.cloudflare_account_id = Some("../../elsewhere".into());
    assert!(args.config().is_err());
    args = temp.args();
    args.cloudflare_sync_interval_secs = 0;
    assert!(args.config().is_err());
    args = temp.args();
    args.cloudflare_reconcile_interval_secs = 0;
    assert!(args.config().is_err());
}

#[test]
fn publishes_full_and_incremental_snapshots_without_waiting_for_cloudflare() {
    let (publisher, snapshots) = DecisionPublisher::channel();
    publisher.publish_incremental(&DecisionsIpRange {
        new: nets(&["192.0.2.1"]),
        deleted: nets(&[]),
    });
    assert!(snapshots.borrow().is_none());
    publisher.publish_full(nets(&["192.0.2.1", "2001:db8::1"]));
    publisher.publish_incremental(&DecisionsIpRange {
        new: nets(&["198.51.100.3"]),
        deleted: nets(&["192.0.2.1"]),
    });
    assert_eq!(
        **snapshots.borrow().as_ref().unwrap(),
        nets(&["198.51.100.3", "2001:db8::1"])
    );
}

#[test]
fn normalizes_and_splits_ranges_without_broadening_bans() {
    let input = nets(&["0.0.0.0/7", "2000::/11", "192.0.2.0/32", "192.0.2.1/32"]);
    let result = candidates(&input);
    assert!(result.contains(&"0.0.0.0/8".parse().unwrap()));
    assert!(result.contains(&"1.0.0.0/8".parse().unwrap()));
    assert!(result.contains(&"2000::/12".parse().unwrap()));
    assert!(result.contains(&"2010::/12".parse().unwrap()));
    assert!(result.contains(&"192.0.2.0/31".parse().unwrap()));
    assert_eq!(
        IpRangeMixed::from(result.into_iter().collect::<Vec<_>>()),
        input
    );
}

#[test]
fn cap_keeps_existing_active_entries_and_fills_vacancies_deterministically() {
    let candidates = candidates(&nets(&["192.0.2.1", "192.0.2.3", "192.0.2.5"]));
    let actual = [(super::parse_net("192.0.2.5").unwrap(), Some("id".into()))]
        .into_iter()
        .collect();
    let desired = select_desired(&candidates, &actual, 2);
    assert_eq!(
        desired,
        [
            super::parse_net("192.0.2.1").unwrap(),
            super::parse_net("192.0.2.5").unwrap()
        ]
        .into_iter()
        .collect::<BTreeSet<_>>()
    );
}

#[tokio::test]
async fn batches_only_differences_and_sends_no_requests_when_unchanged() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let reads = read_state(
        &mut server,
        &[("keep", "192.0.2.1"), ("stale", "2001:db8::1")],
    );
    let delete = mutation(
        &mut server,
        "DELETE",
        json!({"items": [{"id": "stale"}]}),
        "delete",
    );
    let deleted = completed(&mut server, "delete");
    let add = mutation(
        &mut server,
        "POST",
        json!([{"ip": "2001:db8::2/128"}]),
        "add",
    );
    let added = completed(&mut server, "add");
    let snapshot = nets(&["192.0.2.1", "2001:db8::2"]);
    sync.sync_once(&snapshot).await.unwrap();
    sync.sync_once(&snapshot).await.unwrap();
    for read in reads {
        read.assert();
    }
    delete.assert();
    deleted.assert();
    add.assert();
    added.assert();
    assert_eq!(sync.state.items.len(), 2);
    assert!(sync.state.pending.is_none());
    assert_eq!(sync.state.reservations.len(), 2);
    let saved = tokio::fs::read_to_string(&sync.config.state_path)
        .await
        .unwrap();
    assert!(!saved.contains("test-token"));
}

#[tokio::test]
async fn reads_every_cursor_before_calculating_diff() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let metadata = server
        .mock("GET", path("").as_str())
        .with_body(envelope(json!({"kind": "ip", "num_items": 2})))
        .expect(1)
        .create();
    let first = server
        .mock("GET", path("/items").as_str())
        .match_query(Matcher::UrlEncoded("per_page".into(), "500".into()))
        .with_body(
            json!({"success": true, "result": [{"id":"v4", "ip":"192.0.2.1"}],
            "result_info":{"cursors":{"after":"opaque+cursor/="}}})
            .to_string(),
        )
        .expect(1)
        .create();
    let second = server
        .mock("GET", path("/items").as_str())
        .match_query(Matcher::AllOf(vec![
            Matcher::UrlEncoded("per_page".into(), "500".into()),
            Matcher::UrlEncoded("cursor".into(), "opaque+cursor/=".into()),
        ]))
        .with_body(envelope(json!([{"id":"v6", "ip":"2001:0DB8:0:0::1"}])))
        .expect(1)
        .create();
    sync.sync_once(&nets(&["192.0.2.1", "2001:db8::1"]))
        .await
        .unwrap();
    metadata.assert();
    first.assert();
    second.assert();
    assert_eq!(sync.state.items.len(), 2);
}

#[tokio::test]
async fn incomplete_page_read_cannot_replace_confirmed_cache_or_delete_entries() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let metadata = server
        .mock("GET", path("").as_str())
        .with_body(envelope(json!({"kind": "ip", "num_items": 2})))
        .create();
    let page = server
        .mock("GET", path("/items").as_str())
        .match_query(Matcher::Any)
        .with_body(envelope(json!([])))
        .create();
    sync.state
        .items
        .insert(super::parse_net("192.0.2.1").unwrap(), Some("keep".into()));
    assert!(sync.sync_once(&nets(&[])).await.is_err());
    metadata.assert();
    page.assert();
    assert_eq!(sync.state.items.len(), 1);
}

#[tokio::test]
async fn startup_reconciles_remote_drift_and_retains_persistent_quota_history() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut original = sync(&temp, &server).await;
    original.state.items.insert(
        super::parse_net("198.51.100.1").unwrap(),
        Some("local-only".into()),
    );
    assert!(original.state.reserve(123, now()));
    original.store.save(&original.state).await.unwrap();
    drop(original);
    let mut restarted = sync(&temp, &server).await;
    let reads = read_state(&mut server, &[("remote-only", "192.0.2.1")]);
    let delete = mutation(
        &mut server,
        "DELETE",
        json!({"items": [{"id":"remote-only"}]}),
        "delete",
    );
    let done = completed(&mut server, "delete");
    restarted.sync_once(&nets(&[])).await.unwrap();
    for read in reads {
        read.assert();
    }
    delete.assert();
    done.assert();
    assert!(restarted.state.items.is_empty());
    assert_eq!(restarted.state.reservations.len(), 2);
    assert_eq!(restarted.state.reservations[0].modifications, 123);
}

#[tokio::test]
async fn restart_finishes_journaled_operation_before_reconciling_new_decisions() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut original = sync(&temp, &server).await;
    original.state.pending = Some(Pending {
        operation_id: Some("in-flight".into()),
        submitted_at: now(),
        mutation: Mutation::Add(vec![super::parse_net("192.0.2.1").unwrap()]),
    });
    original.store.save(&original.state).await.unwrap();
    drop(original);
    let mut restarted = sync(&temp, &server).await;
    let pending = completed(&mut server, "in-flight");
    let reads = read_state(&mut server, &[("restored-id", "192.0.2.1")]);
    restarted.sync_once(&nets(&["192.0.2.1"])).await.unwrap();
    pending.assert();
    for read in reads {
        read.assert();
    }
    assert!(restarted.state.pending.is_none());
    assert_eq!(restarted.state.items.len(), 1);
}

#[tokio::test]
async fn ambiguous_write_is_relisted_before_retrying() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    sync.state.pending = Some(Pending {
        operation_id: None,
        submitted_at: now(),
        mutation: Mutation::Add(vec![super::parse_net("192.0.2.1").unwrap()]),
    });
    assert!(sync.sync_once(&nets(&["192.0.2.1"])).await.is_err());
    sync.state.pending.as_mut().unwrap().submitted_at = now() - 61;
    let reads = read_state(&mut server, &[("already-added", "192.0.2.1")]);
    sync.sync_once(&nets(&["192.0.2.1"])).await.unwrap();
    for read in reads {
        read.assert();
    }
    assert!(sync.state.pending.is_none());
}

#[tokio::test]
async fn failed_operation_keeps_confirmed_state_until_a_fresh_read() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let reads = read_state(&mut server, &[]);
    let add = mutation(
        &mut server,
        "POST",
        json!([{"ip":"192.0.2.1/32"}]),
        "failed",
    );
    let failure = server
        .mock("GET", operation_path("failed").as_str())
        .with_body(envelope(
            json!({"status":"failed", "error":"quota exceeded"}),
        ))
        .expect(1)
        .create();
    assert!(sync.sync_once(&nets(&["192.0.2.1"])).await.is_err());
    for read in reads {
        read.assert();
    }
    add.assert();
    failure.assert();
    assert!(sync.state.items.is_empty());
    assert!(sync.needs_refresh);
    assert!(sync.state.pending.is_none());
}

#[tokio::test]
async fn rate_limit_cooldown_is_persisted_and_honored_after_restart() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut original = sync(&temp, &server).await;
    let limited = server
        .mock("GET", path("").as_str())
        .with_status(429)
        .with_header("retry-after", "7200")
        .with_body("temporarily rate limited")
        .expect(1)
        .create();
    let mut failures = 0;
    assert!(original.tick(&nets(&[]), &mut failures).await.is_err());
    assert!(original.state.cooldown_until >= now() + 7199);
    limited.assert();
    drop(original);
    let mut restarted = sync(&temp, &server).await;
    restarted.tick(&nets(&[]), &mut failures).await.unwrap();
    limited.assert();
}

#[tokio::test]
async fn local_budget_defers_writes_until_old_reservations_expire() {
    let temp = TempState::new();
    let server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let time = now();
    sync.state.reservations.push_back(Reservation {
        at: time,
        modifications: 900_000,
    });
    assert!(!sync.state.reserve(1, time));
    assert_eq!(sync.state.cooldown_until, time + QUOTA_WINDOW_SECS);
    assert!(sync.state.reserve(1, time + QUOTA_WINDOW_SECS));
    assert_eq!(sync.state.reservations.len(), 1);
}

#[tokio::test]
async fn state_lock_prevents_two_writers_and_releases_on_drop() {
    let temp = TempState::new();
    let server = Server::new_async().await;
    let original = sync(&temp, &server).await;
    assert!(CloudflareSync::new(temp.config()).await.is_err());
    drop(original);
    assert!(CloudflareSync::new(temp.config()).await.is_ok());
}

#[tokio::test]
async fn no_cloudflare_requests_before_first_successful_crowdsec_snapshot() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let sync = sync(&temp, &server).await;
    let unexpected = server.mock("GET", path("").as_str()).expect(0).create();
    let (_publisher, snapshots) = DecisionPublisher::channel();
    assert!(
        tokio::time::timeout(Duration::from_millis(30), sync.run(snapshots))
            .await
            .is_err()
    );
    unexpected.assert();
}

#[tokio::test]
async fn additions_are_split_into_bounded_bulk_requests() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let reads = read_state(&mut server, &[]);
    let snapshot = IpRangeMixed::from(
        (0..1001)
            .map(|i| format!("10.{}.{}.1/32", i / 256, i % 256).parse().unwrap())
            .collect::<Vec<_>>(),
    );
    let expected = candidates(&snapshot).into_iter().collect::<Vec<_>>();
    let first = mutation(
        &mut server,
        "POST",
        json!(expected[..1000]
            .iter()
            .map(|net| json!({"ip":net.to_string()}))
            .collect::<Vec<_>>()),
        "first",
    );
    let second = mutation(
        &mut server,
        "POST",
        json!([{"ip":expected[1000].to_string()}]),
        "second",
    );
    let first_done = completed(&mut server, "first");
    let second_done = completed(&mut server, "second");
    sync.sync_once(&snapshot).await.unwrap();
    for read in reads {
        read.assert();
    }
    first.assert();
    second.assert();
    first_done.assert();
    second_done.assert();
    assert_eq!(sync.state.items.len(), 1001);
    assert_eq!(sync.state.reservations.len(), 2);
}

#[tokio::test]
async fn periodic_refresh_repairs_remote_drift() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    sync.state.items.insert(
        super::parse_net("192.0.2.1").unwrap(),
        Some("old-id".into()),
    );
    sync.needs_refresh = false;
    sync.last_refresh = Some(tokio::time::Instant::now() - sync.config.reconcile_interval);
    let reads = read_state(&mut server, &[]);
    let add = mutation(
        &mut server,
        "POST",
        json!([{"ip":"192.0.2.1/32"}]),
        "repair",
    );
    let done = completed(&mut server, "repair");
    sync.sync_once(&nets(&["192.0.2.1"])).await.unwrap();
    for read in reads {
        read.assert();
    }
    add.assert();
    done.assert();
}

#[tokio::test]
async fn deletion_of_a_recently_added_item_reads_its_id_only_when_needed() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    sync.state
        .items
        .insert(super::parse_net("192.0.2.1").unwrap(), None);
    sync.needs_refresh = false;
    sync.last_refresh = Some(tokio::time::Instant::now());
    let reads = read_state(&mut server, &[("resolved-id", "192.0.2.1")]);
    let delete = mutation(
        &mut server,
        "DELETE",
        json!({"items":[{"id":"resolved-id"}]}),
        "delete",
    );
    let done = completed(&mut server, "delete");
    sync.sync_once(&nets(&[])).await.unwrap();
    for read in reads {
        read.assert();
    }
    delete.assert();
    done.assert();
    assert!(sync.state.items.is_empty());
}

#[tokio::test]
async fn success_response_with_exhausted_rate_header_defers_the_next_request() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let exhausted = server
        .mock("GET", path("").as_str())
        .with_header("ratelimit", "\"default\";r=0;t=1800")
        .with_body(envelope(json!({"kind":"ip", "num_items":0})))
        .expect(1)
        .create();
    let mut failures = 0;
    assert!(sync.tick(&nets(&[]), &mut failures).await.is_err());
    exhausted.assert();
    assert!(sync.state.cooldown_until >= now() + 1799);
    assert!(sync.needs_refresh);
}

#[tokio::test]
async fn pending_operation_is_polled_without_repeating_the_write() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    let reads = read_state(&mut server, &[]);
    let add = mutation(&mut server, "POST", json!([{"ip":"192.0.2.1/32"}]), "slow");
    let running = server
        .mock("GET", operation_path("slow").as_str())
        .with_body(envelope(json!({"status":"running"})))
        .expect(12)
        .create();
    assert!(sync.sync_once(&nets(&["192.0.2.1"])).await.is_err());
    assert!(sync.sync_once(&nets(&["192.0.2.1"])).await.is_err());
    for read in reads {
        read.assert();
    }
    add.assert();
    running.assert();
    assert!(sync.state.pending.is_some());
    assert!(sync.state.items.is_empty());
    assert_eq!(sync.state.reservations.len(), 1);
}

#[tokio::test]
async fn expired_operation_record_falls_back_to_reading_actual_list() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut sync = sync(&temp, &server).await;
    sync.state.pending = Some(Pending {
        operation_id: Some("expired".into()),
        submitted_at: now() - 120,
        mutation: Mutation::Add(vec![super::parse_net("192.0.2.1").unwrap()]),
    });
    let expired = server
        .mock("GET", operation_path("expired").as_str())
        .with_status(404)
        .with_body(
            json!({"success":false,"errors":[{"code":1001,"message":"Unknown operation"}]})
                .to_string(),
        )
        .expect(1)
        .create();
    assert!(sync.sync_once(&nets(&["192.0.2.1"])).await.is_err());
    expired.assert();
    let reads = read_state(&mut server, &[("actual-id", "192.0.2.1")]);
    sync.sync_once(&nets(&["192.0.2.1"])).await.unwrap();
    for read in reads {
        read.assert();
    }
    assert!(sync.state.pending.is_none());
}

#[tokio::test]
async fn rate_limited_write_preserves_journal_and_budget_across_restart() {
    let temp = TempState::new();
    let mut server = Server::new_async().await;
    let mut original = sync(&temp, &server).await;
    let reads = read_state(&mut server, &[]);
    let limited = server
        .mock("POST", path("/items").as_str())
        .match_body(Matcher::Json(json!([{"ip":"192.0.2.1/32"}])))
        .with_status(429)
        .with_header("retry-after", "3600")
        .with_body(
            json!({"success":false,"errors":[{"code":10000,"message":"rate limited"}]}).to_string(),
        )
        .expect(1)
        .create();
    let mut failures = 0;
    assert!(original
        .tick(&nets(&["192.0.2.1"]), &mut failures)
        .await
        .is_err());
    for read in reads {
        read.assert();
    }
    limited.assert();
    assert!(original.state.items.is_empty());
    assert!(original
        .state
        .pending
        .as_ref()
        .unwrap()
        .operation_id
        .is_none());
    assert_eq!(original.state.reservations.len(), 1);
    drop(original);
    let mut restarted = sync(&temp, &server).await;
    restarted
        .tick(&nets(&["192.0.2.1"]), &mut failures)
        .await
        .unwrap();
    assert!(restarted.state.pending.is_some());
    assert_eq!(restarted.state.reservations.len(), 1);
    limited.assert();
}
