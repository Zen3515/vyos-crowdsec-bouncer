use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use axum_server::Server;
use tracing::{error, info, instrument};

use crate::blacklist::{BlacklistCache, IpRangeMixed};
use crate::crowdsec_lapi::types::DecisionsIpRange;
use crate::crowdsec_lapi::DEFAULT_DECISION_ORIGINS;
use crate::crowdsec_lapi::{CrowdsecLAPI, CrowdsecLapiClient, DecisionsOptions};

#[derive(Debug)]
pub struct RemoteGroupState {
    blacklist: BlacklistCache,
    ready: AtomicBool,
}

impl Default for RemoteGroupState {
    fn default() -> Self {
        Self {
            blacklist: BlacklistCache::default(),
            ready: AtomicBool::new(false),
        }
    }
}

impl RemoteGroupState {
    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    fn store_blacklist(&self, blacklist: IpRangeMixed) {
        self.blacklist.store(blacklist);
        self.ready.store(true, Ordering::SeqCst);
    }
}

pub struct RemoteGroupApp {
    lapi: CrowdsecLapiClient,
    trusted_ips: IpRangeMixed,
    update_period: Duration,
    state: Arc<RemoteGroupState>,
}

impl RemoteGroupApp {
    pub fn new(
        lapi: CrowdsecLapiClient,
        trusted_ips: IpRangeMixed,
        update_period: Duration,
        state: Arc<RemoteGroupState>,
    ) -> Self {
        Self {
            lapi,
            trusted_ips,
            update_period,
            state,
        }
    }
}

pub struct RemoteGroupServer {
    server: Server,
    path: String,
    state: Arc<RemoteGroupState>,
}

impl RemoteGroupServer {
    pub fn new(addr: SocketAddr, path: String, state: Arc<RemoteGroupState>) -> Self {
        Self {
            server: axum_server::bind(addr),
            path,
            state,
        }
    }

    pub async fn serve(self) -> std::io::Result<()> {
        info!(path = self.path, "Starting remote-group feed server");
        let router = Router::new()
            .route(&self.path, get(remote_group_feed))
            .with_state(self.state)
            .into_make_service();
        self.server.serve(router).await
    }
}

fn format_blacklist(blacklist: &IpRangeMixed) -> String {
    let mut body = blacklist
        .into_nets()
        .into_iter()
        .map(|net| net.to_string())
        .collect::<Vec<_>>()
        .join("\n");

    if !body.is_empty() {
        body.push('\n');
    }

    body
}

async fn remote_group_feed(State(state): State<Arc<RemoteGroupState>>) -> Response {
    if !state.is_ready() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "CrowdSec blacklist has not synced yet\n",
        )
            .into_response();
    }

    (
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        format_blacklist(&state.blacklist.load()),
    )
        .into_response()
}

#[instrument(skip(app))]
pub async fn sync_once(app: &RemoteGroupApp) -> Result<(), anyhow::Error> {
    let decision_options = DecisionsOptions::new(&DEFAULT_DECISION_ORIGINS, true);
    let desired_decisions = app.lapi.stream_decisions(&decision_options).await?;
    let desired_blacklist = DecisionsIpRange::from(desired_decisions)
        .new
        .exclude(&app.trusted_ips);
    let entry_count = desired_blacklist.net_count();

    app.state.store_blacklist(desired_blacklist);
    info!(
        entry_count,
        "Updated remote-group feed from CrowdSec active decisions"
    );

    Ok(())
}

pub async fn sync_loop(app: RemoteGroupApp) -> Result<(), anyhow::Error> {
    info!("Starting remote-group sync loop");

    loop {
        if let Err(err) = sync_once(&app).await {
            error!(
                ?err,
                ready = app.state.is_ready(),
                "Failed to refresh remote-group feed; serving previous successful list if available"
            );
        }

        tokio::time::sleep(app.update_period).await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use iprange::IpRange;
    use mockito::{Matcher, Server};
    use reqwest::Url;

    use crate::blacklist::IpRangeMixed;
    use crate::crowdsec_lapi::types::{CrowdsecAuth, Decision, DecisionsResponse, Scope};
    use crate::crowdsec_lapi::CrowdsecLapiClient;

    use super::{format_blacklist, remote_group_feed, sync_once, RemoteGroupApp, RemoteGroupState};

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

    fn mock_decisions<'a>(cidrs_new: impl IntoIterator<Item = &'a str>) -> DecisionsResponse {
        DecisionsResponse {
            new: Some(cidrs_new.into_iter().map(mock_decision).collect()),
            deleted: None,
        }
    }

    fn lapi_client(apikey: String, mock: &Server) -> CrowdsecLapiClient {
        let url = format!("http://{}", mock.host_with_port());
        CrowdsecLapiClient::new(
            Url::parse(&url).unwrap(),
            CrowdsecAuth::Apikey(apikey),
            std::time::Duration::from_secs(1),
        )
    }

    #[test]
    fn formats_remote_group_feed_as_newline_delimited_nets() {
        let blacklist = IpRangeMixed::from(vec![
            "203.0.113.0/24".parse().unwrap(),
            "2001:db8::/64".parse().unwrap(),
        ]);

        let actual = format_blacklist(&blacklist);

        assert!(actual.contains("203.0.113.0/24\n"));
        assert!(actual.contains("2001:db8::/64\n"));
    }

    #[tokio::test]
    async fn sync_once_stores_full_crowdsec_list_and_filters_trusted_ips() {
        let apikey = "test_key";
        let mut mock = Server::new_async().await;
        let decisions = mock_decisions(["203.0.113.1", "198.51.100.0/24"]);
        let lapi_stream = mock
            .mock("GET", "/v1/decisions/stream")
            .match_query(Matcher::AllOf(vec![
                Matcher::UrlEncoded(String::from("startup"), String::from("true")),
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
            .create();
        let state = Arc::new(RemoteGroupState::default());
        let app = RemoteGroupApp::new(
            lapi_client(apikey.to_string(), &mock),
            IpRangeMixed::from(vec!["203.0.113.1/32".parse().unwrap()]),
            std::time::Duration::from_secs(1),
            Arc::clone(&state),
        );

        sync_once(&app).await.unwrap();

        lapi_stream.assert();
        assert!(state.is_ready());
        assert_eq!(
            state.blacklist.load().v4,
            IpRange::from_iter(
                ["198.51.100.0/24"]
                    .into_iter()
                    .map(|net| net.parse().unwrap())
            )
        );
    }

    #[tokio::test]
    async fn feed_returns_503_before_first_successful_sync() {
        let state = Arc::new(RemoteGroupState::default());

        let response = remote_group_feed(axum::extract::State(state)).await;

        assert_eq!(
            response.status(),
            axum::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
