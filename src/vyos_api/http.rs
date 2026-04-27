use std::time::Duration;

use ipnet::IpNet;
use reqwest::header::ALLOW;
use reqwest::multipart::Form;
use reqwest::{Client, StatusCode, Url};
use serde::{de::DeserializeOwned, Serialize};
use tracing::instrument;

use crate::metrics::OUTGOING_REQUESTS_COUNTER;
use crate::USER_AGENT;

use super::interface::VyosApi;
use super::types::{
    ipv4_group_exists, ipv4_group_get, ipv6_group_exists, ipv6_group_get, VyosCommandResponse,
    VyosConfigCommand,
};
use super::VyosSaveCommand;

#[derive(Debug)]
pub struct VyosClient {
    client: Client,
    host: Url,
    apikey: String,
}

impl VyosClient {
    pub fn new(host: Url, apikey: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(5))
            .danger_accept_invalid_certs(true)
            .use_rustls_tls()
            .user_agent(USER_AGENT)
            .build()
            .expect("failed to build client");
        Self {
            client,
            host,
            apikey,
        }
    }
}

impl VyosClient {
    fn url(&self, path: &str) -> Url {
        self.host.join(path).expect("invalid url")
    }

    #[instrument(level = "debug", skip(self, payload, timeout), fields(path))]
    async fn send<T: DeserializeOwned, P: Serialize>(
        &self,
        path: &str,
        payload: P,
        timeout: Option<Duration>,
    ) -> Result<T, anyhow::Error> {
        let url = self.url(path);

        let form = Form::new()
            .text("key", self.apikey.clone())
            .text("data", serde_json::to_string(&payload)?);

        let req = self.client.post(url).multipart(form);
        let req = if let Some(duration) = timeout {
            req.timeout(duration)
        } else {
            req
        };

        let resp = req.send().await?;

        match resp.error_for_status_ref() {
            Ok(_) => Ok(resp.json().await?),
            Err(err) => {
                let status = resp.status();
                let allow = resp
                    .headers()
                    .get(ALLOW)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                let body = resp.text().await.unwrap_or_default();

                if err.status() == Some(StatusCode::BAD_REQUEST) {
                    let detail = serde_json::from_str::<serde_json::Value>(&body)
                        .map(|value| value.to_string())
                        .unwrap_or(body);
                    Err(anyhow::anyhow!(detail))
                } else {
                    let allow = allow
                        .map(|value| format!(", allow={value}"))
                        .unwrap_or_default();
                    let body = if body.is_empty() {
                        String::new()
                    } else {
                        format!(", body={body}")
                    };
                    Err(anyhow::anyhow!(
                        "VyOS API request to {} failed with status {}{}{}",
                        path,
                        status,
                        allow,
                        body
                    ))
                }
            }
        }
    }
}

impl VyosApi for VyosClient {
    #[instrument(skip(self, commands, timeout))]
    async fn set_firewall_groups<'a>(
        &self,
        commands: &[VyosConfigCommand<'a>],
        timeout: Option<Duration>,
    ) -> Result<(), anyhow::Error> {
        self.send::<serde_json::Value, _>("/configure", commands, timeout)
            .await?;
        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/configure"])
            .inc();
        Ok(())
    }
    #[instrument(skip(self, timeout))]
    async fn save_config(&self, timeout: Option<Duration>) -> Result<(), anyhow::Error> {
        self.send::<serde_json::Value, _>("/config-file", VyosSaveCommand::default(), timeout)
            .await?;
        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/config-file"])
            .inc();
        Ok(())
    }
    #[instrument(skip(self))]
    async fn retrieve_firewall_network_groups(
        &self,
        group_name: &str,
    ) -> Result<VyosCommandResponse<Vec<IpNet>>, anyhow::Error> {
        OUTGOING_REQUESTS_COUNTER
            .with_label_values(&["VYOS", "/retrieve"])
            .inc_by(2);

        let ipv4_exists = self
            .send::<VyosCommandResponse<bool>, _>("/retrieve", ipv4_group_exists(group_name), None)
            .await?;

        let ipv4 = if ipv4_exists.data {
            OUTGOING_REQUESTS_COUNTER
                .with_label_values(&["VYOS", "/retrieve"])
                .inc();
            self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
                "/retrieve",
                ipv4_group_get(group_name),
                None,
            )
            .await?
            .data
        } else {
            Vec::new()
        };

        let ipv6_exists = self
            .send::<VyosCommandResponse<bool>, _>("/retrieve", ipv6_group_exists(group_name), None)
            .await?;

        let mut ipv6 = if ipv6_exists.data {
            OUTGOING_REQUESTS_COUNTER
                .with_label_values(&["VYOS", "/retrieve"])
                .inc();
            self.send::<VyosCommandResponse<Vec<IpNet>>, _>(
                "/retrieve",
                ipv6_group_get(group_name),
                None,
            )
            .await?
            .data
        } else {
            Vec::new()
        };

        let mut ips = VyosCommandResponse {
            success: true,
            data: ipv4,
            error: None,
        };
        ips.data.append(&mut ipv6);

        Ok(ips)
    }
}
