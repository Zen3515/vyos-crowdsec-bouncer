use std::collections::HashMap;
use std::fmt;
use std::time::Duration;

use anyhow::{bail, Context};
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::{Client, Method, Url};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::Value;
use tokio::time::Instant;

use crate::metrics::OUTGOING_REQUESTS_COUNTER;

#[derive(Deserialize)]
pub(super) struct ApiResponse<T> {
    pub success: bool,
    pub result: Option<T>,
    pub result_info: Option<ResultInfo>,
    #[serde(default)]
    pub errors: Vec<ApiError>,
}

#[derive(Deserialize)]
pub(super) struct ResultInfo {
    pub cursors: Option<Cursors>,
}

#[derive(Deserialize)]
pub(super) struct Cursors {
    pub after: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(super) struct ApiError {
    pub code: u64,
    pub message: String,
}

#[derive(Debug)]
pub(super) struct ApiFailure {
    pub status: reqwest::StatusCode,
    message: String,
}

impl fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Cloudflare API HTTP {}: {}", self.status, self.message)
    }
}

impl std::error::Error for ApiFailure {}

pub(super) struct CloudflareClient {
    client: Client,
    pub base: Url,
    pub cooldown_until: u64,
    next_request: Instant,
    pub request_interval: Duration,
}

pub(super) fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn retry_after(headers: &HeaderMap) -> Option<u64> {
    let value = headers.get("retry-after")?.to_str().ok()?;
    value
        .parse::<u64>()
        .ok()
        .map(|seconds| now().saturating_add(seconds))
        .or_else(|| {
            chrono::DateTime::parse_from_rfc2822(value)
                .ok()
                .map(|date| date.timestamp().max(0) as u64)
        })
}

impl CloudflareClient {
    pub fn new(token: &str) -> anyhow::Result<Self> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {token}"))
            .context("Invalid CLOUDFLARE_API_TOKEN header")?;
        authorization.set_sensitive(true);
        let mut headers = HeaderMap::new();
        headers.insert(reqwest::header::AUTHORIZATION, authorization);
        let client = Client::builder()
            .default_headers(headers)
            .user_agent(crate::USER_AGENT)
            .timeout(Duration::from_secs(30))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            base: "https://api.cloudflare.com/client/v4/".parse()?,
            cooldown_until: 0,
            next_request: Instant::now(),
            // At most 300 requests / five minutes, leaving room for other API clients.
            request_interval: Duration::from_secs(1),
        })
    }

    pub async fn request<T: DeserializeOwned>(
        &mut self,
        method: Method,
        path: &str,
        query: &[(&str, String)],
        body: Option<Value>,
    ) -> anyhow::Result<ApiResponse<T>> {
        if self.cooldown_until > now() {
            bail!("Cloudflare API cooldown until {}", self.cooldown_until);
        }
        tokio::time::sleep_until(self.next_request).await;
        self.next_request = Instant::now() + self.request_interval;
        let metric_path = if path.contains("/bulk_operations/") {
            "/rules/lists/bulk_operations"
        } else if path.ends_with("/items") {
            "/rules/lists/items"
        } else {
            "/rules/lists"
        };
        OUTGOING_REQUESTS_COUNTER
            .with(&HashMap::from([
                ("destination", "CLOUDFLARE"),
                ("path", metric_path),
            ]))
            .inc();
        let mut request = self
            .client
            .request(method, self.base.join(path)?)
            .query(query);
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.context("Cloudflare request failed")?;
        let status = response.status();
        let retry_until = retry_after(response.headers());
        if let Some(until) = retry_until {
            self.cooldown_until = self.cooldown_until.max(until);
        }
        // Honor exhausted quota headers even on a successful response.
        if let Some(policy) = response
            .headers()
            .get("ratelimit")
            .and_then(|value| value.to_str().ok())
        {
            for item in policy.split(',') {
                let fields = item.split(';').map(str::trim).collect::<Vec<_>>();
                if fields.contains(&"r=0") {
                    if let Some(seconds) = fields
                        .iter()
                        .find_map(|field| field.strip_prefix("t=")?.parse::<u64>().ok())
                    {
                        self.cooldown_until =
                            self.cooldown_until.max(now().saturating_add(seconds));
                    }
                }
            }
        }
        // Set the delay before decoding: some 429 responses contain HTML rather than JSON.
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            self.cooldown_until = self.cooldown_until.max(retry_until.unwrap_or(now() + 60));
        }
        let result = match response.json::<ApiResponse<T>>().await {
            Ok(result) => result,
            Err(error) => {
                if !status.is_success() {
                    return Err(ApiFailure {
                        status,
                        message: "Response body could not be decoded".into(),
                    }
                    .into());
                }
                return Err(error).context("Invalid Cloudflare API JSON response");
            }
        };
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS
            && retry_until.is_none()
            && result.errors.iter().any(|error| error.code == 10040)
        {
            // A CrowdSec-managed integration list may permit only one operation per day.
            self.cooldown_until = self.cooldown_until.max(now() + 24 * 60 * 60);
        }
        if !status.is_success() || !result.success {
            let errors = result
                .errors
                .iter()
                .map(|error| format!("{}: {}", error.code, error.message))
                .collect::<Vec<_>>()
                .join("; ");
            return Err(ApiFailure {
                status,
                message: errors,
            }
            .into());
        }
        Ok(result)
    }
}
