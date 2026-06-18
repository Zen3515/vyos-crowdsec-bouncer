use std::net::SocketAddr;
use std::path::PathBuf;

use clap::{Args, Parser, ValueEnum};
use ipnet::IpNet;
use reqwest::Url;

use crate::crowdsec_lapi::types::CrowdsecAuth;
use crate::utils::read_file;

#[derive(Parser, Debug)]
#[command(version = crate::VERSION, about, long_about = None)]
pub struct Cli {
    #[arg(long, env = "BOUNCER_MODE", value_enum, default_value_t = BouncerMode::VyosApi)]
    pub mode: BouncerMode,

    #[arg(long, env, num_args = 1..)]
    pub trusted_ips: Option<Vec<IpNet>>,

    #[arg(long, env = "UPDATE_FREQUENCY_SECS", default_value = "60")]
    pub update_period_secs: u64,

    /// Periodically reconcile the whole VyOS group against CrowdSec active decisions. Set to 0 to disable.
    #[arg(long, env = "FULL_SYNC_INTERVAL_SECS", default_value = "900")]
    pub full_sync_interval_secs: u64,

    #[arg(long, env = "VYOS_APIKEY")]
    pub vyos_apikey: Option<String>,

    #[arg(long, env = "VYOS_API")]
    pub vyos_api: Option<Url>,

    #[arg(long, env = "CROWDSEC_TIMEOUT", default_value = "10")]
    pub crowdsec_timeout: u64,

    #[arg(long, env = "FIREWALL_GROUP", default_value = "CROWDSEC_BOUNCER")]
    pub firewall_group: String,

    #[arg(long, env = "VYOS_SAVE_CONFIG", default_value = "false")]
    pub vyos_save_config: bool,

    #[arg(long, env = "CROWDSEC_API", default_value = "http://localhost:8080")]
    pub crowdsec_api: Url,

    #[arg(long, env = "METRICS_BIND", default_value = "127.0.0.1:3000")]
    pub metrics_bind: SocketAddr,

    #[arg(long, env = "REMOTE_GROUP_BIND", default_value = "0.0.0.0:8080")]
    pub remote_group_bind: SocketAddr,

    #[arg(long, env = "REMOTE_GROUP_PATH", default_value = "/crowdsec")]
    pub remote_group_path: String,

    #[command(flatten)]
    pub auth: Auth,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "kebab-case")]
pub enum BouncerMode {
    VyosApi,
    RemoteGroup,
}

impl Cli {
    pub fn validate(&self) -> Result<(), anyhow::Error> {
        if matches!(self.mode, BouncerMode::VyosApi) {
            if self.vyos_apikey.is_none() {
                return Err(anyhow::anyhow!(
                    "--vyos-apikey or VYOS_APIKEY is required when --mode=vyos-api"
                ));
            }
            if self.vyos_api.is_none() {
                return Err(anyhow::anyhow!(
                    "--vyos-api or VYOS_API is required when --mode=vyos-api"
                ));
            }
        }

        if !self.remote_group_path.starts_with('/') {
            return Err(anyhow::anyhow!(
                "--remote-group-path must start with '/', got '{}'",
                self.remote_group_path
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Args)]
#[group(required = false, multiple = false)]
pub struct Auth {
    #[arg(long, env = "CROWDSEC_APIKEY")]
    pub crowdsec_apikey: Option<String>,

    #[command(flatten)]
    pub cert_auth: CertAuth,
}

#[derive(Debug, Args, Clone)]
#[group(required = false, multiple = true)]
pub struct CertAuth {
    #[arg(
        long,
        env = "CROWDSEC_ROOT_CA_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/ca.crt"
    )]
    pub crowdsec_root_ca_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_CERT",
        default_value = "/etc/crowdsec_bouncer/certs/tls.crt"
    )]
    pub crowdsec_client_cert: PathBuf,

    #[arg(
        long,
        env = "CROWDSEC_CLIENT_KEY",
        default_value = "/etc/crowdsec_bouncer/certs/tls.key"
    )]
    pub crowdsec_client_key: PathBuf,
}

impl CertAuth {
    fn exists(&self) -> bool {
        self.crowdsec_client_key.exists()
            && self.crowdsec_client_cert.exists()
            && self.crowdsec_root_ca_cert.exists()
    }
}

pub struct ClientCerts {
    pub ca_cert: Vec<u8>,
    pub client_cert: Vec<u8>,
    pub client_key: Vec<u8>,
}

impl TryFrom<CertAuth> for ClientCerts {
    type Error = anyhow::Error;
    fn try_from(value: CertAuth) -> Result<Self, Self::Error> {
        Ok(Self {
            ca_cert: read_file(&value.crowdsec_root_ca_cert)?,
            client_cert: read_file(&value.crowdsec_client_cert)?,
            client_key: read_file(&value.crowdsec_client_key)?,
        })
    }
}

impl Auth {
    pub fn try_into_crowdsec_auth(self, crowdsec_api: &Url) -> Result<CrowdsecAuth, anyhow::Error> {
        if let Some(apikey) = self.crowdsec_apikey {
            Ok(CrowdsecAuth::Apikey(apikey))
        } else if self.cert_auth.exists() {
            if crowdsec_api.scheme() != "https" {
                return Err(anyhow::anyhow!(
                    "CrowdSec certificate authentication requires an https:// CROWDSEC_API, got {}",
                    crowdsec_api
                ));
            }
            let certs = ClientCerts::try_from(self.cert_auth)?;
            Ok(CrowdsecAuth::Certs(TryFrom::try_from(certs)?))
        } else {
            Err(anyhow::anyhow!("No authentication provided for CrowdSec!"))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use reqwest::Url;

    use super::{Auth, BouncerMode, CertAuth, Cli};
    use crate::crowdsec_lapi::types::CrowdsecAuth;

    struct TempCertFiles {
        dir: PathBuf,
        cert_auth: CertAuth,
    }

    impl TempCertFiles {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "vyos-crowdsec-bouncer-cli-test-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("valid time")
                    .as_nanos()
            ));
            fs::create_dir_all(&dir).expect("create temp dir");

            let ca = dir.join("ca.crt");
            let cert = dir.join("tls.crt");
            let key = dir.join("tls.key");

            fs::write(&ca, "placeholder").expect("write ca");
            fs::write(&cert, "placeholder").expect("write cert");
            fs::write(&key, "placeholder").expect("write key");

            Self {
                dir,
                cert_auth: CertAuth {
                    crowdsec_root_ca_cert: ca,
                    crowdsec_client_cert: cert,
                    crowdsec_client_key: key,
                },
            }
        }
    }

    impl Drop for TempCertFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn cli_for_mode(mode: BouncerMode) -> Cli {
        Cli {
            mode,
            trusted_ips: None,
            update_period_secs: 60,
            full_sync_interval_secs: 900,
            vyos_apikey: None,
            vyos_api: None,
            crowdsec_timeout: 10,
            firewall_group: String::from("CROWDSEC_BOUNCER"),
            vyos_save_config: false,
            crowdsec_api: Url::parse("http://localhost:8080").unwrap(),
            metrics_bind: "127.0.0.1:3000".parse().unwrap(),
            remote_group_bind: "0.0.0.0:8080".parse().unwrap(),
            remote_group_path: String::from("/crowdsec"),
            auth: Auth {
                crowdsec_apikey: Some(String::from("secret")),
                cert_auth: CertAuth {
                    crowdsec_root_ca_cert: PathBuf::from("/missing/ca.crt"),
                    crowdsec_client_cert: PathBuf::from("/missing/tls.crt"),
                    crowdsec_client_key: PathBuf::from("/missing/tls.key"),
                },
            },
        }
    }

    #[test]
    fn uses_apikey_auth_when_provided() {
        let certs = TempCertFiles::new();
        let auth = Auth {
            crowdsec_apikey: Some(String::from("secret")),
            cert_auth: certs.cert_auth.clone(),
        };

        let crowdsec_auth = auth
            .try_into_crowdsec_auth(&Url::parse("http://localhost:8080").unwrap())
            .expect("apikey auth should work");

        assert!(matches!(crowdsec_auth, CrowdsecAuth::Apikey(apikey) if apikey == "secret"));
    }

    #[test]
    fn rejects_certificate_auth_over_http() {
        let certs = TempCertFiles::new();
        let auth = Auth {
            crowdsec_apikey: None,
            cert_auth: certs.cert_auth.clone(),
        };

        let error = auth
            .try_into_crowdsec_auth(&Url::parse("http://localhost:8080").unwrap())
            .expect_err("http should reject certificate auth");

        assert!(error.to_string().contains("https:// CROWDSEC_API"));
    }

    #[test]
    fn remote_group_mode_does_not_require_vyos_credentials() {
        let cli = cli_for_mode(BouncerMode::RemoteGroup);

        cli.validate().expect("remote-group mode should validate");
    }

    #[test]
    fn vyos_api_mode_requires_vyos_credentials() {
        let cli = cli_for_mode(BouncerMode::VyosApi);

        let error = cli.validate().expect_err("vyos-api mode needs credentials");

        assert!(error.to_string().contains("--vyos-apikey"));
    }

    #[test]
    fn remote_group_path_must_start_with_slash() {
        let mut cli = cli_for_mode(BouncerMode::RemoteGroup);
        cli.remote_group_path = String::from("crowdsec");

        let error = cli.validate().expect_err("relative path should fail");

        assert!(error.to_string().contains("--remote-group-path"));
    }
}
