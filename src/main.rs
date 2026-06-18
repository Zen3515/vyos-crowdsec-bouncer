use clap::Parser;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
use vyos_crowdsec_bouncer::cli::{BouncerMode, Cli};
use vyos_crowdsec_bouncer::control_loop::reconcile;
use vyos_crowdsec_bouncer::crowdsec_lapi::CrowdsecLapiClient;
use vyos_crowdsec_bouncer::prometheus::Prometheus;
use vyos_crowdsec_bouncer::remote_group::{
    sync_loop, RemoteGroupApp, RemoteGroupServer, RemoteGroupState,
};
use vyos_crowdsec_bouncer::tracing_setup::{get_subscriber, init_subscriber};
use vyos_crowdsec_bouncer::vyos_api::VyosClient;
use vyos_crowdsec_bouncer::{App, Config};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let subscriber = get_subscriber(String::from("default"), String::from("info"));
    init_subscriber(subscriber);

    let args = Cli::parse();
    args.validate()?;
    let crowdsec_auth = args
        .auth
        .clone()
        .try_into_crowdsec_auth(&args.crowdsec_api)?;

    let lapi = CrowdsecLapiClient::new(
        args.crowdsec_api.clone(),
        crowdsec_auth,
        Duration::from_secs(args.crowdsec_timeout),
    );
    let metrics = Prometheus::new(args.metrics_bind);
    let metrics = metrics.serve();

    let mut task_set = tokio::task::JoinSet::new();
    task_set.spawn(async { Ok(metrics.await?) });

    match args.mode {
        BouncerMode::VyosApi => {
            let vyos_api = VyosClient::new(
                args.vyos_api
                    .clone()
                    .expect("validated --vyos-api in vyos-api mode"),
                args.vyos_apikey
                    .clone()
                    .expect("validated --vyos-apikey in vyos-api mode"),
            );
            let config = Config {
                firewall_group: args.firewall_group,
                trusted_ips: args.trusted_ips.map(From::from).unwrap_or_default(),
                update_period: Duration::from_secs(args.update_period_secs),
                full_sync_interval: if args.full_sync_interval_secs == 0 {
                    None
                } else {
                    Some(Duration::from_secs(args.full_sync_interval_secs))
                },
                vyos_save_config: args.vyos_save_config,
            };
            let app = App::new(lapi, vyos_api, config);
            task_set.spawn(async { reconcile(app).await });
        }
        BouncerMode::RemoteGroup => {
            let state = Arc::new(RemoteGroupState::default());
            let app = RemoteGroupApp::new(
                lapi,
                args.trusted_ips.map(From::from).unwrap_or_default(),
                Duration::from_secs(args.update_period_secs),
                Arc::clone(&state),
            );
            let server =
                RemoteGroupServer::new(args.remote_group_bind, args.remote_group_path, state);

            task_set.spawn(async { sync_loop(app).await });
            task_set.spawn(async { Ok(server.serve().await?) });
        }
    }

    while let Some(res) = task_set.join_next().await {
        res??;
    }

    info!("Exit!");

    Ok(())
}
