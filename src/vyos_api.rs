mod http;
mod interface;
mod types;

use tracing::{info, instrument};

pub use http::VyosClient;
pub use interface::VyosApi;
pub use types::{
    ipv4_group_exists, ipv4_group_get, ipv6_group_exists, ipv6_group_get, NetSet,
    VyosCommandResponse, VyosConfigOperation, VyosSaveCommand,
};

use crate::crowdsec_lapi::types::{ipnets_for_log, DecisionsIpRange};
use crate::metrics::VYOS_COMMANDS_SENT_COUNTER;

#[instrument(skip(vyos_api, decisions_ip_range))]
pub async fn update_firewall(
    vyos_api: &VyosClient,
    decisions_ip_range: &DecisionsIpRange,
    firewall_group: &str,
    timeout: Option<std::time::Duration>,
    save_changes: bool,
) -> Result<(), anyhow::Error> {
    let decision_ips = decisions_ip_range.into_nets();
    info!(
        new_entries = ipnets_for_log(&decision_ips.new),
        deleted_entries = ipnets_for_log(&decision_ips.deleted),
        "Updating firewall groups",
    );

    let mut commands = NetSet(&decision_ips.deleted)
        .into_vyos_commands(VyosConfigOperation::Delete, firewall_group);
    let mut add_commands =
        NetSet(&decision_ips.new).into_vyos_commands(VyosConfigOperation::Set, firewall_group);
    commands.append(&mut add_commands);
    VYOS_COMMANDS_SENT_COUNTER.inc_by(commands.len() as u64);

    const BATCH_SIZE: usize = 15000;
    for (idx, batch) in commands.chunks(BATCH_SIZE).enumerate() {
        info!("Setting batch {} {}", idx + 1, batch.len());
        vyos_api.set_firewall_groups(batch, timeout).await?;
        if save_changes {
            vyos_api.save_config(timeout).await?;
        }
    }
    info!(
        added_count = decision_ips.new.len(),
        deleted_count = decision_ips.deleted.len()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::blacklist::IpRangeMixed;
    use crate::crowdsec_lapi::types::DecisionsIpRange;
    use crate::vyos_api::{update_firewall, VyosClient};
    use mockito::{Matcher, Server};

    #[tokio::test]
    async fn update_firewall_deletes_before_adding() {
        let mut mock = Server::new_async().await;
        let client = VyosClient::new(
            format!("http://{}", mock.host_with_port()).parse().unwrap(),
            String::from("test_key"),
        );
        let decisions = DecisionsIpRange {
            new: IpRangeMixed::from(vec!["203.0.113.1/32".parse().unwrap()]),
            deleted: IpRangeMixed::from(vec!["127.0.0.1/32".parse().unwrap()]),
        };
        let configure = mock
            .mock("POST", "/configure")
            .match_body(Matcher::Regex(
                r#"(?s).*"op":"delete".*127\.0\.0\.1/32.*"op":"set".*203\.0\.113\.1/32.*"#.into(),
            ))
            .with_body(r#"{"success": true, "data": [], "error": null}"#)
            .with_status(200)
            .expect(1)
            .create();

        update_firewall(
            &client,
            &decisions,
            "group",
            Some(std::time::Duration::from_secs(1)),
            false,
        )
        .await
        .unwrap();

        configure.assert();
    }
}
