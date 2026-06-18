# Vyos crowdsec bouncer

Crowdsec bouncer for vyos router/firewall

The bouncer fetches decisions from the local CrowdSec API and can run in two modes:

* `vyos-api` updates a specified VyOS firewall network group through the VyOS HTTP API.
* `remote-group` serves a newline-delimited HTTP feed for `set firewall group remote-group`.

In `vyos-api` mode, the configured firewall group is treated as managed by this bouncer. Startup and periodic full syncs
reconcile the VyOS group against the active CrowdSec decisions, so stale entries that no longer exist
in CrowdSec are removed from that group.

It also exposes Prometheus metrics on `/metrics`. By default this listens on `127.0.0.1:3000`, and can be overridden with `--metrics-bind` or `METRICS_BIND`.

### [Vyos](https://vyos.io/)
Authentication to vyos is made through apikeys

#### Manual setup
In `vyos-api` mode, to make use of the blocklist, the firewall group (default CROWDSEC_BOUNCER)
needs to be added to the vyos firewall section as desired 

Example
```
rule 4 {
    action drop
    log
    source {
        group {
            network-group CROWDSEC_BOUNCER
        }
    }
 }
```

In `remote-group` mode, configure VyOS to fetch the bouncer's feed URL:

```
set firewall group remote-group CROWDSEC_BOUNCER url http://<bouncer-host>:8080/crowdsec
```

Then reference the remote group in firewall rules as desired:

```
rule 4 {
    action drop
    log
    source {
        group {
            remote-group CROWDSEC_BOUNCER
        }
    }
 }
```

### [Crowdsec](https://docs.crowdsec.net/docs/intro/)
Authentication to crowdsec supports both apikey and MTLS
When using MTLS, `CROWDSEC_API` must be an `https://` URL.
#### Limitations
Due to a [bug/limitation](https://vyos.dev/T6625) in VYOS, no more than 15k items can exist in a static firewall group.
In `vyos-api` mode, we cap writes at 15k entries and limit the origins of the decisions from crowdsec to `Origin::Crowdsec, Origin::Lists, Origin::Cscli`\
This strikes a balance between having a base of blocked ips coming from custom lists and blocking bad actors from local decisions

The bouncer also only requests IP and CIDR decisions from CrowdSec, which matches what VyOS network groups can enforce.
If the firewall group reaches 15k entries, additional bans are skipped and a warning is logged until capacity is freed by deletions.

The bouncer uses incremental CrowdSec streams between full syncs. A full sync runs at startup, after any
failed or ambiguous VyOS write/save attempt, and periodically every `FULL_SYNC_INTERVAL_SECS`
(default: 900 seconds, set to `0` to disable periodic full sync). Full sync reads the existing VyOS
group, fetches active CrowdSec decisions with `startup=true`, then applies the computed add/delete diff.

`remote-group` mode is not capped by the bouncer because it does not write individual entries into the VyOS configuration. It refreshes the full active CrowdSec decision list every `UPDATE_FREQUENCY_SECS` and keeps serving the last successful list if CrowdSec is temporarily unavailable. Before the first successful sync, the feed returns HTTP 503 so VyOS can keep its cached list instead of replacing it with an empty response.

Once this problem is fixed we can enable the crowdsourced blocklist coming from the central api (CAPI) and allow for customizing the origins.

### CLI
```
Usage: vyos-crowdsec-bouncer [OPTIONS]

Options:
      --mode <MODE>
          [env: BOUNCER_MODE=] [default: vyos-api] [possible values: vyos-api, remote-group]
      --trusted-ips <TRUSTED_IPS>...
          [env: TRUSTED_IPS=]
      --update-period-secs <UPDATE_PERIOD_SECS>
          [env: UPDATE_FREQUENCY_SECS=] [default: 60]
      --full-sync-interval-secs <FULL_SYNC_INTERVAL_SECS>
          [env: FULL_SYNC_INTERVAL_SECS=] [default: 900]
      --vyos-apikey <VYOS_APIKEY>
          [env: VYOS_APIKEY=]
      --vyos-api <VYOS_API>
          [env: VYOS_API=]
      --crowdsec-timeout <CROWDSEC_TIMEOUT>
          [env: CROWDSEC_TIMEOUT=] [default: 10]
      --firewall-group <FIREWALL_GROUP>
          [env: FIREWALL_GROUP=] [default: CROWDSEC_BOUNCER]
      --vyos-save-config
          [env: VYOS_SAVE_CONFIG=]
      --crowdsec-api <CROWDSEC_API>
          [env: CROWDSEC_API=] [default: http://localhost:8080]
      --metrics-bind <METRICS_BIND>
          [env: METRICS_BIND=] [default: 127.0.0.1:3000]
      --remote-group-bind <REMOTE_GROUP_BIND>
          [env: REMOTE_GROUP_BIND=] [default: 0.0.0.0:8080]
      --remote-group-path <REMOTE_GROUP_PATH>
          [env: REMOTE_GROUP_PATH=] [default: /crowdsec]
      --crowdsec-apikey <CROWDSEC_APIKEY>
          [env: CROWDSEC_APIKEY=]
      --crowdsec-root-ca-cert <CROWDSEC_ROOT_CA_CERT>
          [env: CROWDSEC_ROOT_CA_CERT=] [default: /etc/crowdsec_bouncer/certs/ca.crt]
      --crowdsec-client-cert <CROWDSEC_CLIENT_CERT>
          [env: CROWDSEC_CLIENT_CERT=] [default: /etc/crowdsec_bouncer/certs/tls.crt]
      --crowdsec-client-key <CROWDSEC_CLIENT_KEY>
          [env: CROWDSEC_CLIENT_KEY=] [default: /etc/crowdsec_bouncer/certs/tls.key]
  -h, --help
          Print help
  -V, --version
          Print version
```
