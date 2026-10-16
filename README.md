# Vyos crowdsec bouncer

Crowdsec bouncer for vyos router/firewall

The bouncer fetches decisions from the local CrowdSec API and can run in two modes:

* `vyos-api` updates a specified VyOS firewall network group through the VyOS HTTP API.
* `remote-group` serves a newline-delimited HTTP feed for `set firewall group remote-group`.

In `vyos-api` mode, the configured firewall group is treated as managed by this bouncer. Startup and periodic full syncs
reconcile the VyOS group against the active CrowdSec decisions, so stale entries that no longer exist
in CrowdSec are removed from that group.

It also exposes Prometheus metrics on `/metrics`. By default this listens on `127.0.0.1:3000`, and can be overridden with `--metrics-bind` or `METRICS_BIND`.

Optional Cloudflare synchronization updates a custom IP list through the Cloudflare REST API in either mode.
It is disabled by default. All synchronization runs in this bouncer; **no Cloudflare Workers, Pages, or KV are created or used**.

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

`remote-group` mode is not capped by the bouncer because it does not write individual entries into the VyOS configuration. It refreshes the full active CrowdSec decision list every `UPDATE_FREQUENCY_SECS`, including CrowdSec's CAPI/community decisions, and keeps serving the last successful list if CrowdSec is temporarily unavailable. Before the first successful sync, the feed returns HTTP 503 so VyOS can keep its cached list instead of replacing it with an empty response.

### Optional Cloudflare blocking

Set up these resources once in the Cloudflare dashboard:

1. Create a **dedicated custom IP list**, for example `crowdsec_bouncer`, and record its list ID and account ID.
   The bouncer manages every entry in this list, removing entries that are absent from the desired CrowdSec state.
   Use a separate custom list from any CrowdSec-managed Cloudflare integration or manually maintained list.
2. In each zone you want to protect, create a WAF custom rule with expression `(ip.src in $crowdsec_bouncer)` and action **Block**.
   A list by itself does not block traffic. The same account list can be referenced by rules in multiple zones.
3. Create an API token with **Account → Account Filter Lists → Edit**, scoped to that account.
   The bouncer does not need permissions to edit WAF rules, Workers, or Pages.

Free accounts currently have [one custom list and 10,000 total custom-list entries](https://developers.cloudflare.com/waf/tools/lists/#availability).
This requires that the account's list capacity is available. WAF rules protect traffic proxied through Cloudflare;
VyOS continues to enforce its own firewall rules independently.

Add the following environment variables to the existing bouncer configuration:

```sh
CLOUDFLARE_ENABLED=true
CLOUDFLARE_API_TOKEN=<account-filter-lists-edit-token>
CLOUDFLARE_ACCOUNT_ID=<32-character-account-id>
CLOUDFLARE_LIST_ID=<32-character-list-id>
CLOUDFLARE_STATE_PATH=/var/lib/vyos-crowdsec-bouncer/cloudflare.json
```

The state directory must be writable by the bouncer. For the nonroot Docker image, mount a persistent volume at `/state`
and set `CLOUDFLARE_STATE_PATH=/state/cloudflare.json`; a bind-mounted directory must be writable by UID/GID `65532:65532`.
Preserve the state file across container replacements. Run one bouncer per managed Cloudflare list; an OS file lock prevents
two processes from using the same state path. Building from source requires Rust 1.89 or newer.

| Environment variable | Default | Purpose |
| --- | --- | --- |
| `CLOUDFLARE_ENABLED` | `false` | Explicitly enable Cloudflare synchronization. |
| `CLOUDFLARE_API_TOKEN` | unset | API token; required when enabled. |
| `CLOUDFLARE_ACCOUNT_ID` | unset | Account containing the list; required when enabled. |
| `CLOUDFLARE_LIST_ID` | unset | Dedicated custom IP list; required when enabled. |
| `CLOUDFLARE_STATE_PATH` | unset | Persistent cache and operation journal; required when enabled. |
| `CLOUDFLARE_SYNC_INTERVAL_SECS` | `60` | Update cycle interval; must be positive. |
| `CLOUDFLARE_RECONCILE_INTERVAL_SECS` | `3600` | Interval between full Cloudflare list reads; must be positive. |
| `CLOUDFLARE_MAX_ITEMS` | `10000` | Maximum managed entries, from 1 to 10,000. |

With Cloudflare disabled, no Cloudflare requests or state-file operations occur, even if token or list variables are present.
When enabled, incomplete configuration or an inaccessible/invalid state file fails startup with an error.

The Cloudflare task shares the existing CrowdSec decision stream and applies `TRUSTED_IPS`. It receives full desired state
before the VyOS write cap, so the Cloudflare and VyOS capacities are independent. Decision origins follow the selected bouncer mode:
`crowdsec,lists,cscli` for `vyos-api`, also including `CAPI` for `remote-group`. The task waits for the first successful CrowdSec
snapshot before changing Cloudflare. If CrowdSec becomes unavailable, it retains the last successful desired state.

On startup, after recovering an unfinished operation, it reads the actual Cloudflare list with pagination. It then batches
only differences into requests of up to 1,000 items, deleting stale entries before adding new ones. Each asynchronous operation
must finish before another write is submitted. Confirmed state is cached locally; new item IDs are fetched only when needed
for a later deletion or during reconciliation. Unchanged cycles send no API requests until the periodic list read is due.
Full reads also repair dashboard changes and follow failed or ambiguous API operations. The token is never stored in the state file.

Overlapping/adjacent networks are combined without broadening their coverage. Ranges wider than Cloudflare permits are split
into supported CIDRs. At capacity, existing active entries are retained first, then remaining capacity is filled in network
order; skipped entries are logged. Cloudflare receives up to its own configured cap, even if the remote-group feed is larger.

Cloudflare documents a shared [1,200 requests per five minutes](https://developers.cloudflare.com/fundamentals/api/reference/limits/)
and [30,000 modification requests / 1,000,000 item modifications per 12 hours](https://developers.cloudflare.com/waf/tools/lists/lists-api/#rate-limiting-for-lists-api-requests).
The client spaces all its API requests at least one second apart, honors `Retry-After` and exhausted `Ratelimit` headers,
and backs off on errors. It reserves a conservative local budget of 27,000 write requests / 900,000 item modifications per
rolling 12 hours, counting uncertain or failed write attempts too. Budget exhaustion defers changes; it does not wipe the list.
Quota history and cooldowns survive restarts. These local counters cannot measure other applications' account usage, so server
rate limits still take precedence. Cloudflare-managed CrowdSec integration lists can have stricter daily update limits;
use the dedicated custom list described above.

Cloudflare runtime failures are logged and retried without blocking VyOS writes or the remote-group HTTP feed.
API request counts appear in the existing `crowdsec_vyos_bouncer_outgoing_requests` metric with `destination="CLOUDFLARE"`.

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
          Periodically reconcile the whole VyOS group against CrowdSec active decisions. Set to 0 to disable [env: FULL_SYNC_INTERVAL_SECS=] [default: 900]
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
      --cloudflare-enabled
          Enable direct Cloudflare custom IP list synchronization [env: CLOUDFLARE_ENABLED=]
      --cloudflare-api-token <CLOUDFLARE_API_TOKEN>
          [env: CLOUDFLARE_API_TOKEN]
      --cloudflare-account-id <CLOUDFLARE_ACCOUNT_ID>
          [env: CLOUDFLARE_ACCOUNT_ID=]
      --cloudflare-list-id <CLOUDFLARE_LIST_ID>
          ID of an existing, dedicated custom IP list managed entirely by this bouncer [env: CLOUDFLARE_LIST_ID=]
      --cloudflare-state-path <CLOUDFLARE_STATE_PATH>
          Writable persistent file; also used to prevent concurrent writers [env: CLOUDFLARE_STATE_PATH=]
      --cloudflare-sync-interval-secs <CLOUDFLARE_SYNC_INTERVAL_SECS>
          [env: CLOUDFLARE_SYNC_INTERVAL_SECS=] [default: 60]
      --cloudflare-reconcile-interval-secs <CLOUDFLARE_RECONCILE_INTERVAL_SECS>
          [env: CLOUDFLARE_RECONCILE_INTERVAL_SECS=] [default: 3600]
      --cloudflare-max-items <CLOUDFLARE_MAX_ITEMS>
          [env: CLOUDFLARE_MAX_ITEMS=] [default: 10000]
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
