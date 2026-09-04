# Whisker Ting Integration for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-41BDF5.svg)](https://github.com/hacs/integration)
[![GitHub Release](https://img.shields.io/github/release/jasonjhofmann/ha-whisker-ting.svg)](https://github.com/jasonjhofmann/ha-whisker-ting/releases)

Home Assistant integration for the [Whisker Labs Ting](https://www.tingfire.com/) electrical-fire-safety sensor. This repository consolidates the fixes and features from every fork lineage of the original integration into one maintained codebase — the spec-compliant SignalR transport that ends the connection churn, the named-field voltage decode that ends the spurious spike misreads, alert/notification entities, multi-device support, and a full test suite. Ting plugs into an outlet and continuously monitors your home's electrical system for the arcing and power-quality problems that precede electrical fires. This integration connects to the Ting cloud service on your behalf and exposes real-time voltage readings plus electrical, utility, and power-quality hazard status as native Home Assistant entities.

## Features

- **Real-time voltage monitoring** via a WebSocket connection to the Ting cloud
  - Current voltage, voltage high/low, and average peak voltage
- **Fire hazard status** monitoring
  - Electrical Fire Hazard (EFH) detection
  - Utility Fire Hazard (UFH) detection
  - Learning-mode status
- **Power quality hazard** and **frozen pipe risk** detection (site-level)
- **Connectivity sensor** — reflects whether the real-time data stream is live
- **Device diagnostics** — firmware version, WiFi/Bluetooth MAC addresses (also registered as device connections), serial number, subscription start date, and account group

## Installation

### HACS (recommended)

Whisker Ting is not (yet) in the default HACS store, so add it as a custom repository:

1. Open **HACS** in Home Assistant.
2. Click the three-dot menu in the top right corner and select **Custom repositories**.
3. Add `https://github.com/jasonjhofmann/ha-whisker-ting` as the repository URL, choose **Integration** as the category, and click **Add**.
4. Find **Whisker Ting** in HACS and click **Download**.
5. Restart Home Assistant.

### Manual

1. Download the latest release from [GitHub](https://github.com/jasonjhofmann/ha-whisker-ting/releases), or clone the repository.
2. Copy the `custom_components/whisker_ting` folder into your Home Assistant `config/custom_components/` directory.
3. Restart Home Assistant.

## Configuration

1. Go to **Settings** → **Devices & Services** and click **+ Add Integration**.
2. Search for **Whisker Ting**.
3. Enter your Ting account credentials:

| Field | Description |
|---|---|
| **Email** | The email address for your Whisker Labs / Ting account. |
| **Password** | The password for that account — the same credentials you use in the Ting mobile app. |

These credentials are verified against the Ting cloud during setup; setup will not complete with incorrect credentials.

## Options

After setup, open **Settings** → **Devices & Services** → **Whisker Ting** and click **Configure** to change:

| Option | Description |
|---|---|
| **Update interval** | How often, in seconds, the integration polls the Ting API for hazard and diagnostic data. Range 30–3600, default 60. Real-time voltage sensors are unaffected by this setting — they update continuously from the WebSocket stream. |
| **Real-time voltage publish interval** | How often, in seconds, the live voltage stream (~4 samples/second) writes to Home Assistant state. Range 1–60, default 5. Lower values give finer voltage history at the cost of recorder growth (1 s ≈ 86,000 recorder rows per voltage entity per day; 5 s ≈ 17,000). In-memory readings and freshness tracking always run at full stream rate regardless of this setting. |
| **Alert notifications** | Post a Home Assistant persistent notification for each new *significant* Ting alert — power outages, restorations, fire, and frozen-pipe alerts. Off by default (opt-in). Brownouts (`Sag`/`Swell`) and weather alerts are never posted this way by design; automate on the `Alerts` event entity or the `Last brownout` / `Last weather alert` sensors instead — see [Automations](#automations) below. |

## Removal

1. Go to **Settings** → **Devices & Services**.
2. Find the **Whisker Ting** integration card, open its three-dot menu, and select **Delete**.
3. If it was installed through HACS, open **HACS** → **Integrations**, find **Whisker Ting**, open its three-dot menu, and select **Remove** to remove the repository and files.

## Entities

### Multi-device installs

Each Ting device is added to Home Assistant as its own device, named after its Ting **site** (e.g. "Kitchen", "Garage") rather than one shared account name — so accounts with multiple sensors get distinguishable devices, and entity IDs are prefixed with the site's slug (e.g. `binary_sensor.kitchen_power_outage`). This follows normal Home Assistant rename semantics: upgrading does not rename entities you already have just because the underlying device name changed — only entities created fresh (a new install, a newly added device, or a newly enabled entity) pick up the site-based name.

### Sensors

| Name | Description | Category | Enabled by default |
|---|---|---|---|
| Current voltage | Real-time line voltage from the WebSocket stream | — | Yes |
| Voltage high | Real-time peak high voltage from the WebSocket stream | — | Yes |
| Voltage low | Real-time peak low voltage from the WebSocket stream | — | Yes |
| Average peaks max | Rolling average of peak voltage from the WebSocket stream | — | No |
| Hazard Status | Overall hazard status: `no_hazards`, `hazard_detected`, `reviewed_not_fire`, or `learning` | — | Yes |
| Hazard Message | Human-readable hazard summary from Ting | — | Yes |
| Electrical Fire Hazard Status | Raw EFH status code from Ting | — | Yes |
| Electrical Fire Hazard Message | Human-readable EFH message | — | Yes |
| Electrical Fire Hazard Level | EFH severity level | — | Yes |
| Utility Fire Hazard Status | Raw UFH status code from Ting | — | Yes |
| Utility Fire Hazard Message | Human-readable UFH message | — | Yes |
| Device Type | Ting device type reported by the API | Diagnostic | Yes |
| Firmware Version | Installed firmware version | Diagnostic | No |
| WiFi MAC Address | Device's WiFi MAC address (also registered as a device connection) | Diagnostic | No |
| Bluetooth MAC Address | Device's Bluetooth MAC address (also registered as a device connection) | Diagnostic | No |
| Serial Number | Device serial number | Diagnostic | No |
| Subscription Start | Timestamp the Ting subscription began | Diagnostic | No |
| Group | Ting account group/location name | Diagnostic | No |
| Last brownout | Timestamp of the most recent brownout (voltage sag/swell) notification from Ting; the notification message is in the `message` attribute | — | Yes |
| Last weather alert | Timestamp of the most recent weather-alert notification relayed by Ting; the alert's `title` and `message` are in attributes | — | Yes |

### Binary sensors

| Name | Description | Category | Enabled by default |
|---|---|---|---|
| Fire Hazard | On when Ting reports any active fire hazard | — | Yes |
| Electrical Fire Hazard | On when an electrical fire hazard (EFH) is active | — | Yes |
| Utility Fire Hazard | On when a utility-side fire hazard (UFH) is active | — | Yes |
| Frozen Pipe Risk | On when Ting detects a frozen-pipe risk condition | — | Yes |
| Power Quality Hazard | On when a site-level power-quality hazard is detected | — | Yes |
| Power outage | On while the device's most recent power event is an unrestored outage, derived from Ting's `PowerOutage`/`PowerRestored`/`PowerOutageAndRestored` notifications (per Ting, unplugging the sensor itself also trips this) | — | Yes |
| Connectivity | On while the real-time WebSocket stream is live | Diagnostic | Yes |
| Learning Mode | On while Ting is in its initial learning period | — | Yes |
| HVAC Verified | On when Ting has verified HVAC equipment on the circuit | Diagnostic | No |
| Is Owner | On when this account is the device owner (vs. a shared/guest user) | Diagnostic | No |

> **Note:** the Utility Fire Hazard binary sensor's entity ID keeps the legacy `unverified_fire_hazard` key for backward compatibility with existing installs — only its display name changed.

### Events

| Name | Description | Category | Enabled by default |
|---|---|---|---|
| Alerts | Fires once for each new Ting notification. `event_type` is one of `PowerOutage`, `PowerOutageAndRestored`, `PowerRestored`, `Sag`, `Swell`, `WeatherAlert`, `FireHazard`, `FrozenPipe`, or `unknown` (for any type Ting adds that this integration doesn't yet recognize) | — | Yes |

Each fired event also carries the notification's details as attributes: `title`, `subtitle`, `message`, `category` (Ting's event category, e.g. `PowerQuality`), `raw_event_type` (Ting's original type string — useful when `event_type` above is `unknown`), `timestamp` (when Ting recorded the event), `notification_id`, `acknowledged`, and `cleared`.

## Requirements

- Home Assistant 2024.12.0 or newer
- A Whisker Labs Ting device
- A Whisker Labs account

## Automations

The entities above are built to be automated against directly — no template sensors required. Each example below is a single automation's config, as you'd paste into Home Assistant's **Edit in YAML** automation editor; if you're editing `automations.yaml` directly, wrap it in a list item under the top-level `automation:` key. Replace `<device>` with your device's slug — the lowercase, underscore-separated form of its name as shown in **Settings** → **Devices & Services** (e.g. `kitchen`, `living_room`); see [Multi-device installs](#multi-device-installs) above if you have more than one Ting device.

### Event-triggered: notify on a new power outage

The `Alerts` event entity fires on every new Ting notification. Trigger on any state change of the entity and filter by `event_type` in a condition, rather than scoping the trigger to that attribute directly — an `attribute:`-scoped state trigger only re-fires when the attribute's *value* changes, so it would silently miss a second `PowerOutage` notification arriving without a `PowerRestored` in between:

```yaml
alias: "Ting: notify on power outage"
trigger:
  - platform: state
    entity_id: event.<device>_alerts
condition:
  - condition: template
    value_template: "{{ trigger.to_state.attributes.event_type == 'PowerOutage' }}"
action:
  - service: notify.mobile_app_phone
    data:
      title: Ting power outage
      message: "{{ trigger.to_state.attributes.message }}"
```

### State-based: notify only on a sustained outage

The `Power outage` binary sensor is a plain on/off state, so a regular `for:`-qualified state trigger works well here — this waits 5 minutes before notifying, to skip momentary blips:

```yaml
alias: "Ting: notify on sustained power outage"
trigger:
  - platform: state
    entity_id: binary_sensor.<device>_power_outage
    to: "on"
    for: "00:05:00"
action:
  - service: notify.mobile_app_phone
    data:
      title: Ting power outage
      message: "{{ state_attr(trigger.entity_id, 'friendly_name') }} has been without power for 5 minutes."
```

### Recency: gate an automation on "did this just happen"

`Last brownout` and `Last weather alert` hold the *timestamp* of the most recent occurrence rather than an on/off state, so freshness is a template condition, not a trigger. This example escalates the Power Quality Hazard binary sensor into a notification only when a brownout was also recorded in the last 10 minutes:

```yaml
alias: "Ting: escalate power-quality hazard after a recent brownout"
trigger:
  - platform: state
    entity_id: binary_sensor.<device>_power_quality_hazard
    to: "on"
condition:
  - condition: template
    value_template: >-
      {{ states('sensor.<device>_last_brownout') not in ('unknown', 'unavailable')
         and now() - states('sensor.<device>_last_brownout') | as_datetime < timedelta(minutes=10) }}
action:
  - service: notify.mobile_app_phone
    data:
      title: Ting power-quality hazard
      message: A power-quality hazard was flagged shortly after a brownout was recorded.
```

`Last brownout` reads `unknown` until the first brownout notification ever arrives; the guard clause above makes the condition evaluate to false in that state instead of raising a template error (`as_datetime` of `unknown` is `None`, and comparing `now()` against `None` errors).

### Importable blueprint

For the common case — notify on outage, optionally notify on restore — skip writing YAML: in Home Assistant, go to **Settings** → **Automations & Scenes** → **Blueprints** → **Import Blueprint** and import [`power_outage_notification.yaml`](https://github.com/jasonjhofmann/ha-whisker-ting/blob/main/blueprints/automation/whisker_ting/power_outage_notification.yaml) from this repository (or copy it into your `config/blueprints/automation/whisker_ting/` folder). It asks for your `Power outage` binary sensor and a notify target, and handles the rest.

### Skip automations entirely

Turn on **Alert notifications** under **Settings** → **Devices & Services** → **Whisker Ting** → **Configure** to have the integration post an HA persistent notification for each new significant alert itself — see [Options](#options) above.

## How the live voltage stream works

Useful if you are debugging this integration or writing another client.
All of it was established empirically against the live service and
cross-checked against the official app's JavaScript bundle.

The stream is [ASP.NET Core SignalR](https://github.com/dotnet/aspnetcore/blob/main/src/SignalR/docs/specs/HubProtocol.md)
over a WebSocket at `wss://signalr.api.wskr.io/dataHub`, MessagePack
protocol, connected directly with `skipNegotiation` (no `/negotiate`
call). Credentials are the Cognito attributes `custom:api_key` and
`custom:user_id`; `StationId` is the sensor's serial number.

Four things are easy to get wrong, and every published fork got at least
one of them wrong:

1. **Binary framing.** Every outgoing hub message must be a flat array
   prefixed with a 7-bit VarInt length. The original client sent a bare
   `{1: [...]}` MessagePack map with no prefix; the server dropped such
   connections about 70 ms after the first keepalive ping, producing an
   endless reconnect loop.
2. **The Completion answering `InitializeStreaming` is a success acknowledgement, not a rejection.**
   `InitializeStreaming` is a blocking invocation, so the server answers
   it with a Completion. On the wire that frame is `[3, {}, "1", 3, None]`
   — ResultKind 3 (non-void) with a `null` result; ResultKind 2 (void) is
   equally benign. Voltage arrives
   *afterwards*, as separate server-to-client invocations on the same
   socket. Only `ResultKind 1` carries an error and means the
   subscription was refused. Closing the connection on an error-free
   Completion makes data delivery impossible — this is the single defect
   that has been observed to break a fork outright.
3. **Release the subscription before subscribing.** The official app pairs
   the two calls — `connection.onreconnected` invokes
   `UnInitializeStreaming` and then re-subscribes
   (`chunk-GBDILMAT.js:6208-6226`) — and no third-party client has ever
   called the teardown. Something server-side can latch for a station such
   that every subscribe is acknowledged and served nothing; that was
   observed once, for about thirty hours, and cleared around the time a
   release was first sent. A controlled A/B/A on a healthy station shows
   the release makes no difference (244 / 260 / 258 samples per 60 s), so
   treat it as matching the reference client and cheap insurance rather
   than a demonstrated cure.
4. **`StationId` is the sensor serial.** Probing alternative identifiers
   (site id, SoC serial, group id) cannot work, because the hub returns
   the same void acknowledgement for *any* value supplied — "no data
   arrived" never distinguishes a wrong station from a blocked stream.

The stream itself runs at about 4 Hz. This integration keeps every sample
in memory but rate-limits state writes (see the **Real-time voltage
publish interval** option) so the recorder isn't flooded.

## Troubleshooting

### Voltage shows "Unknown" briefly on startup

This is normal — the integration waits for the WebSocket connection to receive its first data packet before displaying values.

### Voltage sensors show "Unavailable"

The real-time voltage sensors depend on a live WebSocket stream. If the stream disconnects and cannot be re-established, these sensors report unavailable (rather than a frozen last value) until the stream recovers. The hazard and diagnostic sensors continue to update from the regular API poll regardless of stream state.

### Voltage stays "Unknown" or "Unavailable" indefinitely

If hazard and diagnostic entities work but voltage never populates, the
subscription is being acknowledged and then not served. On one account this
persisted for about thirty hours across restarts, reinstalls, credential
refreshes and version reverts, then cleared and has not recurred.

Things that are worth trying, cheapest first:

1. Restart Home Assistant. The integration releases the station's
   subscription before subscribing (as the official app does on reconnect),
   so a restart re-runs that sequence.
2. Open the official Ting app briefly. It performs the same
   release-and-resubscribe on its own reconnect.
3. Wait. The one observed occurrence cleared on its own timescale, not in
   response to anything conclusive on the client side.

If it persists beyond a day, please open an issue with debug logs — the
trigger is not understood and a second data point would help a lot.

### Upgrading from a pre-3.0 fork: log spam / reconnect loops

Versions before 3.0.0 (including the other forks this repository consolidates, except those noted in the changelog) sent malformed SignalR frames that made the server drop the connection every few seconds — visible as endless `WebSocket disconnected ... triggering reconnect` / `data stale` log lines, even while voltage values appeared to update. 3.0.0's spec-compliant framing fixes the root cause; after upgrading, a single `Connected to SignalR hub` line and silence is the healthy state.

### Authentication errors

Ensure you're using the same email and password you use in the Whisker Labs / Ting mobile app. If your password has changed, Home Assistant will prompt you to reauthenticate the integration; repeated errors after reauthenticating usually mean the credentials themselves are incorrect.

## Credits

This integration is not affiliated with or endorsed by Whisker Labs, Inc.

This codebase consolidates the work of the entire fork family:

- **Aiden Mitchell / simplytoast1** — the original integration ([simplytoast1/ha-whisker-ting](https://github.com/simplytoast1/ha-whisker-ting)).
- **Stu Chuang Matthews (fourmajor)** — spec-compliant SignalR VarInt framing, six-field invocation encoding, framed keepalive pings, and named-field voltage decoding ([fourmajor/ha-whisker-ting](https://github.com/fourmajor/ha-whisker-ting)).
- **Adam Thompson (adamjthompson)** — the `x-wl-api-key` upgrade-header authorization (from a capture of the official app's traffic) and nested binary-blob payload decoding ([adamjthompson/whisker_ting](https://github.com/adamjthompson/whisker_ting)). His fork also independently found the SignalR framing bug, in parallel with the diagnosis in simplytoast1#1.
- **Bill (billda)** — the alert feed (event entity, typed timestamp sensors, power-outage binary sensor), opt-in notifications and blueprint, multi-device site naming, redacted diagnostics, reauth flow, and the pytest test harness ([billda/ha-ting-fire](https://github.com/billda/ha-ting-fire)).
- **Amit Patel (amitcpatel)** — the earliest independent fix of the SignalR MessagePack framing bug, on 10 June 2026, predating the rest of the family's diagnoses ([amitcpatel/ha-whisker-ting-acp](https://github.com/amitcpatel/ha-whisker-ting-acp)).
- **calasanzio, mbedworth, marccatalano, tcsmedes** — the field debugging in [simplytoast1/ha-whisker-ting#1](https://github.com/simplytoast1/ha-whisker-ting/issues/1) that pinned the framing root cause (the millisecond-precise ping-kill capture, the credential-swap analysis, and the server-response writeups).
- **Jason Hofmann (jasonjhofmann)** — WebSocket decode/availability hardening, update throttling, Cognito token-expiry handling, MAC-address device connections, surfaced power-quality/connectivity/subscription fields, and this consolidation.

## License

MIT License — see [LICENSE](LICENSE) for details.
