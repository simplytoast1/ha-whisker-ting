# Changelog

## 3.3.2

Corrections from deploying the other forks against the live hub and
capturing the actual wire traffic (2026-08-05). No behaviour change.

### Fixed

- **The Completion frame was documented wrong.** Everything here described
  it as `ResultKind 2` (void). The frame Ting actually sends is
  `07 95 03 80 a1 31 03 c0` = `[3, {}, "1", 3, None]` — ResultKind 3
  (non-void) with a `null` result. The code was always correct (only
  ResultKind 1 is treated as an error) but the test fixture asserted a
  frame shape the server never sends. The fixture now uses the captured
  frame, and the regression test is parametrized over both ResultKind 3
  and ResultKind 2 so either remains a success.
- Corrected the same claim in the README, the `protocol.py` and
  `websocket.py` docstrings, and the coordinator comment.

### Note on the framing requirement

Deploying each fork against a free station showed the SignalR framing
defect does not currently prevent streaming: `billda/ha-ting-fire` v2.1.0
(unframed) delivered 824 samples in 3m19s with zero disconnects, and this
project's own v1.2.0 (unframed, no auth header) delivered 795 with zero
disconnects and zero stale events — despite that build having produced a
continuous reconnect loop in production for forty days. The spec-compliant
framing is retained as correct, but its historical impact could not be
reproduced. The one defect observed to break a fork outright is treating
the Completion as a rejection.

## 3.3.1

Documentation only; no functional change from 3.3.0. Released so the
published artifact carries the corrected docs — the 3.3.0 release tree
still contained the retracted "server-side authorization gate" narrative
and referred to a station-id probe that had already been removed.

- README: rewrote the stuck-voltage troubleshooting entry around the real
  cause (a stale subscription held for the station) and added a "How the
  live voltage stream works" section documenting the four things every
  fork got wrong.
- `websocket.py` / `protocol.py` module docstrings now state the void-ack
  and one-subscription-per-station behaviours that drive the design.
- Corrected the rejection-backoff comments and the credits line that
  attributed since-removed behaviour; flagged the 3.0.x entries below as
  superseded rather than rewriting them.

## 3.3.0

### Changed

- **Release the station's subscription before subscribing, and on every
  disconnect.** The official app does this: `connection.onreconnected`
  calls `stopRealTimeData()` (which invokes `UnInitializeStreaming`) and
  then re-subscribes (`chunk-GBDILMAT.js:6208-6226`). No third-party
  client has ever called the teardown, so this brings the reconnect path
  in line with the reference client.

> **Correction (2026-08-05).** This release originally claimed the change
> was *the* fix for "subscription accepted but no data arrives", on the
> strength of a back-to-back comparison described as being run under
> identical conditions. It was not a controlled comparison: the two arms
> were different scripts with different keepalive behaviour. A proper
> A/B/A afterwards — one script, three fresh connections, 60 s each, no
> keepalives, the release call as the only variable — showed **no
> difference**: 244 samples subscribe-only, 260 with the release, 258
> subscribe-only again.
>
> What is supported: something server-side latched for about thirty hours
> on one account, during which every subscribe was acknowledged and served
> nothing across restarts, reinstalls, credential refreshes and version
> reverts; it cleared around the time a release was first sent, and has
> not recurred. Whether the release cleared it is unproven. The change is
> kept because it matches the app and cannot hurt, not because it is a
> demonstrated cure.

## 3.2.0

### Changed

- `PING_INTERVAL` is now 3 seconds, matching the official app's
  `keepAliveIntervalInMilliseconds = 3000`. **This is app parity, not a
  fix.** It was released as the fix for "subscription accepted but no
  data arrives" on the strength of one simultaneous A/B, and that was
  wrong: the same 3-second-ping probe that received 360 samples at 02:00
  received 0 samples at 02:08 with nothing changed on our side. The
  cadence is retained because it matches the reference client, but it
  does not control stream delivery.

### Known issue (RESOLVED — see below)

> **Superseded by 3.3.0.** This correlation did not hold. The integration
> has since streamed continuously for 14+ hours with the app closed. The
> app-foreground correlation was an artefact of testing during a period
> when the stream was latched server-side; it was never a dependency.

- ~~The voltage stream is delivered only while the official Ting mobile app
  is actively running in the foreground. With the app foregrounded, any
  subscriber receives a clean 4 Hz stream (600 samples in 150 s,
  measured). With the app backgrounded or closed, the hub still
  acknowledges `InitializeStreaming` with a void Completion but never
  fans out data, on every client configuration tested — including the
  exact encoding that ran for 40 days before 2026-08-03. Hazard,
  notification and diagnostic entities are unaffected; they use the REST
  API and remain fully functional.~~

## 3.1.1

### Fixed

- **Retired station-id probing — it was subscribing to the wrong station.**
  The hub answers every `InitializeStreaming` with a void Completion no
  matter which StationId is supplied, so "no data yet" never
  distinguished a wrong station id from an inactive stream. In practice
  the probe rotated onto site/group ids (e.g. `1118490`) and subscribed
  there. The official app uses the sensor serial as StationId
  (`chunk-GBDILMAT.js`: `StationId: sensorSerial`); so do we, always.
  Station ids persisted by earlier versions are still honored.

## 3.1.0

### Fixed

- **Regression introduced in 3.0.0: a void Completion tore down the
  connection.** SignalR answers the blocking `InitializeStreaming`
  invocation with a Completion carrying `ResultKind 2` (void) — a normal
  success acknowledgement — and the voltage stream then arrives as
  separate server-to-client invocations on the same socket. 3.0.0-3.0.3
  treated any Completion as a rejection and closed the socket within
  milliseconds of subscribing, so no sample could ever be delivered. Only
  `ResultKind 1` (which carries an error) is a rejection now. Guarded by
  a RED/GREEN regression test.
- Corrected the `completion_message()` docstring and the test fixture
  that mislabelled a void acknowledgement as "the stream-rejection
  signal" — that wrong premise is what produced the regression.

## 3.0.3

> **Superseded.** The 3.0.x entries below describe a "server-side
> streaming-authorization gate" that does not exist. The real cause was a
> stale server-side subscription plus two regressions of our own; see
> 3.1.0, 3.1.1 and 3.3.0. The text is kept for history.

### Changed

- Rejection-aware reconnect cadence: after three consecutive explicit
  subscription rejections (`Completion result:null`), retries slow from
  the 5-minute cap to 30-minute intervals (any received data resets the
  slowdown), and the station-id probe's failed-rotation cooldown widens
  from 30 minutes to 4 hours. A live wire-format matrix probe showed the
  rejection is independent of invocation field count and the
  `x-wl-api-key` header — it is server-side authorization state, and
  hammering it at reconnect cadence may itself look like the anomalous
  traffic that sustains it.

## 3.0.2

### Fixed

- One-time registry migration: byte-reversed MAC connection rows
  registered by older builds (reversed Wi-Fi before 1.2.0, reversed
  Bluetooth before 3.0.1) are now removed on setup. Only the reversed
  forms of the currently known MACs are touched; connections shared with
  other integrations are preserved.

## 3.0.1

### Fixed

- `bluetoothMacAddress` is byte-reversed by the Ting API exactly like the
  Wi-Fi MAC, but was passed through unnormalized — the device registry's
  Bluetooth connection showed the reversed form. Now normalized at the
  parse boundary like the Wi-Fi MAC. (Registry rows registered by earlier
  versions — the reversed Bluetooth MAC and the pre-1.2.0 reversed Wi-Fi
  MAC — persist until manually cleaned; new installs are correct.)

## 3.0.0 — The consolidation release

This release merges the fixes and features of every fork lineage of the
Whisker Ting integration into one codebase. See the Credits section of the
README for the full attribution map.

### Fixed

- **SignalR reconnect churn (root cause).** Outgoing hub messages were an
  unframed `{1: [...]}` MessagePack map; the server dropped every such
  connection (~70 ms after the first keepalive ping), producing an endless
  reconnect loop — with voltage sometimes still trickling through by
  byte-length coincidence, and never arriving at all for other accounts
  (simplytoast1/ha-whisker-ting#1). All outgoing messages are now
  length-prefixed flat arrays per the SignalR HubProtocol spec: six-field
  Invocations and framed `[6]` pings, with the handshake response
  validated.
- **Spurious voltage spikes (~200–750 V).** Voltage is now decoded from
  the payload's named fields (`Voltage`, `VoltageHi`, `VoltageLo`,
  `AveragePeaksMax`) — including payloads nested inside a binary blob —
  instead of scanning raw bytes for float64 markers, which could misread
  unrelated message bytes as readings.
- Options-flow saves now merge over existing options instead of replacing
  them, so internally persisted state survives a settings change.

### Added

- **`x-wl-api-key` upgrade-header authorization** on the WebSocket
  connection, matching the official app's traffic.
- **Station-id candidate probing.** When the streaming subscription stays
  silent on the device serial, the integration probes site id, SoC serial,
  and group id in the background and persists the first identifier that
  produces data.
- **Rejection-aware connection lifecycle.** A SignalR Completion for
  `InitializeStreaming` is treated as a subscription rejection (the server
  only sends one on failure) and tears the connection down; a server Close
  message does the same. Reconnect backoff resets only on received data,
  never gives up (capped at 5-minute intervals — the server-side
  streaming-authorization gate has been observed to clear on its own), and
  connections that never produce data recycle after a 60 s grace period.
  Silent stations re-arm the station-id probe on every poll, guarded by a
  30-minute cooldown after a fully failed rotation.
- **Single-notifier, identity-aware disconnect handling.** Every recycle
  path closes the socket and lets the receive loop deliver exactly one
  disconnect notification; the manager tears down the reporting instance
  (tasks cancelled, socket closed) and ignores late notifications from
  already-replaced connections — no duplicate connections, no leaked
  sockets or tasks, including across integration unload.
- Real-time pushes notify entity listeners without touching the poll
  scheduler, so a publish interval shorter than the scan interval can no
  longer starve the REST hazard/notification poll.
- **Configurable real-time publish interval** (options, 1–60 s, default
  5 s): how often the ~4 Hz voltage stream writes to Home Assistant state.
  In-memory readings and freshness tracking always run at full rate.
- Protocol golden-byte and regression tests, station-probe tests, and
  manager lifecycle tests (publish throttle, identity-aware disconnect
  handling, capped never-give-up backoff, ping/close/grace runtime
  paths); 94 tests total.

### Changed

- Voltage state writes moved from a fixed 1 Hz coordinator throttle to the
  manager-level publish interval above (default 5 s) to limit recorder
  growth.
- Integration metadata (codeowners, documentation, issue tracker) now
  points at `jasonjhofmann/ha-whisker-ting`; `msgpack` requirement relaxed
  from an exact pin to `>=1.0.0`.
- The power-outage blueprint lives at
  `blueprints/automation/whisker_ting/power_outage_notification.yaml`.

### Inherited from the merged forks

- Per-device alert feed from `/Notifications/history`: `Alerts` event
  entity, `Last brownout` / `Last weather alert` timestamp sensors, and a
  derived `Power outage` binary sensor; opt-in HA notifications for
  significant alerts plus an importable automation blueprint (billda).
- Multi-device support with site-based device naming (billda).
- Redacted diagnostics, reauth flow with wrong-account guard, tz-aware
  datetimes, entity base class, quality-scale manifest, pytest + HA test
  harness, ruff/coverage CI (billda).
- WebSocket decode/availability hardening, Cognito `ExpiresIn` token
  expiry, Wi-Fi/Bluetooth MAC device connections (with byte-order fix),
  power-quality hazard / connectivity / subscription-start entities
  (jasonjhofmann, previously released here as 1.1.0–1.2.0).

## 1.2.0 and earlier

See the git history: 1.2.0 surfaced dropped API fields (power-quality
hazard, connectivity, subscription start), 1.1.0 hardened the WebSocket
decode and availability semantics, 1.0.1 added brand assets, and 1.0.0
was the original release by Aiden Mitchell / simplytoast1.
