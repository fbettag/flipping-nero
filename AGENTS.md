# AGENTS.md

Guidance for anyone, human or AI, changing Flipping Nero.

## The parity rule

**Every function the UI offers must also be available to the chat agent as a tool.**
When you add or change something a user can do in the app, add or update the matching tool in
the same change, with a test. "The agent can't do X but the button can" is a bug.

Current mapping, keep it up to date:

| UI | Tool |
|---|---|
| Run: one-tap run, stop, partial report | `get_network_context`, `discover_hosts`, `scan_ports`, `grab_banner`, `browse_bonjour`, `http_request`, `dns_lookup`, `record_finding`, `export_report` (the run is the agent loop with a profile) |
| Run: scope card | `set_scope`, `get_app_settings` |
| Chat: everything above, plus findings list | `get_findings` |
| Findings: report share | `export_report` (writes into the app container only) |
| Settings: YOLO, ask-after-reading, auto-approve medium | `set_yolo_mode`, `set_yolo_asks_after_untrusted`, `set_auto_approve_medium` (consent dialog when loosening) |
| Settings: engagement arm dialog, banner | `set_engagement` (consent dialog when arming) |
| Settings: provider, model, key present | `get_app_settings`; provider/model switches and key checks are credential-only UI |
| Settings: model catalog, connection test | `list_models`, `test_model_connection` (use a stored key; saving/removing keys stays credential-only UI) |
| Shortcuts: Instruct / Start / Stop | the run session itself, `StartRunIntent`, `StopRunIntent` |
| Live Activity: Allow / Deny / Stop | `ApproveStepIntent`, `DenyStepIntent` (resolve the same approval), `StopRunIntent` |

The one deliberate asymmetry, as in FlipperHero: **the agent can never silently loosen its own
permissions.** `set_yolo_mode(true)` and `set_engagement(enabled: true)` are
`requiresExplicitConsent` and always show the dialog, even under YOLO or an armed engagement.
A `set_scope` call that widens the scope (`loosensScope`) gets the same treatment. Tightening
runs through the normal approval path.

A second deliberate asymmetry: **the pivot relay has no tool at all.** It is started and
stopped by the operator in Settings and only with the `pivot` capability armed; the agent
cannot open an outbound bridge. See "Pivot relay" below.

## Safety rules that are not negotiable

- **Without scope, nothing leaves the phone.** `ScopeGuard.check` runs before risk, approval
  and execution on every network tool. No scope, no wire.
- **Risk is computed in `RiskAssessor` from the parsed, validated call.** Never let the model
  supply or influence the risk level.
- **Everything from the network goes through `Untrusted.wrap`** with the executor nonce, and
  reading it taints the turn (`ToolExecutor.tainted`). Secrets found in output are replaced by
  `[loot:Lx]` references before the model sees them (`LootScanner`).
- **Blocked is final.** Link-local, loopback, multicast, reserved ranges never pass. A sweep
  block may not overlap them. Link-local single hosts need the `cloud_readonly` capability plus
  an explicitly named target.
- **Capability-gated tools refuse to run until the operator armed engagement**: `exploit`
  unlocks `exploit_check`, `exploit_run` and `auth_spray`. The arm dialog is a Hold-to-confirm
  with its own audit entry.
- **No free-form network tool.** No shell, no raw sockets, no argv. Exploit modules have a
  fixed contract (`check`/`run`) and a fixed registry; the spray bundles are fixed lists with a
  1/s rate limit. Everything else is a typed tool.
- **What the operator approves is what gets executed.** There is no re-fetch between approval
  and execution in v1 because nothing is prepared ahead; keep it that way: if you add prepared
  content, prepare it during approval like FlipperHero does.
- **Reports and transcripts carry redacted evidence only.** Full loot values appear exactly
  once, in the approval dialog; reports carry the loot index without values.
- **Loot reaches the Keychain only through an approval.** The executor attaches the newest
  loot as previews to the next approval request; approving it persists those values via
  `LootVault` (`KeychainLootVault` in the app), denying does not. Without a dialog (low risk,
  auto-approve, YOLO without taint) loot stays in memory for the session.
- **The report never leaves the app container on its own.** `export_report` writes locally;
  sharing is the operator's ShareLink.

## Engagement and capabilities

`EngagementState` (AgentKit) is session-only: never persisted, gone on restart, and the run
disarms on stop, expiry or app kill. Capabilities (`Capabilities` in NeroKit):
`auto_approvals` (skip per-action prompts; blocked levels stay blocked), `exploit`,
`pivot` (unlocks the Settings-side relay start), `cloud_readonly`. Auto-approved actions are
audited as `engaged`; YOLO-run actions as `yolo`.

## Pivot relay

`PivotRelay` (NeroKit) turns the phone into a TCP bridge for an operator-side handler: it
listens inside the LAN, drops peers outside the scope CIDRs (audited as `blocked`), and pipes
every allowed session byte-for-byte to the configured connect-back host and port. Typical
use: point reverse_tcp payloads at the phone's LAN IP and the listen port; the handler
outside sees the sessions. Rules:

- Operator-only: start/stop lives in Settings, requires an armed scope and engagement with
  the `pivot` capability; disarming stops the relay. There is deliberately no agent tool.
- The connect-back host is operator-configured and validated (never loopback/multicast/
  reserved as a literal address); every bridged and rejected peer lands in the audit log.
- Listening on the LAN needs the Local Network permission, which the run already requests.

## Background and Lock Screen

- iOS 26+: `BGContinuedProcessingTask` (`BackgroundRunController`), submitted only from the
  Run tap. The identifier is `<bundle>.run.*`; it must stay in
  `BGTaskSchedulerPermittedIdentifiers` and `UIBackgroundModes` keeps `processing`.
- Progress must be reported continuously or the system expires the task; tool events and the
  Live Activity feed it. `expirationHandler` saves a partial report and marks the run paused.
- Approvals in the background go to the Lock Screen (`ApproveStepIntent` requires local device
  authentication, `DenyStepIntent` does not) with a 60 second timeout that counts as denied.
- Permission changes (`requiresExplicitConsent`) never go to the Lock Screen; in the background
  they are audited as `skipped_needs_foreground` and the run moves on.
- Foreground fallback: the screen stays awake while a run is active (`keepAwake` setting).

## Layout

- `Sources/NeroKit`: scope, probes (NWConnection, ICMP datagram, URLSession, dnssd), discovery,
  exploit modules, spray, findings, loot. No AgentKit imports.
- `Sources/AgentKit`: tool surface, risk, scope-aware executor, approval, audit, untrusted,
  LLM client, session, prompts, report. Depends on NeroKit.
- `App/`: SwiftUI app, intents, controllers. `Shared/`: Live Activity attributes and the
  Lock Screen intents, compiled into app and widget (`#if WIDGET_EXTENSION` guards the
  app-side work).
- `Widgets/`: the Live Activity UI. `project.yml` is the XcodeGen spec; the `.xcodeproj` is
  generated. `scripts/make-assets.swift` regenerates the icon and logo bitmaps.
- `cmd/fieldnode/` (Go scanner behind the pivot capability) is a later stage; nothing imports
  it yet.

## Build and test

```sh
swift test                                    # needs full Xcode for XCTest
cp Config/Local.xcconfig.example Config/Local.xcconfig   # once, then fill in your team
xcodegen generate
xcodebuild build -project FlippingNero.xcodeproj -scheme Nero \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' CODE_SIGNING_ALLOWED=NO
```

A new agent tool needs a sample in `ToolSweepTests.samples`; the sweep fails otherwise.
`testDeniedAndOutOfScopeChangeNothing` proves that denied and out-of-scope calls touch no
wire; extend it when you add targets. Tests use `FakeProbe`, `ScriptedGate`, `ScriptedLLM`
and `FakeAppControls` (AgentKitTests); no network, no device.

Debug builds understand `NE_DEMO=1` (sample data, no network needed) and
`NE_DEMO_APPROVAL=1` (with a pending approval sheet) for UI review and screenshots.

## iOS networking facts baked into the code

- No `SOCK_RAW`, no `/dev/bpf`: TCP is a full connect (`NWConnection`), ICMP is
  `SOCK_DGRAM` + `IPPROTO_ICMP` only.
- Bonjour browsing works only for the types declared in `NSBonjourServices` (no multicast
  entitlement in this build); the list in `Info.plist` and `BonjourTypes.declared` must match.
- `NSAllowsLocalNetworking` is on because `http_request` speaks plain HTTP to LAN hosts.
- https with self-signed certificates is accepted **only** for hosts the scope covers at
  handshake time (`NWProbe(hostInScope:)`, wired to `ScopeGuard` in the app). Publicly
  invalid chains outside the scope cancel the challenge. This is deliberate: authorized LAN
  assessment would be blind otherwise.
- The route table (gateway lookup) is macOS-only; on iOS `get_network_context` reports no
  gateway. If Apple ever ships the headers, drop the `#if os(macOS)`.
- `NEHotspotNetwork.fetchCurrent` needs the Wi-Fi info access plus location permission; every
  failure falls back to a timestamped LAN title.

## Conventions

- Keep changes small and tested. `swift test` must stay green and the app scheme must build.
- English-only strings in v1; when localization comes, tool summaries and risk reasons are
  user-facing and go through string catalogs first.
- Do not commit `Config/Local.xcconfig` or anything with a team id, key or personal bundle id.
