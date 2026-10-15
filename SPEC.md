# Flipping Nero

Agentische iPhone-App für autorisiertes Red Teaming im LAN. Eigenes Produkt, eigenes Repo, kein Ableger von FlipperHero. Sideload / GitHub, kein App Store.

Icon: schwarzer Kater, Mittelfinger, flach, eine Farbe.

Der Agent sitzt auf dem Phone. Jede Netz-Aktion läuft durch Scope, Risiko, Approval und Audit. Das Modell liefert nie das Risiko.

## Zielbild

Ein Tap startet einen Run. Titel ist die aktuelle WLAN-SSID. Scope ist das aktuelle Subnetz. Der Agent reconnt, scannt, prüft unauth Services, schreibt Findings und am Ende einen teilbaren Report.

Während der Run läuft, gibt der Operator per Siri oder Chat nach. Approvals erscheinen auf dem Lock Screen. Der Screen bleibt wach, oder der Run läuft über `BGContinuedProcessingTask` weiter.

## Harness

Kette, immer in dieser Reihenfolge:

```
ToolInvocation → ScopeGuard → RiskAssessor → Approval → ToolExecutor → Untrusted.wrap → Audit
```

- Parser baut einen Enum. Unbekanntes Tool oder freier Command-String ist ein Fehler.
- `ScopeGuard` prüft Ziel, Port, Zeitfenster, Caps, bevor irgendetwas ins Netz geht.
- `RiskAssessor` klassifiziert den geparsten Call. Das Modell hat darauf keinen Einfluss.
- Low läuft. Medium fragt, außer YOLO oder Engagement `auto_approvals`. High ist Hold-to-approve bzw. Lock-Screen-Button mit Face ID. Blocked führt der Executor nicht aus.
- Alles vom Netz (Banner, HTTP, mDNS-TXT, nmap-XML, Exploit-Output, Hostnamen) geht durch `Untrusted.wrap` mit Nonce. Lesen taintet die Runde.
- Audit ist append-only: Tool, Ziel, Risiko, Entscheidung (`approved` / `denied` / `yolo` / `engaged` / `blocked` / `skipped_needs_foreground`).

Engagement ist session-only. YOLO bleibt gespeichert, bis es ausgeschaltet wird; Einschalten ist immer ein Consent-Dialog, auch wenn die Session schon bewaffnet ist. Lockern der Capabilities ist immer ein Consent-Dialog. Ausschalten ist frei. API-Keys der Provider bleiben UI-only.

## Scope

Ohne Scope ist jedes Netz-Tool `blocked`.

- CIDR-Allowlist, Host-Denylist, Port-Allowlist, Zeitfenster
- Default beim Run-Tap: aktuelles Interface-Subnetz
- Link-Local und `169.254.169.254` bleiben blocked, außer Capability `cloud_readonly` plus explizites Ziel
- Harte Caps pro Call: Hosts, Ports, Concurrency, Timeout. Ein `/8` ist kein gültiges Argument
- Disconnect, Ablauf oder App-Kill entwaffnet

## YOLO

- Schalter in Settings plus Tool `set_yolo_mode`
- Einschalten immer Consent, auch unter YOLO
- An: medium und high ohne Sheet, Audit-Entscheidung `yolo`
- `blocked`, Scope, Denylist, Caps bleiben
- `yolo_asks_after_untrusted` default an: nach Banner/HTTP/nmap/Exploit-Output fragt die nächste offensive Aktion trotzdem. Abschalten ist Consent
- YOLO ändert Scope und Provider-Keys nicht

## Exploitation

Capability `exploit`. Module mit festem Vertrag, kein Skript-Loader, kein freies Payload-Tool:

```
check(target, scope) → CheckResult
run(target, scope)   → RunResult   // Evidence, Session-Handle, Loot-Refs
```

Jedes Modul ist Code mit Test. Ergebnis ist Evidence (Befehl, Antwort, Timestamp), kein Urteil des Modells.

Session-Handles liegen im Loot-Store, im Transcript redaktiert. Folgeaktionen sind eigene Tools (`session_exec`, `http_request_as`, …) und werden neu bewertet.

Bruteforce nur mit festen Bundle-Listen und Rate-Limit. Kein offenes Wordlist-Tool in v1.

## Loot und Cloud

Gefundene Secrets als Finding, im Transcript rotaktiert. Benutzen nur über typisierte Calls und Capability `cloud_readonly`. Credentials ins Approval-Sheet, dann Keychain. Kein AWS-CLI im Bundle, kein „führ den gefundenen Befehl aus“.

## One-Tap Run

Einmalig: Local Network, für die SSID Access Wi-Fi Information plus präziser Standort.

Danach:

1. Tap **Run**
2. Titel = `NEHotspotNetwork.fetchCurrent` SSID, sonst `LAN <datum uhrzeit>`
3. Scope = aktuelles Subnetz
4. Profil = Default (`recon` + `top-ports` + unauth-Checks)
5. YOLO und Capabilities = letzter Stand aus Settings. Der Run-Tap ändert sie nicht

Kein Formular. Fehlt Local Network, ist der Button der Permission-Prompt.

## Hintergrund und Lock Screen

Primär, iOS 26: `BGContinuedProcessingTask`, gestartet nur aus dem Run-Tap.

- Live Activity: SSID, Phase (`discover` → `ports` → `checks`), Hosts, Findings, Restzeit
- Fortschritt mindestens alle 30 s, sonst beendet das System den Task
- `expirationHandler`: Stand speichern, Teil-Report, Status `paused`
- User kann auf dem Lock Screen abbrechen

Fallback: Setting **Keep screen awake while a run is active**, default an. `isIdleTimerDisabled = true` solange der Run im Vordergrund läuft. Manuelles Sperren fällt auf den Background-Task zurück. Am Ende / Abbruch / Expiration wieder `false`.

System-Prompts (Local Network, Standort, Mitteilungen, Live Activities) nur im Vordergrund, vor dem ersten Scan. YOLO-Armieren vor dem Run.

App-Freigaben auf dem Lock Screen: Live Activity Buttons, `LiveActivityIntent`, `openAppWhenRun = false`, `authenticationPolicy = .requiresLocalDeviceAuthentication`. Allow/Deny. Timeout 60 s → `denied`, Run macht mit dem nächsten Step weiter. Push-Actions nur als Reserve.

Steps, die einen Dialog brauchen während die App hinten ist: `skipped_needs_foreground`, weiter.

## Siri während eines Runs

App Intent **Instruct Nero**: Freitext an die laufende Session. `openAppWhenRun = false`.

- Gleicher Agent-Loop, gleiche Policy, gleiches Audit
- Die Nachricht ist Operator-Text, hat Vorrang vor dem aktuellen Plan
- Beispiele: „nur 10.0.0.0/24“, „Redis auf .12 überspringen“, „Report jetzt“, „Run stoppen“
- Antwort kurz, per Siri und in der Activity
- Liegt ein High-Step an, bestätigt Siri über denselben Intent-Confirm wie FlipperHero, plus Lock-Screen-Button
- Ohne laufenden Run startet der Intent keinen Scan. Dafür gibt es **Start run** / **Stop run** als eigene Intents

Shortcuts-Parität: alles, was die UI kann, kann Siri. Credentials und Policy-Lockern bleiben Consent.

## Report

Ein Run = ein Engagement. Export Markdown plus JSON, Share Sheet.

Drin: Titel, Operator-Notiz, Scope, Fenster, Timeline aus dem Audit, Findings (Schwere, Host, Port, Modul, gekürzte Evidence, Empfehlung), Loot-Index rotaktiert, Hosts gesehen vs. Hosts mit Befund.

Nicht drin: Provider-Keys, volle Secrets, rohe Tool-Bodies, System-Prompt. Volle Evidence-Anhänge opt-in pro Finding.

Tool `export_report` ist low und schreibt nur in den App-Container. Der Agent schickt den Report nicht ins Scope-Netz.

## Toolfläche v1

On-Device:

| Tool | Risiko | Zweck |
|---|---|---|
| `get_network_context` | low | Eigene IP, Gateway, DNS, Interface |
| `discover_hosts` | medium | ICMP plus Connect auf wenigen Ports, nur im CIDR |
| `scan_ports` | medium | Connect-Scan, Preset `top-100` oder explizite Liste |
| `browse_bonjour` | low | Deklarierte Service-Typen, TXT, Port |
| `grab_banner` | medium | Ein Host, ein Port |
| `http_request` | medium, POST high | Nur in-scope URLs, Body gedeckelt |
| `dns_lookup` | low | A/AAAA/PTR/SRV im Scope |
| `record_finding` | low | Strukturierter Befund, vom Code validiert |
| `export_report` / `get_audit_log` | low | Wie oben |
| `set_engagement` / `set_yolo_mode` | consent | Nur der Mensch bewaffnet |

Field Node, Capability `pivot`, mTLS, kein freies argv: nmap-Profile `discovery` / `top-ports` / `service-version`, plus TLS- und SSH-Audit. Keine NSE-Exploit-Skripte.

Cloud, Capability `cloud_readonly`: typisierte Read-Calls nach Approval.

Bewusst nicht in v1: ARP, SYN-Scan, pcap, Packet Tunnel, MITM, Reverse Shell, Persistenz, freies Shell-Tool.

## iOS-Grenzen

Sideload ändert die Sandbox nicht.

- Kein `SOCK_RAW`, kein `/dev/bpf`, kein ARP, keine fremden MACs
- TCP nur als voller Connect (`NWConnection`)
- ICMP über `SOCK_DGRAM` + `IPPROTO_ICMP`
- Multicast (SSDP, Bonjour-Wildcard) braucht `com.apple.developer.networking.multicast`
- Ohne das Entitlement nur die Typen in `NSBonjourServices`
- Local Network Permission Pflicht
- nmap als eingebettete Engine bleibt unprivileged: Connect-Scan, Banner, erlaubte NSE. SYN/UDP-Rohscan/OS-Detect/Idle-Scan tot. Wrapper nimmt nur typisierte Profile, kein argv. Voller nmap lebt auf dem Field Node

## Repo-Schnitt

Eigenes App-Repo.

```
App/                 SwiftUI, Run, Chat, Approvals, Findings, Audit
Sources/AgentKit/    Loop, Tools, Risk, Untrusted, Audit, Prompts
Sources/NeroKit/     Scope, recon, spray, exploit modules, loot
Shared/              Live Activity attributes
cmd/fieldnode/       Go, volle Scanner, nur über Pivot
```

Tests: `ScriptedLLM`, `ScriptedGate`, `FakeNetwork`. Neues Tool ohne Sample im Sweep bricht den Build. Denied und out-of-scope ändern nachweislich nichts.

## Reihenfolge

1. App-Gerüst, Icon, Agent-Loop gegen Fake-Netz. Scope, YOLO, Audit, Report-Stub
2. One-Tap Run, SSID-Titel, Idle-Timer
3. On-Device-Recon: Context, Discover, Connect-Scan, Banner, Bonjour, Finding
4. Live Activity plus Lock-Screen Allow/Deny, `BGContinuedProcessingTask`
5. Siri **Instruct Nero** / Start / Stop
6. Exploit-Module hinter Capability
7. Loot mit Redaction, `cloud_readonly`
8. Field Node

## Policy in einem Satz

Ohne Scope passiert nichts. Mit Scope und ohne YOLO fragt jede offensive Aktion. Mit Scope und YOLO läuft sie, wird geloggt, und landet im Report. Siri spricht in denselben Loop.
