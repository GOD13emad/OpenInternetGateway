# OpenInternetGateway — Project Knowledge / Evidence Record

Status: CURRENT
Updated: 2026-09-30

## 2026-09-30 — Linux OpenVPN quality/reliability change set (v2.5.17 candidate)

### Context / Objective
Improve Linux OpenVPN relay quality and resilience without disrupting a healthy active tunnel. Windows remained outside mutation scope until Linux passes package/live validation.

### Confirmed baseline
- Direct physical ISP benchmark: ~29.53 Mbps down / 9.75 Mbps up / ~264 ms HTTPS latency.
- Previously active VPN relay `138.64.235.144:48483/UDP` (`e779feec...`) benchmarked ~6.24 Mbps down / 0.78 Mbps up / ~887 ms HTTPS latency.
- Source/runtime baseline before mutation backed up under `~/.local/share/OpenInternetGateway/evidence/v2517-prelive-backup-20260930/`.
- Evidence status: CONFIRMED from live benchmark and runtime state.

### Implemented decisions
1. **Adaptive relay ranking**
   - Ranking now uses protocol/port preference, VPN Gate source latency/speed/score, direct-ISP fast probes, persistent real throughput/latency measurements, prior successes, and failures.
   - Fresh failures (<6 h) receive a strong temporary demotion so recovery does not immediately retry a relay that just failed live handshake/validation.
   - Rationale: source-advertised metrics were repeatedly shown to be insufficient predictors of actual tunnel quality.

2. **Pool expansion and refresh resilience**
   - Linux Config Factory target pool increased from 24 to 48 generated candidates; retained LKG count increased from 4 to 8.
   - Refresh queries official `https://www.vpngate.net` plus known mirrors in parallel with bounded curl connect/total timeouts.
   - Multiple snapshots are merged/deduplicated when available; cached snapshot remains fallback.
   - Live refresh expanded active pool from 28 to 56 profiles (26 UDP / 30 TCP) while the existing tunnel stayed active.

3. **Public-profile safety filter**
   - Rejects imported profiles containing local execution/plugin directives including `script-security`, `up`, `down`, `route-up`, `route-pre-down`, `ipchange`, `plugin`, `client-connect`, `client-disconnect`, `learn-address`.
   - Rationale: downloaded public profile content is treated as data, not trusted local execution policy.

4. **Non-disruptive exact-relay preflight**
   - Candidate is imported as `OIG-VPN-PREFLIGHT` with `ipv4.never-default=yes`, route/DNS auto-import ignored, and 10 s activation timeout.
   - A healthy working tunnel is not torn down unless the candidate can complete OpenVPN handshake while preserving default route and effective DNS server set.
   - Preflight evidence: `~/.local/share/OpenInternetGateway/evidence/preflight-last.json`.

5. **No automatic healthy-tunnel quality switching**
   - `factory-refresh` and fast qualification are read-only with respect to the active/default VPN route.
   - Foreground `connect`/`refresh` qualifies relays over the physical ISP path before ranking.
   - Automatic quality work does not replace a healthy tunnel solely to chase a higher score.
   - Rationale: NetworkManager dual-full-route make-before-break was experimentally unsafe on this laptop (see failure evidence below).

6. **Shorter explicit-switch outage path**
   - Fixed `sleep 2` teardown delay removed; backend now waits only while an OIG VPN is actually still active, bounded by 1 s.
   - One controlled relay switch achieved 100/100 TCP continuity probes after this change.

7. **Interrupted activation state reconciliation**
   - Immediately after NetworkManager activates a candidate, current profile identity is written with `validationPending=true`.
   - Pending identity is not trusted as geo/IP health fallback.
   - After validation it is atomically promoted to `validationPending=false`; failed validation restores previous metadata.
   - Prevents stale relay identity after caller/tool interruption during post-connect validation.

8. **Process provenance race fix**
   - `/proc/$PPID/cmdline` is read only when readable, preventing harmless parent-exit races from leaking warnings into product output.

### Live experiments / failures converted to guards
- **Dual full-route NetworkManager make-before-break experiment: FAIL / REJECTED.**
  - Second VPN handshake completed, but NetworkManager helper `SetConfig/SetIp4Config` calls were rejected by D-Bus policy; OpenVPN entered repeated `ping-restart`; continuity suffered a long timeout streak.
  - NetworkManager journal around 20:55 local records `OIG-VPN-NEXT`, `tun1`, default-policy changes, D-Bus rejections, and repeated restart cycles.
  - Decision: do not implement two simultaneous full-route NetworkManager VPNs on this stack.
- **Candidate `vpn129727690 / 133.32.152.219:1076/UDP`:** preflight PASS; real benchmark ~3.98↓ / 1.30↑ Mbps / 2211 ms; rejected as worse quality.
- **Candidate `vpn281089294 / 118.240.63.106:1195/UDP`:** preflight PASS; ~5.09↓ / 1.16↑ / 984 ms; rejected versus historical baseline.
- **Candidate `vpn739654595 / 114.184.56.135:1596/UDP`:** preflight PASS; switch continuity 100/100; ~4.51↓ / 0.74↑ / 1105 ms; rejected versus historical baseline.
- **Candidate `vpn904156182 / 218.41.216.13:1195/UDP`:** preflight FAIL code 13; current tunnel preserved; failure recorded.
- **Candidate `vpn443136775 / 222.228.238.250:4094/UDP`:** preflight FAIL code 13; current tunnel preserved; failure recorded.
- **Historical baseline `138.64.235.144:48483/UDP`:** earlier benchmark remained best among current measured profiles, but a later exact restore attempt failed validation; it is therefore not treated as presently available authority.
- Auto-recovery subsequently restored protection on `vpn767479473 / 211.226.144.221:1195/UDP` (KR), benchmark ~4.21↓ / 1.33↑ / 1145 ms.

### Validation / regression evidence
- Source test suite after latest changes: **59/59 PASS**.
- `npm run lint`: PASS.
- `npm audit --omit=dev`: 0 vulnerabilities.
- Linux source/runtime backend hash parity verified repeatedly during live tests.
- Live pool refresh from official HTTPS source: pool 56, metadata complete, Config Factory healthy.
- Auto-Recovery remained enabled/active; desired state stayed `on`.

### Limitations / truth boundary
- **Zero-loss relay switching is not proven as a universal guarantee.** Some controlled switches recorded one 2 s TCP probe timeout, while another switch recorded 100/100 pass. The product therefore avoids automatic switching of a healthy tunnel.
- VPN Gate relay quality is inherently time-varying. Historical throughput is evidence, not a permanent promise.
- Direct ISP capacity (~29.5/9.8 Mbps) is much higher than tested public relay throughput; the bottleneck is current public-relay quality, not the local physical path.
- Old historical relays with ~12.32↓/3.95↑ and ~8.39↓/2.52↑ benchmarks no longer have recoverable profile files in the active/LKG generations; they are not usable current candidates.

### Reuse targets
- Release notes / changelog: adaptive ranking, bounded multi-source refresh, safe profile filtering, non-disruptive preflight, recent-failure demotion, activation reconciliation.
- Future Windows parity review: reuse the evidence model and quality scoring concepts, but do not copy Linux NetworkManager-specific handover logic.
- Project Brain milestone: propagate after Linux packaged artifact and live install validation pass.

## 2026-09-30 — Exact relay rollback failure → immediate adaptive recovery guard

### Failure / Root Cause
A real product-level selection of `public-vpn-199 / 219.100.37.196:443/TCP` passed non-disruptive preflight but failed post-switch validation. The immediately preceding exact relay (`118.240.63.106:1195/UDP`) also failed exact rollback at that moment. `connectProfile()` then threw and left no OIG tunnel active until a later/manual general recovery. This violates the protection objective even though `desiredState=on` was preserved.

### Prevention / Guard
- `connectProfile()` now retains exact rollback as first choice.
- On Linux only, if exact rollback cannot restore protection, it immediately invokes adaptive general `connect` recovery before returning control.
- Recovery is accepted only when live status is connected and a current profile SHA exists.
- The recovered relay becomes preferred, so later recovery does not keep targeting the now-unavailable exact relay.
- Structured outcomes distinguish exact rollback from general recovery:
  - `SELECTED_RELAY_FAILED_GENERAL_RECOVERY`
  - `SELECTED_RELAY_NOT_ACTIVE_GENERAL_RECOVERY`
  - `SELECTED_RELAY_COUNTRY_MISMATCH_GENERAL_RECOVERY`
- Windows behavior remains unchanged in this Linux-first phase.

### Regression Evidence
- Added dynamic unit test reproducing: selected exact failure → previous exact rollback failure → adaptive Linux connect succeeds → protected recovered result + preferred metadata update.
- Added static coverage asserting adaptive recovery is present in all three post-selection validation failure branches.
- Full suite after guard: **61/61 PASS**, lint PASS, npm audit production vulnerabilities = 0, syntax/diff gates PASS.

### Live Recovery Evidence
After the real failure, emergency adaptive recovery selected `223.204.223.151:1965/UDP` (TH), restored `OIG-VPN-LIVE`, `tun0`, `desiredState=on`, and full-route traffic. This live incident is the reason the new guard is mandatory before final Linux promotion.

### Status
Source guard: CONFIRMED/PASS. Packaged/install parity for this newest guard: PENDING rebuild and live promotion.


## 2026-09-30 — v2.5.17 Linux OpenVPN quality engine acceptance
Previous accepted authority: v2.5.16 / 92aae85137fe3dc8a3770ff36721b4f09f1677df.
Current delta: Linux-only OpenVPN quality/reliability work on feature/openvpn-quality-v2517, package version 2.5.17. Adaptive ranking now consumes protocol/port, source metrics, direct-ISP fast probes, persistent throughput/latency, successes and failures; pool refresh is bounded/parallel, public profiles are execution-directive filtered, exact selection has non-disruptive handshake preflight, stale activation metadata is reconciled, and failed exact rollback falls through to adaptive Linux recovery. No WireGuard or non-OpenVPN engine was added.
Rejected design by live evidence: two simultaneous full-route NetworkManager VPNs caused D-Bus SetConfig/SetIp4Config rejection, OpenVPN restart loops and a traffic blackhole; this path is explicitly not used. Automatic quality work never switches an already healthy tunnel.
Source gates: 61/61 tests PASS; lint PASS; npm audit=0; Bash/Python/diff gates PASS.
Artifact evidence: AppImage SHA256 c65a40d5707c50339769df8f0b8ed37d4f672fce1c55201fa8af9233c7029762; DEB SHA256 40f6aba84dbb5191997c4254a0c2cb5457365ecfcc41bc0fca08002a782f9b30. AppImage embedded core/runtime files are source-exact; packaged version=2.5.17.
Installed runtime: ~/.local/opt/OpenInternetGateway-2.5.17-final; platform-backend SHA256 ef355eec8d8c79d771d29f3a01675782a5bec522fb557662cb7e102816dea81d source==installed; Linux backend/config-factory hashes also source==runtime. Renderer uses --enable-sandbox; no real app process uses --no-sandbox; compatible root:root/4755 helper remains active.
Promotion V&V: dashboard runtime was replaced using staged/verified bytes while the independent tunnel stayed live. Across 56 continuity samples: BAD_IFACE=0, VPN_MISS=0, TCP_FAIL=0, max TCP sample 1304 ms. Pre/mid/post route all remained tun0. Egress remained TH 223.204.223.151; desiredState=on; poison=false; fullRoutes=2. Current relay benchmark ~5.86 Mbps down / 1.63 Mbps up / 839.2 ms HTTPS latency. Auto-Recovery timer remains active/enabled; last service status=0/success.
Evidence record: evidence/v2517-linux-final-acceptance-20260930.json SHA256 075fbf5bd0d29fab1b5d67efd2ed1a4a195b1ff5fa93a0c5aae729e35c4ad7c6.
Status: LINUX PASS / WINDOWS PENDING. This is not yet cross-platform FINAL.
Exact Next Action: port the evidence-backed OpenVPN quality/source/history improvements to Windows, but do not copy Linux NetworkManager-specific handover logic; preserve Windows pre-existing network state during initial implementation/testing.

## 2026-09-30 - v2.5.17 Windows OpenVPN quality source candidate
Previous accepted cross-platform base: v2.5.16 / 92aae85137fe3dc8a3770ff36721b4f09f1677df. Linux v2.5.17 checkpoint tree was transferred byte-for-byte before Windows work.
Windows delta is intentionally Windows-native: bounded parallel VPN Gate refresh, structurally safe partial-row recovery with previous-cache coverage fill, public-profile execution-directive filtering, larger diverse pool (target 48), and connector ranking using source metrics + persistent success/failure history + direct fast probes + historical throughput/latency. No Linux NetworkManager handover logic or dual-tunnel experiment was copied.
Root cause addressed: Windows connector selection previously prioritized preferred/success/UDP/rank but did not consume the already-existing connection-benchmarks history. Pool refresh was serial/first-source and public profiles lacked the Linux execution-directive filter.
Cold-start V&V in an isolated temp root with no cache: PASS in ~10.1 s; 59 complete live rows; 48 promoted profiles; UDP=6, TCP=42; 7 countries; unsafe profiles=0. A strict 48-row promotion threshold was rejected as unnecessary: 39 valid live rows had previously caused a false cold-start failure even though the builder supports a smaller healthy pool. Minimum live promotion threshold is 8 structurally complete rows, while Count=48 remains the target ceiling.
Regression gates after final threshold: 65/65 PASS; lint PASS; npm audit production vulnerabilities=0; PowerShell parse PASS; git diff --check PASS.
Windows user/network prestate remained preserved throughout source work: desired=off, OVPNConnectorService stopped/manual, no OIG /1 routes, physical default route Ethernet 3 via 192.168.20.1. Installed app remains 2.5.16 at this milestone.
Evidence: C:\Users\Aa.Emad\AppData\Local\OpenInternetGateway\evidence\v2517-windows-source-candidate-20260930.json ; SHA256 010fa4a6de30eb437d67ef8514ac3f86b8e689bd88d7235e72f5f77d39873fdd. Prestate evidence SHA256 a5252418250a0ab231a8780cdbcf10690ff12d8624d9e3be82e84576babf0559.
Status: SOURCE PASS / WINDOWS ARTIFACT+INSTALL+LIVE V&V PENDING.
Exact Next Action: commit this source candidate, build Windows 2.5.17, verify packaged source/runtime parity and no-admin installer metadata, then install while desired=off and run runtime/regression validation before any optional live tunnel test.

## 2026-09-30 - v2.5.17 Windows installed/runtime acceptance
Authority before evidence-only commit: 232bed12c56d14e0e53a932fb9b2b4dedc655a3d.
Artifact: OpenInternetGateway-Setup-2.5.17.exe SHA256 dfa15123f8870326eec62e88af0c368e75b82579a73b68524ba2d620a604ab70, 111650261 bytes. NSIS build evidence: requestedExecutionLevel=asInvoker, perMachine=false, allowElevation=false. Packaged version=2.5.17; app.asar and Windows backend resources are source-exact.
Pre-install rollback backup: C:\Users\Aa.Emad\AppData\Local\OpenInternetGateway\backups\install-2.5.16-pre2517; 143/143 files and 388765337 bytes matched; critical hashes exact.
Installed runtime: 2.5.17. Launch from the non-admin Commander process reported LAUNCHER_ADMIN=False. Package->installed app.asar/backend and installed->runtime backend hashes are exact. Renderer has --enable-sandbox; no real app process uses --no-sandbox.
Runtime Config Factory refresh: PASS in 9899 ms; pool 56; validated 6; standby 50; quarantined 14; UDP 21 / TCP 35; 8 countries; metadataComplete=true. Bounded partial live fetch supplied 44 complete rows and cache fill supplied 120 unique historical rows (164 merged), preserving coverage without treating an incomplete file as a complete snapshot.
Direct fast qualification: PASS over physical Ethernet 3 (192.168.20.5 via 192.168.20.1, proxy bypassed); 56/56 profiles probed, 13 currently reachable, median reachable fast latency ~243 ms, 6497 ms total. This wrote quality evidence only and did not change VPN state.
AutoRecovery post-install manual trigger: PASS / LastTaskResult=0. desired remained off, OVPNConnectorService remained stopped/manual, and no OIG /1 routes appeared.
UI lifecycle smoke using Win32 state: second launch changed the existing Open Internet Gateway top-level window hidden->visible; WM_CLOSE changed visible->hidden while 4 Electron processes remained alive; no terminal-like child process was present. Native Commander GUI lease itself returned GUI_OUTCOME_UNCERTAIN_RESTART_REQUIRED, so no mouse/keyboard claim is made from that unavailable path.
Validation boundary: live Windows VPN connect/switch was intentionally not executed because the project constraint forbids changing the active Windows Internet/route. The connector engine and service control path are unchanged from the accepted v2.5.16 baseline; this change set modifies source refresh, profile safety and ranking. This is a deliberate non-disruptive validation boundary, not an inferred live-connect PASS.
Evidence: C:\Users\Aa.Emad\AppData\Local\OpenInternetGateway\evidence\v2517-windows-final-acceptance-20260930.json ; SHA256 a34c52d1c44528ad983824403f694ae1bb16213ae92a25980c32d83d1475aeed.
Status: WINDOWS INSTALLED/RUNTIME PASS (NON-DISRUPTIVE SCOPE). Linux installed/runtime PASS remains accepted from the prior milestone.
Exact Next Action: publish the combined branch authority, synchronize Linux source authority to the same commit/tree, rerun cross-platform source regression, then promote main/tag/release if GitHub publication gates pass.

## 2026-09-30 - Release seed blocker: bounded partial VPN Gate transfer handling
Context: after PR #1 and main build gates passed for authority 8288ab30c682c460a6e10eef242a367a7e831bb0, the exact release.yml seed command was tested in a clean temp root before creating v2.5.17. It failed with No live VPN Gate mirror and no cached API snapshot; therefore the tag was deliberately not created.
Root Cause: Linux config_factory.fetch discarded every curl result with non-zero exit code. On the current Linux network, the VPN Gate endpoints return useful data before the hard 6 s deadline but curl exits 28. Direct evidence: official HTTPS endpoint delivered 736,978 bytes / 55 newline-complete CSV rows before curl=28; mirror 210.222.246.148:12814 delivered 332,578 bytes / 25 complete rows before curl=28. The old Linux logic discarded both. Windows had already demonstrated safe structurally validated use of partial transfers.
Prevention/Guard candidate: only for the VPN Gate API, curl timeout 28 may return already-received bytes with a partial flag. refresh_snapshot drops any unterminated tail row, accepts a source only when at least 8 complete CSV rows remain, deduplicates rows, and still passes every candidate through the existing base64/OpenVPN structure and unsafe-directive validation in promote(). Connect/total timeouts remain bounded; no unbounded retries are added. Evidence now records partialSourceCount.
Source gates on Windows after candidate patch: 65/65 tests PASS; lint PASS; production audit vulnerabilities=0; Python compile and git diff-check PASS. Windows runtime/network unchanged: desired=off, connector stopped, OIG fullRoutes=0.
Status: ROOT CAUSE CONFIRMED / FIX CANDIDATE; Linux clean-root release-seed validation PENDING.
Exact Next Action: publish candidate to feature branch, synchronize Linux source to that exact commit, rerun the exact release.yml seed command in a clean temp root, then accept/reject before main/tag promotion.

## 2026-10-01 — v2.5.17 Windows OpenVPN quality source gate
Context: After Linux v2.5.17 acceptance, the evidence-backed OpenVPN quality/source/history concepts were ported to Windows without Linux NetworkManager handover logic. Windows prestate remained desired=off, OVPNConnectorService stopped, and the only default route remained physical Ethernet 3.
Decision/Delta: Windows Config Factory now targets up to 48 profiles (6/country, 8 preserved), filters public profiles containing executable/script/plugin directives, refreshes VPN Gate sources in bounded parallel jobs with HTTPS-first seeds and structurally-valid partial-row handling, and keeps prior cache coverage when available. Headless-Control now ranks candidates using source metrics, protocol/port preference, persistent success/failure history, recent direct-ISP fast probes, and stored throughput/latency; recent failures receive explicit demotion. Foreground Windows Connect qualifies the current pool through the existing physical-ISP benchmark before connector mutation; Refresh/Factory Refresh qualify after atomic cache promotion and do not change desired state.
Evidence: cold-start temp-root Config Factory with no prior cache produced 59 complete live rows in ~10.1s, promoted 48 profiles atomically (UDP=6/TCP=42), covered 7 countries, unsafe-profile count=0. Source gates after final threshold correction: 65/65 tests PASS, lint PASS, npm audit=0, git diff --check PASS. Windows network remained desired=off, connector stopped, physical default route unchanged throughout source/testing work.
Rationale: a fixed minimum of 48 live rows was rejected as unnecessary rigor: Count=48 is the pool ceiling, not a correctness minimum. Cold-start promotion requires >=8 structurally-complete live rows (same threshold used to mark a source usable); subsequent refreshes can add live rows and preserve validated cached diversity. Partial transport output is never blindly treated as a complete snapshot.
Status: WINDOWS SOURCE PASS / PACKAGED-INSTALL RUNTIME PENDING.
Reuse Targets: architecture, release notes, final evidence, future OpenVPN ranking maintenance.
Exact Next Action: verify the Windows 2.5.17 NSIS artifact byte-for-byte against this source checkpoint, then perform a per-user no-elevation install while preserving desired=off.

## 2026-10-01 — Windows no-blackhole handover investigation
Context: Native OpenVPN Connect 3.9 / OpenVPN3 core 3.11.3 connection succeeded on Windows but continuity monitor observed ~2.8 s TCP blackhole during native full-route takeover. Goal is no user-visible Internet cut while preserving headless per-user operation.
Rejected experiment 1: `route-delay 3` in the derived service profile. OpenVPN3 explicitly logged `Unsupported option (ignored)` for route-delay, so the experiment was rolled back.
Rejected experiment 2: `route-nopull` + manual net30 host-route preflight + manual /1 promotion. OpenVPN3 accepted route-nopull and multiple relays reached EVENT: CONNECTED with valid net30 endpoints, but manual host-route data-plane probes failed. The controlled JP relay `fa7b4ad...` failed this class three times and was quarantined. Independent physical continuity remained intact (43/43 TCP probes in the final exact run; no /1 takeover), proving fail-safe behavior but not functional promotion.
Historical evidence: Native successful session installed TAP address, native /1 routes, DNS, then OpenVPN Connect WFP ActionBase rules including `allow IPv4 traffic from TAP`, followed by EVENT: CONNECTED. route-nopull sessions showed pushed redirect-gateway/DNS ignored and no corresponding ActionBase/WFP allow lines in the tested session. This makes missing native WFP routing setup a probable contributor to manual-host-route failure; not independently proven.
Method evidence: OpenVPN 2.6 manual documents route-nopull as rejecting pushed routes, block-outside-dns, and DHCP/DNS while still permitting TUN/TAP TCP/IP properties. OpenVPN Connect service-daemon docs expose seamless-tunnel and connector settings but no supported delayed-route handover primitive. Microsoft routing docs state that for equal-prefix routes, preference uses route + interface metric; current Windows measurements: Ethernet 3 interface metric 25, TAP `Local Area Connection` metric 9000.
Decision: Stop patching route-nopull after repeated same failure. Next architecture prototype is external/non-product: retain native OpenVPN Connect profile/routing/WFP, preinstall temporary physical /1 shadow routes on Ethernet 3 with lower metric, wait until native EVENT: CONNECTED/WFP setup, then remove only the shadow routes. If this live prototype does not preserve continuity and yield healthy VPN egress, reject it without product promotion.
Sources: OpenVPN 2.6 Manual https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual.html ; OpenVPN Connect service daemon mode https://openvpn.net/connect-docs/tutorials/windows-connect-service-daemon-mode.html ; Microsoft route/interface metric documentation https://learn.microsoft.com/en-us/windows-hardware/customize/desktop/unattend/microsoft-windows-tcpip-interfaces-interface-ipv4settings-metric and https://learn.microsoft.com/en-us/windows-server/networking/technologies/network-subsystem/net-sub-interface-metric
Status: route-delay REJECTED; route-nopull manual promotion REJECTED; physical-shadow native-handover PROPOSED/UNPROVEN.
Reuse Targets: Windows architecture, failure-prevention design, release evidence, maintenance guide.

## 2026-10-01 — Windows native shadow handover accepted in source
Context: Connect-time continuity was the remaining Windows blocker. Native OpenVPN Connect previously reached healthy foreign egress but produced ~2.8 s blackhole during /1 takeover.
Claim/Decision: ACCEPT the native-profile physical-shadow handover. OIG now installs temporary ActiveStore physical /1 shadow routes on the real non-tunnel default path, lets OpenVPN Connect perform its native TAP routes/DNS/WFP setup, waits for exact EVENT: CONNECTED + `allow IPv4 traffic from TAP` + the native /1 pair, then isolates 1.0.0.1/32 through the TAP and waits for a real TCP 443 data-plane PASS before removing the physical shadows. Source profile bytes remain unchanged. Failure paths stop the connector while physical shadows still cover general traffic; exact temporary routes are cleaned afterward.
Evidence: prototype v1 proved EVENT: CONNECTED alone was too early and still allowed a short blackhole. Prototype v2 exact live test on JP relay 59.138.16.13:1546 exited 0, health Healthy=true/JP/DNS clean/FullRoutes=2 and continuity monitor recorded 51 samples with TCP_FAIL=0. The isolated TAP probe became ready only after multiple early failures, proving the data-plane gate is necessary. Source-copy adaptive live regression also exited 0 with 39 samples, TCP_FAIL=0, native/WFP ready, isolated TAP probe PASS, and healthy JP egress. Final post-test state restored desired=off, service stopped, /1=0, probe-route=0, shadow-state absent, default Ethernet 3 via 192.168.20.1.
Source gates: PowerShell parse PASS; 67/67 tests PASS; lint PASS; npm audit production vulnerabilities=0; git diff --check PASS. Source Headless-Control SHA256=0e0405a218267b9fb98a3d884c92a7eeedea58784e91ef0b9c5952ccf33a8452.
Rejected alternatives: route-delay was unsupported/ignored by OpenVPN3; route-nopull manual promotion repeatedly failed the tunnel data-plane and was stopped after the third controlled recurrence. These remain rejected.
Evidence/Provenance: v2517-shadow-v2-exact-monitor.log SHA256=ad5a798750dbedda33543bc096869a167c3aea6719cad757a8761312ae5972ca; v2517-shadow-v2-exact-result.json SHA256=8eb0a59ce5831273f658f7942a3733716e3252c8d9048ea51c6a1686e557bf75; v2517-source-adaptive-monitor.log SHA256=98fd99145691b40c93fa79c14cbac3a5b3b1c0619d3d36e5e43ef19b9087bd42; v2517-source-adaptive-result.json SHA256=6c1902b83ee9bdbf76f57124e6e3e9228494ee9afcde8978dbdd6b5ae270d452; shadow-handover-last.json SHA256=72a043f8620cb21903d62efccc2ca1c264645488871cb1a51e72319f1e7d5d84. Runtime prototype history retained under %LOCALAPPDATA%\OpenInternetGateway\evidence.
Confidence/Status: HIGH / SOURCE+LIVE ACCEPTED; packaged/install parity for this handover is PENDING rebuild.
Reuse Targets: Windows architecture, release notes, failure-prevention section, maintenance guide, final evidence.
Exact Next Action: commit this accepted source delta, rebuild the Windows 2.5.17 installer from that authority, verify package parity, install per-user with desired=off, then run installed-runtime continuity regression and restore off.


## 2026-10-01 — Windows v2.5.17 packaged/installed zero-blackhole acceptance
Context: The accepted native-shadow handover at functional source authority `4bf59b61cf4fd35367b68153c33663fbd403fa11` was rebuilt, installed as the same per-user version, and revalidated from the installed runtime.
Claim/Decision: Windows v2.5.17 handover is PACKAGED + INSTALLED + LIVE ACCEPTED. Fresh NSIS build exited 0. Artifact `OpenInternetGateway-Setup-2.5.17.exe` SHA256=`7b04a28380843aca5abdfbc6942a719ac82617e8ab8765fb2251d8b7e28afbbb`, 111652180 bytes, version 2.5.17. Package→installed EXE/app.asar/Headless-Control parity is exact; source/package/installed/runtime Headless-Control SHA256 is `0e0405a218267b9fb98a3d884c92a7eeedea58784e91ef0b9c5952ccf33a8452`.
Installed runtime evidence: launched from a non-admin user context; one main Electron instance, renderer sandbox enabled, no exact `--no-sandbox`, no remote-debug. Installed adaptive connect exited 0. Continuity monitor observed 46 samples across physical-shadow hold, native TAP route creation, isolated TAP probe, and final takeover with `TCP_FAIL=0`; shadow was observed for 20 samples, probe route for 9 samples, simultaneous physical+TAP /1 routes for 11 samples, and TAP-only final state for 8 samples. Handover evidence result=PASS; health Healthy=true, JP egress 59.138.16.13, clean DNS, FullRoutes=2.
Final poststate after explicit disconnect: desired=off; OVPNConnectorService stopped/manual; full /1 routes=0; probe route=0; physical shadow state absent; default route Ethernet 3 via 192.168.20.1; AutoRecovery Ready.
Evidence/Provenance: `%LOCALAPPDATA%\OpenInternetGateway\evidence\v2517-windows-handover-final-acceptance-20261001.json` SHA256=`e37498cdb29d8b3b22893b6c37e6fbcca9179b6d14a5edd6a35533a46c2796eb`; installed continuity monitor SHA256=`3af121abd486e4f9f28fc16227147179ffe6d78bf93316b89c7a5e6ab4f5610b`; installed result SHA256=`11f6a806124b799858da8f19520ee6c5b8c06a3b9ee78ca95f59e69a66c7e1c3`; final handover evidence SHA256=`e585a1b27a4093386c0555a0fbd802b77622d3b738487098f65a86a82a637ef6`.
Limitations: Windows artifact remains publicly unsigned (`Authenticode=NotSigned`); this is the pre-existing external publisher-trust gap and is not claimed fixed.
Confidence/Status: HIGH / WINDOWS v2.5.17 FUNCTIONAL+PACKAGE+INSTALL+LIVE PASS.
Reuse Targets: final release evidence, architecture, release notes, troubleshooting, maintenance guide.
Exact Next Action: reconcile cross-platform authority/publication state; do not change Windows networking again unless a new release gate requires it.


## 2026-10-01 — v2.5.17 clean-root release-seed gate PASS
Context: v2.5.17 tagging remained blocked because the exact `release.yml` seed command had previously failed in a clean root. After Windows handover acceptance, the shared feature authority `7fdbf97b5eb6b4d052c310226b17e027879a19c0` was fast-forwarded to Linux and rechecked before main/tag promotion.
Claim/Decision: The historical release-seed blocker is RESOLVED for the tested authority. A clean snapshot created with `git archive 7fdbf97...` contained no pre-existing `app/common/runtime/udp-cache/index.json`. The exact workflow sequence `config_factory.py refresh --common app/common`, `status`, index existence check, and >=6 `.ovpn` check exited 0.
Evidence: clean-root seed produced pool=29, validated=0, standby=29, quarantined=0, metadataComplete=true, protocols UDP=1/TCP=28, countries JP=24/KR=3/US=1/HK=1, elapsed=6305 ms. `app/common/runtime/udp-cache/index.json` SHA256=`b0e23d4ffce0ab51d3e23b4de901dc8a7619ee8ae6fccab5870e3cc17b9075ce`. Evidence outputs included `mirror-refresh-last.json` and `vpngate-mirror-api.csv`. Note: release seed creates a fallback pool; validated=0 at this stage is not a failure and the workflow requirement is pool file presence plus >=6 profiles.
Cross-platform verification: Linux repo fast-forwarded cleanly to `7fdbf97...`; delta from prior Linux authority `f9505ed...` was only Project Knowledge, Windows Headless-Control, and tests. Linux runtime-relevant files were unchanged. Linux ran 67/67 tests PASS, lint PASS, production audit=0, Bash/Python static checks PASS.
Repository state: feature branch was pushed to GitHub at `7fdbf97...`. Existing PR #1 had already merged the earlier candidate at `8288ab3...`; no newer PR existed at the time of this audit.
Confidence/Status: HIGH / RELEASE SEED PASS for `7fdbf97...`; MAIN/TAG PROMOTION PENDING.
Reuse Targets: release evidence, CI/release engineering, final handoff.
Exact Next Action: commit this evidence-only record, push feature branch, re-run the clean-root seed on that exact final evidence commit (functional files unchanged), then open/merge the delta PR only after GitHub checks are acceptable.


## 2026-10-01 — v2.5.17 public release publication PASS
Context: PR #2 was merged after GitHub CI passed, tag `v2.5.17` was created on the tree-exact main merge authority, and the tag-triggered release workflow was allowed to complete before publication was accepted.
Claim/Decision: PUBLICATION PASS. Release `OpenInternetGateway v2.5.17` exists on GitHub, is `draft=false` and `prerelease=false`, and was published by the release workflow. Tag `v2.5.17` dereferences to main merge commit `a0d841d467e767978bbf88a909bb22110b130a49`; its tree `261315cc23a55707679c3993513bc85b845704c1` is exactly the tested feature-head tree.
CI/Release evidence: PR #2 build run `36795941856` completed test/windows/linux jobs successfully. Tag release run #21, id `36796342176`, completed `seed`, `test`, `windows`, `linux`, and `publish` all with conclusion=success; publish steps included artifact downloads, checksum generation, and GitHub Release creation.
Published assets and authoritative SHA-256:
- `OpenInternetGateway-Setup-2.5.17.exe` — `63a1122c1c7986ae8f8b03d90f3d1e3fa44cdc2650c7d8731e8662bd1f5f2335` — 112040805 bytes.
- `OpenInternetGateway-2.5.17-x86_64.AppImage` — `320a93522f526edaff14bc5efe762614bf53f4c92a98b91f445d3b3161458df7` — 125793851 bytes.
- `OpenInternetGateway-2.5.17-amd64.deb` — `2af72c43eae33ea3c9d01ca281d160fbe333c80cf4f78c43d19c92bf60a10f14` — 91357612 bytes.
- `SHA256SUMS.txt` — `2f18ad55793f6dc949bb440bad2e1889d8a2390b56d84719346a8e30ed564768` — 315 bytes.
Checksum cross-check: the downloaded public `SHA256SUMS.txt` contains exactly the same three binary SHA-256 values as GitHub release asset metadata. This independently confirms the workflow-generated checksum file matches the published binary digests.
Release authority note: the locally built Windows acceptance setup had a different SHA-256 because the public release workflow injects the clean release seed into packaging; this is expected. The published Windows asset SHA above is the release authority.
Limitations: Windows public artifact remains unsigned with Authenticode publisher trust not established; this is an external/deferred signing-credential gap and not claimed fixed.
Status: FINAL PUBLIC RELEASE PASS / v2.5.17. Do not move or recreate this tag for documentation-only changes.
Reuse Targets: final release record, handoff, release notes, maintenance guide, incident audit.


## 2026-10-01 — Exact public v2.5.17 local alignment on Windows and Linux
Context: After public release publication, both development machines were intentionally aligned to the exact published binaries rather than retaining only locally-built 2.5.17 artifacts. The v2.5.17 tag/release authority remains immutable at main merge commit `a0d841d467e767978bbf88a909bb22110b130a49`; this record is post-release evidence only.
Decision/Result: EXACT PUBLIC LOCAL ALIGNMENT PASS on both Windows and Linux, with VPN intent kept OFF throughout alignment and no release-authority mutation.
Windows evidence: exact public NSIS asset `OpenInternetGateway-Setup-2.5.17.exe` downloaded and SHA256 verified as `63a1122c1c7986ae8f8b03d90f3d1e3fa44cdc2650c7d8731e8662bd1f5f2335` (112040805 bytes), then installed silent/per-user with exit=0 while desired=off and connector stopped. Public package includes release fallback seed pool=48, countries=11, UDP=16, TCP=32, index SHA256=`56cd6dcc78f3f8c7905ca48abf7f0504f39b214437bf7bfafb828bdedeb89f46`. Installed Electron launch PASS: one main process, renderer `--enable-sandbox`, exact `--no-sandbox` count=0, remote-debug count=0, VPN remained off and default route remained Ethernet 3 -> 192.168.20.1.
Windows source/public parity nuance: raw `Headless-Control.ps1` hashes differ only because the GitHub Windows runner packaged CRLF while the local source is LF. Local source raw SHA256=`0e0405a218267b9fb98a3d884c92a7eeedea58784e91ef0b9c5952ccf33a8452`; public-installed raw SHA256=`d387b2e09ee61b4403ac46f69372437ad6619dd148f7e5a43a96fd509622009d`; after BOM-safe line-ending normalization the contents are exactly equal with normalized SHA256=`7fbb8a1cd2d058a7ed6cd826843114187f20a0d47a0b697342c7c1a9f89027d5`. Therefore semantic parity is CONFIRMED; raw byte parity is intentionally not claimed.
Windows updater gate: `updateInfo(true)` reports current=latest=2.5.17, `upToDate=true`, `updateAvailable=false`, and selects the exact public EXE/digest above. `downloadUpdate()` at same version returns `ok=true`, `alreadyCurrent=true`, `path=null`, proving a non-mutating no-op when current. Windows local-alignment evidence: `%LOCALAPPDATA%\OpenInternetGateway\evidence\v2517-public-release-local-alignment-windows-20261001.json`, SHA256=`6b6f6c400c75204ae5bcca17ee46b83ba512d777bb6d9168b2257cc359a2c22e`.
Linux evidence: exact public AppImage downloaded and SHA256 verified as `320a93522f526edaff14bc5efe762614bf53f4c92a98b91f445d3b3161458df7` (125793851 bytes). Critical Linux backend files are byte-exact with source. Public release seed is the same 48/11 pool and same index SHA256 `56cd6dcc78f3f8c7905ca48abf7f0504f39b214437bf7bfafb828bdedeb89f46`. Promotion used staging + backup + atomic rename; rollback backup retained at `/home/aliemad/.local/opt/OpenInternetGateway-2.5.17-pre-public-20261001-041754`. Sandbox hardening reused hash-compatible `/opt/open-internet-gateway/chrome-sandbox`, root:root mode 4755, SHA256=`a4f6dfd7325ddd55f94ddc0c487d22726d40ef099ded6475d5dffe236e277896`, via runtime symlink. Public Linux launch PASS: renderer `--enable-sandbox`, exact `--no-sandbox` count=0, desired=off, only physical default route via enp1s0.
Linux updater gate: current=latest=2.5.17, `upToDate=true`, `updateAvailable=false`, exact AppImage selected with published digest; same-version `downloadUpdate()` returned `ok=true`, `alreadyCurrent=true`, `path=null`. Linux local-alignment evidence: `/home/aliemad/.local/share/OpenInternetGateway/evidence/v2517-public-release-local-alignment-linux-20261001.json`, SHA256=`be81ff39c01748e9efa3a9003548f8b053c660b84769c2a8bc9a25565e26d703`.
Final machine state: Windows desired=off, OVPNConnectorService stopped, /1 routes=0, physical default Ethernet 3; Linux desired=off, no /1 tunnel routes, physical default enp1s0. Both exact public applications are running in sandboxed desktop mode without activating VPN.
Known external limitation: Windows public setup remains Authenticode `NotSigned`; no trusted publisher credential was available, and this is not claimed fixed.
Confidence/Status: HIGH / EXACT PUBLIC LOCAL ALIGNMENT PASS / v2.5.17 FINAL.
Reuse Targets: final handoff, deployment evidence, updater verification, maintenance guide.
Exact Next Action: no mutation of v2.5.17. Only post-release monitoring or a new version/change request may open a new change set.
