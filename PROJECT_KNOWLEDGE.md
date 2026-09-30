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
