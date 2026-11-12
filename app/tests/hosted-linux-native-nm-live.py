#!/usr/bin/env python3
"""Hosted-only NetworkManager OpenVPN real transport acceptance.

Runs ONLY as root in the disposable GitHub-hosted Docker bridge namespace.
Authenticates a pinned public OpenVPN peer through the actual NM OpenVPN plugin,
binds a small HTTPS probe to the observed TUN, and verifies cleanup.
This is an isolated *scoped* transport test, NOT product full-device/leak acceptance.
No owner network or credentials are accessed.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
BACKEND = HERE.parent / "backend" / "linux"
SCOPED_RECEIPT = Path("/out/oig-hosted-native-nm-live.json")
FULL_IPV4_RECEIPT = Path("/out/oig-hosted-native-nm-fullipv4.json")


def check_scope():
    if (sys.argv[1:] not in (["--native-scoped-live"], ["--native-fullipv4"])
            or os.geteuid() != 0
            or os.environ.get("OIG_HOSTED_CONTAINER") != "1"
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("GITHUB_REPOSITORY") != "GOD13emad/OpenInternetGateway"
            or os.environ.get("GITHUB_EVENT_NAME") != "pull_request"
            or not re.fullmatch(r"[0-9]+", os.environ.get("GITHUB_RUN_ID", ""))
            or not Path("/.dockerenv").exists()
            or not Path("/work/app/backend/linux/operator_profile.py").is_file()):
        raise SystemExit("REFUSED: owner host or non-disposable runner")
    return sys.argv[1] == "--native-fullipv4"


def cmd(argv, timeout=15, *, pass_fds=()):
    return subprocess.run(argv, capture_output=True, check=False,
                          timeout=timeout, pass_fds=pass_fds,
                          env={**os.environ, "LC_ALL": "C", "LANG": "C"})


def required(argv, *, timeout=15, pass_fds=()):
    result = cmd(argv, timeout, pass_fds=pass_fds)
    if result.returncode:
        raise RuntimeError("CONTROL_STEP_FAILED")
    return result.stdout


def snapshot():
    entries = []
    for argv in (["ip", "-4", "route", "show", "table", "all"],
                 ["ip", "-6", "route", "show", "table", "all"]):
        output = required(argv, timeout=8)
        if len(output) > 30000:
            raise RuntimeError("ROUTE_SNAPSHOT_OVERSIZE")
        entries.append(hashlib.sha256(output).hexdigest())
    entries.append(hashlib.sha256(Path("/etc/resolv.conf").read_bytes()).hexdigest())
    return entries


def put_receipt(data, is_full_ipv4):
    receipt = FULL_IPV4_RECEIPT if is_full_ipv4 else SCOPED_RECEIPT
    receipt.parent.mkdir(parents=True, exist_ok=True)
    payload = (json.dumps(data, sort_keys=True) + "\n").encode()
    fd = os.open(receipt, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as writer:
        writer.write(payload)
        writer.flush()
        os.fsync(writer.fileno())
    marker = ("HOSTED_NATIVE_NM_FULL_IPV4_RECEIPT=" if is_full_ipv4
              else "HOSTED_NATIVE_NM_SCOPED_LIVE_RECEIPT=")
    print(marker + json.dumps(data, sort_keys=True))


def fail_stage(label):
    raise RuntimeError(label)


def main():
    is_full_ipv4 = check_scope()
    sys.path.insert(0, str(BACKEND))
    import operator_profile
    import operator_trial

    spec = importlib.util.spec_from_file_location(
        "hosted_provider", HERE / "hosted-linux-provider-data-plane.py")
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)

    out = {
        "schema": ("oig-hosted-native-networkmanager-full-ipv4-v1" if is_full_ipv4
                   else "oig-hosted-native-networkmanager-scoped-live-v1"),
        "scope": "Disposable Docker netns, real OIG native NM OpenVPN transport; no owner VPN",
        "fullDeviceTunnelVerified": False,
        "systemDnsLeakContainmentVerified": False,
        "productionKillSwitchVerified": False,
        "pass": False
    }
    stage = "BASELINE"
    stem = None
    checked = None
    uuid = None
    before = None
    authenticated = False
    completed = False
    owned_probe_route = None
    owned_underlay_routes = []
    resolver_file = Path("/etc/resolv.conf")
    resolver_original = None
    resolver_changed = False
    resolved_base_baseline = None
    try:
        # Host preconditions are checked before any provider secret is fetched.
        if not Path("/dev/net/tun").exists():
            fail_stage("TUN_UNAVAILABLE")
        before = snapshot()
        if is_full_ipv4:
            stage = "RESOLVED_BASE_DNS_BASELINE"
            # The disposable NM-managed dummy is the competing physical
            # resolver; it must reappear after the VPN is removed. No
            # host/runner resolver participates in this test.
            resolved_base_baseline = required(
                ["resolvectl", "dns", "oigqa0"], timeout=8).decode("utf8", "replace")
            if "9.9.9.9" not in resolved_base_baseline:
                fail_stage("RESOLVED_COMPETING_BASE_LINK_UNAVAILABLE")
        baseline = operator_profile._connection_uuids()
        if any(
            "vpn" in line.lower()
            for line in required(["nmcli", "-t", "-f", "TYPE",
                                  "connection", "show", "--active"],
                                 timeout=8).decode("utf8", "replace").splitlines()
        ):
            fail_stage("INDEPENDENT_CONTAINER_VPN_ACTIVE")

        stage = "TRUSTED_PROFILE"
        raw_profile, profile_sha = provider.official_profile()
        public_pass, _ = provider.official_login()
        public_targets = {
            item[4][0] for item in socket.getaddrinfo(
                "www.cloudflare.com", 443, socket.AF_INET, socket.SOCK_STREAM)
            if ipaddress.ip_address(item[4][0]).is_global
        }
        if not public_targets:
            fail_stage("NO_TRUSTED_HTTPS_PROBE_TARGET")
        probe_ip = sorted(public_targets)[0]
        if is_full_ipv4:
            # Pre-resolve the single public speed source before installing
            # VPN default routes; data transfer still binds only to the TUN.
            speed_addresses = sorted({
                item[4][0] for item in socket.getaddrinfo(
                    "speed.cloudflare.com", 443, socket.AF_INET, socket.SOCK_STREAM)
                if ipaddress.ip_address(item[4][0]).is_global
            })
            if not speed_addresses:
                fail_stage("SPEED_SOURCE_DNS_NOT_TRUSTED")
            speed_ip = speed_addresses[0]
            # Docker-only: pin provider peer to the original eth0 gateway
            # before NM introduces an owned default path.
            stage = "PINNED_PROVIDER_UNDERLAY_ROUTE"
            peer_ips = sorted({
                item[4][0] for item in socket.getaddrinfo(
                    provider.ENDPOINT, 443, socket.AF_INET, socket.SOCK_STREAM)
                if ipaddress.ip_address(item[4][0]).is_global
            })
            if not peer_ips:
                fail_stage("PROVIDER_IP_INVENTORY_EMPTY")
            for peer_ip in peer_ips:
                route = required(["ip", "-4", "route", "get", peer_ip], timeout=7)
                parts = route.decode("utf8", "replace").split()
                if ("dev" not in parts or "via" not in parts
                        or parts[parts.index("dev")+1] != "eth0"):
                    fail_stage("PROVIDER_UNDERLAY_ROUTE_UNVERIFIED")
                gateway = parts[parts.index("via")+1]
                if ipaddress.ip_address(gateway).is_global:
                    fail_stage("PROVIDER_GATEWAY_UNEXPECTED")
                prefix = peer_ip + "/32"
                if required(["ip", "-4", "route", "show", "exact", prefix], timeout=7).strip():
                    fail_stage("PROVIDER_HOST_ROUTE_ALREADY_PRESENT")
                required(["ip", "-4", "route", "add", prefix, "via", gateway,
                          "dev", "eth0"], timeout=7)
                owned_underlay_routes.append((prefix, gateway))
        with tempfile.TemporaryDirectory(prefix="oig-native-live-") as folder:
            os.chmod(folder, 0o700)
            stem = "oig-native-" + os.urandom(12).hex()
            source = Path(folder) / (stem + ".ovpn")
            source.write_text(raw_profile, encoding="utf8")
            source.chmod(0o600)
            checked, endpoint, proto = operator_profile.load_and_check(
                source, provider.EXPECTED_CA, provider.EXPECTED_CN)
            source.write_bytes(checked)
            stage = "NM_IMPORT"
            response = operator_profile._run_nmcli(
                "connection", "import", "--temporary", "type", "openvpn",
                "file", str(source), timeout=12)
            after = operator_profile._connection_uuids()
            additions = after - baseline
            if len(additions) != 1:
                fail_stage("NM_IMPORT_UUID_AMBIGUOUS")
            uuid = next(iter(additions))
            if response.returncode:
                fail_stage("NM_IMPORT_NONZERO")
            stage = "TRUST_PRESERVATION"
            operator_profile.verify_nm_import(
                uuid, stem, checked, endpoint, proto,
                provider.EXPECTED_CA, provider.EXPECTED_CN)

            # Full IPv4 is allowed only in the disposable, verified Docker
            # namespace. IPv6 and DNS remain independently unaccepted.
            stage = "NM_FULL_IPV4_POLICY" if is_full_ipv4 else "SCOPED_POLICY"
            required(["nmcli", "--wait", "5", "connection", "modify",
                      "--temporary", "uuid", uuid,
                      "connection.autoconnect", "no",
                      "vpn.user-name", "vpnbook",
                      "ipv4.never-default", "no" if is_full_ipv4 else "yes",
                      "ipv6.never-default", "yes",
                      "ipv4.ignore-auto-dns", "yes",
                      "ipv6.ignore-auto-dns", "yes",
                      # This is only profile-policy acceptance in Docker
                      # (NM daemon currently runs dns=none), NOT a claim
                      # that a production resolver or every app is leak-free.
                      *(["ipv4.dns", "1.1.1.1",
                         "ipv4.dns-search", "~.",
                         "ipv4.dns-priority", "-2147483647"]
                        if is_full_ipv4 else []),
                      "ipv4.ignore-auto-routes", "no" if is_full_ipv4 else "yes",
                      "ipv6.ignore-auto-routes", "yes",
                      # VPNBook's imported profile does not necessarily push
                      # redirect-gateway. Ask NM to own the exact OIG half
                      # routes, rather than manipulating system routes from
                      # the test harness after activation.
                      *(["ipv4.routes", "0.0.0.0/1,128.0.0.0/1"]
                        if is_full_ipv4 else [])], timeout=12)
            operator_profile.verify_nm_import(
                uuid, stem, checked, endpoint, proto,
                provider.EXPECTED_CA, provider.EXPECTED_CN)
            if is_full_ipv4:
                stage = "NM_PINNED_DNS_ROUTING_POLICY"
                expected_dns = {
                    "ipv4.dns": "1.1.1.1",
                    "ipv4.dns-search": "~.",
                    "ipv4.dns-priority": "-2147483647",
                    "ipv4.ignore-auto-dns": "yes",
                    "ipv6.ignore-auto-dns": "yes",
                }
                for field, expected in expected_dns.items():
                    observed = required(
                        ["nmcli", "--wait", "5", "-g", field,
                         "connection", "show", "uuid", uuid],
                        timeout=9).decode("utf8", "replace").strip()
                    if observed != expected:
                        fail_stage("NM_DNS_POLICY_NOT_PRESERVED")
                out["nmPinnedDnsPriorityConfigVerified"] = True
            stage = "NM_AUTHENTICATED_ACTIVATION"
            fd = operator_trial.make_password_fd(public_pass)
            public_pass = None
            try:
                started = cmd(["nmcli", "--wait", "75", "connection", "up",
                               "uuid", uuid, "ifname", "oigqa0",
                               "passwd-file", f"/proc/self/fd/{fd}"],
                              timeout=83, pass_fds=(fd,))
                out["nmUpExitCode"] = started.returncode
                if started.returncode:
                    # Expose only fixed diagnostics, never provider credentials
                    # or raw nmcli stdout/stderr (which may hold profile data).
                    error = started.stderr.decode("utf8", "replace").lower()
                    categories = {
                        "no suitable device": "BASE_INTERFACE_UNSUITABLE",
                        "no active connection": "BASE_CONNECTION_MISSING",
                        "secrets were required": "NM_SECRET_HANDOFF_REFUSED",
                        "no valid vpn secrets": "NM_SECRET_HANDOFF_REFUSED",
                        "could not find": "NM_RESOURCE_NOT_FOUND",
                        "vpn service failed": "VPN_PLUGIN_FAILURE",
                        "vpn service was stopped": "VPN_PLUGIN_FAILURE",
                        "connection activation failed": "NM_ACTIVATION_FAILED",
                    }
                    out["nmUpFailureCategory"] = next(
                        (value for needle, value in categories.items()
                         if needle in error), "NM_UNKNOWN_FAILURE")
                    fail_stage("NM_UP_RETURNED_NONZERO")
            finally:
                os.close(fd)
            active = required(["nmcli", "-t", "-f", "UUID",
                               "connection", "show", "--active"], timeout=8)
            if uuid not in active.decode("utf8", "replace").lower().splitlines():
                fail_stage("NM_ACTIVE_UUID_NOT_FOUND")
            authenticated = True
            if is_full_ipv4:
                stage = "NM_ACTIVE_DNS_POLICY_PERSISTENCE"
                active_policy = {
                    "ipv4.dns": "1.1.1.1",
                    "ipv4.dns-search": "~.",
                    "ipv4.dns-priority": "-2147483647",
                }
                for field, expected in active_policy.items():
                    observed = required(
                        ["nmcli", "--wait", "5", "-g", field,
                         "connection", "show", "uuid", uuid],
                        timeout=9).decode("utf8", "replace").strip()
                    if observed != expected:
                        fail_stage("NM_ACTIVE_DNS_POLICY_CHANGED")
                out["nmActiveDnsRoutingPolicyVerified"] = True
            out["trustedProfileAccepted"] = True
            out["profileSha256"] = profile_sha
            out["nativeNmAuthenticated"] = True
            out["pinnedPeerCAAndCNConfigured"] = True

            stage = "TUN_BOUND_DATA_PLANE"
            result = cmd(["ip", "-j", "-4", "address", "show"], timeout=8)
            if result.returncode:
                fail_stage("TUN_INTERFACE_OBSERVATION_FAILED")
            interfaces = json.loads(result.stdout)
            candidates = [x["ifname"] for x in interfaces
                          if re.fullmatch(r"(?:tun|vpn)[A-Za-z0-9_.-]*", x.get("ifname", ""))
                          and any(i.get("family") == "inet" for i in x.get("addr_info", []))]
            if len(candidates) != 1:
                fail_stage("TUN_INTERFACE_AMBIGUOUS")
            tunnel = candidates[0]
            out["ownedTunPresent"] = True
            if is_full_ipv4:
                stage = "RESOLVED_VPN_EXCLUSIVE_ROUTING"
                # Inspect resolved's live per-link configuration, not merely
                # the saved NM profile. It must receive an exclusive route-only
                # root domain and a single VPN DNS upstream.
                link_dns = required(["resolvectl", "dns", tunnel], timeout=8).decode(
                    "utf8", "replace")
                link_domains = required(["resolvectl", "domain", tunnel], timeout=8).decode(
                    "utf8", "replace")
                if (not re.search(r"(?<![0-9.])1\.1\.1\.1(?![0-9.])", link_dns)
                        or not re.search(r"(?<!\S)~\.(?!\S)", link_domains)):
                    fail_stage("RESOLVED_VPN_LINK_DNS_OR_ROUTING_DOMAIN_MISSING")
                dns_inventory = required(["resolvectl", "dns"], timeout=8).decode(
                    "utf8", "replace")
                if "9.9.9.9" in dns_inventory:
                    fail_stage("RESOLVED_COMPETING_BASE_DNS_NOT_EXCLUDED")
                out["resolvedVpnDnsOnlyPolicyVerified"] = True
                stage = "RESOLVED_GLOBAL_QUERY_OVER_VPN"
                # A bounded real query through the systemd-resolved service
                # itself (without --interface) proves route selection for this
                # test name. The host underlay never becomes a fallback.
                resolved_ok = False
                for resolved_attempt in range(2):
                    routed = required(["ip", "-4", "route", "get", "1.1.1.1"], timeout=7)
                    if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", routed):
                        fail_stage("RESOLVED_DNS_UPSTREAM_ROUTE_LEFT_TUN")
                    queried = cmd(["resolvectl", "-4", "query", "example.com"], timeout=12)
                    out["resolvedQueryAttempts"] = resolved_attempt + 1
                    if queried.returncode or len(queried.stdout) > 4096:
                        continue
                    addresses = re.findall(rb"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])", queried.stdout)
                    if addresses and all(
                            ipaddress.ip_address(value.decode()).is_global
                            for value in addresses):
                        resolved_ok = True
                        break
                if not resolved_ok:
                    fail_stage("RESOLVED_DEFAULT_QUERY_NOT_VERIFIED")
                out["resolvedQueryViaVpnVerified"] = True
                stage = "FULL_IPV4_ROUTE_OWNERSHIP"
                # No test-specific data /32: the real NM default path must
                # cover two independent public resolvers and HTTPS itself.
                for label, target in (("DNS_ONE", "1.1.1.1"),
                                      ("DNS_TWO", "9.9.9.9"),
                                      ("HTTPS_TARGET", probe_ip)):
                    stage = "FULL_IPV4_ROUTE_" + label
                    effective = required(["ip", "-4", "route", "get", target], timeout=7)
                    if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", effective):
                        fail_stage("FULL_IPV4_ROUTE_NOT_TUNNEL_OWNED")
                stage = "PROVIDER_CONTROL_CHANNEL_UNDERLAY"
                for peer_ip in peer_ips:
                    effective = required(["ip", "-4", "route", "get", peer_ip], timeout=7)
                    if not re.search(rb"\bdev\s+eth0\b", effective):
                        fail_stage("PROVIDER_CONTROL_CHANNEL_NOT_UNDERLAY_BOUND")
                stage = "IPV6_ROUTE_INVENTORY"
                from ipv6_route_guard import verify_ipv6_route_inventory
                ipv6_routes = required(["ip", "-6", "route", "show", "table", "all"], timeout=7)
                verify_ipv6_route_inventory(ipv6_routes.decode("utf8", "replace"), owned=tunnel)
                out["fullIPv4RoutesOwned"] = True
                out["ipv6RouteInventoryScoped"] = True
                stage = "TUN_BOUND_EXPLICIT_DNS"
                # A separate explicit resolver probe complements the real
                # per-link resolved test above. Neither proves arbitrary
                # application/IPv6 leak containment on physical owner hosts.
                response = cmd(["dig", "-4", "+time=4", "+tries=1",
                                "+short", "@1.1.1.1", "example.com", "A"],
                               timeout=9)
                answers = response.stdout.decode("ascii", "replace").splitlines()
                if (response.returncode or len(response.stdout) > 2048
                        or not answers or not all(
                            ipaddress.ip_address(address).version == 4
                            and ipaddress.ip_address(address).is_global
                            for address in answers)):
                    fail_stage("EXPLICIT_RESOLVER_VIA_TUN_NOT_VERIFIED")
                out["explicitResolverDnsViaTun"] = True
                # Docker owns this namespace and its own resolver file. Test
                # the ordinary OS default DNS path (no "@" server override)
                # without changing NetworkManager or the runner/owner host.
                # The original bytes are restored immediately and in finally
                # on EVERY failure. This is deliberately not a global leak or
                # kill-switch acceptance claim.
                stage = "CONTAINER_DEFAULT_DNS_BASELINE"
                if resolver_file.is_symlink() or not resolver_file.is_file():
                    fail_stage("CONTAINER_RESOLVER_NOT_REGULAR")
                meta = resolver_file.stat()
                if (not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0
                        or meta.st_nlink != 1 or meta.st_size > 4096):
                    fail_stage("CONTAINER_RESOLVER_IDENTITY_UNTRUSTED")
                resolver_original = resolver_file.read_bytes()
                if not resolver_original or len(resolver_original) > 4096:
                    fail_stage("CONTAINER_RESOLVER_BASELINE_UNAVAILABLE")
                isolated_resolver = b"nameserver 1.1.1.1\noptions timeout:3 attempts:1\n"
                stage = "CONTAINER_DEFAULT_DNS_OVERRIDE"
                resolver_changed = True
                with resolver_file.open("wb") as stream:
                    stream.write(isolated_resolver)
                    stream.flush()
                    os.fsync(stream.fileno())
                if resolver_file.read_bytes() != isolated_resolver:
                    fail_stage("CONTAINER_DEFAULT_RESOLVER_WRITE_UNVERIFIED")
                path = required(["ip", "-4", "route", "get", "1.1.1.1"], timeout=7)
                if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", path):
                    fail_stage("CONTAINER_DEFAULT_RESOLVER_NOT_TUN_BOUND")
                stage = "CONTAINER_ORDINARY_DEFAULT_DNS"
                # A single public recursive UDP DNS exchange can suffer
                # transient loss. Permit one bounded retry using exactly the
                # same container resolver and TUN route; never query eth0,
                # switch DNS servers, or accept an invalid/non-global answer.
                ordinary_valid = False
                for dns_attempt in range(2):
                    path = required(["ip", "-4", "route", "get", "1.1.1.1"], timeout=7)
                    if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", path):
                        fail_stage("CONTAINER_DEFAULT_DNS_ROUTE_CHANGED")
                    normal = cmd(["dig", "-4", "+time=4", "+tries=1",
                                  "+short", "example.com", "A"], timeout=9)
                    out["containerDefaultDnsAttempts"] = dns_attempt + 1
                    out["containerDefaultDnsDigExitCode"] = normal.returncode
                    answers = normal.stdout.decode("ascii", "replace").splitlines()
                    if normal.returncode or len(normal.stdout) > 2048 or not answers:
                        continue
                    try:
                        ordinary_valid = all(
                            ipaddress.ip_address(address).version == 4
                            and ipaddress.ip_address(address).is_global
                            for address in answers)
                    except ValueError:
                        ordinary_valid = False
                    if ordinary_valid:
                        break
                if not ordinary_valid:
                    fail_stage("CONTAINER_DEFAULT_DNS_QUERY_NOT_VERIFIED")
                out["containerDefaultDnsViaTunVerified"] = True
                stage = "CONTAINER_DEFAULT_RESOLVER_RESTORE"
                with resolver_file.open("wb") as stream:
                    stream.write(resolver_original)
                    stream.flush()
                    os.fsync(stream.fileno())
                if resolver_file.read_bytes() != resolver_original:
                    fail_stage("CONTAINER_DEFAULT_RESOLVER_RESTORE_UNVERIFIED")
                resolver_changed = False
                out["containerDefaultResolverRestoredExact"] = True
            else:
                # Scoped mode owns only one temporary /32 route, no default.
                probe_prefix = probe_ip + "/32"
                if required(["ip", "-4", "route", "show", "exact", probe_prefix],
                            timeout=7).strip():
                    fail_stage("PROBE_ROUTE_ALREADY_PRESENT")
                required(["ip", "-4", "route", "add", probe_prefix, "dev", tunnel], timeout=7)
                owned_probe_route = (probe_prefix, tunnel)
                effective = required(["ip", "-4", "route", "get", probe_ip], timeout=7)
                if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", effective):
                    fail_stage("PROBE_ROUTE_NOT_TUNNEL_OWNED")
            http = cmd(["curl", "-4", "--resolve", "www.cloudflare.com:443:" + probe_ip,
                        "--interface", tunnel, "--connect-timeout", "9",
                        "--max-time", "24", "--fail", "--silent", "--show-error",
                        "https://www.cloudflare.com/cdn-cgi/trace"], timeout=28)
            if http.returncode or len(http.stdout) > 4000:
                fail_stage("TUN_BOUND_HTTPS_UNAVAILABLE")
            facts = dict(line.split("=", 1) for line in http.stdout.decode(
                "ascii", "replace").splitlines() if "=" in line)
            address = ipaddress.ip_address(facts.get("ip", "127.0.0.1"))
            if address.version != 4 or not address.is_global:
                fail_stage("TUN_BOUND_PUBLIC_IPV4_UNVERIFIED")
            out["tunnelBoundHttpsSucceeded"] = True
            out["tunneledIPv4PublicEgress"] = True
            out["serverIdentityVerifiedByPinnedNMProfile"] = True
            if is_full_ipv4:
                # Reuse the same bounded public speed test endpoints as the
                # already accepted disposable provider data-plane harness.
                # Bind each transfer to the identified TUN; no physical ISP
                # retry or alternative source is permitted.
                stage = "NATIVE_NM_VPN_BOUND_DOWNLOAD"
                # At most one bounded retry on exactly the same pinned
                # endpoint/interface. Never retry via Docker's physical link.
                for attempt in range(2):
                    dl = cmd(["curl", "-4", "--noproxy", "*",
                              "--resolve", "speed.cloudflare.com:443:" + speed_ip,
                              "--interface", tunnel,
                              "--connect-timeout", "12", "--max-time", "35",
                              "--fail", "--silent", "--show-error",
                              "--output", "/dev/null",
                              "--write-out", "%{size_download} %{time_total} %{http_code}",
                              "https://speed.cloudflare.com/__down?bytes=1000000"],
                             timeout=41)
                    if dl.returncode == 0:
                        break
                out["nmDownloadAttempts"] = attempt + 1
                out["nmDownloadCurlExitCode"] = dl.returncode
                try:
                    dbytes, dsecs, dstatus = dl.stdout.decode("ascii").strip().split()
                    dbytes, dsecs = float(dbytes), float(dsecs)
                    out["nmDownloadHttpCode"] = dstatus
                    out["nmDownloadReceivedBytes"] = int(dbytes)
                except (ValueError, UnicodeDecodeError, OverflowError):
                    fail_stage("NATIVE_NM_DOWNLOAD_OBSERVATION_INVALID")
                if dl.returncode or dstatus != "200" or dbytes < 900000 or dsecs <= 0:
                    fail_stage("NATIVE_NM_DOWNLOAD_BYTES_NOT_VERIFIED")
                stage = "NATIVE_NM_VPN_BOUND_UPLOAD"
                sample = Path(folder) / "upload-test.bin"
                sample.write_bytes(os.urandom(262144))
                sample.chmod(0o600)
                for attempt in range(2):
                    ul = cmd(["curl", "-4", "--noproxy", "*",
                              "--resolve", "speed.cloudflare.com:443:" + speed_ip,
                              "--interface", tunnel,
                              "--connect-timeout", "12", "--max-time", "35",
                              "--fail", "--silent", "--show-error",
                              "--data-binary", "@" + str(sample),
                              "--output", "/dev/null",
                              "--write-out", "%{size_upload} %{time_total} %{http_code}",
                              "https://speed.cloudflare.com/__up"], timeout=41)
                    if ul.returncode == 0:
                        break
                out["nmUploadAttempts"] = attempt + 1
                out["nmUploadCurlExitCode"] = ul.returncode
                try:
                    ubytes, usecs, ustatus = ul.stdout.decode("ascii").strip().split()
                    ubytes, usecs = float(ubytes), float(usecs)
                    out["nmUploadHttpCode"] = ustatus
                    out["nmUploadSentBytes"] = int(ubytes)
                except (ValueError, UnicodeDecodeError, OverflowError):
                    fail_stage("NATIVE_NM_UPLOAD_OBSERVATION_INVALID")
                if ul.returncode or ustatus != "200" or ubytes < 262144 or usecs <= 0:
                    fail_stage("NATIVE_NM_UPLOAD_BYTES_NOT_VERIFIED")
                stage = "NATIVE_NM_POST_TRANSFER_ROUTES"
                for target in ("1.1.1.1", "9.9.9.9"):
                    path = required(["ip", "-4", "route", "get", target], timeout=7)
                    if not re.search(rb"\bdev\s+" + re.escape(tunnel.encode()) + rb"\b", path):
                        fail_stage("NATIVE_NM_TUN_ROUTE_CHANGED_AFTER_TRANSFER")
                out["nativeNmDownloadMbps"] = round(dbytes * 8 / dsecs / 1000000, 2)
                out["nativeNmUploadMbps"] = round(ubytes * 8 / usecs / 1000000, 2)
                out["nativeNmDownloadBytes"] = int(dbytes)
                out["nativeNmUploadBytes"] = int(ubytes)
                out["nativeNmMeasuredVpnBoundThroughput"] = True
            completed = True
    except Exception as exc:
        out["failureClass"] = type(exc).__name__
        out["failureStage"] = stage
        out["pass"] = False
    finally:
        # Revert a partially written resolver even after a failed DNS probe.
        # Retain a false receipt when restoration cannot be proven.
        if resolver_changed and resolver_original is not None:
            try:
                with resolver_file.open("wb") as stream:
                    stream.write(resolver_original)
                    stream.flush()
                    os.fsync(stream.fileno())
                out["containerDefaultResolverRestoredExact"] = (
                    resolver_file.read_bytes() == resolver_original)
            except Exception:
                out["containerDefaultResolverRestoredExact"] = False
        # All mutations belong only to the new UUID and its unique PEM namespace.
        # On error, leave no active NM VPN while the bounded Docker namespace lives.
        cleanup_ok = True
        if owned_probe_route:
            prefix, interface = owned_probe_route
            try:
                deleted_route = cmd(["ip", "-4", "route", "del", prefix,
                                     "dev", interface], timeout=7)
                if deleted_route.returncode:
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
        if uuid:
            try:
                identity = operator_profile._run_nmcli(
                    "-g", "connection.id", "connection", "show", "uuid", uuid)
                if identity.returncode == 0 and identity.stdout.decode(
                    "utf8", "replace").strip() == stem:
                    operator_profile._run_nmcli(
                        "connection", "down", "uuid", uuid, timeout=12)
                    removed = operator_profile._run_nmcli(
                        "connection", "delete", "uuid", uuid, timeout=12)
                    if removed.returncode:
                        cleanup_ok = False
                elif identity.returncode == 0:
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
        if stem and checked:
            try:
                operator_profile.cleanup_nm_import_artifacts(stem, checked)
            except Exception:
                cleanup_ok = False
        if uuid:
            try:
                cleanup_ok = cleanup_ok and uuid not in operator_profile._connection_uuids()
            except Exception:
                cleanup_ok = False
        # The original Docker provider-control /32 routes are removed after
        # NM has been disconnected. Never delete another route or global table.
        for prefix, gateway in reversed(owned_underlay_routes):
            try:
                removed_underlay = cmd(
                    ["ip", "-4", "route", "del", prefix, "via", gateway, "dev", "eth0"],
                    timeout=7)
                if removed_underlay.returncode:
                    cleanup_ok = False
            except Exception:
                cleanup_ok = False
        out["temporaryProfileAndPEMCleanupVerified"] = cleanup_ok
        if is_full_ipv4 and resolved_base_baseline is not None:
            # NM -> resolved D-Bus updates may complete asynchronously.
            # Fail closed if the competing link's DNS is not restored or a
            # deleted TUN still advertises the exclusive VPN resolver.
            out["resolvedDnsPolicyRestored"] = False
            for _ in range(8):
                try:
                    restored = required(
                        ["resolvectl", "dns", "oigqa0"], timeout=7).decode(
                        "utf8", "replace") == resolved_base_baseline
                    inventory = required(
                        ["resolvectl", "dns"], timeout=7).decode("utf8", "replace")
                    if restored and "1.1.1.1" not in inventory:
                        out["resolvedDnsPolicyRestored"] = True
                        break
                except Exception:
                    pass
                time.sleep(0.25)
        try:
            out["containerNetworkRestored"] = before is not None and before == snapshot()
        except Exception:
            out["containerNetworkRestored"] = False
        out["pass"] = (completed and authenticated
                       and out.get("tunnelBoundHttpsSucceeded") is True
                       and (not is_full_ipv4 or (
                           out.get("fullIPv4RoutesOwned") is True
                           and out.get("nmPinnedDnsPriorityConfigVerified") is True
                           and out.get("nmActiveDnsRoutingPolicyVerified") is True
                           and out.get("resolvedVpnDnsOnlyPolicyVerified") is True
                           and out.get("resolvedQueryViaVpnVerified") is True
                           and out.get("resolvedDnsPolicyRestored") is True
                           and out.get("containerDefaultDnsViaTunVerified") is True
                           and out.get("containerDefaultResolverRestoredExact") is True))
                       and out["temporaryProfileAndPEMCleanupVerified"]
                       and out["containerNetworkRestored"])
        put_receipt(out, is_full_ipv4)
    return 0 if out["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
