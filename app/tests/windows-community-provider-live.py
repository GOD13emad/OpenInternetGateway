#!/usr/bin/env python3
"""Disposable Windows-only real-provider TLS/management identity gate.

No TUN, routes, DNS changes, drivers or services. This test reads the
provider's HTTPS-published shared client material, checks a previously
accepted immutable CA pin, then runs the QA-only app-owned OpenVPN controller
against one fixed provider. No credentials or private keys enter receipts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

PINNED_CA = "c0c7c3663bd229bce127647dece873d37e022a5d283a35b162bb125ac70bb9ff"
MODES = ("live-provider", "live-wrong-cn")


def assert_runner():
    expected = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_OS": "Windows",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY": "GOD13emad/OpenInternetGateway",
        "OIG_HOSTED_LIVE_PROVIDER_QA": "1",
    }
    if os.name != "nt" or any(os.environ.get(k) != v for k, v in expected.items()):
        raise RuntimeError("DISPOSABLE_WINDOWS_LIVE_PROVIDER_ONLY")
    value = os.environ.get("RUNNER_TEMP", "")
    if not value or value.startswith("\\\\") or not Path(value).resolve().is_dir():
        raise RuntimeError("HOSTED_RUNNER_TEMP_INVALID")


def provider_module():
    source = Path(__file__).resolve().parent / "hosted-linux-provider-data-plane.py"
    sys.dont_write_bytecode = True
    spec = importlib.util.spec_from_file_location("oig_pinned_provider_qa", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def extract_unique_pem(config, tag):
    matches = re.findall(
        rf"<{tag}>\s*(-----BEGIN (?:RSA |EC )?(?:CERTIFICATE|PRIVATE KEY)-----"
        rf"[\s\S]+?-----END (?:RSA |EC )?(?:CERTIFICATE|PRIVATE KEY)-----)\s*</{tag}>",
        config, flags=re.I
    )
    if len(matches) != 1:
        raise RuntimeError("OFFICIAL_INLINE_PEM_MISSING_OR_AMBIGUOUS_" + tag)
    text = matches[0]
    if len(text) > 18000 or len(text) < 100:
        raise RuntimeError("UNEXPECTED_PEM_BOUNDS_" + tag)
    return text


def write_private(directory, name, payload):
    target = directory / name
    fd = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii", newline="\n") as fh:
        fh.write(payload + "\n")
    return str(target)


def call_controller(node, controller, payload):
    # JSON credentials are ephemeral stdin, never argv/environment/receipt.
    trial = subprocess.run(
        [str(node), str(controller)], input=json.dumps(payload),
        capture_output=True, text=True, timeout=72, encoding="utf-8",
        cwd=payload["root"],
        env={**os.environ, "OIG_HOSTED_LIVE_PROVIDER_QA": "1"},
    )
    if trial.returncode != 0:
        # Node already redacts bounded log diagnostics. Never echo the
        # provider's fetched profile, credential, or management exchange.
        diagnostic = trial.stderr.replace(payload["password"], "[REDACTED]")
        raise RuntimeError("HOSTED_PROVIDER_CONTROLLER_FAILED_" +
                           payload["mode"] + "_" + diagnostic[:1350])
    try:
        result = json.loads(trial.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("INVALID_HOSTED_PROVIDER_CONTROLLER_JSON") from exc
    if result.get("schema") != "oig-community-controller-qa-v1":
        raise RuntimeError("CONTROLLER_SCHEMA_MISMATCH")
    if result.get("mode") != payload["mode"]:
        raise RuntimeError("CONTROLLER_MODE_MISMATCH")
    guards = (
        "managementConnected", "managementHoldObserved", "ownedProcessStopped",
        "closedManagementListener", "managementPasswordProtected",
        "managementTokenErased", "devNull", "routesNotExecuted",
        "remoteProviderProbed",
    )
    if any(result.get(k) is not True for k in guards):
        raise RuntimeError("CONTROLLER_TEARDOWN_OR_ROUTE_GUARD_MISSING")
    if result.get("localOnly") is not False or result.get("productionEngineChanged") is not False:
        raise RuntimeError("CONTROLLER_FALSE_SCOPE_CLAIM")
    if result.get("pinnedProviderCaSha256") != PINNED_CA:
        raise RuntimeError("CONTROLLER_CA_PIN_MISMATCH")
    if payload["mode"] == "live-provider":
        if not all(result.get(k) is True for k in (
            "tlsAccepted", "pinnedPeerVerified", "publicUserAuthenticated",
            "managementPromptObserved",
        )):
            raise RuntimeError("LIVE_PROVIDER_CA_CN_OR_AUTH_NOT_CONFIRMED")
        if result.get("identityRejected") or result.get("authRejected"):
            raise RuntimeError("LIVE_PROVIDER_REJECTED")
    else:
        if not result.get("identityRejected") or result.get("tlsAccepted") or \
           result.get("pinnedPeerVerified") or result.get("publicUserAuthenticated"):
            raise RuntimeError("INVALID_CN_NOT_REJECTED")
    return {k: result.get(k) for k in (
        "mode", "tlsAccepted", "identityRejected", "authRejected",
        "pinnedPeerVerified", "publicUserAuthenticated",
        "managementConnected", "managementHoldObserved",
        "managementPromptObserved", "ownedProcessStopped",
        "closedManagementListener", "managementPasswordProtected",
        "managementTokenErased", "remoteProviderProbed", "devNull",
        "routesNotExecuted", "productionEngineChanged",
    )}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--openvpn", required=True)
    parser.add_argument("--node-bin", required=True)
    parser.add_argument("--receipt", required=True)
    args = parser.parse_args()
    assert_runner()
    receipt = Path(args.receipt).resolve()
    if receipt.exists() or receipt.parent != Path(os.environ["RUNNER_TEMP"]).resolve():
        raise RuntimeError("HOSTED_RECEIPT_PATH_REFUSED")
    node = Path(args.node_bin).resolve(strict=True)
    engine = Path(args.openvpn).resolve(strict=True)
    controller = Path(__file__).resolve().parent / "qa-community-cli-controller.cjs"
    if not controller.is_file():
        raise RuntimeError("QA_CONTROLLER_MISSING")
    # Windows Python and Node may resolve TEMP/TMP differently on hosted
    # runners. Derive the scratch parent from the controller's actual Node
    # runtime; never weaken the controller's same-parent safety boundary.
    temp_query = subprocess.run(
        [str(node), "-p", 'require("node:os").tmpdir()'],
        capture_output=True, text=True, timeout=8, check=True,
    )
    node_temp = Path(temp_query.stdout.strip()).resolve()
    if not node_temp.is_dir() or node_temp.is_symlink() or        str(node_temp).startswith("\\\\"):
        raise RuntimeError("NODE_RUNTIME_SCRATCH_ROOT_INVALID")
    p = provider_module()
    profile, profile_sha = p.official_profile()
    if p.EXPECTED_CA != PINNED_CA or p.ENDPOINT != "uk205.vpnbook.com" or \
       p.EXPECTED_CN != "server.vpnbook.com":
        raise RuntimeError("TRUST_AUTHORITY_NOT_PINNED")
    password, updated = p.official_login()
    if not re.fullmatch(r"[A-Za-z0-9]{4,32}", password):
        raise RuntimeError("PUBLIC_LOGIN_INVALID")
    with tempfile.TemporaryDirectory(
            prefix="oig-community-loopback-", dir=str(node_temp)) as temp:
        root = Path(temp).resolve()
        ca = write_private(root, "ca.pem", extract_unique_pem(profile, "ca"))
        cert = write_private(root, "client.pem", extract_unique_pem(profile, "cert"))
        key = write_private(root, "client.key", extract_unique_pem(profile, "key"))
        checks = []
        for mode in MODES:
            result = call_controller(node, controller, {
                "mode": mode, "root": str(root), "exe": str(engine),
                "ca": ca, "cert": cert, "key": key, "port": 443,
                "username": "vpnbook", "password": password,
            })
            checks.append(result)
        password = ""
    output = {
        "schema": "oig-hosted-windows-community-provider-identity-v1",
        "sourceSha": os.environ.get("GITHUB_SHA", ""),
        "scope": "hosted Windows native OpenVPN no-TUN authenticated TLS only",
        "provider": "uk205.vpnbook.com",
        "peerCN": "server.vpnbook.com",
        "caDerSha256": PINNED_CA,
        "officialProfileSha256": profile_sha,
        "publicCredentialUpdated": updated,
        "providerIdentityPinned": True,
        "providerAuthenticatedWithPublicSharedLogin": True,
        "noTunOrRouteOrDnsMutation": True,
        "productEngineChanged": False,
        "ownerHostTouched": False,
        "cases": checks, "pass": True,
    }
    # JSON contains no password, private key, full logs, or IP metadata.
    with receipt.open("x", encoding="utf-8") as fh:
        json.dump(output, fh, indent=2)
        fh.write("\n")
    print("PASS_NATIVE_WINDOWS_PINNED_PROVIDER_CA_CN_AUTH_AND_REJECTION_NO_TUN")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("FAIL_WINDOWS_PROVIDER_GATE_" + type(exc).__name__ + "_" +
              str(exc).replace("\n", " ")[:1500], file=sys.stderr)
        sys.exit(1)
