"""Deterministic VPN Gate mirror ordering/transport provenance smoke tests.

No sockets, system DNS/route, live factory or VPN connections are used.
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

FACTORY = Path(__file__).resolve().parents[1] / "backend" / "linux" / "config_factory.py"
spec = importlib.util.spec_from_file_location("oig_test_config_factory", FACTORY)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def rows(prefix):
    return ("\n".join(
        f"{prefix}-{i},198.51.100.{i + 1},1,2,3,4,JP,8,9,10,11,12,13,14,QUJD"
        for i in range(8)
    ) + "\n").encode("utf8")


def scenario(secure_available, limit, expected_security, expected_source):
    with tempfile.TemporaryDirectory(prefix="oig-source-provenance-") as tmp:
        evidence = Path(tmp) / "evidence"
        evidence.mkdir()
        secure = "https://official.example"
        insecure = "http://mirror.example"

        def fake_fetch(url, timeout=6, allow_partial=True):
            if url.startswith(secure):
                time.sleep(0.03)  # Ensure HTTP finishes first under concurrency.
                if not secure_available:
                    raise OSError("trusted source is inaccessible")
                return rows("secure"), False
            return rows("untrusted"), False

        with patch.object(module, "SEEDS", [insecure, secure]), patch.object(module, "fetch", fake_fetch), patch.dict(os.environ, {"OIG_FACTORY_OFFLINE": "0"}):
            csv, source = module.refresh_snapshot(evidence, max_sources=limit)
        result = json.loads((evidence / "mirror-refresh-last.json").read_text())
        assert result["sourceSecurity"] == expected_security, result
        assert source == expected_source, result
        assert result["usedMirrors"][0] == expected_source, result
        assert csv.read_text().splitlines()[0].startswith(
            "secure-" if secure_available else "untrusted-"
        ), "HTTP first response must not displace the HTTPS source"
        if secure_available and limit == 1:
            assert all("untrusted-" not in line for line in csv.read_text().splitlines())
        if secure_available and limit == 2:
            assert "untrusted-" in csv.read_text()

        # Unknown trust when working solely from existing cached snapshots.
        with patch.dict(os.environ, {"OIG_FACTORY_OFFLINE": "1"}):
            module.refresh_snapshot(evidence, max_sources=limit)
        cached = json.loads((evidence / "mirror-refresh-last.json").read_text())
        assert cached["sourceSecurity"] == "unknown", cached
        # A new HTTPS fetch is not evidence that an older active generation
        # was built from it. Test provenance at the active generation boundary.
        active = Path(tmp) / "common" / "runtime" / "udp-cache"
        active.mkdir(parents=True)
        (active / "index.json").write_text("[]")
        (evidence / "mirror-refresh-last.json").write_text(json.dumps({
            "sourceSecurity": "https-only", "refresh": True,
            "source": secure, "at": module.now()
        }))
        st = module.status(Path(tmp) / "common", evidence)
        assert st["sourceSecurity"] == "unknown", st
        (active / "source-provenance.json").write_text(json.dumps({
            "sourceSecurity": expected_security, "source": expected_source,
            "sourceAt": module.now(), "promotedAt": module.now()
        }))
        st = module.status(Path(tmp) / "common", evidence)
        assert st["sourceSecurity"] == expected_security, st


def promotion_scenario():
    """Promote/recover two real-format but synthetic generations offline."""
    import base64
    with tempfile.TemporaryDirectory(prefix="oig-generation-proof-") as tmp:
        root = Path(tmp)
        common = root / "common"
        evidence = root / "evidence"
        evidence.mkdir()

        def write_feed(prefix, security, source):
            csv = []
            for i in range(8):
                ip = f"198.51.100.{i + (11 if prefix == 'a' else 51)}"
                profile = (f"client\ndev tun\nproto tcp\nremote {ip} 443\n"
                           "<ca>TEST-CA</ca>\n<cert>TEST-CERT</cert>\n<key>TEST-KEY</key>\n")
                fields = [f"{prefix}-{i}", ip, "400", "20", "30000", "Synthetic", "JP", "5",
                          "9", "10", "11", "12", "13", "14", base64.b64encode(profile.encode()).decode()]
                csv.append(",".join(fields))
            (evidence / "vpngate-mirror-api.csv").write_text("\n".join(csv) + "\n")
            (evidence / "mirror-refresh-last.json").write_text(json.dumps({
                "sourceSecurity": security, "source": source,
                "refresh": True, "at": module.now()
            }))

        write_feed("a", "https-only", "https://official.example")
        module.promote(common, evidence, count=4, preserve_count=0)
        assert module.status(common, evidence)["sourceSecurity"] == "https-only"
        active = common / "runtime" / "udp-cache"
        assert (active / "source-provenance.json").is_file()

        write_feed("b", "http-fallback", "http://mirror.example")
        module.promote(common, evidence, count=4, preserve_count=0)
        assert module.status(common, evidence)["sourceSecurity"] == "http-fallback"
        assert module.restore_latest_generation(common)
        assert module.status(common, evidence)["sourceSecurity"] == "https-only"

        # Mixed in preserved older profiles is never promoted as HTTPS-only.
        write_feed("b", "https-only", "https://official.example")
        module.promote(common, evidence, count=4, preserve_count=1)
        assert module.status(common, evidence)["sourceSecurity"] == "unknown"


if __name__ == "__main__":
    scenario(True, 1, "https-only", "https://official.example")
    scenario(True, 2, "http-fallback", "https://official.example")
    scenario(False, 1, "http-fallback", "http://mirror.example")
    promotion_scenario()
    print("PASS: HTTPS-first, HTTP fallback, pool promotion and rollback trust")
