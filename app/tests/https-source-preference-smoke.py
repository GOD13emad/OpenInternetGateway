"""Offline regression for HTTPS-first VPN Gate feed selection on stable 2.5.19."""
import importlib.util
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "backend" / "linux" / "config_factory.py"
spec = importlib.util.spec_from_file_location("oig_source_https_test", MODULE)
factory = importlib.util.module_from_spec(spec)
spec.loader.exec_module(factory)


def rows(prefix, count=8, newline=True):
    value = "\n".join(
        f"{prefix}-{i},198.51.100.{i+1},1,2,3,4,JP,8,9,10,11,12,13,14,QUJD"
        for i in range(count)
    )
    return (value + ("\n" if newline else "")).encode()


def scenario(https_available, expected_security, expected_source, max_sources):
    with tempfile.TemporaryDirectory(prefix="oig-2519-secure-mirror-") as temp:
        evidence = Path(temp) / "evidence"
        evidence.mkdir()
        https = "https://official.example"
        http = "http://mirror.example"
        def fetch(url, timeout=6, allow_partial=True):
            if url.startswith(https):
                time.sleep(0.025)  # HTTP completes first; trust must win anyway.
                if not https_available:
                    raise OSError("HTTPS feed unavailable")
                return rows("trusted"), False
            return rows("untrusted"), False
        with patch.object(factory,"SEEDS",[http,https]), patch.object(factory,"fetch",fetch), patch.dict(os.environ,{"OIG_FACTORY_OFFLINE":"0"}):
            csv, source = factory.refresh_snapshot(evidence,max_sources=max_sources)
        result = json.loads((evidence/"mirror-refresh-last.json").read_text())
        assert source == expected_source, result
        assert result["sourceSecurity"] == expected_security, result
        assert result["usedMirrors"] == [expected_source], result
        text = csv.read_text()
        lines = text.splitlines()
        expected_prefix = "trusted-" if https_available else "untrusted-"
        assert lines and all(line.startswith(expected_prefix) for line in lines), lines[:1]
        with patch.dict(os.environ,{"OIG_FACTORY_OFFLINE":"1"}):
            factory.refresh_snapshot(evidence,max_sources=max_sources)
        cached = json.loads((evidence/"mirror-refresh-last.json").read_text())
        assert cached["sourceSecurity"] == "unknown", cached


def redirect_policy():
    from subprocess import CompletedProcess
    with patch.object(factory.shutil,"which",return_value="/usr/bin/curl"), patch.object(factory.subprocess,"run",return_value=CompletedProcess([],0,b"ok",b"")) as command:
        factory.fetch("https://official.example/api/iphone/")
        args=command.call_args.args[0]
        assert args[args.index("--proto-redir")+1]=="=https", args
    with patch.object(factory.shutil,"which",return_value="/usr/bin/curl"), patch.object(factory.subprocess,"run",return_value=CompletedProcess([],0,b"ok",b"")) as command:
        factory.fetch("http://mirror.example/api/iphone/")
        args=command.call_args.args[0]
        assert args[args.index("--proto-redir")+1]=="=http,https", args


if __name__=="__main__":
    scenario(True,"https-only","https://official.example",1)
    scenario(True,"https-only","https://official.example",3)
    scenario(False,"http-fallback","http://mirror.example",1)
    redirect_policy()
    print("PASS: stable HTTPS priority even when HTTP finishes first; fallback and redirects bounded")
