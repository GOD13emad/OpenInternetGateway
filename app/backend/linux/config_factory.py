#!/usr/bin/env python3
import argparse, base64, concurrent.futures, datetime as dt, fcntl, hashlib, json, os, re, shutil, subprocess, sys, tempfile, urllib.request, urllib.parse
from pathlib import Path

SEEDS = [
    "https://www.vpngate.net",
    "http://210.222.246.148:12814",
    "http://150.40.105.19:35399",
    "http://150.40.105.6:11803",
    "http://150.40.105.5:32536",
    "http://150.40.105.24:38827",
]

MAX_SOURCE_CSV_BYTES = 24 * 1024 * 1024
MAX_CSV_LINE_BYTES = 256 * 1024
MAX_CACHED_CSV_BYTES = 3 * MAX_SOURCE_CSV_BYTES

COUNTRY_PRIORITY = ["JP","KR","US","SG","TH","VN","FR","DE","NL","GB","CA","AU","PT","RU"]

def now():
    return dt.datetime.now().astimezone().isoformat()

def read_json(path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return default

def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".partial")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=False), encoding="utf-8")
    tmp.replace(path)

class NoHttpsDowngrade(urllib.request.HTTPRedirectHandler):
    """Never label an HTTPS feed secure after following a plaintext redirect."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if (urllib.parse.urlsplit(req.full_url).scheme.lower() == "https" and
                urllib.parse.urlsplit(newurl).scheme.lower() != "https"):
            raise ValueError("HTTPS feed redirect downgrade refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)

def fetch(url, timeout=8, allow_partial=False):
    # urllib timeouts are per blocking socket operation, not a hard wall-clock
    # deadline. Prefer curl's bounded connect + total transfer limits so dead
    # mirrors cannot stall refresh while a working VPN remains active.
    curl = shutil.which("curl")
    if curl:
        proc = subprocess.run([
            curl,"-4","-L","--proto","=http,https",
            "--proto-redir",("=https" if url.lower().startswith("https://") else "=http,https"),
            "--fail","--noproxy","*",
            "--connect-timeout","2","--max-time",str(timeout),
            "--max-filesize",str(MAX_SOURCE_CSV_BYTES),"-sS",url
        ], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
           timeout=timeout+2, check=False)
        if len(proc.stdout) > MAX_SOURCE_CSV_BYTES:
            raise RuntimeError("VPN Gate source CSV size exceeded")
        if proc.returncode:
            # curl 28 means the hard transfer deadline fired. For the VPN Gate
            # CSV only, retain bytes already received; refresh_snapshot keeps
            # newline-terminated complete rows and promote() independently
            # validates base64/OpenVPN structure and unsafe directives.
            if allow_partial and proc.returncode == 28 and proc.stdout:
                return proc.stdout, True
            raise RuntimeError(f"curl failed ({proc.returncode})")
        return proc.stdout, False
    req = urllib.request.Request(url, headers={"User-Agent":"OpenInternetGateway/2.5"})
    # The no-curl fallback must honor the same HTTPS-to-HTTPS redirect rule.
    opener = urllib.request.build_opener(NoHttpsDowngrade())
    with opener.open(req, timeout=timeout) as r:
        data = r.read(MAX_SOURCE_CSV_BYTES + 1)
        if len(data) > MAX_SOURCE_CSV_BYTES:
            raise RuntimeError("VPN Gate source CSV size exceeded")
        return data, False

def refresh_snapshot(evidence, max_sources=3):
    csv_path = evidence / "vpngate-mirror-api.csv"
    used = []
    merged = []
    seen = set()
    partial_sources = 0

    def fetch_one(base):
        try:
            data, partial = fetch(base + "/api/iphone/", timeout=6, allow_partial=True)
            return base, data, partial
        except Exception:
            return base, None, False

    if os.environ.get("OIG_FACTORY_OFFLINE") != "1":
        # Query the official HTTPS endpoint and known mirrors in parallel.  We
        # only need a few independent snapshots; bounded fan-out avoids making
        # refresh time scale with dead mirrors.
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(6, len(SEEDS))) as pool:
            futures = [pool.submit(fetch_one, base) for base in SEEDS]
            for future in concurrent.futures.as_completed(futures):
                base, data, partial = future.result()
                if not data:
                    continue
                text = data.decode("utf-8", errors="replace")
                lines = text.splitlines()
                # A timed-out transfer may end in the middle of one CSV row.
                # Never treat that unterminated tail as a complete record.
                if partial and data and not data.endswith((b"\n", b"\r")) and lines:
                    lines = lines[:-1]
                rows = []
                source_seen = set()
                for line in lines:
                    if len(line.encode("utf-8")) > MAX_CSV_LINE_BYTES:
                        continue
                    if not line or line.startswith("*") or line.startswith("#"):
                        continue
                    parts = line.split(",")
                    if len(parts) < 15:
                        continue
                    # Deduplicate identical OpenVPN endpoints/configs across
                    # mirrors while retaining different transports/profiles.
                    key = (parts[0].strip(), parts[1].strip(), parts[-1].strip())
                    if key in seen or key in source_seen:
                        continue
                    source_seen.add(key)
                    rows.append(line)
                # Eight complete rows are enough to exceed the release/runtime
                # minimum after structural OpenVPN validation, without turning
                # a network timeout into an unbounded retry.
                if len(rows) >= 8:
                    merged.extend(rows)
                    seen.update(source_seen)
                    used.append(base)
                    if partial:
                        partial_sources += 1
                if len(used) >= max_sources:
                    for pending in futures:
                        pending.cancel()
                    break

        if merged:
            # Parse into a temporary candidate before replacing a known-good
            # snapshot. CSV column counts are not OpenVPN profile validity.
            tmp = csv_path.with_suffix(".partial")
            try:
                encoded = ("\n".join(merged) + "\n").encode("utf-8")
                if len(encoded) > MAX_CACHED_CSV_BYTES:
                    raise ValueError("Merged VPN Gate CSV exceeds size limit")
                tmp.write_bytes(encoded)
                if len(parse_candidates(tmp, count=48, per_country=6)) < 3:
                    raise ValueError("No usable OpenVPN profiles in downloaded CSV")
                tmp.replace(csv_path)
            except (ValueError, RuntimeError, OSError):
                # Leave the previous complete CSV untouched, if any.
                tmp.unlink(missing_ok=True)
                used.clear()
                partial_sources = 0

    if not csv_path.exists():
        raise RuntimeError("No live VPN Gate mirror and no cached API snapshot.")
    source = " + ".join(used) if used else "cached VPN Gate mirror snapshot"
    write_json(evidence / "mirror-refresh-last.json", {
        "at": now(), "refresh": bool(used), "usedMirror": (used[0] if used else None),
        "usedMirrors": used, "sourceCount": len(used), "partialSourceCount": partial_sources,
        "mergedRows": len(merged), "source": source
    })
    return csv_path, (used[0] if used else None)

# Imported profiles are untrusted data, never executable local policy.
# Deny unknown directives, external paths/commands and extra destinations.
def profile_is_data_only(text):
    import ipaddress
    if "\x00" in text or len(text.encode("utf-8")) > 131072:
        return False
    allowed = {
        "client", "dev", "proto", "remote", "cipher", "data-ciphers",
        "data-ciphers-fallback", "auth", "resolv-retry", "nobind",
        "persist-key", "persist-tun", "verb", "mute", "tun-mtu",
        "mssfix", "sndbuf", "rcvbuf", "reneg-sec", "key-direction",
        "auth-nocache", "explicit-exit-notify", "tls-client",
        "remote-cert-tls", "verify-x509-name", "tls-version-min",
        "tls-version-max", "tls-cipher", "tls-ciphersuites",
        "ping", "ping-restart", "ping-exit", "keepalive",
        "connect-retry", "connect-retry-max", "connect-timeout",
        "server-poll-timeout"
    }
    inline_allowed = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2"}
    seen, inline_seen = {}, {}
    block = None
    for original in text.splitlines():
        line = original.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if block:
            if line.lower() == f"</{block}>":
                block = None
            elif line.startswith("<") and line.endswith(">"):
                return False
            continue
        opening = re.fullmatch(r"<([a-z][a-z0-9-]*)>", line.lower())
        if opening:
            tag = opening.group(1)
            if tag not in inline_allowed or tag in inline_seen:
                return False
            inline_seen[tag] = 1
            block = tag
            continue
        if line.startswith("<"):
            return False
        fields = line.split()
        directive = fields[0].lower()
        if directive not in allowed:
            return False
        seen[directive] = seen.get(directive, 0) + 1
        if directive in {"client", "dev", "proto", "remote"} and seen[directive] > 1:
            return False
        if directive == "remote":
            if len(fields) != 3:
                return False
            try:
                ipaddress.IPv4Address(fields[1])
                if not (1 <= int(fields[2]) <= 65535):
                    return False
            except ValueError:
                return False
    return block is None and all(seen.get(name) == 1 for name in ("client", "dev", "proto", "remote")) and all(inline_seen.get(name) == 1 for name in ("ca", "cert", "key"))

def bounded_csv_rows(csv_path):
    if csv_path.stat().st_size > MAX_CACHED_CSV_BYTES:
        raise RuntimeError("Cached VPN Gate CSV exceeds size limit")
    with csv_path.open(encoding="utf-8", errors="replace") as stream:
        for line in stream:
            if len(line.encode("utf-8")) <= MAX_CSV_LINE_BYTES:
                yield line.rstrip("\r\n")

def parse_candidates(csv_path, count=48, per_country=6):
    rows, seen = [], set()
    for line in bounded_csv_rows(csv_path):
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 15:
            continue
        country = p[6].strip().upper()
        country_name = p[5].strip()
        if not country:
            continue
        if len(p[-1].strip()) > MAX_CSV_LINE_BYTES:
            continue
        try:
            text = base64.b64decode(p[-1].strip()).decode("utf-8", errors="replace")
        except Exception:
            continue
        if not profile_is_data_only(text): continue
        pm = re.search(r"(?m)^proto\s+(\S+)\s*$", text)
        rm = re.search(r"(?m)^remote\s+([0-9.]+)\s+(\d+)\s*$", text)
        if not pm or not rm:
            continue
        proto_token = pm.group(1).lower()
        if proto_token.startswith("udp"):
            protocol, transport_rank = "udp", 0
        elif proto_token.startswith("tcp"):
            protocol, transport_rank = "tcp", 1
        else:
            continue
        ip, port = rm.group(1), int(rm.group(2))
        key = f"{protocol}:{ip}:{port}"
        if key in seen:
            continue
        # Do not reserve an endpoint until the entire candidate qualifies.
        if not re.search(r"(?m)^client\s*$", text): continue
        if not re.search(r"(?m)^dev\s+tun\s*$", text): continue
        if not re.search(r"(?s)<ca>.+?</ca>", text): continue
        if not re.search(r"(?s)<cert>.+?</cert>", text): continue
        if not re.search(r"(?s)<key>.+?</key>", text): continue
        # Public profiles are data, never executable policy. Reject directives
        # that can launch local programs or load external plugins/scripts.
        if re.search(r"(?mi)^\s*(?:script-security|up|down|route-up|route-pre-down|ipchange|plugin|client-connect|client-disconnect|learn-address)\b", text):
            continue
        try:
            score, speed, sessions = int(p[2]), int(p[4]), int(p[7])
        except Exception:
            continue
        # Only structurally safe rows may claim a duplicate endpoint.
        seen.add(key)
        rows.append({
            "Host":p[0],"IP":ip,"Port":port,"Score":score,"Ping":p[3],
            "Speed":speed,"Sessions":sessions,"Text":text,"Source":"VPNGate",
            "Protocol":protocol,"TransportRank":transport_rank,
            "Country":country,"CountryName":country_name
        })

    groups = {}
    for row in rows:
        groups.setdefault(row["Country"], []).append(row)
    for bucket in groups.values():
        bucket.sort(key=lambda x: (x["TransportRank"], -x["Score"]))

    remaining = [c for c in groups if c not in COUNTRY_PRIORITY]
    remaining.sort(key=lambda c: -max(x["Score"] for x in groups[c]))
    country_order = [c for c in COUNTRY_PRIORITY if c in groups] + remaining

    selected = []
    for country in country_order:
        selected.extend(groups[country][:per_country])
        if len(selected) >= count:
            return selected[:count]

    if len(selected) < count:
        used = {f'{x["Protocol"]}:{x["IP"]}:{x["Port"]}' for x in selected}
        rest = [x for x in rows if f'{x["Protocol"]}:{x["IP"]}:{x["Port"]}' not in used]
        rest.sort(key=lambda x: (x["TransportRank"], -x["Score"]))
        selected.extend(rest[:count-len(selected)])
    return selected[:count]

def preserve_old(active, stage, meta, success, limit=4):
    old = read_json(active/"index.json", [])
    scored=[]
    for c in old:
        sha=str(c.get("SHA256","")).lower()
        scored.append((1 if sha in success else 0, int(c.get("Rank",9999) or 9999), c))
    scored.sort(key=lambda x:(-x[0],x[1]))
    kept=0
    current_shas={str(x.get("SHA256","")).lower() for x in meta}
    for _,_,c in scored:
        if kept>=limit: break
        sha=str(c.get("SHA256","")).lower()
        if not sha or sha in current_shas: continue
        # Only retain an existing on-disk, bounded, hash-matching file inside
        # the active pool.  Never follow a symlink or an indexed external path.
        if not indexed_usable_profiles(active, [c]): continue
        raw=str(c.get("Profile","")).replace("\\","/")
        old_path=active/Path(raw).name
        text=old_path.read_text(encoding="utf-8",errors="replace")
        if not profile_is_data_only(text): continue
        protocol="udp" if re.search(r"(?m)^proto\s+udp",text) else ("tcp" if re.search(r"(?m)^proto\s+tcp",text) else "unknown")
        kept+=1
        name=f"LKG-{kept:02d}-{old_path.name}"
        shutil.copy2(old_path,stage/name)
        prior = success.get(sha,{}) if isinstance(success,dict) else {}
        country = c.get("Country","") or (prior.get("country","") if isinstance(prior,dict) else "") or "JP"  # legacy pools before 2.3 were JP-only
        meta.append({
            "Rank":len(meta)+1,"Host":c.get("Host",""),"IP":c.get("IP",""),"Port":c.get("Port",0),
            "Protocol":protocol,"Country":country,"CountryName":c.get("CountryName",""),
            "Score":c.get("Score",0),"Ping":c.get("Ping",""),"Speed":c.get("Speed",0),"Sessions":c.get("Sessions",0),
            "Profile":f"runtime/udp-cache/{name}","SHA256":sha,
            "Source":"LastKnownGood","GeneratedAt":now()
        })
        current_shas.add(sha)
    return kept

def promote(common, evidence, count=48, keep_generations=4, preserve_count=8):
    active = common / "runtime" / "udp-cache"
    factory = common / "runtime" / "config-factory"
    generations = factory / "generations"
    staging = factory / "staging"
    quarantine_dir = factory / "quarantine"
    for p in (factory, generations, staging, quarantine_dir):
        p.mkdir(parents=True, exist_ok=True)

    csv_path = evidence / "vpngate-mirror-api.csv"
    rows = parse_candidates(csv_path, count)
    if len(rows) < 3:
        raise RuntimeError(f"Only {len(rows)} structurally valid OpenVPN profiles found.")

    success = read_json(factory/"successes.json", {})
    stage = Path(tempfile.mkdtemp(prefix="pool-", dir=staging))
    meta=[]
    generated = now()
    for i,r in enumerate(rows,1):
        safe=re.sub(r"[^A-Za-z0-9_-]","_",r["Host"])
        name=f"{i:02d}-{r['Protocol']}-{safe}-{r['IP']}-{r['Port']}.ovpn"
        p=stage/name
        p.write_text(r["Text"],encoding="utf-8",newline="")
        sha=hashlib.sha256(p.read_bytes()).hexdigest()
        meta.append({
            "Rank":i,"Host":r["Host"],"IP":r["IP"],"Port":r["Port"],"Protocol":r["Protocol"],
            "Country":r["Country"],"CountryName":r["CountryName"],"Score":r["Score"],"Ping":r["Ping"],"Speed":r["Speed"],"Sessions":r["Sessions"],
            "Profile":f"runtime/udp-cache/{name}","SHA256":sha,
            "Source":"VPNGate","GeneratedAt":generated
        })

    kept = preserve_old(active, stage, meta, success, preserve_count) if active.exists() else 0
    write_json(stage/"index.json", meta)
    for c in meta:
        p=stage/Path(str(c["Profile"]).replace("\\","/")).name
        if not p.exists() or hashlib.sha256(p.read_bytes()).hexdigest()!=c["SHA256"]:
            raise RuntimeError("Staged profile validation failed: "+str(p))

    archive = None
    if active.exists():
        if (active/"index.json").exists():
            archive=generations/dt.datetime.now().strftime("%Y%m%d-%H%M%S%f")
            active.rename(archive)
        else:
            shutil.rmtree(active,ignore_errors=True)
    try:
        stage.rename(active)
    except Exception:
        # A failed activation must never strand a verified previous pool
        # inside generations/ with no active index.json.
        if archive is not None and archive.exists() and not active.exists():
            archive.rename(active)
        raise

    old=sorted([p for p in generations.iterdir() if p.is_dir()],reverse=True)
    for p in old[keep_generations:]:
        shutil.rmtree(p,ignore_errors=True)
    for p in list(staging.iterdir()):
        try:
            age=(dt.datetime.now().timestamp()-p.stat().st_mtime)/3600
            if age>2: shutil.rmtree(p,ignore_errors=True)
        except Exception: pass
    return meta, kept

def indexed_usable_profiles(active, idx):
    """Check indexed profile location, file bounds and content hash."""
    valid = []
    for item in idx if isinstance(idx, list) else []:
        if not isinstance(item, dict):
            continue
        raw = str(item.get("Profile", "")).replace("\\", "/")
        match = re.fullmatch(r"runtime/udp-cache/([A-Za-z0-9][A-Za-z0-9_.-]*\.ovpn)", raw)
        sha = str(item.get("SHA256", "")).lower()
        if not match or not re.fullmatch(r"[0-9a-f]{64}", sha):
            continue
        file = active / match.group(1)
        try:
            if file.is_symlink() or not file.is_file() or file.stat().st_size > 131072:
                continue
            if hashlib.sha256(file.read_bytes()).hexdigest() != sha:
                continue
        except OSError:
            continue
        valid.append(item)
    return valid

def status(common, evidence, min_pool=6):
    active=common/"runtime"/"udp-cache"
    factory=common/"runtime"/"config-factory"
    idx=read_json(active/"index.json",[])
    if not isinstance(idx, list): idx=[]
    usable=indexed_usable_profiles(active,idx)
    success=read_json(factory/"successes.json",{})
    quarantine=read_json(factory/"quarantine.json",{})
    validated=sum(1 for c in usable if str(c.get("SHA256","")).lower() in success)
    last=None
    source="Bundled VPN Gate snapshot" if idx else ""
    mirror=read_json(evidence/"mirror-refresh-last.json",{})
    if mirror:
        last=mirror.get("at")
        source=mirror.get("usedMirror") or mirror.get("source") or "cached VPN Gate mirror snapshot"
    if not last and idx:
        last=idx[0].get("GeneratedAt")
    age=None
    if last:
        try:
            ts=dt.datetime.fromisoformat(str(last).replace("Z","+00:00"))
            age=round((dt.datetime.now().astimezone()-ts.astimezone()).total_seconds()/3600,2)
        except Exception: pass
    # Last observed fetch transport only, not an active profile-origin signature.
    raw_mirrors = mirror.get("usedMirrors")
    mirrors = [str(u).strip() for u in raw_mirrors if u] if isinstance(raw_mirrors, list) else []
    if not mirrors and mirror.get("usedMirror"):
        mirrors = [str(mirror["usedMirror"]).strip()]
    schemes = {u.split(":", 1)[0].lower() for u in mirrors}
    if not mirrors:
        last_fetch_transport = "cached" if mirror else "unknown"
    elif schemes == {"https"}:
        last_fetch_transport = "https"
    elif schemes == {"http"}:
        last_fetch_transport = "http"
    else:
        last_fetch_transport = "mixed"
    generations=len([p for p in (factory/"generations").glob("*") if p.is_dir()]) if (factory/"generations").exists() else 0
    protocols={}
    countries={}
    for c in usable:
        pr=str(c.get("Protocol","unknown"))
        protocols[pr]=protocols.get(pr,0)+1
        cc=str(c.get("Country","") or "??")
        countries[cc]=countries.get(cc,0)+1
    metadata_complete=all(bool(str(c.get("Country","")).strip()) for c in usable) if usable else False
    obj={
        "at":now(),"schemaVersion":2,"pool":len(idx),"usable":len(usable),
        "integrityInvalid":len(idx)-len(usable),"validated":validated,
        "standby":max(0,len(usable)-validated),"quarantined":len(quarantine),
        "generations":generations,"lastRefresh":last,"ageHours":age,
        "source":source,"lastFetchTransport":last_fetch_transport,
        "lastFetchTransportTlsOnly":last_fetch_transport=="https","profileOriginAuthenticated":False,
        "healthy":len(usable)>=min_pool,"metadataComplete":metadata_complete,
        "protocols":protocols,"countries":countries
    }
    write_json(factory/"status.json",obj)
    return obj

def restore_latest_generation(common):
    active=common/"runtime"/"udp-cache"
    generations=common/"runtime"/"config-factory"/"generations"
    if not generations.exists():
        return False
    choices=sorted([p for p in generations.iterdir() if p.is_dir()], reverse=True)
    if not choices:
        return False
    if active.exists():
        shutil.rmtree(active,ignore_errors=True)
    shutil.copytree(choices[0],active)
    return (active/"index.json").exists()

def ensure(common,evidence,min_pool=6,max_age=8):
    s=status(common,evidence,min_pool)
    stale=s["ageHours"] is None or s["ageHours"]>max_age
    migration_needed=not bool(s.get("metadataComplete"))
    if not s["healthy"] or stale or migration_needed:
        try:
            refresh_snapshot(evidence)
            promote(common,evidence)
        except Exception:
            if not (common/"runtime"/"udp-cache"/"index.json").exists():
                if not restore_latest_generation(common):
                    raise
    return status(common,evidence,min_pool)

def refresh(common,evidence):
    refresh_snapshot(evidence)
    promote(common,evidence)
    return status(common,evidence)

def record(common, mode, sha, host="", ip="", port=0, reason="", observed_ip="", country=""):
    factory=common/"runtime"/"config-factory"
    factory.mkdir(parents=True,exist_ok=True)
    successes=read_json(factory/"successes.json",{})
    failures=read_json(factory/"failures.json",{})
    quarantine=read_json(factory/"quarantine.json",{})
    key=(sha or f"{ip}:{port}").lower()
    if mode=="success":
        prior=successes.get(key,{}) if isinstance(successes.get(key,{}),dict) else {}
        stamp=now()
        successes[key]={
            "at":stamp,"first":prior.get("first") or prior.get("at") or stamp,
            "count":int(prior.get("count",0) or 0)+1,
            "host":host,"ip":ip,"port":int(port or 0),"sha256":sha,
            "observedIP":observed_ip,"country":country
        }
        failures.pop(key,None); quarantine.pop(key,None)
    else:
        prev=failures.get(key,{})
        count=int(prev.get("count",0))+1
        failures[key]={"count":count,"last":now(),"reason":reason,"host":host,"ip":ip,"port":int(port or 0),"sha256":sha}
        if count>=3:
            quarantine[key]={"at":now(),"reason":reason,"failures":count,"host":host,"ip":ip,"port":int(port or 0),"sha256":sha}
    write_json(factory/"successes.json",successes)
    write_json(factory/"failures.json",failures)
    write_json(factory/"quarantine.json",quarantine)
    return status(common, common/"evidence")

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("action",choices=["status","ensure","refresh","success","failure"])
    ap.add_argument("--common",required=True)
    ap.add_argument("--sha",default="")
    ap.add_argument("--host",default="")
    ap.add_argument("--ip",default="")
    ap.add_argument("--port",type=int,default=0)
    ap.add_argument("--reason",default="")
    ap.add_argument("--observed-ip",default="")
    ap.add_argument("--country",default="")
    args=ap.parse_args()
    common=Path(args.common).resolve()
    evidence=common/"evidence"
    evidence.mkdir(parents=True,exist_ok=True)
    lock=common/"runtime"/"config-factory"/"factory.lock"
    lock.parent.mkdir(parents=True,exist_ok=True)
    with lock.open("w") as fh:
        fcntl.flock(fh,fcntl.LOCK_EX)
        if args.action=="status": out=status(common,evidence)
        elif args.action=="ensure": out=ensure(common,evidence)
        elif args.action=="refresh": out=refresh(common,evidence)
        else: out=record(common,args.action,args.sha,args.host,args.ip,args.port,args.reason,args.observed_ip,args.country)
    print(json.dumps(out,separators=(",",":")))

if __name__=="__main__":
    main()
