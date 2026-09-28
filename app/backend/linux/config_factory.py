#!/usr/bin/env python3
import argparse, base64, datetime as dt, fcntl, hashlib, json, os, re, shutil, sys, tempfile, urllib.request
from pathlib import Path

SEEDS = [
    "http://210.222.246.148:12814",
    "http://150.40.105.19:35399",
    "http://150.40.105.6:11803",
    "http://150.40.105.5:32536",
    "http://150.40.105.24:38827",
]

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

def fetch(url, timeout=8):
    req = urllib.request.Request(url, headers={"User-Agent":"OpenInternetGateway/2.2"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()

def refresh_snapshot(evidence):
    csv_path = evidence / "vpngate-mirror-api.csv"
    used = None
    if os.environ.get("OIG_FACTORY_OFFLINE") != "1":
        for base in SEEDS:
            try:
                data = fetch(base + "/api/iphone/")
                if len(data) > 100_000:
                    tmp = csv_path.with_suffix(".partial")
                    tmp.write_bytes(data)
                    tmp.replace(csv_path)
                    used = base
                    break
            except Exception:
                pass
    if not csv_path.exists():
        raise RuntimeError("No live VPN Gate mirror and no cached API snapshot.")
    write_json(evidence / "mirror-refresh-last.json", {
        "at": now(), "refresh": bool(used), "usedMirror": used,
        "source": used or "cached VPN Gate mirror snapshot"
    })
    return csv_path, used

def parse_candidates(csv_path, count=24, per_country=4):
    rows, seen = [], set()
    for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line or line.startswith("*") or line.startswith("#"):
            continue
        p = line.split(",")
        if len(p) < 15:
            continue
        country = p[6].strip().upper()
        country_name = p[5].strip()
        if not country:
            continue
        try:
            text = base64.b64decode(p[-1].strip()).decode("utf-8", errors="replace")
        except Exception:
            continue
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
        seen.add(key)
        if not re.search(r"(?m)^client\s*$", text): continue
        if not re.search(r"(?m)^dev\s+tun\s*$", text): continue
        if not re.search(r"(?s)<ca>.+?</ca>", text): continue
        if not re.search(r"(?s)<cert>.+?</cert>", text): continue
        if not re.search(r"(?s)<key>.+?</key>", text): continue
        try:
            score, speed, sessions = int(p[2]), int(p[4]), int(p[7])
        except Exception:
            continue
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
        raw=str(c.get("Profile","")).replace("\\","/")
        old_path=active/Path(raw).name
        if not old_path.exists(): continue
        if hashlib.sha256(old_path.read_bytes()).hexdigest()!=sha: continue
        text=old_path.read_text(encoding="utf-8",errors="replace")
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

def promote(common, evidence, count=24, keep_generations=4, preserve_count=4):
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

    if active.exists():
        if (active/"index.json").exists():
            archive=generations/dt.datetime.now().strftime("%Y%m%d-%H%M%S%f")
            active.rename(archive)
        else:
            shutil.rmtree(active,ignore_errors=True)
    stage.rename(active)

    old=sorted([p for p in generations.iterdir() if p.is_dir()],reverse=True)
    for p in old[keep_generations:]:
        shutil.rmtree(p,ignore_errors=True)
    for p in list(staging.iterdir()):
        try:
            age=(dt.datetime.now().timestamp()-p.stat().st_mtime)/3600
            if age>2: shutil.rmtree(p,ignore_errors=True)
        except Exception: pass
    return meta, kept

def status(common, evidence, min_pool=6):
    active=common/"runtime"/"udp-cache"
    factory=common/"runtime"/"config-factory"
    idx=read_json(active/"index.json",[])
    success=read_json(factory/"successes.json",{})
    quarantine=read_json(factory/"quarantine.json",{})
    validated=sum(1 for c in idx if str(c.get("SHA256","")).lower() in success)
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
    generations=len([p for p in (factory/"generations").glob("*") if p.is_dir()]) if (factory/"generations").exists() else 0
    protocols={}
    countries={}
    for c in idx:
        pr=str(c.get("Protocol","unknown"))
        protocols[pr]=protocols.get(pr,0)+1
        cc=str(c.get("Country","") or "??")
        countries[cc]=countries.get(cc,0)+1
    metadata_complete=all(bool(str(c.get("Country","")).strip()) for c in idx) if idx else False
    obj={
        "at":now(),"schemaVersion":2,"pool":len(idx),"validated":validated,
        "standby":max(0,len(idx)-validated),"quarantined":len(quarantine),
        "generations":generations,"lastRefresh":last,"ageHours":age,
        "source":source,"healthy":len(idx)>=min_pool,"metadataComplete":metadata_complete,
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
    if s["pool"]<min_pool or stale or migration_needed:
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
        successes[key]={"at":now(),"host":host,"ip":ip,"port":int(port or 0),"sha256":sha,"observedIP":observed_ip,"country":country}
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
