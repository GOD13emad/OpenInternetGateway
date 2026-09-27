#!/usr/bin/env python3
import subprocess,sys
from pathlib import Path
common=Path(sys.argv[1]).resolve()
script=Path(__file__).with_name("config_factory.py")
raise SystemExit(subprocess.call([sys.executable,str(script),"refresh","--common",str(common)]))
