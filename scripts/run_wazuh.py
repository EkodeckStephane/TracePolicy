#!/usr/bin/env python3
import subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __name__=='__main__':subprocess.run([sys.executable,str(ROOT/'experiments/run_wazuh_metrics.py')],check=True)
