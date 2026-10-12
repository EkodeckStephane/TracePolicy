import json
from pathlib import Path

d = Path(__file__).parent
c = json.loads((d / "controller_result.json").read_text())
print("summary=", json.dumps(c["summary"], indent=2))
print("arrivals=", json.dumps(c["arrivals"], indent=2))
for name in ("source_A.json", "source_B.json"):
    x = json.loads((d / name).read_text())
    events = [(o["event"]["eid"], o["event"]["action"], o["event"]["ts"], o["policy_version"])
              for o in x["observations"]]
    print(name, x["identity"], events, x["deliveries"])
