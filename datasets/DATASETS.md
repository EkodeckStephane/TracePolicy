# Dataset lock and acquisition notes

## 1. DARPA Transparent Computing — Engagement 3 / CADETS

**Primary source:** DARPA I2O Transparent Computing repository:
`https://github.com/darpa-i2o/Transparent-Computing/blob/master/README-E3.md`

DARPA's README states that the release material is hosted on a Five Directions Google Drive because of its size. Use the Drive linked from that official README.

Required final-run files:
- `ta1-cadets-e3-official.json.tar.gz`
- `ta1-cadets-e3-official-2.json.tar.gz`
- `tc_ground_truth_report_e3_update.pdf`

The archive filenames are also used by the public MAGIC preprocessing instructions for CADETS E3. Do not delete earlier/intermediate extracted log segments: CDM records can define entities that are referenced by later event records.

Target paths:
```text
datasets/raw/darpa_e3/cadets/ta1-cadets-e3-official.json.tar.gz
datasets/raw/darpa_e3/cadets/ta1-cadets-e3-official-2.json.tar.gz
datasets/raw/darpa_e3/ground_truth/tc_ground_truth_report_e3_update.pdf
```

The kit includes `datasets/seed/cadets_groundtruth_threatrace.txt`, a machine-readable UUID mapping from the public ThreaTrace project. This is **derived data** and must never be described as the official DARPA ground truth. `scripts/audit_darpa_groundtruth.py` retains a provenance diagnostic against UUID-like strings visible in the official PDF; it does not assume that the two sets must be equal.

## 2. TON_IoT — Modbus subset

Primary project page:
`https://research.unsw.edu.au/projects/toniot-datasets`

The kit contains the exact Modbus seed used in the preliminary Phase-5 run:
`datasets/seed/Train_Test_IoT_Modbus.csv`

Frozen SHA-256:
`78345a857244e671b0c255ca65aac619049632448fc5aa736f1cea255f308cbb`

Leakage controls are mandatory:
- only the four Modbus register fields are features for the policy/RF/IF comparison;
- date and time are excluded;
- identical four-register vectors are grouped and may not cross train/validation/test;
- all hyperparameter selection occurs on validation only;
- the test split is used only after selection is frozen.

## 3. Real local instrumented bench

The kit creates an actual Dockerized HTTP service, sends deterministic benign/attack-pattern requests, captures its gateway log and PCAP, and produces truth from the independent driver. It is a controlled local system experiment, not a claim of an Internet-facing production deployment.

The exact same campaign is evaluated by:
- Trace–Policy engine;
- Suricata;
- Wazuh.
