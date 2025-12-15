# adAPT — ELK Threat Rules for APT Detection

This repository contains reference artifacts for building threat detection rules in the ELK stack (Elasticsearch, Logstash, Kibana) focused on Advanced Persistent Threat (APT) behaviors. The goal is to provide example configs, detection rule templates, sample event data and a small test harness so you can import, test and iterate on rules in your own ELK environment.

Summary of contents

- `docs/` — architecture notes, MITRE ATT&CK mapping and runbook.
- `configs/` — example Beats and Logstash pipeline configs to ingest Windows/endpoint logs.
- `detections/` — example detection rules (ElastAlert YAML + JSON/NDJSON skeletons for Kibana/Elastic SIEM detections).
- `samples/` — small, safe sample events you can ingest to test rules.
- `tools/` — helper scripts (Python) to bulk-index sample events into Elasticsearch for testing.

How to use

1. Prepare your environment (ELK and a Windows endpoint or log generator). This repo intentionally contains examples — not a full automated installer. See `docs/ARCHITECTURE.md` and `README.md` for manual setup steps.
2. Place Beats configs on the host(s) you want to ship logs from (e.g., `configs/beats/winlogbeat.yml`).
3. Drop `configs/logstash/pipeline.conf` into your Logstash `pipeline` directory and adjust the Elasticsearch output and credentials.
4. Import rules/detections in `detections/` into ElastAlert or the Kibana Detection Engine as appropriate.
5. Use `tools/ingest_sample.py` to index `samples/sample_events.json` into Elasticsearch and validate rule firing.

Running the quick test harness

1. Install python dependencies:

```bash
python3 -m pip install -r requirements.txt
```

2. Index sample events:

```bash
python3 tools/ingest_sample.py
```

3. Run the detection checker (prints hit counts per detection):

```bash
python3 tools/check_detections.py
```

Notes and disclaimers

- This repository contains only safe, synthetic example events — no malware, no exploits.
- You must adapt paths, hostnames, and credentials to your environment before using these configs.
