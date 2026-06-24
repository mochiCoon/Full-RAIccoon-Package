# Architecture

The package is intentionally simple:

- Portal: FastAPI, server-rendered Jinja templates, SQLite persistence, optional Hermes CLI dispatch.
- Skills: Markdown playbooks that can be loaded into Hermes or adapted into other agent runtimes.
- Sandbox: Python runner wrapping VirtualBox, host-only network services, PCAP capture, static triage, and report generation.
- OpenCTI: optional local compose skeleton and uploader integration pattern.

The default deployment should stay internal-only. Put the portal behind network controls and keep malware detonation isolated on host-only lab networks.
