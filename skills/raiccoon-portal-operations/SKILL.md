---
name: raiccoon-portal-operations
description: Operate and tune the RAIccoon portal for internal analyst workflows.
---
# RAIccoon portal operations

Use this skill when creating portal tasks, reviewing queued work, publishing internal deliverables, or troubleshooting portal deployment.

Checklist:
1. Verify `/healthz` before changing workflow state.
2. Keep portal access internal-only behind VPN/firewall controls.
3. Keep generated reports and uploaded files out of Git.
4. Treat Hermes/OpenCTI/sandbox integrations as optional modules that should fail visibly, not break page rendering.
5. After configuration changes, run `scripts/smoke-test.sh` and a real browser or curl health check.
