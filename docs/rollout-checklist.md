# Rollout checklist

- [ ] Fork/clone the package into your organization namespace.
- [ ] Copy `.env.example` to `.env`.
- [ ] Replace bootstrap admin password and portal secret.
- [ ] Choose internal URL/reverse proxy path.
- [ ] Set app CIDR allowlist and upstream firewall/VPN controls.
- [ ] Start portal locally and verify `/healthz`.
- [ ] Create a test research task.
- [ ] If using Hermes, verify CLI path and timeout.
- [ ] If using OpenCTI, create local tokens and test one upload.
- [ ] If using sandbox, verify host-only VirtualBox topology with benign test files first.
- [ ] If using WSL2 for sandbox control, enable `components/local-sandbox/adapters/wsl/`, verify `VBoxManage list vms`, and validate packet capture before real samples.
- [ ] Add organization branding only after the unbranded skeleton is healthy.
