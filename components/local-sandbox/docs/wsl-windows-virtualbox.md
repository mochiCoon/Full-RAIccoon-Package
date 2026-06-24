# WSL2 + Windows-host VirtualBox adapter

This adapter lets the Linux sandbox runner inside WSL2 call the Oracle VirtualBox installation on the Windows host. It is intended as a convenience bridge for teams that want the portal and CLI tooling in WSL but keep VirtualBox installed on Windows.

Important: this is an adapter layer, not a guarantee that every detonation workflow is safe or production-ready under WSL. Treat WSL mode as an advanced deployment pattern. For high-assurance malware work, a dedicated Linux lab host is still preferred.

## Supported topology

```text
Windows host
  Oracle VirtualBox
  Windows Defender exclusions/tuning for your lab paths, if approved by policy
  Host-only VirtualBox network

WSL2 distro
  RAIccoon package checkout
  Python sandbox runner
  tshark / 7z / xorriso / optional YARA/Suricata tools
  PATH points `VBoxManage` to this adapter
```

The adapter translates selected WSL host paths to Windows paths before invoking `VBoxManage.exe`. It deliberately does not translate guest paths after `guestcontrol --`, because those paths belong to the guest operating system.

## Install prerequisites

On Windows:

1. Install Oracle VirtualBox.
2. Create or import the malware-analysis and optional analysis VMs in the Windows VirtualBox UI.
3. Configure host-only networking in VirtualBox.
4. Keep malware guests isolated from production networks.

Inside WSL2:

```bash
sudo apt update
sudo apt install -y python3 python3-venv p7zip-full xorriso tshark dnsmasq openssl
```

Optional tools depend on your workflow: Suricata, YARA, Volatility, Zeek, capa, FLOSS, etc.

## Enable the adapter

From the repository root:

```bash
cd components/local-sandbox
chmod +x adapters/wsl/VBoxManage adapters/wsl/setup-wsl-vboxmanage.sh
adapters/wsl/setup-wsl-vboxmanage.sh
```

For normal use, add this to your shell profile or run it before sandbox commands:

```bash
export PATH="$PWD/adapters/wsl:$PATH"
export RAICCOON_VBOXMANAGE_EXE="/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
VBoxManage --adapter-self-test
```

If VirtualBox is installed somewhere else, set `RAICCOON_VBOXMANAGE_EXE` to that WSL path.

## Smoke-test Windows VirtualBox from WSL

```bash
VBoxManage --version
VBoxManage list vms
VBoxManage showvminfo win-malware-lab --machinereadable
VBoxManage snapshot win-malware-lab list --machinereadable
```

If those commands work, the sandbox runner can usually perform snapshot restore, power control, storage attach, and guestcontrol operations through the adapter.

## Path translation behavior

The adapter translates values passed to known VirtualBox host-path options:

- `--medium`
- `--hostpath`
- `--filename`
- `--basefolder`
- `--screenshotpng`
- `--recordingfile`
- `--settingspwfile`

Examples:

```bash
VBoxManage storageattach win-malware-lab \
  --storagectl IDE --port 1 --device 0 --type dvddrive \
  --medium /home/analyst/sample.iso
```

The adapter invokes Windows VirtualBox with a Windows path such as:

```text
C:\Users\...\AppData\Local\Packages\...\sample.iso
```

Disable translation for debugging:

```bash
RAICCOON_WSL_VBOX_NO_PATH_TRANSLATE=1 VBoxManage list vms
```

Print the exact Windows command without executing it:

```bash
RAICCOON_WSL_VBOX_DRY_RUN=1 VBoxManage storageattach ...
```

Print the translated command before execution:

```bash
RAICCOON_WSL_VBOX_DEBUG=1 VBoxManage list vms
```

## Recommended WSL sandbox command pattern

```bash
cd components/local-sandbox
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export PATH="$PWD/adapters/wsl:$PATH"
VBoxManage --adapter-self-test
PYTHONPATH=src python3 -m raiccoon_sandbox.local_vbox_detonate \
  /path/to/sample.7z \
  --password CHANGE_ME_SAMPLE_ARCHIVE_PASSWORD \
  --vm win-malware-lab \
  --snapshot clean-guestadditions-sysmon \
  --duration 180
```

## Known WSL limitations

1. Low ports and packet capture can behave differently under WSL networking. Validate DNS/HTTP/TLS simulation and PCAP collection before relying on results.
2. Windows-host VirtualBox host-only networks are controlled by Windows, not WSL. Confirm WSL can reach the host-only gateway and guest IPs.
3. File paths that cross the Windows/WSL boundary can be slower. Prefer working under the WSL filesystem and let the adapter translate only paths passed to VirtualBox.
4. Guestcontrol commands depend on Guest Additions and guest credentials; validate them with harmless commands before detonating samples.
5. Do not use bridged networking for malware guests just because WSL networking is inconvenient.

## Troubleshooting

Adapter cannot find VirtualBox:

```bash
export RAICCOON_VBOXMANAGE_EXE="/mnt/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
ls -l "$RAICCOON_VBOXMANAGE_EXE"
```

VM not found:

```bash
VBoxManage list vms
```

Snapshot not found:

```bash
VBoxManage snapshot <vm-name> list --machinereadable
```

Guestcontrol fails:

```bash
VBoxManage guestcontrol <vm-name> run \
  --username <guest-user> --password '<guest-password>' \
  --exe C:\\Windows\\System32\\cmd.exe --wait-stdout -- \
  /c whoami
```

Network capture is empty:

- Confirm the guest NIC is on the intended host-only network.
- Confirm WSL sees the interface you are capturing.
- Consider capturing on the Windows host if WSL cannot see the VirtualBox host-only interface reliably.
