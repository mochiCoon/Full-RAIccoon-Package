import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / "adapters" / "wsl" / "VBoxManage"


class WslVBoxManageAdapterTests(unittest.TestCase):
    def run_adapter(self, *args: str) -> str:
        env = os.environ.copy()
        env["RAICCOON_VBOXMANAGE_EXE"] = "/bin/echo"
        env["RAICCOON_WSL_VBOX_DRY_RUN"] = "1"
        env["RAICCOON_WSL_VBOX_NO_PATH_TRANSLATE"] = "1"
        result = subprocess.run([str(ADAPTER), *args], env=env, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return result.stdout.strip()

    def test_dry_run_invokes_configured_executable(self):
        output = self.run_adapter("list", "vms")
        self.assertTrue(output.startswith("/bin/echo"), output)
        self.assertIn("list", output)
        self.assertIn("vms", output)

    def test_guestcontrol_guest_paths_are_not_rewritten(self):
        output = self.run_adapter("guestcontrol", "analysis-vm", "run", "--exe", "/bin/sh", "--", "-lc", "whoami")
        self.assertIn("--exe /bin/sh", output)
        self.assertIn("-- -lc whoami", output)

    def test_host_path_options_are_preserved_as_option_value_pairs(self):
        with tempfile.TemporaryDirectory() as tmp:
            iso = Path(tmp) / "sample.iso"
            iso.write_bytes(b"not-real-iso")
            output = self.run_adapter("storageattach", "vm", "--medium", str(iso))
            self.assertIn("--medium", output)
            self.assertIn(str(iso), output)


if __name__ == "__main__":
    unittest.main()
