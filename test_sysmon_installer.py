# test_sysmon_installer.py
import os
import unittest
from sentinel_core.sysmon_installer import SysmonInstallerManager


class TestSysmonInstaller(unittest.TestCase):

    def setUp(self):
        self.mgr = SysmonInstallerManager()

    def test_status_structure(self):
        st = self.mgr.get_status()
        self.assertIn("platform_windows", st)
        self.assertIn("is_admin", st)
        self.assertIn("service_installed", st)
        self.assertIn("service_running", st)
        self.assertIn("channel_active", st)
        self.assertIn("config_exists", st)
        self.assertIn("recommendation", st)

    def test_config_file_exists(self):
        self.assertTrue(os.path.exists(self.mgr.config_path), f"Arquivo não encontrado: {self.mgr.config_path}")

    def test_ps1_script_exists(self):
        self.assertTrue(os.path.exists(self.mgr.script_path), f"Script não encontrado: {self.mgr.script_path}")

    def test_get_install_command(self):
        cmd = self.mgr.get_install_command()
        self.assertIn("powershell", cmd)
        self.assertIn("install_sysmon.ps1", cmd)
        cmd_force = self.mgr.get_install_command(force=True)
        self.assertIn("-ForceUpdate", cmd_force)

    def test_install_requires_elevation(self):
        # Em processos de teste não-elevados, deve retornar código ELEVATION_REQUIRED ou NON_WINDOWS
        if not self.mgr.is_admin():
            res = self.mgr.install()
            if self.mgr.get_status()["platform_windows"]:
                self.assertEqual(res.get("code"), "ELEVATION_REQUIRED")
                self.assertIn("recommended_command", res)


if __name__ == "__main__":
    unittest.main()
