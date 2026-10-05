"""複数サイト設定の読み込み、検証、各種サブコマンドの動作を検証する。"""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import sites


class SitesTests(unittest.TestCase):
    """YAML/JSONからのサイト定義読み込みと検証をテストする。"""

    def setUp(self) -> None:
        build_dir = sites.PROJECT / ".build"
        build_dir.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="sites-test-", dir=build_dir)
        self.directory = Path(temporary.name).resolve()
        self.addCleanup(temporary.cleanup)

        self.valid_yaml_content = """
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
  region: ap-northeast-1
  record_ttl: 60
  log_retention_days: 30
  lambda_reserved_concurrency: 1
  asn_restriction_enabled: false
  asn_restriction_method: static

sites:
  tokyo-v4:
    record_name: tokyo.example.com
    record_type: A
    ix_wan_if: GigaEthernet0.1

  tokyo-v6:
    record_name: tokyo.example.com
    record_type: AAAA
    ix_source_if: GigaEthernet0.1
    ix_notify_if: GigaEthernet1.0

  osaka:
    stack_name: ixddns-osaka-custom
    record_name: osaka.example.com
    record_type: A
    ix_wan_if: GigaEthernet0.1
    record_ttl: 120
    asn_restriction_enabled: true
    asn_restriction_method: static
    allowed_asns: "64496,64500"
    ix_config_output: examples/custom-osaka.cfg
"""

    def _write_file(self, filename: str, content: str) -> Path:
        path = self.directory / filename
        path.write_text(content, encoding="utf-8")
        return path

    def test_load_valid_yaml(self) -> None:
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)
        self.assertEqual(len(configs), 3)

        tokyo_v4 = configs["tokyo-v4"]
        self.assertEqual(tokyo_v4.site_id, "tokyo-v4")
        self.assertEqual(tokyo_v4.stack_name, "ixddns-tokyo-v4")
        self.assertEqual(tokyo_v4.record_name, "tokyo.example.com")
        self.assertEqual(tokyo_v4.record_type, "A")
        self.assertEqual(tokyo_v4.ix_wan_if, "GigaEthernet0.1")
        self.assertEqual(tokyo_v4.record_ttl, 60)
        self.assertFalse(tokyo_v4.asn_restriction_enabled)
        self.assertTrue(
            str(tokyo_v4.ix_config_output).endswith("nec-ix-ddns-tokyo-v4.cfg")
        )

        tokyo_v6 = configs["tokyo-v6"]
        self.assertEqual(tokyo_v6.record_type, "AAAA")
        self.assertEqual(tokyo_v6.ix_source_if, "GigaEthernet0.1")
        self.assertEqual(tokyo_v6.ix_notify_if, "GigaEthernet1.0")

        osaka = configs["osaka"]
        self.assertEqual(osaka.stack_name, "ixddns-osaka-custom")
        self.assertEqual(osaka.record_ttl, 120)
        self.assertTrue(osaka.asn_restriction_enabled)
        self.assertEqual(osaka.allowed_asns, "64496,64500")
        self.assertTrue(str(osaka.ix_config_output).endswith("custom-osaka.cfg"))

    def test_load_valid_json(self) -> None:
        data = {
            "defaults": {"hosted_zone_id": "Z1111111111"},
            "sites": {
                "site1": {
                    "record_name": "s1.example.com",
                    "ix_wan_if": "GigaEthernet0.1",
                }
            },
        }
        path = self._write_file("sites.json", json.dumps(data))
        configs = sites.load_sites_file(path)
        self.assertIn("site1", configs)
        self.assertEqual(configs["site1"].hosted_zone_id, "Z1111111111")
        self.assertEqual(configs["site1"].stack_name, "ixddns-site1")

    def test_to_env_and_to_settings(self) -> None:
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)
        tokyo_v4 = configs["tokyo-v4"]

        env = tokyo_v4.to_env()
        self.assertEqual(env["STACK_NAME"], "ixddns-tokyo-v4")
        self.assertEqual(env["RECORD_NAME"], "tokyo.example.com")
        self.assertEqual(env["RECORD_TYPE"], "A")
        self.assertEqual(env["IX_WAN_IF"], "GigaEthernet0.1")
        self.assertEqual(env["ASN_RESTRICTION_ENABLED"], "false")

        settings = tokyo_v4.to_settings(aws="custom-aws")
        self.assertEqual(settings.aws, "custom-aws")
        self.assertEqual(settings.stack_name, "ixddns-tokyo-v4")
        self.assertEqual(settings.interfaces, {"<WAN_IF>": "GigaEthernet0.1"})

    def test_duplicate_stack_name_rejected(self) -> None:
        content = """
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
sites:
  site1:
    stack_name: dup-stack
    record_name: s1.example.com
    ix_wan_if: Gi0.1
  site2:
    stack_name: dup-stack
    record_name: s2.example.com
    ix_wan_if: Gi0.1
"""
        path = self._write_file("dup.yaml", content)
        with self.assertRaises(sites.SitesConfigError) as ctx:
            sites.load_sites_file(path)
        self.assertIn("重複", str(ctx.exception))

    def test_duplicate_dns_target_rejected(self) -> None:
        content = """
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
sites:
  site1:
    record_name: same.example.com
    record_type: A
    ix_wan_if: Gi0.1
  site2:
    record_name: same.example.com
    record_type: A
    ix_wan_if: Gi0.2
"""
        path = self._write_file("dup_dns.yaml", content)
        with self.assertRaises(sites.SitesConfigError) as ctx:
            sites.load_sites_file(path)
        self.assertIn("重複", str(ctx.exception))

    def test_duplicate_output_path_rejected(self) -> None:
        content = """
defaults:
  hosted_zone_id: Z0123456789EXAMPLE
sites:
  site1:
    record_name: s1.example.com
    ix_wan_if: Gi0.1
    ix_config_output: examples/same.cfg
  site2:
    record_name: s2.example.com
    ix_wan_if: Gi0.2
    ix_config_output: examples/same.cfg
"""
        path = self._write_file("dup_out.yaml", content)
        with self.assertRaises(sites.SitesConfigError) as ctx:
            sites.load_sites_file(path)
        self.assertIn("重複", str(ctx.exception))

    def test_missing_required_fields_rejected(self) -> None:
        invalid_cases = [
            ("no_zone", "sites:\n  s1:\n    record_name: s.ex.com\n    ix_wan_if: Gi0"),
            (
                "no_record",
                "defaults:\n  hosted_zone_id: Z123\nsites:\n  s1:\n    ix_wan_if: Gi0",
            ),
            (
                "no_wan_if",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
""",
            ),
            (
                "no_ipv6_if",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
    record_type: AAAA
""",
            ),
        ]
        for name, yaml_str in invalid_cases:
            with self.subTest(case=name):
                p = self._write_file(f"{name}.yaml", yaml_str)
                with self.assertRaises(sites.SitesConfigError):
                    sites.load_sites_file(p)

    def test_invalid_values_rejected(self) -> None:
        invalid_cases = [
            (
                "bad_zone",
                """defaults:
  hosted_zone_id: invalid!
sites:
  s1:
    record_name: s.ex.com
    ix_wan_if: Gi0
""",
            ),
            (
                "bad_fqdn",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: UPPER.COM
    ix_wan_if: Gi0
""",
            ),
            (
                "trailing_dot",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: dot.com.
    ix_wan_if: Gi0
""",
            ),
            (
                "bad_ttl",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
    ix_wan_if: Gi0
    record_ttl: 10
""",
            ),
            (
                "bad_retention",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
    ix_wan_if: Gi0
    log_retention_days: 99
""",
            ),
            (
                "bad_concurrency",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
    ix_wan_if: Gi0
    lambda_reserved_concurrency: 0
""",
            ),
            (
                "bad_asn_type",
                """defaults:
  hosted_zone_id: Z123
sites:
  s1:
    record_name: s.ex.com
    ix_wan_if: Gi0
    asn_restriction_enabled: true
    allowed_asns: 'AS123'
""",
            ),
        ]
        for name, yaml_str in invalid_cases:
            with self.subTest(case=name):
                p = self._write_file(f"{name}.yaml", yaml_str)
                with self.assertRaises(sites.SitesConfigError):
                    sites.load_sites_file(p)

    def test_cmd_list_and_check_and_env(self) -> None:
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_list(configs)
        self.assertEqual(code, 0)
        self.assertIn("tokyo-v4", stdout.getvalue())
        self.assertIn("tokyo-v6", stdout.getvalue())
        self.assertIn("osaka", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_check(configs)
        self.assertEqual(code, 0)
        self.assertIn("3件", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_env(configs, "tokyo-v4", export_format=True)
        self.assertEqual(code, 0)
        self.assertIn("export STACK_NAME='ixddns-tokyo-v4'", stdout.getvalue())

    @patch("scripts.sites.generate_config")
    def test_cmd_ix_config(self, mock_gen: MagicMock) -> None:
        mock_gen.return_value = Path("/path/to/cfg")
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_ix_config(configs, site_filter="tokyo-v4")
        self.assertEqual(code, 0)
        self.assertIn("[tokyo-v4] 生成成功", stdout.getvalue())
        self.assertEqual(mock_gen.call_count, 1)

    @patch("scripts.sites.subprocess.run")
    @patch("scripts.sites._build_template_for_site")
    def test_cmd_deploy(self, mock_build: MagicMock, mock_run: MagicMock) -> None:
        mock_build.return_value = self.directory / "template.json"
        mock_run.return_value = MagicMock(returncode=0)
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_deploy(configs, site_filter="tokyo-v4")
        self.assertEqual(code, 0)
        self.assertIn("[tokyo-v4] デプロイ成功", stdout.getvalue())
        self.assertEqual(mock_run.call_count, 1)

    @patch("scripts.sites.aws_json")
    def test_cmd_outputs_and_token(self, mock_aws: MagicMock) -> None:
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        configs = sites.load_sites_file(path)

        mock_aws.side_effect = [
            {
                "Stacks": [
                    {
                        "Outputs": [
                            {
                                "OutputKey": "UpdateUrl",
                                "OutputValue": "https://example.com/update",
                            }
                        ]
                    }
                ]
            },
            {
                "Stacks": [
                    {
                        "Outputs": [
                            {
                                "OutputKey": "TokenSecretArn",
                                "OutputValue": "arn:secret",
                            }
                        ]
                    }
                ]
            },
            {"SecretString": json.dumps({"token": "secret123"})},
        ]

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_outputs(configs, site_filter="tokyo-v4")
        self.assertEqual(code, 0)
        self.assertIn("UpdateUrl", stdout.getvalue())

        stdout = io.StringIO()
        with redirect_stdout(stdout):
            code = sites.cmd_token(configs, site_id="tokyo-v4")
        self.assertEqual(code, 0)
        self.assertIn("secret123", stdout.getvalue())

    def test_main_cli_routing(self) -> None:
        path = self._write_file("sites.yaml", self.valid_yaml_content)
        with (
            patch("sys.argv", ["sites.py", "--file", str(path), "list"]),
            redirect_stdout(io.StringIO()),
        ):
            code = sites.main()
        self.assertEqual(code, 0)

        with (
            patch(
                "sys.argv",
                ["sites.py", "--file", str(path), "check", "--site", "nonexistent"],
            ),
            redirect_stderr(io.StringIO()),
        ):
            code = sites.main()
        self.assertEqual(code, 1)


if __name__ == "__main__":
    unittest.main()
