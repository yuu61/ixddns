"""AWSを模擬して、生成設定・秘密情報の扱い・失敗時の動作を検証する。"""

import io
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

from scripts import generate_ix_config as generator


class IxConfigTests(unittest.TestCase):
    """実機へ投入する設定の置換・取得・失敗時の保持を検証する。"""

    def setUp(self) -> None:
        build = generator.PROJECT / ".build"
        build.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="ix-config-test-", dir=build)
        self.directory = Path(temporary.name).resolve()
        if not self.directory.is_relative_to(build.resolve()):
            message = "テスト用ディレクトリがプロジェクトの.build外にあります。"
            raise RuntimeError(message)
        self.addCleanup(temporary.cleanup)
        self.output = self.directory / "generated" / "router.cfg"
        self.token = "Ab0123456789" * 4
        self.url = "https://abcdefghijklmnopqrstuvwxyz012345.lambda-url.ap-northeast-1.on.aws/update"
        self.environment = {
            "AWS": "aws",
            "AWS_PROFILE": "profile with spaces",
            "REGION": "ap-northeast-1",
            "STACK_NAME": "ixddns-test",
            "HOSTED_ZONE_ID": "ZEXAMPLE",
            "RECORD_NAME": "router.example.com",
            "RECORD_TYPE": "A",
            "IX_WAN_IF": "GigaEthernet0.1",
            "IX_SOURCE_IF": "GigaEthernet0.1",
            "IX_NOTIFY_IF": "GigaEthernet1.0",
            "IX_CONFIG_OUTPUT": str(self.output),
            "ASN_RESTRICTION_ENABLED": "false",
            "ALLOWED_ASNS": "",
        }
        self.stack = {
            "Stacks": [
                {
                    "Parameters": [
                        {"ParameterKey": "RecordType", "ParameterValue": "A"},
                        {
                            "ParameterKey": "RecordName",
                            "ParameterValue": "router.example.com",
                        },
                        {"ParameterKey": "HostedZoneId", "ParameterValue": "ZEXAMPLE"},
                    ],
                    "Outputs": [
                        {"OutputKey": "UpdateUrl", "OutputValue": self.url},
                        {
                            "OutputKey": "TokenSecretArn",
                            "OutputValue": "arn:aws:secretsmanager:test:secret:example",
                        },
                    ],
                }
            ],
        }
        self.secret = {"SecretString": json.dumps({"token": self.token})}

    def aws_result(
        self, command: list[str], **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        response = self.stack if "describe-stacks" in command else self.secret
        return subprocess.CompletedProcess(
            command, 0, stdout=json.dumps(response), stderr=""
        )

    def invoke(self, side_effect: object = None) -> tuple[int, str, str, MagicMock]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with (
            patch.dict(os.environ, self.environment, clear=True),
            patch.object(
                generator.subprocess, "run", side_effect=side_effect or self.aws_result
            ) as run,
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            code = generator.main()
        self.assertNotIn(self.token, stdout.getvalue() + stderr.getvalue())
        return code, stdout.getvalue(), stderr.getvalue(), run

    def test_generates_ipv4_and_ipv6_without_replacing_ix_macros(self) -> None:
        for record_type, macro, family in (
            ("A", "<IP4>", "ipv4"),
            ("AAAA", "<IP6>", "ipv6"),
        ):
            with self.subTest(record_type=record_type):
                self.environment["RECORD_TYPE"] = record_type
                self.stack["Stacks"][0]["Parameters"][0]["ParameterValue"] = record_type
                code, stdout, stderr, run = self.invoke()
                self.assertEqual(code, 0, stderr)
                self.assertIn(str(self.output), stdout)
                config = self.output.read_text(encoding="utf-8")
                self.assertIn(f"ddns profile route53-{family}", config)
                self.assertIn(f"  query ip={macro}&token=<PW>", config)
                self.assertIn(f"  url {self.url}", config)
                self.assertIn("  source-interface GigaEthernet0.1", config)
                self.assertEqual(config.count(self.token), 1)
                self.assertIn(f"  password plain {self.token}", config)
                for placeholder in (
                    "<UPDATE_URL>",
                    "<SHARED_TOKEN>",
                    "<WAN_IF>",
                    "<SOURCE_IF>",
                    "<NOTIFY_IF>",
                ):
                    self.assertNotIn(placeholder, config)
                self.assertIn("! write memory", config)
                if record_type == "AAAA":
                    self.assertIn("  notify-interface GigaEthernet1.0", config)
                self.assertEqual(run.call_count, 2)
                self.assertNotIn(self.token, str(run.call_args_list))

    def test_aws_uses_selected_stack_profile_and_secret_without_a_shell(self) -> None:
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 0, stderr)
        stack_command = run.call_args_list[0].args[0]
        self.assertEqual(
            stack_command[stack_command.index("--profile") + 1], "profile with spaces"
        )
        self.assertEqual(
            stack_command[stack_command.index("--region") + 1], "ap-northeast-1"
        )
        self.assertEqual(
            stack_command[stack_command.index("--stack-name") + 1], "ixddns-test"
        )
        secret_command = run.call_args_list[1].args[0]
        self.assertEqual(
            secret_command[secret_command.index("--secret-id") + 1],
            "arn:aws:secretsmanager:test:secret:example",
        )
        self.assertNotIn("shell", run.call_args.kwargs)

    def test_blank_profile_uses_default_credentials(self) -> None:
        self.environment["AWS_PROFILE"] = ""
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 0, stderr)
        for call in run.call_args_list:
            self.assertNotIn("--profile", call.args[0])
            self.assertNotIn("AWS_PROFILE", call.kwargs["env"])

    def test_missing_or_unsafe_interfaces_stop_before_reading_aws(self) -> None:
        for name, value, record_type in (
            ("IX_WAN_IF", "", "A"),
            ("IX_SOURCE_IF", "", "AAAA"),
            ("IX_NOTIFY_IF", "", "AAAA"),
            ("IX_WAN_IF", "GigaEthernet0.1\nwrite memory", "A"),
            ("IX_WAN_IF", "GigaEthernet0.1;exit", "A"),
        ):
            with self.subTest(name=name, value=value):
                environment = {
                    **self.environment,
                    name: value,
                    "RECORD_TYPE": record_type,
                }
                with patch.object(self, "environment", environment):
                    code, _, stderr, run = self.invoke()
                self.assertEqual(code, 1)
                self.assertIn(name, stderr)
                run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_stack_mismatch_stops_before_reading_the_secret(self) -> None:
        for name, value in (
            ("RECORD_TYPE", "AAAA"),
            ("RECORD_NAME", "other.example.com"),
            ("HOSTED_ZONE_ID", "ZOTHER"),
        ):
            with self.subTest(name=name):
                with patch.object(
                    self, "environment", {**self.environment, name: value}
                ):
                    code, _, stderr, run = self.invoke()
                self.assertEqual(code, 1)
                self.assertIn("一致しません", stderr)
                self.assertEqual(run.call_count, 1)
                self.assertFalse(self.output.exists())

    def test_missing_outputs_stop_before_reading_the_secret(self) -> None:
        self.stack["Stacks"][0]["Outputs"] = []
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("UpdateUrl", stderr)
        self.assertEqual(run.call_count, 1)
        self.assertFalse(self.output.exists())

    def test_invalid_url_or_secret_cannot_inject_ix_commands(self) -> None:
        for url, secret in (
            ("http://example.com/update", self.secret),
            (self.url + "\nwrite memory", self.secret),
            (self.url + "?token=wrong", self.secret),
            (self.url, {"SecretString": "invalid json"}),
            (
                self.url,
                {"SecretString": json.dumps({"token": self.token + "\nwrite memory"})},
            ),
        ):
            with self.subTest(url=url, secret=secret):
                self.stack["Stacks"][0]["Outputs"][0]["OutputValue"] = url
                with patch.object(self, "secret", secret):
                    code, _, _, _ = self.invoke()
                self.assertEqual(code, 1)
                self.assertFalse(self.output.exists())

    def test_aws_failure_does_not_expose_output_or_replace_existing_file(self) -> None:
        self.output.parent.mkdir()
        self.output.write_text("既存コンフィグ\n", encoding="utf-8")
        for result in (
            subprocess.CompletedProcess([], 1, stdout=self.token, stderr=self.token),
            subprocess.CompletedProcess([], 0, stdout=self.token, stderr=""),
            subprocess.TimeoutExpired("aws", 60, output=self.token),
            FileNotFoundError("aws"),
        ):
            with self.subTest(result=type(result).__name__):
                code, _, stderr, _ = self.invoke(side_effect=[result])
                self.assertEqual(code, 1)
                self.assertTrue(stderr)
                self.assertEqual(
                    self.output.read_text(encoding="utf-8"), "既存コンフィグ\n"
                )

    def test_unknown_template_placeholder_is_rejected(self) -> None:
        with self.assertRaises(generator.ConfigError):
            generator.render_config("url <UNSUPPORTED>\n", {})

    def test_output_defaults_follow_record_type(self) -> None:
        for record_type, family in (("A", "ipv4"), ("AAAA", "ipv6")):
            with self.subTest(record_type=record_type):
                environment = {
                    **self.environment,
                    "RECORD_TYPE": record_type,
                    "IX_CONFIG_OUTPUT": "",
                }
                with patch.dict(os.environ, environment, clear=True):
                    settings = generator.Settings.from_environment()
                self.assertEqual(
                    settings.output,
                    generator.PROJECT / "examples" / f"nec-ix-ddns-{family}.cfg",
                )

    def test_asn_mode_and_allow_list_must_match_the_deployed_stack(self) -> None:
        self.environment.update(
            ASN_RESTRICTION_ENABLED="true",
            ASN_RESTRICTION_METHOD="waf",
            ALLOWED_ASNS="64496,64500",
        )
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("AsnRestrictionEnabled", stderr)
        self.assertEqual(run.call_count, 1)
        self.stack["Stacks"][0]["Parameters"].extend([
            {"ParameterKey": "AsnRestrictionEnabled", "ParameterValue": "true"},
            {"ParameterKey": "AllowedAsns", "ParameterValue": "64496"},
        ])
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("AllowedAsns", stderr)
        self.assertEqual(run.call_count, 1)
        self.stack["Stacks"][0]["Parameters"][-1]["ParameterValue"] = "64500, 64496"
        self.stack["Stacks"][0]["Outputs"][0]["OutputValue"] = (
            "https://example.execute-api.ap-northeast-1.amazonaws.com/ddns/update"
        )
        code, _, stderr, _ = self.invoke()
        self.assertEqual(code, 0, stderr)
        self.assertIn("/ddns/update", self.output.read_text(encoding="utf-8"))

    def test_static_method_must_match_the_stack_before_reading_secret(self) -> None:
        self.environment.update(
            ASN_RESTRICTION_ENABLED="true",
            ASN_RESTRICTION_METHOD="static",
            ALLOWED_ASNS="3333",
        )
        parameters = self.stack["Stacks"][0]["Parameters"]
        parameters.extend([
            {"ParameterKey": "AsnRestrictionEnabled", "ParameterValue": "true"},
            {"ParameterKey": "AllowedAsns", "ParameterValue": "3333"},
        ])
        # 方式パラメータがない旧スタックをstaticと誤認しません。
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 1)
        self.assertIn("AsnRestrictionMethod", stderr)
        self.assertEqual(run.call_count, 1)
        parameters.append({
            "ParameterKey": "AsnRestrictionMethod",
            "ParameterValue": "static",
        })
        code, _, stderr, run = self.invoke()
        self.assertEqual(code, 0, stderr)
        self.assertEqual(run.call_count, 2)


if __name__ == "__main__":
    unittest.main()
