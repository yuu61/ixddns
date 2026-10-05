"""模擬AWS CLIでデプロイ設定を検証する。実際のAWSには接続しない。"""

import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")


@unittest.skipUnless(MAKE and shutil.which("sh"), "GNU Make and sh are required")
class MakefileTests(unittest.TestCase):
    def setUp(self):
        build_directory = PROJECT / ".build"
        build_directory.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            prefix="make-test-", dir=build_directory
        )
        self.directory = Path(temporary.name).resolve()
        if not self.directory.is_relative_to(build_directory.resolve()):
            raise RuntimeError(
                "Test directory is outside the project's build directory"
            )
        self.addCleanup(temporary.cleanup)
        self.config = self.directory / "config.env"
        self.log = self.directory / "aws-calls.jsonl"
        self.values = {
            "AWS_PROFILE": "profile with spaces",
            "REGION": "ap-northeast-1",
            "STACK_NAME": "ixddns-test",
            "HOSTED_ZONE_ID": "ZEXAMPLE",
            "RECORD_NAME": "router.example.com",
            "RECORD_TYPE": "A",
            "RECORD_TTL": "120",
            "LOG_RETENTION_DAYS": "14",
            "ASN_RESTRICTION_ENABLED": "false",
            "ASN_RESTRICTION_METHOD": "static",
            "ASN_PREFIXES_FILE": "",
            "ALLOWED_ASNS": "",
        }
        stub_python = self.directory / "aws_stub.py"
        stub_python.write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "args = sys.argv[1:]\n"
            f"with Path({str(self.log)!r}).open('a', encoding='utf-8') as stream:\n"
            "    stream.write(json.dumps({'args': args, 'profile': os.environ.get('AWS_PROFILE')}) + '\\n')\n"
            "if 'describe-stacks' in args:\n"
            "    if any('TokenSecretArn' in value for value in args):\n"
            "        print(os.environ.get('FAKE_TOKEN_ARN', 'arn:aws:secretsmanager:test:secret:example'))\n"
            "    else:\n"
            "        print('fake stack outputs')\n"
            "elif 'get-secret-value' in args:\n"
            "    print(json.dumps({'token': 'fake-test-token'}))\n",
            encoding="utf-8",
        )
        self.aws = self.directory / "aws-mock.sh"
        self.aws.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(Path(sys.executable).as_posix())
            + " "
            + shlex.quote(stub_python.as_posix())
            + ' "$@"\n',
            encoding="utf-8",
        )
        self.aws.chmod(0o755)

    def invoke(self, target, *overrides, extra_environment=None):
        self.config.write_text(
            "\n".join(f"{key}={value}" for key, value in self.values.items()) + "\n",
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment.pop("MAKEFLAGS", None)
        environment.pop("MFLAGS", None)
        environment.update(extra_environment or {})
        # 検証全体は別途実行するため、このテストの再帰実行を避けます。
        return subprocess.run(
            [
                MAKE,
                "--no-print-directory",
                "--old-file=validate",
                target,
                f"ENV_FILE={self.config.as_posix()}",
                f"AWS={self.aws.as_posix()}",
                *overrides,
            ],
            cwd=PROJECT,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )

    def calls(self):
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_deploy_uses_env_and_command_line_overrides_without_splitting_profile(self):
        result = self.invoke("deploy", "RECORD_NAME=override.example.com")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        args = calls[0]["args"]
        self.assertEqual(args[args.index("--profile") + 1], "profile with spaces")
        self.assertEqual(args[args.index("--stack-name") + 1], "ixddns-test")
        self.assertEqual(
            args[args.index("--parameter-overrides") + 1 :],
            [
                "HostedZoneId=ZEXAMPLE",
                "RecordName=override.example.com",
                "RecordType=A",
                "RecordTTL=120",
                "LogRetentionDays=14",
                "AsnRestrictionEnabled=false",
                "AsnRestrictionMethod=static",
                "AllowedAsns=0",
            ],
        )

    def test_missing_required_settings_stop_before_any_aws_call(self):
        for key in ("HOSTED_ZONE_ID", "RECORD_NAME"):
            with self.subTest(key=key):
                result = self.invoke("deploy", f"{key}=")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(key, result.stderr)
                self.assertEqual(self.calls(), [])

    def test_blank_profile_uses_default_credential_chain(self):
        result = self.invoke("outputs", "AWS_PROFILE=")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = self.calls()[0]
        self.assertNotIn("--profile", call["args"])
        self.assertIsNone(call["profile"])
        self.assertEqual(
            call["args"][call["args"].index("--stack-name") + 1], "ixddns-test"
        )

    def test_token_uses_secret_arn_from_the_configured_stack(self):
        result = self.invoke("token")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertIn("describe-stacks", calls[0]["args"])
        args = calls[1]["args"]
        self.assertIn("get-secret-value", args)
        self.assertEqual(
            args[args.index("--secret-id") + 1],
            "arn:aws:secretsmanager:test:secret:example",
        )
        self.assertEqual(json.loads(result.stdout), {"token": "fake-test-token"})

    def test_missing_secret_arn_stops_before_secret_read(self):
        result = self.invoke("token", extra_environment={"FAKE_TOKEN_ARN": "None"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TokenSecretArn", result.stderr)
        self.assertEqual(len(self.calls()), 1)

    def test_ix_config_requires_interfaces_before_any_aws_call(self):
        result = self.invoke("ix-config", "IX_WAN_IF=")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("IX_WAN_IF", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_deploy_passes_enabled_asns_as_one_argument(self):
        result = self.invoke(
            "deploy",
            "ASN_RESTRICTION_ENABLED=true",
            "ASN_RESTRICTION_METHOD=waf",
            "ALLOWED_ASNS=64496, 64500",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        args = self.calls()[0]["args"]
        self.assertIn("AsnRestrictionEnabled=true", args)
        self.assertIn("AsnRestrictionMethod=waf", args)
        self.assertIn("AllowedAsns=64496, 64500", args)

    def test_invalid_or_empty_asn_settings_stop_before_any_aws_call(self):
        for overrides in (
            ("ASN_RESTRICTION_ENABLED=tru",),
            ("ASN_RESTRICTION_METHOD=statc",),
            ("ASN_RESTRICTION_ENABLED=true", "ALLOWED_ASNS="),
            ("ASN_RESTRICTION_ENABLED=true", "ALLOWED_ASNS=0"),
            ("ASN_RESTRICTION_ENABLED=true", "ALLOWED_ASNS=AS64496"),
        ):
            with self.subTest(overrides=overrides):
                result = self.invoke("deploy", *overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(self.calls(), [])

    def test_disabled_asn_restriction_ignores_the_allow_list(self):
        result = self.invoke("deploy", "ALLOWED_ASNS=64496")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("AllowedAsns=0", self.calls()[0]["args"])

    def test_static_build_uses_the_env_snapshot_without_aws_calls(self):
        from test_asn_prefixes import snapshot

        source = self.directory / "input.json"
        output = self.directory / "template.json"
        source.write_text(json.dumps(snapshot()), encoding="utf-8")
        self.values.update(
            ASN_RESTRICTION_ENABLED="true",
            ALLOWED_ASNS="3333",
            ASN_PREFIXES_FILE=source.as_posix(),
        )
        result = self.invoke("build", f"TEMPLATE={output.as_posix()}")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        code = json.loads(output.read_text(encoding="utf-8"))["Resources"][
            "UpdateFunction"
        ]["Properties"]["Code"]["ZipFile"]
        self.assertNotIn('ASN_SNAPSHOT_DATA = ""', code)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
