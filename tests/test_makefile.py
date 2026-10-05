"""模擬AWS CLIとsites.yamlでMakefileターゲットを検証する。"""

import ctypes
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from tests.test_asn_prefixes import snapshot

PROJECT = Path(__file__).resolve().parents[1]
MAKE = shutil.which("make")


def _restore_console_mode() -> None:
    """Windows コンソールの出力処理・VT処理フラグを復元する。"""
    if sys.platform != "win32":
        return
    kernel32 = ctypes.windll.kernel32
    # 標準出力と標準エラー出力のハンドルを取得する。
    for handle_id in (-11, -12):
        handle = kernel32.GetStdHandle(handle_id)
        mode = ctypes.c_ulong()
        if kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            kernel32.SetConsoleMode(handle, mode.value | 0x7)


@unittest.skipUnless(MAKE and shutil.which("sh"), "GNU Make and sh are required")
class MakefileTests(unittest.TestCase):
    """sites.yamlとMakeからAWS CLIや各スクリプトへ渡す引数を検証する。"""

    def setUp(self) -> None:
        build_directory = PROJECT / ".build"
        build_directory.mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            prefix="make-test-", dir=build_directory
        )
        self.directory = Path(temporary.name).resolve()
        if not self.directory.is_relative_to(build_directory.resolve()):
            message = "Test directory is outside the project's build directory"
            raise RuntimeError(message)
        self.addCleanup(temporary.cleanup)

        self.env_file = self.directory / "test.env"
        self.sites_file = self.directory / "test_sites.yaml"
        self.log = self.directory / "aws-calls.jsonl"
        self.output_cfg = self.directory / "router.cfg"
        self.asn_prefixes_file = self.directory / "prefixes.json"
        snap = snapshot()
        snap["asns"] = [64496]
        snap["query_times"] = {"64496": snap["fetched_at"]}
        self.asn_prefixes_file.write_text(json.dumps(snap), encoding="utf-8")

        self.sites_data = {
            "defaults": {
                "hosted_zone_id": "ZEXAMPLE",
                "region": "ap-northeast-1",
                "aws_profile": "profile with spaces",
                "record_ttl": 120,
                "log_retention_days": 14,
                "lambda_reserved_concurrency": 3,
                "asn_restriction_enabled": False,
                "asn_restriction_method": "static",
                "allowed_asns": "",
                "asn_prefixes_file": "",
            },
            "sites": {
                "tokyo-v4": {
                    "stack_name": "ixddns-tokyo",
                    "record_name": "tokyo.example.com",
                    "record_type": "A",
                    "ix_wan_if": "GigaEthernet0.1",
                    "ix_config_output": str(self.output_cfg),
                },
                "osaka-v4": {
                    "stack_name": "ixddns-osaka",
                    "record_name": "osaka.example.com",
                    "record_type": "A",
                    "ix_wan_if": "GigaEthernet0.1",
                    "asn_restriction_enabled": True,
                    "allowed_asns": [64496],
                    "asn_prefixes_file": str(self.asn_prefixes_file),
                },
            },
        }

        stub_python = self.directory / "aws_stub.py"
        log_path_repr = repr(str(self.log))
        stub_lines = (
            "import json, os, sys\n",
            "from pathlib import Path\n",
            "args = sys.argv[1:]\n",
            f"with Path({log_path_repr}).open('a', encoding='utf-8') as stream:\n",
            (
                "    stream.write(json.dumps({'args': args, "
                "'profile': os.environ.get('AWS_PROFILE')}) + '\\n')\n"
            ),
            "if 'describe-stacks' in args:\n",
            (
                "    token_arn = os.environ.get('FAKE_TOKEN_ARN', "
                "'arn:aws:secretsmanager:test:secret:example')\n"
            ),
            (
                "    stack_idx = "
                "args.index('--stack-name') + 1 if '--stack-name' in args else -1\n"
            ),
            "    st_name = args[stack_idx] if stack_idx > 0 else 'ixddns-tokyo'\n",
            (
                "    rec_name = "
                "'osaka.example.com' if 'osaka' in st_name else 'tokyo.example.com'\n"
            ),
            "    asn_en = 'true' if 'osaka' in st_name else 'false'\n",
            (
                "    outputs = [{'OutputKey': 'UpdateUrl', "
                "'OutputValue': 'https://example.lambda-url.ap-northeast-1.on.aws/update'}]\n"
            ),
            "    if token_arn != 'None':\n",
            (
                "        outputs.append({'OutputKey': 'TokenSecretArn', "
                "'OutputValue': token_arn})\n"
            ),
            "    params = [\n",
            "        {'ParameterKey': 'RecordType', 'ParameterValue': 'A'},\n",
            "        {'ParameterKey': 'RecordName', 'ParameterValue': rec_name},\n",
            "        {'ParameterKey': 'HostedZoneId', 'ParameterValue': 'ZEXAMPLE'},\n",
            (
                "        {'ParameterKey': 'AsnRestrictionEnabled', "
                "'ParameterValue': asn_en},\n"
            ),
            (
                "        {'ParameterKey': 'AsnRestrictionMethod', "
                "'ParameterValue': 'static'},\n"
            ),
            "        {'ParameterKey': 'AllowedAsns', 'ParameterValue': '64496'},\n",
            "    ]\n",
            (
                "    print(json.dumps({'Stacks': "
                "[{'Outputs': outputs, 'Parameters': params}]}))\n"
            ),
            "elif 'get-secret-value' in args:\n",
            (
                "    print(json.dumps({'SecretString': "
                "json.dumps({'token': 'FakeTestToken12345'})}))\n"
            ),
        )
        stub_python.write_text("".join(stub_lines), encoding="utf-8")
        if os.name == "nt":
            self.aws = self.directory / "aws-mock.cmd"
            self.aws.write_text(
                f'@echo off\n"{sys.executable}" "{stub_python}" %*\n',
                encoding="utf-8",
            )
        else:
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

    def write_sites(self, data: dict[str, object] | None = None) -> None:
        """sites.yaml を書き出す。"""
        content = yaml.dump(data or self.sites_data)
        self.sites_file.write_text(content, encoding="utf-8")

    def invoke(
        self,
        target: str,
        *overrides: str,
        extra_environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        """Makefile ターゲットを実行する。

        Returns:
            make コマンドの実行結果。

        """
        if not self.sites_file.exists():
            self.write_sites()
        environment = os.environ.copy()
        environment.pop("MAKEFLAGS", None)
        environment.pop("MFLAGS", None)
        environment["PYTHONUTF8"] = "1"
        environment["PYTHONIOENCODING"] = "utf-8"
        environment.update(extra_environment or {})
        flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            return subprocess.run(
                [
                    MAKE,
                    "--no-print-directory",
                    target,
                    f"ENV_FILE={self.env_file.as_posix()}",
                    f"SITES_FILE={self.sites_file.as_posix()}",
                    f"AWS={self.aws.as_posix()}",
                    *overrides,
                ],
                cwd=PROJECT,
                env=environment,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                creationflags=flags,
                check=False,
            )
        finally:
            _restore_console_mode()

    def calls(self) -> list[dict[str, object]]:
        """AWS CLI 呼び出しログを取得する。

        Returns:
            実行された AWS CLI 呼び出しの引数一覧。

        """
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def test_list_displays_all_sites(self) -> None:
        result = self.invoke("list")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("tokyo-v4", result.stdout)
        self.assertIn("osaka-v4", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_check_succeeds_with_valid_config(self) -> None:
        result = self.invoke("check")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("設定ファイルは正常です", result.stdout)
        self.assertEqual(self.calls(), [])

    def test_check_fails_with_invalid_config(self) -> None:
        self.sites_data["sites"]["tokyo-v4"]["record_name"] = "INVALID_NAME"
        self.write_sites()
        result = self.invoke("check")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("record_name", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_deploy_single_site_passes_correct_parameters(self) -> None:
        result = self.invoke("deploy", "SITE=tokyo-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        args = calls[0]["args"]
        self.assertEqual(args[args.index("--profile") + 1], "profile with spaces")
        self.assertEqual(args[args.index("--stack-name") + 1], "ixddns-tokyo")
        overrides = args[args.index("--parameter-overrides") + 1 :]
        self.assertIn("HostedZoneId=ZEXAMPLE", overrides)
        self.assertIn("RecordName=tokyo.example.com", overrides)
        self.assertIn("RecordType=A", overrides)
        self.assertIn("RecordTTL=120", overrides)
        self.assertIn("LogRetentionDays=14", overrides)
        self.assertIn("LambdaReservedConcurrency=3", overrides)
        self.assertIn("AsnRestrictionEnabled=false", overrides)
        self.assertIn("AllowedAsns=0", overrides)

    def test_deploy_blank_profile_omits_profile_flag(self) -> None:
        self.sites_data["defaults"]["aws_profile"] = ""
        self.write_sites()
        result = self.invoke("deploy", "SITE=tokyo-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        call = self.calls()[0]
        self.assertNotIn("--profile", call["args"])

    def test_deploy_with_asn_restriction(self) -> None:
        result = self.invoke("deploy", "SITE=osaka-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        args = calls[0]["args"]
        overrides = args[args.index("--parameter-overrides") + 1 :]
        self.assertIn("AsnRestrictionEnabled=true", overrides)
        self.assertIn("AllowedAsns=64496", overrides)

    def test_deploy_all_deploys_each_site(self) -> None:
        result = self.invoke("deploy")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        stack_names = [
            call["args"][call["args"].index("--stack-name") + 1] for call in calls
        ]
        self.assertEqual(sorted(stack_names), ["ixddns-osaka", "ixddns-tokyo"])

    def test_outputs_invokes_describe_stacks(self) -> None:
        result = self.invoke("outputs", "SITE=tokyo-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 1)
        self.assertIn("describe-stacks", calls[0]["args"])
        self.assertIn("UpdateUrl", result.stdout)

    def test_token_requires_site(self) -> None:
        result = self.invoke("token")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Specify SITE=<site_id>", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_token_retrieves_secret(self) -> None:
        result = self.invoke("token", "SITE=tokyo-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 2)
        self.assertIn("describe-stacks", calls[0]["args"])
        self.assertIn("get-secret-value", calls[1]["args"])
        self.assertEqual(result.stdout.strip(), "FakeTestToken12345")

    def test_token_fails_when_secret_arn_missing(self) -> None:
        result = self.invoke(
            "token", "SITE=tokyo-v4", extra_environment={"FAKE_TOKEN_ARN": "None"}
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TokenSecretArn", result.stderr)

    def test_ix_config_generates_config(self) -> None:
        result = self.invoke("ix-config", "SITE=tokyo-v4")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.output_cfg.exists())
        content = self.output_cfg.read_text(encoding="utf-8")
        self.assertIn("FakeTestToken12345", content)
        self.assertIn("GigaEthernet0.1", content)

    def test_init_creates_env_and_sites_file_when_missing(self) -> None:
        target_env = self.directory / "new.env"
        target_sites = self.directory / "new.sites.yaml"
        result = self.invoke(
            "init",
            f"ENV_FILE={target_env.as_posix()}",
            f"SITES_FILE={target_sites.as_posix()}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(target_env.exists())
        self.assertTrue(target_sites.exists())
        self.assertIn("Created", result.stdout)

    def test_init_preserves_existing_files(self) -> None:
        target_env = self.directory / "existing.env"
        target_sites = self.directory / "existing.sites.yaml"
        target_env.write_text("REGION=custom-region\n", encoding="utf-8")
        target_sites.write_text(
            "defaults:\n  hosted_zone_id: ZCUSTOM\n", encoding="utf-8"
        )
        result = self.invoke(
            "init",
            f"ENV_FILE={target_env.as_posix()}",
            f"SITES_FILE={target_sites.as_posix()}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            target_env.read_text(encoding="utf-8"), "REGION=custom-region\n"
        )
        self.assertEqual(
            target_sites.read_text(encoding="utf-8"),
            "defaults:\n  hosted_zone_id: ZCUSTOM\n",
        )
        self.assertIn("already exists", result.stdout)


if __name__ == "__main__":
    unittest.main()
