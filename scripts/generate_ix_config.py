"""Makefileから渡された設定とAWSのスタック出力でIX用コンフィグを生成する。"""

import json
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

PROJECT = Path(__file__).resolve().parents[1]
IX_MACROS = {"<IP4>", "<IP6>", "<PW>", "<SN>"}


class ConfigError(Exception):
    """設定不足や取得データの不整合を、秘密情報を含めずに通知する。"""


@dataclass
class Settings:
    """AWS CLIとIXコンフィグ生成に必要な検証済み設定。"""

    aws: str
    profile: str
    region: str
    stack_name: str
    record_type: str
    interfaces: dict[str, str]
    output: Path

    @classmethod
    def from_environment(cls) -> Settings:
        """環境変数を検証し、生成に必要な設定を組み立てる。

        Returns:
            検証済みのコンフィグ生成設定。

        Raises:
            ConfigError: 設定・AWSの応答・コンフィグの形式が不正な場合。

        """
        if os.environ.get("ASN_RESTRICTION_METHOD", "static") not in {"static", "waf"}:
            message = "ASN_RESTRICTION_METHODにはstaticまたはwafを設定してください。"
            raise ConfigError(message)
        if os.environ.get("ASN_RESTRICTION_ENABLED", "false") not in {"true", "false"}:
            message = "ASN_RESTRICTION_ENABLEDにはtrueまたはfalseを設定してください。"
            raise ConfigError(message)
        record_type = os.environ.get("RECORD_TYPE", "A")
        if record_type not in {"A", "AAAA"}:
            message = "RECORD_TYPEにはAまたはAAAAを設定してください。"
            raise ConfigError(message)
        names = (
            {"<WAN_IF>": "IX_WAN_IF"}
            if record_type == "A"
            else {"<SOURCE_IF>": "IX_SOURCE_IF", "<NOTIFY_IF>": "IX_NOTIFY_IF"}
        )
        interfaces = {}
        for placeholder, name in names.items():
            value = os.environ.get(name, "")
            if not value:
                message = f".envの{name}に実機のインタフェース名を設定してください。"
                raise ConfigError(message)
            if not re.fullmatch(r"[A-Za-z][A-Za-z0-9./:_-]*", value):
                message = f"{name}に空白や制御文字を含めることはできません。"
                raise ConfigError(message)
            interfaces[placeholder] = value
        region = os.environ.get("REGION", "ap-northeast-1")
        stack_name = os.environ.get("STACK_NAME", "ixddns-ipv4")
        if not region or not stack_name:
            message = "REGIONとSTACK_NAMEを設定してください。"
            raise ConfigError(message)
        family = "ipv4" if record_type == "A" else "ipv6"
        output = os.environ.get("IX_CONFIG_OUTPUT", "")
        return cls(
            aws=os.environ.get("AWS", "aws"),
            profile=os.environ.get("AWS_PROFILE", ""),
            region=region,
            stack_name=stack_name,
            record_type=record_type,
            interfaces=interfaces,
            output=Path(output)
            if output
            else PROJECT / "examples" / f"ix3315-ddns-{family}.cfg",
        )


def aws_json(settings: Settings, *arguments: str) -> dict[str, object]:
    """指定された認証・リージョンでAWS CLIを実行し、JSONを読み込む。

    Returns:
        AWS CLIのJSON応答。

    Raises:
        ConfigError: 設定・AWSの応答・コンフィグの形式が不正な場合。

    """
    command = [settings.aws]
    environment = os.environ.copy()
    if settings.profile:
        command.extend(["--profile", settings.profile])
    else:
        environment.pop("AWS_PROFILE", None)
    command.extend([
        "--region",
        settings.region,
        "--no-cli-pager",
        *arguments,
        "--output",
        "json",
    ])
    try:
        result = subprocess.run(
            command,
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        message = "AWS CLIを実行できません。インストールと接続を確認してください。"
        raise ConfigError(message) from error
    if result.returncode:
        # CLIの出力にはシークレットが含まれ得るため、そのまま表示しません。
        message = (
            f"AWSの{arguments[0]} {arguments[1]}に失敗しました。"
            "プロファイル・リージョン・スタック名・読み取り権限を確認してください。"
        )
        raise ConfigError(message)
    try:
        return json.loads(result.stdout)
    except (ValueError, UnicodeError) as error:
        message = "AWS CLIから有効なJSONを取得できませんでした。"
        raise ConfigError(message) from error


def validate_stack_settings(settings: Settings, parameters: dict[str, str]) -> None:
    """デプロイ済みスタックとローカルのDNS・ASN設定の一致を確認する。

    Raises:
        ConfigError: 設定・AWSの応答・コンフィグの形式が不正な場合。

    """
    expected = {
        "RecordType": settings.record_type,
        "RecordName": os.environ.get("RECORD_NAME", ""),
        "HostedZoneId": os.environ.get("HOSTED_ZONE_ID", ""),
        "AsnRestrictionEnabled": os.environ.get("ASN_RESTRICTION_ENABLED", "false"),
    }
    # ASN対応前にデプロイしたスタックは、制限なしとして扱います。
    parameters.setdefault("AsnRestrictionEnabled", "false")
    for name, value in expected.items():
        if value and parameters.get(name) != value:
            message = (
                f".envとスタックの{name}が一致しません。"
                "設定を確認し、必要ならmake deployを実行してください。"
            )
            raise ConfigError(message)
    if expected["AsnRestrictionEnabled"] == "true":
        # 方式パラメータ追加前のASN対応スタックはWAF方式です。
        if parameters.get("AsnRestrictionMethod", "waf") != os.environ.get(
            "ASN_RESTRICTION_METHOD", "static"
        ):
            message = (
                ".envとスタックのAsnRestrictionMethodが一致しません。"
                "先にmake deployを実行してください。"
            )
            raise ConfigError(message)
        configured = [
            value.strip() for value in os.environ.get("ALLOWED_ASNS", "").split(",")
        ]
        deployed = [
            value.strip() for value in parameters.get("AllowedAsns", "").split(",")
        ]
        if set(configured) != set(deployed) or not all(configured):
            message = (
                ".envとスタックのAllowedAsnsが一致しません。"
                "先にmake deployを実行してください。"
            )
            raise ConfigError(message)


def fetch_replacements(settings: Settings) -> dict[str, str]:
    """スタック設定の一致を確認し、URL・トークン・インタフェースを取得する。

    Returns:
        置換するURL・共有トークン・インタフェースの対応表。

    Raises:
        ConfigError: 設定・AWSの応答・コンフィグの形式が不正な場合。

    """
    response = aws_json(
        settings,
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        settings.stack_name,
    )
    try:
        stack = response["Stacks"][0]
        parameters = {
            item["ParameterKey"]: item["ParameterValue"] for item in stack["Parameters"]
        }
        outputs = {item["OutputKey"]: item["OutputValue"] for item in stack["Outputs"]}
        url = outputs["UpdateUrl"]
        secret_arn = outputs["TokenSecretArn"]
    except (KeyError, IndexError, TypeError) as error:
        message = "スタックからUpdateUrl・TokenSecretArn・パラメータを取得できません。"
        raise ConfigError(message) from error
    validate_stack_settings(settings, parameters)
    if not isinstance(url, str) or not re.fullmatch(r"https://[A-Za-z0-9.:/-]+", url):
        message = "UpdateUrlはHTTPSの更新用URLである必要があります。"
        raise ConfigError(message)
    parsed_url = urlsplit(url)
    if not parsed_url.hostname or not parsed_url.path.endswith("/update"):
        message = "UpdateUrlから更新用のホスト名とパスを確認できません。"
        raise ConfigError(message)
    if not isinstance(secret_arn, str) or not secret_arn:
        message = "TokenSecretArnが空です。スタック出力を確認してください。"
        raise ConfigError(message)
    response = aws_json(
        settings, "secretsmanager", "get-secret-value", "--secret-id", secret_arn
    )
    try:
        token = json.loads(response["SecretString"])["token"]
    except (KeyError, TypeError, ValueError) as error:
        message = "Secrets ManagerのSecretStringからtokenを取得できません。"
        raise ConfigError(message) from error
    if not isinstance(token, str) or not re.fullmatch(r"[A-Za-z0-9]+", token):
        message = "共有トークンは半角英数字で設定してください。"
        raise ConfigError(message)
    return {"<UPDATE_URL>": url, "<SHARED_TOKEN>": token, **settings.interfaces}


def render_config(template: str, replacements: dict[str, str]) -> str:
    """IXのマクロを保持したままサンプルのプレースホルダーを置換する。

    Returns:
        共有トークンを含む投入用コンフィグ。

    Raises:
        ConfigError: 設定・AWSの応答・コンフィグの形式が不正な場合。

    """
    lines = ["! make ix-configで生成した投入用コンフィグです。共有トークンを含みます。"]
    used = set()
    for template_line in template.splitlines():
        line = template_line
        if line.lstrip().startswith("!"):
            # 手動置換の説明を除き、秘密情報をコメントに重複して書き込みません。
            if any(placeholder in line for placeholder in replacements):
                continue
        else:
            for placeholder, value in replacements.items():
                if placeholder in line:
                    used.add(placeholder)
                    line = line.replace(placeholder, value)
            unresolved = set(re.findall(r"<[^<>]+>", line)) - IX_MACROS
            if unresolved:
                message = "サンプルに未対応のプレースホルダーが残っています。"
                raise ConfigError(message)
        lines.append(line)
    if used != set(replacements):
        message = "サンプルに必要なプレースホルダーがありません。"
        raise ConfigError(message)
    return "\n".join(lines) + "\n"


def write_config(output: Path, content: str) -> None:
    """共有トークンを含む設定を一時ファイル経由で安全に保存する。"""
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = None
    try:
        # 全内容を書き終えてから置換し、失敗時は既存ファイルを保持します。
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=output.parent, delete=False
        ) as stream:
            temporary_path = Path(stream.name)
            stream.write(content)
        if os.name != "nt":
            temporary_path.chmod(0o600)
        temporary_path.replace(output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def config_template(record_type: str) -> Path:
    """レコード種別に対応するIXサンプルのファイル名を返す。

    Returns:
        レコード種別に対応するサンプルのパス。

    """
    family = "ipv4" if record_type == "A" else "ipv6"
    return PROJECT / "examples" / f"ix3315-ddns-{family}.cfg.example"


def main() -> int:
    """設定とAWS出力からIX用コンフィグを生成し、結果を終了コードで返す。

    Returns:
        成功時は0、失敗時は1。

    """
    try:
        settings = Settings.from_environment()
        template = config_template(settings.record_type)
        replacements = fetch_replacements(settings)
        content = render_config(template.read_text(encoding="utf-8"), replacements)
        write_config(settings.output, content)
    except (ConfigError, OSError, UnicodeError) as error:
        # ファイル操作エラーにも生成したコンフィグの内容は含めません。
        print(f"生成失敗: {error}", file=sys.stderr)
        return 1
    print(f"IX用コンフィグを生成しました: {settings.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
