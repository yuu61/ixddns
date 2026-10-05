"""複数サイト・レコードのDDNS設定をYAML/JSONから読み込み、検証・操作する。"""

import argparse
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import yaml

from scripts.asn_prefixes import fetch_snapshot, read_snapshot
from scripts.build_template import build_template, write_atomic
from scripts.check_asn_config import check_asn_config
from scripts.generate_ix_config import (
    ConfigError,
    Settings,
    aws_json,
    generate_config,
)

PROJECT = Path(__file__).resolve().parents[1]
DEFAULT_SITES_FILE = PROJECT / "sites.yaml"
VALID_RECORD_TYPES = {"A", "AAAA"}
VALID_LOG_RETENTION_DAYS = {1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365}
VALID_ASN_METHODS = {"static", "waf"}
RECORD_NAME_PATTERN = (
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)
IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9_-]*$"
STACK_NAME_PATTERN = r"^[A-Za-z][A-Za-z0-9-]{0,127}$"
INTERFACE_PATTERN = r"^[A-Za-z][A-Za-z0-9./:_-]*$"
ZONE_ID_PATTERN = r"^Z[A-Z0-9]+$"
MAX_ZONE_ID_LENGTH = 32
MAX_RECORD_NAME_LENGTH = 253
MIN_TTL = 30
MAX_TTL = 86400
MIN_CONCURRENCY = 1
MAX_CONCURRENCY = 1000


class SitesConfigError(Exception):
    """サイト設定の構文エラーや検証エラーを通知する。"""


@dataclass(frozen=True)
class SiteConfig:
    """単一サイト・レコードの検証済み設定。"""

    site_id: str
    stack_name: str
    record_name: str
    record_type: str
    ix_wan_if: str
    ix_source_if: str
    ix_notify_if: str
    ix_config_output: Path
    hosted_zone_id: str
    region: str
    aws_profile: str
    record_ttl: int
    log_retention_days: int
    lambda_reserved_concurrency: int
    asn_restriction_enabled: bool
    asn_restriction_method: str
    allowed_asns: str
    asn_prefixes_file: str

    def to_env(self) -> dict[str, str]:
        """設定を環境変数辞書に変換する。

        Returns:
            環境変数名の文字列辞書。

        """
        return {
            "AWS_PROFILE": self.aws_profile,
            "REGION": self.region,
            "STACK_NAME": self.stack_name,
            "HOSTED_ZONE_ID": self.hosted_zone_id,
            "RECORD_NAME": self.record_name,
            "RECORD_TYPE": self.record_type,
            "RECORD_TTL": str(self.record_ttl),
            "LOG_RETENTION_DAYS": str(self.log_retention_days),
            "LAMBDA_RESERVED_CONCURRENCY": str(self.lambda_reserved_concurrency),
            "ASN_RESTRICTION_ENABLED": "true"
            if self.asn_restriction_enabled
            else "false",
            "ASN_RESTRICTION_METHOD": self.asn_restriction_method,
            "ALLOWED_ASNS": self.allowed_asns,
            "ASN_PREFIXES_FILE": self.asn_prefixes_file,
            "IX_WAN_IF": self.ix_wan_if,
            "IX_SOURCE_IF": self.ix_source_if,
            "IX_NOTIFY_IF": self.ix_notify_if,
            "IX_CONFIG_OUTPUT": str(self.ix_config_output),
        }

    def to_settings(self, aws: str = "aws") -> Settings:
        """IXコンフィグ生成用のSettingsオブジェクトを作成する。

        Returns:
            検証済みのSettingsオブジェクト。

        """
        interfaces = (
            {"<WAN_IF>": self.ix_wan_if}
            if self.record_type == "A"
            else {
                "<SOURCE_IF>": self.ix_source_if,
                "<NOTIFY_IF>": self.ix_notify_if,
            }
        )
        return Settings(
            aws=aws,
            profile=self.aws_profile,
            region=self.region,
            stack_name=self.stack_name,
            record_type=self.record_type,
            interfaces=interfaces,
            output=self.ix_config_output,
        )


def _to_bool(value: object, field_name: str, site_id: str) -> bool:
    """値を真偽値に変換する。

    Returns:
        変換後の真偽値。

    Raises:
        SitesConfigError: 真偽値として解釈できない場合。

    """
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered == "true":
            return True
        if lowered == "false":
            return False
    message = (
        f"[{site_id}] {field_name}にはtrueまたはfalseを指定してください: {value!r}"
    )
    raise SitesConfigError(message)


def _to_int(value: object, field_name: str, site_id: str) -> int:
    """値を整数に変換する。

    Returns:
        変換後の整数。

    Raises:
        SitesConfigError: 整数として解釈できない場合。

    """
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    message = f"[{site_id}] {field_name}には整数を指定してください: {value!r}"
    raise SitesConfigError(message)


def _validate_dns(site_id: str, merged: dict[str, object]) -> tuple[str, str, str, int]:
    """DNS設定 (hosted_zone_id, record_name, record_type, ttl) を検証する。

    Returns:
        検証済みの (hosted_zone_id, record_name, record_type, record_ttl)。

    Raises:
        SitesConfigError: 設定が無効な場合。

    """
    hosted_zone_id = str(merged.get("hosted_zone_id", "")).strip()
    if not hosted_zone_id:
        message = f"[{site_id}] hosted_zone_id (またはdefaults) を指定してください。"
        raise SitesConfigError(message)
    if (
        not re.fullmatch(ZONE_ID_PATTERN, hosted_zone_id)
        or len(hosted_zone_id) > MAX_ZONE_ID_LENGTH
    ):
        message = f"[{site_id}] hosted_zone_idが無効です: {hosted_zone_id}"
        raise SitesConfigError(message)

    record_name = str(merged.get("record_name", "")).strip()
    if not record_name:
        message = f"[{site_id}] record_nameを指定してください。"
        raise SitesConfigError(message)
    if (
        not re.fullmatch(RECORD_NAME_PATTERN, record_name)
        or len(record_name) > MAX_RECORD_NAME_LENGTH
    ):
        message = (
            f"[{site_id}] record_nameが無効です"
            f" (小文字FQDN、末尾ドットなし、最大253文字): {record_name}"
        )
        raise SitesConfigError(message)

    record_type = str(merged.get("record_type", "A")).strip().upper()
    if record_type not in VALID_RECORD_TYPES:
        message = (
            f"[{site_id}] record_typeにはAまたはAAAAを指定してください: {record_type}"
        )
        raise SitesConfigError(message)

    record_ttl = _to_int(merged.get("record_ttl", 60), "record_ttl", site_id)
    if not MIN_TTL <= record_ttl <= MAX_TTL:
        message = (
            f"[{site_id}] record_ttlは{MIN_TTL}〜{MAX_TTL}の間で指定してください: "
            f"{record_ttl}"
        )
        raise SitesConfigError(message)

    return hosted_zone_id, record_name, record_type, record_ttl


def _validate_interfaces(
    site_id: str, record_type: str, merged: dict[str, object]
) -> tuple[str, str, str]:
    """インタフェース設定を検証する。

    Returns:
        検証済みの (ix_wan_if, ix_source_if, ix_notify_if)。

    Raises:
        SitesConfigError: インタフェース設定が無効な場合。

    """
    ix_wan_if = str(merged.get("ix_wan_if", "")).strip()
    ix_source_if = str(merged.get("ix_source_if", "")).strip()
    ix_notify_if = str(merged.get("ix_notify_if", "")).strip()

    if record_type == "A":
        if not ix_wan_if:
            message = f"[{site_id}] record_type=A の場合は ix_wan_if が必要です。"
            raise SitesConfigError(message)
        if not re.fullmatch(INTERFACE_PATTERN, ix_wan_if):
            message = (
                f"[{site_id}] ix_wan_ifに空白や制御文字を含めることはできません: "
                f"{ix_wan_if}"
            )
            raise SitesConfigError(message)
    else:
        if not ix_source_if or not ix_notify_if:
            message = (
                f"[{site_id}] record_type=AAAA の場合は "
                "ix_source_if と ix_notify_if の両方が必要です。"
            )
            raise SitesConfigError(message)
        if not re.fullmatch(INTERFACE_PATTERN, ix_source_if):
            message = (
                f"[{site_id}] ix_source_ifに空白や制御文字を含めることはできません: "
                f"{ix_source_if}"
            )
            raise SitesConfigError(message)
        if not re.fullmatch(INTERFACE_PATTERN, ix_notify_if):
            message = (
                f"[{site_id}] ix_notify_ifに空白や制御文字を含めることはできません: "
                f"{ix_notify_if}"
            )
            raise SitesConfigError(message)

    return ix_wan_if, ix_source_if, ix_notify_if


def _validate_asn(
    site_id: str, merged: dict[str, object]
) -> tuple[bool, str, str, str]:
    """ASN制限設定を検証する。

    Returns:
        検証済みの (asn_enabled, asn_method, allowed_asns, asn_prefixes_file)。

    Raises:
        SitesConfigError: ASN制限設定が無効な場合。

    """
    asn_enabled = _to_bool(
        merged.get("asn_restriction_enabled", False),
        "asn_restriction_enabled",
        site_id,
    )
    asn_method = str(merged.get("asn_restriction_method", "static")).strip()
    if asn_method not in VALID_ASN_METHODS:
        message = (
            f"[{site_id}] asn_restriction_methodには"
            f"staticまたはwafを指定してください: {asn_method}"
        )
        raise SitesConfigError(message)

    allowed_asns = str(merged.get("allowed_asns", "")).strip()
    if asn_enabled:
        try:
            check_asn_config("true", allowed_asns, asn_method)
        except ValueError as error:
            message = f"[{site_id}] ASN制限の設定が不正です: {error}"
            raise SitesConfigError(message) from error

    asn_prefixes_file = str(merged.get("asn_prefixes_file", "")).strip()
    return asn_enabled, asn_method, allowed_asns, asn_prefixes_file


def _validate_runtime(
    site_id: str, merged: dict[str, object]
) -> tuple[str, str, int, int]:
    """ランタイム設定 (region, profile, retention, concurrency) を検証する。

    Returns:
        検証済みの (region, aws_profile, log_retention_days, concurrency)。

    Raises:
        SitesConfigError: 設定が無効な場合。

    """
    region = str(merged.get("region", "ap-northeast-1")).strip()
    if not region:
        message = f"[{site_id}] regionを指定してください。"
        raise SitesConfigError(message)
    aws_profile = str(merged.get("aws_profile", "")).strip()

    log_retention_days = _to_int(
        merged.get("log_retention_days", 30), "log_retention_days", site_id
    )
    if log_retention_days not in VALID_LOG_RETENTION_DAYS:
        valid_days = sorted(VALID_LOG_RETENTION_DAYS)
        message = (
            f"[{site_id}] log_retention_daysは"
            f"{valid_days}のいずれかを指定してください: {log_retention_days}"
        )
        raise SitesConfigError(message)

    concurrency = _to_int(
        merged.get("lambda_reserved_concurrency", 1),
        "lambda_reserved_concurrency",
        site_id,
    )
    if not MIN_CONCURRENCY <= concurrency <= MAX_CONCURRENCY:
        message = (
            f"[{site_id}] lambda_reserved_concurrencyは"
            f"{MIN_CONCURRENCY}〜{MAX_CONCURRENCY}の間で指定してください: {concurrency}"
        )
        raise SitesConfigError(message)

    return region, aws_profile, log_retention_days, concurrency


def _resolve_stack_name(site_id: str, merged: dict[str, object]) -> str:
    """スタック名を検証・決定する。

    Returns:
        検証済みのスタック名。

    Raises:
        SitesConfigError: スタック名が無効な場合。

    """
    default_stack = f"ixddns-{re.sub(r'[^A-Za-z0-9-]', '-', site_id)}"
    stack_name = str(merged.get("stack_name", "") or default_stack)
    if not re.fullmatch(STACK_NAME_PATTERN, stack_name):
        message = (
            f"[{site_id}] stack_nameが無効です"
            f" (英字始まり、英数字とハイフンのみ、最大128文字): {stack_name}"
        )
        raise SitesConfigError(message)
    return stack_name


def _resolve_output_path(site_id: str, merged: dict[str, object]) -> Path:
    """コンフィグ出力先パスを決定する。

    Returns:
        設定出力先のPathオブジェクト。

    """
    config_output_str = str(merged.get("ix_config_output", "")).strip()
    if config_output_str:
        output_path = Path(config_output_str)
        return output_path if output_path.is_absolute() else PROJECT / output_path
    return PROJECT / "examples" / f"nec-ix-ddns-{site_id}.cfg"


def _validate_site(
    site_id: str,
    data: dict[str, object],
    defaults: dict[str, object],
) -> SiteConfig:
    """単一サイトの設定を検証してSiteConfigを生成する。

    Returns:
        検証済みのSiteConfigインスタンス。

    Raises:
        SitesConfigError: 設定が無効な場合。

    """
    if not isinstance(data, dict):
        message = f"[{site_id}] サイト設定は辞書型である必要があります。"
        raise SitesConfigError(message)
    if not re.fullmatch(IDENTIFIER_PATTERN, site_id):
        message = (
            "サイト識別子には英数字、ハイフン、"
            f"アンダースコアのみ使用できます: {site_id}"
        )
        raise SitesConfigError(message)

    merged = {**defaults, **data}
    stack_name = _resolve_stack_name(site_id, merged)
    dns = _validate_dns(site_id, merged)
    interfaces = _validate_interfaces(site_id, dns[2], merged)
    asn = _validate_asn(site_id, merged)
    runtime = _validate_runtime(site_id, merged)
    ix_config_output = _resolve_output_path(site_id, merged)

    return SiteConfig(
        site_id=site_id,
        stack_name=stack_name,
        record_name=dns[1],
        record_type=dns[2],
        ix_wan_if=interfaces[0],
        ix_source_if=interfaces[1],
        ix_notify_if=interfaces[2],
        ix_config_output=ix_config_output,
        hosted_zone_id=dns[0],
        region=runtime[0],
        aws_profile=runtime[1],
        record_ttl=dns[3],
        log_retention_days=runtime[2],
        lambda_reserved_concurrency=runtime[3],
        asn_restriction_enabled=asn[0],
        asn_restriction_method=asn[1],
        allowed_asns=asn[2],
        asn_prefixes_file=asn[3],
    )


def load_sites_file(path: Path) -> dict[str, SiteConfig]:
    """YAMLまたはJSON設定ファイルを読み込み、検証済みのSiteConfig辞書を返す。

    Returns:
        サイトIDをキーとするSiteConfig辞書。

    Raises:
        SitesConfigError: ファイル不存在、構文不正、または検証不備の場合。

    """
    if not path.is_file():
        message = f"設定ファイルが見つかりません: {path}"
        raise SitesConfigError(message)
    try:
        content = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(content)
    except (yaml.YAMLError, UnicodeError) as error:
        message = f"設定ファイルの解析に失敗しました: {error}"
        raise SitesConfigError(message) from error

    if not isinstance(raw, dict):
        message = "設定ファイルの最上位は辞書 (オブジェクト) である必要があります。"
        raise SitesConfigError(message)

    defaults = raw.get("defaults") or {}
    if not isinstance(defaults, dict):
        message = "defaultsセクションは辞書型である必要があります。"
        raise SitesConfigError(message)

    raw_sites = raw.get("sites")
    if not raw_sites or not isinstance(raw_sites, dict):
        message = "sitesセクションに1つ以上のサイトを定義してください。"
        raise SitesConfigError(message)

    sites: dict[str, SiteConfig] = {}
    stack_names: dict[str, str] = {}
    dns_targets: dict[tuple[str, str, str], str] = {}
    output_files: dict[Path, str] = {}

    for raw_id, site_data in raw_sites.items():
        site_id = str(raw_id)
        site_dict = site_data if isinstance(site_data, dict) else {}
        site = _validate_site(site_id, site_dict, defaults)

        if site.stack_name in stack_names:
            prev = stack_names[site.stack_name]
            message = (
                f"スタック名 '{site.stack_name}' がサイト '{prev}' と "
                f"'{site.site_id}' で重複しています。"
            )
            raise SitesConfigError(message)
        stack_names[site.stack_name] = site.site_id

        dns_target = (site.hosted_zone_id, site.record_name, site.record_type)
        if dns_target in dns_targets:
            prev = dns_targets[dns_target]
            message = (
                f"更新対象レコード {dns_target} が "
                f"サイト '{prev}' と '{site.site_id}' で重複しています。"
            )
            raise SitesConfigError(message)
        dns_targets[dns_target] = site.site_id

        if site.ix_config_output in output_files:
            prev = output_files[site.ix_config_output]
            message = (
                f"コンフィグ出力先 '{site.ix_config_output}' が "
                f"サイト '{prev}' と '{site.site_id}' で重複しています。"
            )
            raise SitesConfigError(message)
        output_files[site.ix_config_output] = site.site_id

        sites[site.site_id] = site

    return sites


def cmd_list(sites: dict[str, SiteConfig]) -> int:
    """定義されているサイト一覧を表示する。

    Returns:
        終了コード0。

    """
    col_site = 16
    col_stack = 20
    col_record = 28
    col_type = 6
    col_ttl = 6
    col_if = 24
    header = (
        f"{'SITE':<{col_site}} {'STACK_NAME':<{col_stack}} "
        f"{'RECORD_NAME':<{col_record}} {'TYPE':<{col_type}} "
        f"{'TTL':<{col_ttl}} {'INTERFACE':<{col_if}} {'REGION'}"
    )
    print(header)
    print("-" * len(header))
    for site in sites.values():
        interface = (
            site.ix_wan_if
            if site.record_type == "A"
            else f"src:{site.ix_source_if} notify:{site.ix_notify_if}"
        )
        print(
            f"{site.site_id:<{col_site}} {site.stack_name:<{col_stack}} "
            f"{site.record_name:<{col_record}} {site.record_type:<{col_type}} "
            f"{site.record_ttl:<{col_ttl}} {interface:<{col_if}} {site.region}"
        )
    return 0


def cmd_check(sites: dict[str, SiteConfig], site_filter: str | None = None) -> int:
    """設定ファイルの検証結果を表示する。

    Returns:
        終了コード0。

    """
    target_sites = [sites[site_filter]] if site_filter else list(sites.values())
    print(f"設定ファイルは正常です ({len(target_sites)}件のサイト定義)。")
    return 0


def cmd_env(
    sites: dict[str, SiteConfig], site_id: str, *, export_format: bool = False
) -> int:
    """指定サイトの環境変数を表示する。

    Returns:
        終了コード0。

    """
    site = sites[site_id]
    env_vars = site.to_env()
    for key, value in env_vars.items():
        if export_format:
            print(f"export {key}={value!r}")
        else:
            print(f"{key}={value}")
    return 0


def cmd_ix_config(
    sites: dict[str, SiteConfig],
    site_filter: str | None = None,
    aws_cmd: str = "aws",
) -> int:
    """指定サイトまたは全サイトのIXコンフィグを生成する。

    Returns:
        成功時は0、失敗時は1。

    """
    targets = [sites[site_filter]] if site_filter else list(sites.values())
    errors = 0
    for site in targets:
        print(f"[{site.site_id}] IX用コンフィグを生成中...")
        settings = site.to_settings(aws=aws_cmd)
        orig_env = os.environ.copy()
        os.environ.update(site.to_env())
        try:
            output = generate_config(settings)
            print(f"[{site.site_id}] 生成成功: {output}")
        except (ConfigError, OSError, UnicodeError) as error:
            print(f"[{site.site_id}] 生成失敗: {error}", file=sys.stderr)
            errors += 1
        finally:
            os.environ.clear()
            os.environ.update(orig_env)
    return 1 if errors else 0


def _build_template_for_site(site: SiteConfig) -> Path:
    """サイト固有のテンプレートをビルドして保存する。

    Returns:
        生成されたテンプレートJSONファイルのパス。

    """
    build_dir = PROJECT / ".build"
    build_dir.mkdir(exist_ok=True)
    template_path = build_dir / f"template-{site.site_id}.json"

    snapshot = None
    if site.asn_restriction_enabled and site.asn_restriction_method == "static":
        configured_asns = check_asn_config(
            "true", site.allowed_asns, site.asn_restriction_method
        )
        if site.asn_prefixes_file:
            snapshot = read_snapshot(Path(site.asn_prefixes_file), configured_asns)
        else:
            snapshot = fetch_snapshot(configured_asns)

    template_data = build_template(snapshot)
    write_atomic(template_path, json.dumps(template_data, indent=2))
    return template_path


def _deploy_single_site(site: SiteConfig, aws_cmd: str) -> bool:
    """単一サイトのデプロイを実行する。

    Returns:
        成功時はTrue。

    """
    print(f"[{site.site_id}] テンプレートをビルド中...")
    try:
        template_path = _build_template_for_site(site)
    except (ValueError, OSError) as error:
        print(f"[{site.site_id}] テンプレートビルド失敗: {error}", file=sys.stderr)
        return False

    print(f"[{site.site_id}] CloudFormationスタックをデプロイ中...")
    asn_flag = "true" if site.asn_restriction_enabled else "false"
    asns_value = site.allowed_asns if site.asn_restriction_enabled else "0"
    command = [
        aws_cmd,
        "--region",
        site.region,
        "--no-cli-pager",
        "cloudformation",
        "deploy",
        "--stack-name",
        site.stack_name,
        "--template-file",
        str(template_path),
        "--capabilities",
        "CAPABILITY_IAM",
        "--no-fail-on-empty-changeset",
        "--parameter-overrides",
        f"HostedZoneId={site.hosted_zone_id}",
        f"RecordName={site.record_name}",
        f"RecordType={site.record_type}",
        f"RecordTTL={site.record_ttl}",
        f"LogRetentionDays={site.log_retention_days}",
        f"LambdaReservedConcurrency={site.lambda_reserved_concurrency}",
        f"AsnRestrictionEnabled={asn_flag}",
        f"AsnRestrictionMethod={site.asn_restriction_method}",
        f"AllowedAsns={asns_value}",
    ]
    if site.aws_profile:
        command[1:1] = ["--profile", site.aws_profile]

    env = os.environ.copy()
    if not site.aws_profile:
        env.pop("AWS_PROFILE", None)

    result = subprocess.run(command, env=env, check=False)
    if result.returncode != 0:
        print(f"[{site.site_id}] デプロイ失敗", file=sys.stderr)
        return False
    print(f"[{site.site_id}] デプロイ成功")
    return True


def cmd_deploy(
    sites: dict[str, SiteConfig],
    site_filter: str | None = None,
    aws_cmd: str = "aws",
) -> int:
    """指定サイトまたは全サイトを順次デプロイする。

    Returns:
        全サイト成功時は0、失敗があれば1。

    """
    targets = [sites[site_filter]] if site_filter else list(sites.values())
    errors = 0
    for site in targets:
        success = _deploy_single_site(site, aws_cmd)
        if not success:
            errors += 1
    return 1 if errors else 0


def cmd_outputs(
    sites: dict[str, SiteConfig],
    site_filter: str | None = None,
    aws_cmd: str = "aws",
) -> int:
    """指定サイトまたは全サイトのスタック出力を表示する。

    Returns:
        成功時は0、失敗時は1。

    """
    targets = [sites[site_filter]] if site_filter else list(sites.values())
    errors = 0
    for site in targets:
        print(f"=== [{site.site_id}] ({site.stack_name}) ===")
        settings = site.to_settings(aws=aws_cmd)
        try:
            response = aws_json(
                settings,
                "cloudformation",
                "describe-stacks",
                "--stack-name",
                site.stack_name,
            )
            outputs = response.get("Stacks", [{}])[0].get("Outputs", [])
            for item in outputs:
                print(f"  {item.get('OutputKey')}: {item.get('OutputValue')}")
        except ConfigError as error:
            print(f"[{site.site_id}] 出力取得失敗: {error}", file=sys.stderr)
            errors += 1
    return 1 if errors else 0


def _fetch_site_token(settings: Settings, stack_name: str) -> str:
    """スタック出力からシークレットARNを取得し、共有トークンを読み出す。

    Returns:
        共有トークン文字列。

    Raises:
        ConfigError: ARNまたはトークンが見つからない場合。

    """
    response = aws_json(
        settings,
        "cloudformation",
        "describe-stacks",
        "--stack-name",
        stack_name,
    )
    outputs = response.get("Stacks", [{}])[0].get("Outputs", [])
    secret_arn = None
    for item in outputs:
        if item.get("OutputKey") == "TokenSecretArn":
            secret_arn = item.get("OutputValue")
            break
    if not secret_arn:
        message = "TokenSecretArnがスタック出力に見つかりません。"
        raise ConfigError(message)

    secret_response = aws_json(
        settings,
        "secretsmanager",
        "get-secret-value",
        "--secret-id",
        secret_arn,
    )
    secret_data = json.loads(secret_response.get("SecretString", "{}"))
    token = secret_data.get("token")
    if not token or not isinstance(token, str):
        message = "SecretStringに有効なtokenが含まれていません。"
        raise ConfigError(message)
    return token


def cmd_token(sites: dict[str, SiteConfig], site_id: str, aws_cmd: str = "aws") -> int:
    """指定サイトの共有トークンを表示する。

    Returns:
        成功時は0、失敗時は1。

    """
    site = sites[site_id]
    settings = site.to_settings(aws=aws_cmd)
    try:
        token = _fetch_site_token(settings, site.stack_name)
        print(token)
    except ConfigError as error:
        print(f"[{site_id}] トークン取得失敗: {error}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    """コマンドライン引数パーサーを構築する。

    Returns:
        引数パーサー。

    """
    parser = argparse.ArgumentParser(
        description="複数サイト・レコードのDDNS設定を操作するユーティリティ。"
    )
    parser.add_argument(
        "--file",
        dest="sites_file",
        default=str(DEFAULT_SITES_FILE),
        help=f"設定ファイルのパス (既定値: {DEFAULT_SITES_FILE})",
    )
    parser.add_argument(
        "--aws",
        dest="aws_cmd",
        default=os.environ.get("AWS", "aws"),
        help="AWS CLI実行コマンド (既定値: aws)",
    )

    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    subparsers.add_parser("list", help="定義されているサイト一覧を表示")

    check_p = subparsers.add_parser("check", help="設定ファイルを検証")
    check_p.add_argument("--site", help="対象サイトID (省略時は全サイト)")

    env_p = subparsers.add_parser("env", help="指定サイトの環境変数を表示")
    env_p.add_argument("site_id", help="対象サイトID")
    env_p.add_argument(
        "--export", action="store_true", help="export KEY='VALUE' 形式で出力"
    )

    cfg_p = subparsers.add_parser("ix-config", help="IX用コンフィグを生成")
    cfg_p.add_argument("--site", help="対象サイトID (省略時は全サイト)")

    deploy_p = subparsers.add_parser("deploy", help="スタックをデプロイ")
    deploy_p.add_argument("--site", help="対象サイトID (省略時は全サイト)")

    out_p = subparsers.add_parser("outputs", help="スタック出力を表示")
    out_p.add_argument("--site", help="対象サイトID (省略時は全サイト)")

    tok_p = subparsers.add_parser("token", help="指定サイトの共有トークンを表示")
    tok_p.add_argument("site_id", help="対象サイトID")

    return parser


def main() -> int:
    """コマンドライン引数を解析し、指定されたサブコマンドを実行する。

    Returns:
        成功時は0、失敗時は1。

    """
    parser = build_parser()
    args = parser.parse_args()

    sites_file = Path(args.sites_file)
    try:
        sites = load_sites_file(sites_file)
    except SitesConfigError as error:
        print(f"設定エラー: {error}", file=sys.stderr)
        return 1

    site_arg = getattr(args, "site", None)
    site_id_arg = getattr(args, "site_id", None)
    target_site = site_arg or site_id_arg

    if target_site and target_site not in sites:
        print(
            f"指定されたサイト '{target_site}' は設定ファイルに定義されていません。",
            file=sys.stderr,
        )
        return 1

    handlers = {
        "list": lambda: cmd_list(sites),
        "check": lambda: cmd_check(sites, args.site),
        "env": lambda: cmd_env(sites, args.site_id, export_format=args.export),
        "ix-config": lambda: cmd_ix_config(sites, args.site, aws_cmd=args.aws_cmd),
        "deploy": lambda: cmd_deploy(sites, args.site, aws_cmd=args.aws_cmd),
        "outputs": lambda: cmd_outputs(sites, args.site, aws_cmd=args.aws_cmd),
        "token": lambda: cmd_token(sites, args.site_id, aws_cmd=args.aws_cmd),
    }
    handler = handlers.get(args.subcommand)
    if handler:
        return handler()
    return 0


if __name__ == "__main__":
    sys.exit(main())
