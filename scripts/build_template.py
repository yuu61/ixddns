"""分割した定義とLambdaコードを、単一スタック用のテンプレートへ結合する。"""

import argparse
import base64
import hashlib
import json
import os
import sys
import tempfile
import zlib
from pathlib import Path

from cfnlint.decode import decode

from scripts.asn_prefixes import fetch_snapshot, read_snapshot
from scripts.check_asn_config import check_asn_config

PROJECT = Path(__file__).resolve().parents[1]
MAX_TEMPLATE_BYTES = 51200
FRAGMENTS = ("function-url.yaml", "rest-api.yaml", "waf.yaml")


def read_definition(path: Path) -> dict[str, object]:
    """CloudFormationの組み込み関数を保持してYAML定義を読み込む。

    Returns:
        組み込み関数を保持したCloudFormation定義。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    data, errors = decode(str(path))
    if errors or not isinstance(data, dict):
        message = f"定義ファイルを読み込めません: {path}"
        raise ValueError(message)
    return data


def build_template(snapshot: dict[str, object] | None = None) -> dict[str, object]:
    """共通定義・API・WAF・Lambdaコードを単一テンプレートに結合する。

    Returns:
        Lambdaコードを含む単一のCloudFormation定義。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    template = read_definition(PROJECT / "cloudformation.yaml")
    for name in FRAGMENTS:
        fragment = read_definition(PROJECT / "infrastructure" / name)
        for section, entries in fragment.items():
            if section not in {"Parameters", "Rules", "Resources", "Outputs"}:
                message = f"未対応のセクションです: {name} / {section}"
                raise ValueError(message)
            target = template.setdefault(section, {})
            duplicates = set(target) & set(entries)
            if duplicates:
                message = f"定義名が重複しています: {name} / {section}"
                raise ValueError(message)
            target.update(entries)
    template["Resources"]["UpdateFunction"]["Properties"]["Code"]["ZipFile"] = (
        PROJECT / "lambda" / "index.py"
    ).read_text(encoding="utf-8")
    if snapshot is not None:
        snapshot_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
        payload = base64.b85encode(
            zlib.compress(snapshot_json.encode("utf-8"), level=9)
        ).decode("ascii")
        template["Resources"]["UpdateFunction"]["Properties"]["Code"]["ZipFile"] = (
            template["Resources"]["UpdateFunction"]["Properties"]["Code"][
                "ZipFile"
            ].replace('ASN_SNAPSHOT_DATA = ""', f"ASN_SNAPSHOT_DATA = {payload!r}")
        )
    # REST APIのDeploymentは設定変更だけでは再配置されません。
    # 定義を変更したときは、DeploymentのIDも変えます。
    api_definition = {
        name: resource
        for name, resource in template["Resources"].items()
        if resource["Type"]
        in {
            "AWS::ApiGateway::RestApi",
            "AWS::ApiGateway::Resource",
            "AWS::ApiGateway::Method",
        }
    }
    digest = hashlib.sha256(
        json.dumps(api_definition, sort_keys=True).encode("utf-8")
    ).hexdigest()[:12]
    deployment_id = f"RestDeployment{digest}"
    template["Resources"][deployment_id] = template["Resources"].pop("RestDeployment")
    template["Resources"]["RestStage"]["Properties"]["DeploymentId"] = {
        "Ref": deployment_id
    }
    return template


def write_atomic(path: Path, content: str) -> None:
    """一時ファイルを書き終えてから生成先を置換する。"""
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent, delete=False
        ) as output:
            temporary = Path(output.name)
            output.write(content)
        temporary.replace(path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def generate_template(output: Path) -> dict[str, object] | None:
    """設定と一覧を検証し、テンプレートと参照用一覧を保存する。

    Returns:
        埋め込んだ一覧。制限なし・WAF方式の場合はNone。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    inputs = {
        PROJECT / "cloudformation.yaml",
        PROJECT / "lambda" / "index.py",
        *(PROJECT / "infrastructure" / name for name in FRAGMENTS),
    }
    prefix_file = os.environ.get("ASN_PREFIXES_FILE", "")
    if prefix_file:
        inputs.add(Path(prefix_file))
    if output.resolve() in {path.resolve() for path in inputs}:
        message = "生成先にソースの定義ファイルを指定することはできません。"
        raise ValueError(message)
    enabled = os.environ.get("ASN_RESTRICTION_ENABLED", "false")
    method = os.environ.get("ASN_RESTRICTION_METHOD", "static")
    asns = check_asn_config(enabled, os.environ.get("ALLOWED_ASNS", ""), method)
    snapshot = None
    if enabled == "true" and method == "static":
        snapshot = (
            read_snapshot(Path(prefix_file), asns)
            if prefix_file
            else fetch_snapshot(asns)
        )
    template = build_template(snapshot)
    content = json.dumps(template, ensure_ascii=False, indent=2) + "\n"
    if len(content.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        content = json.dumps(template, ensure_ascii=False, separators=(",", ":")) + "\n"
    if len(content.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        message = (
            "生成テンプレートが51,200バイトを超えました。S3への配置を検討してください。"
        )
        raise ValueError(message)
    # 取得・形式・容量の検証が終わるまで、既存の生成物には触れません。
    write_atomic(output, content)
    if snapshot is not None:
        snapshot_output = output.parent / "asn-prefixes.json"
        if snapshot_output.resolve() != output.resolve() and (
            not prefix_file or snapshot_output.resolve() != Path(prefix_file).resolve()
        ):
            write_atomic(
                snapshot_output,
                json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n",
            )
    return snapshot


def main() -> int:
    """設定と生成物を検証し、テンプレートの保存結果を終了コードで返す。

    Returns:
        成功時は0、失敗時は1。

    """
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=PROJECT / ".build" / "template.json",
        help="生成先のファイル",
    )
    args = parser.parse_args()
    try:
        snapshot = generate_template(args.output)
    except (OSError, TypeError, ValueError) as error:
        print(f"テンプレート生成失敗: {error}", file=sys.stderr)
        return 1
    print(f"CloudFormationテンプレートを生成しました: {args.output}")
    if snapshot is not None:
        print(f"ASNの公開CIDRを埋め込みました: {len(snapshot['cidrs'])}件")
    return 0


if __name__ == "__main__":
    sys.exit(main())
