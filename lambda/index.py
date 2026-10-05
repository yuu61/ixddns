"""IXの通知を認証し、許可した送信元から固定のRoute 53レコードを更新する。"""

import base64
import hmac
import ipaddress
import json
import logging
import os
import zlib
from http import HTTPStatus
from urllib.parse import parse_qs

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
sdk_config = Config(
    connect_timeout=2,
    read_timeout=3,
    retries={"mode": "standard", "total_max_attempts": 2},
)
route53 = boto3.client("route53", config=sdk_config)
secrets = boto3.client("secretsmanager", config=sdk_config)
MAX_QUERY_LENGTH = 2048
MAX_QUERY_FIELDS = 4
MAX_TOKEN_LENGTH = 127

# make buildが取得したCIDR一覧を圧縮して埋め込みます。通信時の外部照会はありません。
ASN_SNAPSHOT_DATA = ""
ASN_SNAPSHOT = (
    json.loads(zlib.decompress(base64.b85decode(ASN_SNAPSHOT_DATA)))
    if ASN_SNAPSHOT_DATA
    else None
)
SOURCE_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in (ASN_SNAPSHOT["cidrs"] if ASN_SNAPSHOT else [])
)


class RequestError(Exception):
    """認証情報を含めず、通知の拒否理由とHTTP応答を保持する。"""

    def __init__(self, status_code: int, status: str) -> None:
        """HTTP応答に使う固定の状態名を受け取る。"""
        super().__init__(status)
        self.status_code = status_code
        self.status = status


def source_allowed(event: dict[str, object]) -> bool:
    """送信元IPをAPI Gatewayの情報から取得し、CIDR一覧と照合する。

    Returns:
        送信元が許可される場合はTrue。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    enabled = os.environ.get("ASN_RESTRICTION_ENABLED", "false")
    if enabled == "false":
        return True
    method = os.environ.get("ASN_RESTRICTION_METHOD", "static")
    if enabled != "true" or method not in {"static", "waf"}:
        message = "Invalid ASN restriction configuration"
        raise ValueError(message)
    if method == "waf":
        return True
    configured = {int(value) for value in os.environ["ALLOWED_ASNS"].split(",")}
    if (
        not SOURCE_NETWORKS
        or not ASN_SNAPSHOT
        or configured != set(ASN_SNAPSHOT["asns"])
    ):
        message = "Missing or mismatched ASN snapshot"
        raise ValueError(message)
    request = event.get("requestContext", {})
    value = request.get("http", {}).get(
        "sourceIp", request.get("identity", {}).get("sourceIp")
    )
    if not isinstance(value, str) or "%" in value:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return any(address in network for network in SOURCE_NETWORKS)


def response(status_code: int, status: str, **details: str) -> dict[str, object]:
    """キャッシュを禁止したJSON形式のHTTP応答を作る。

    Returns:
        API Gatewayへ返す状態コード・ヘッダー・JSON本文。

    """
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps({"status": status, **details}),
    }


def read_query(event: dict[str, object]) -> dict[str, str]:
    """両APIのクエリ形式を検証し、重複のない通知パラメータを返す。

    Returns:
        重複と形式を検証した単一値の通知パラメータ。

    Raises:
        RequestError: 通知の形式・認証・IPが不正な場合。

    """
    if "rawQueryString" in event:
        raw_query = event["rawQueryString"]
        if not isinstance(raw_query, str) or len(raw_query) > MAX_QUERY_LENGTH:
            raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_query")
        try:
            query = parse_qs(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=MAX_QUERY_FIELDS,
            )
        except ValueError as error:
            raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_query") from error
    else:
        # REST APIの複数値を保持したクエリを使い、重複を単一値に丸めません。
        query = event.get("multiValueQueryStringParameters") or {}
    if not isinstance(query, dict) or any(
        not isinstance(key, str)
        or not isinstance(values, list)
        or len(values) != 1
        or not isinstance(values[0], str)
        for key, values in query.items()
    ):
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_query")
    if set(query) - {"token", "ip"}:
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_query")
    if (
        sum(len(key) + len(values[0]) for key, values in query.items())
        > MAX_QUERY_LENGTH
    ):
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_query")
    return {key: values[0] for key, values in query.items()}


def authenticate(supplied_token: str) -> None:
    """通知ごとに現在の共有トークンを取得し、定数時間の比較で認証する。

    Raises:
        RequestError: 通知の形式・認証・IPが不正な場合。
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    if not supplied_token or len(supplied_token) > MAX_TOKEN_LENGTH:
        raise RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")

    # 通知ごとにAWSCURRENTを取得し、手動で差し替えたトークンを即座に反映します。
    secret = secrets.get_secret_value(SecretId=os.environ["TOKEN_SECRET_ARN"])
    expected_token = json.loads(secret["SecretString"])["token"]
    if not isinstance(expected_token, str) or not expected_token:
        message = "Invalid shared token configuration"
        raise ValueError(message)
    if not hmac.compare_digest(
        supplied_token.encode("utf-8"), expected_token.encode("utf-8")
    ):
        raise RequestError(HTTPStatus.UNAUTHORIZED, "unauthorized")


def validate_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    """設定されたレコード種別に合う公開IPアドレスだけを受け付ける。

    Returns:
        公開IPアドレスを表すオブジェクト。

    Raises:
        RequestError: 通知の形式・認証・IPが不正な場合。

    """
    if not value or "%" in value:
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_ip")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise RequestError(HTTPStatus.BAD_REQUEST, "invalid_ip") from error
    record_type = os.environ["RECORD_TYPE"]
    expected_version = 4 if record_type == "A" else 6
    if address.version != expected_version:
        raise RequestError(HTTPStatus.BAD_REQUEST, "wrong_address_family")
    if not address.is_global or address.is_multicast or address.is_reserved:
        raise RequestError(HTTPStatus.BAD_REQUEST, "non_public_ip")
    if isinstance(address, ipaddress.IPv6Address) and (
        address.is_site_local or address.ipv4_mapped is not None
    ):
        raise RequestError(HTTPStatus.BAD_REQUEST, "non_public_ip")
    return address


def update(event: dict[str, object]) -> dict[str, object]:
    """メソッド・送信元・認証・IPを検証した後に固定のDNSレコードを更新する。

    Returns:
        更新の受理、または通知拒否のHTTP応答。

    """
    method = (
        event
        .get("requestContext", {})
        .get("http", {})
        .get("method", event.get("httpMethod"))
    )
    if method != "GET":
        return response(HTTPStatus.METHOD_NOT_ALLOWED, "method_not_allowed")
    if not source_allowed(event):
        logger.warning("ddns_source_rejected")
        return response(HTTPStatus.FORBIDDEN, "source_not_allowed")
    query = read_query(event)
    authenticate(query.get("token", ""))
    address = validate_address(query.get("ip", ""))

    result = route53.change_resource_record_sets(
        HostedZoneId=os.environ["HOSTED_ZONE_ID"],
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": os.environ["RECORD_NAME"],
                        "Type": os.environ["RECORD_TYPE"],
                        "TTL": int(os.environ["RECORD_TTL"]),
                        "ResourceRecords": [{"Value": str(address)}],
                    },
                }
            ]
        },
    )
    logger.info("ddns_update_accepted")
    return response(HTTPStatus.OK, "accepted", change_id=result["ChangeInfo"]["Id"])


def handler(event: dict[str, object], _context: object) -> dict[str, object]:
    """通知の拒否とAWS処理の失敗を、秘密情報を含めないHTTP応答へ変換する。

    Returns:
        受理・通知拒否・処理失敗のHTTP応答。

    """
    try:
        return update(event)
    except RequestError as error:
        return response(error.status_code, error.status)
    except (ClientError, BotoCoreError, KeyError, TypeError, ValueError) as error:
        # イベント、クエリ、シークレット、SDK例外の本文はログに記録しません。
        logger.error("ddns_update_failed", extra={"error_type": type(error).__name__})
        return response(HTTPStatus.SERVICE_UNAVAILABLE, "update_failed")
