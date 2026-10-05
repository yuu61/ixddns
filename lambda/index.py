import base64
import hmac
import ipaddress
import json
import logging
import os
import zlib
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


def source_allowed(event):
    enabled = os.environ.get("ASN_RESTRICTION_ENABLED", "false")
    if enabled == "false":
        return True
    method = os.environ.get("ASN_RESTRICTION_METHOD", "static")
    if enabled != "true" or method not in ("static", "waf"):
        raise ValueError("Invalid ASN restriction configuration")
    if method == "waf":
        return True
    configured = {int(value) for value in os.environ["ALLOWED_ASNS"].split(",")}
    if (
        not SOURCE_NETWORKS
        or not ASN_SNAPSHOT
        or configured != set(ASN_SNAPSHOT["asns"])
    ):
        raise ValueError("Missing or mismatched ASN snapshot")
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


def response(status_code, status, **details):
    return {
        "statusCode": status_code,
        "headers": {
            "Content-Type": "application/json",
            "Cache-Control": "no-store",
        },
        "body": json.dumps({"status": status, **details}),
    }


def update(event):
    method = (
        event.get("requestContext", {})
        .get("http", {})
        .get("method", event.get("httpMethod"))
    )
    if method != "GET":
        return response(405, "method_not_allowed")
    if not source_allowed(event):
        logger.warning("ddns_source_rejected")
        return response(403, "source_not_allowed")
    if "rawQueryString" in event:
        raw_query = event["rawQueryString"]
        if not isinstance(raw_query, str) or len(raw_query) > 2048:
            return response(400, "invalid_query")
        try:
            query = parse_qs(
                raw_query,
                keep_blank_values=True,
                strict_parsing=True,
                max_num_fields=4,
            )
        except ValueError:
            return response(400, "invalid_query")
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
        return response(400, "invalid_query")
    if set(query) - {"token", "ip"}:
        return response(400, "invalid_query")
    if sum(len(key) + len(values[0]) for key, values in query.items()) > 2048:
        return response(400, "invalid_query")
    supplied_token = query.get("token", [""])[0]
    if not supplied_token or len(supplied_token) > 127:
        return response(401, "unauthorized")

    # 通知ごとにAWSCURRENTを取得し、手動で差し替えたトークンを即座に反映します。
    secret = secrets.get_secret_value(SecretId=os.environ["TOKEN_SECRET_ARN"])
    expected_token = json.loads(secret["SecretString"])["token"]
    if not isinstance(expected_token, str) or not expected_token:
        raise ValueError("Invalid shared token configuration")
    if not hmac.compare_digest(
        supplied_token.encode("utf-8"), expected_token.encode("utf-8")
    ):
        return response(401, "unauthorized")

    value = query.get("ip", [""])[0]
    if not value or "%" in value:
        return response(400, "invalid_ip")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return response(400, "invalid_ip")
    record_type = os.environ["RECORD_TYPE"]
    expected_version = 4 if record_type == "A" else 6
    if address.version != expected_version:
        return response(400, "wrong_address_family")
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or (
            address.version == 6
            and (address.is_site_local or address.ipv4_mapped is not None)
        )
    ):
        return response(400, "non_public_ip")

    result = route53.change_resource_record_sets(
        HostedZoneId=os.environ["HOSTED_ZONE_ID"],
        ChangeBatch={
            "Changes": [
                {
                    "Action": "UPSERT",
                    "ResourceRecordSet": {
                        "Name": os.environ["RECORD_NAME"],
                        "Type": record_type,
                        "TTL": int(os.environ["RECORD_TTL"]),
                        "ResourceRecords": [{"Value": str(address)}],
                    },
                }
            ]
        },
    )
    logger.info("ddns_update_accepted")
    return response(200, "accepted", change_id=result["ChangeInfo"]["Id"])


def handler(event, context):
    try:
        return update(event)
    except (ClientError, BotoCoreError, KeyError, TypeError, ValueError) as error:
        # イベント、クエリ、シークレット、SDK例外の本文はログに記録しません。
        logger.error("ddns_update_failed", extra={"error_type": type(error).__name__})
        return response(503, "update_failed")
