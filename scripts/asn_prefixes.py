"""RIPE RISの最新の起点経路から、デプロイ用のCIDR一覧を作る。"""

import ipaddress
import json
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

if TYPE_CHECKING:
    from pathlib import Path

API_URL = "https://stat.ripe.net/data/ris-prefixes/data.json"
MAX_BYTES = 10 * 1024 * 1024
MAX_AGE = timedelta(hours=48)


def timestamp(value: object) -> datetime:
    """RIPEstatのUTC日時をタイムゾーン付きの日時へ変換する。

    Returns:
        タイムゾーン付きの観測日時。

    Raises:
        TypeError: 取得データの型が不正な場合。

    """
    if not isinstance(value, str):
        message = "取得日時が不正です。"
        raise TypeError(message)
    parsed = datetime.fromisoformat(value)
    # RIPEstatのquery_timeはUTCのタイムゾーン表記なしです。
    return (
        datetime.fromisoformat(f"{parsed.isoformat()}+00:00")
        if parsed.tzinfo is None
        else parsed
    )


def check_fresh(value: object, now: datetime) -> None:
    """取得・観測日時が許容する鮮度の範囲にあることを確認する。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    age = now - timestamp(value)
    if age > MAX_AGE or age < -timedelta(hours=1):
        message = (
            "ASN経路情報が48時間より古いか、取得日時が未来です。再取得してください。"
        )
        raise ValueError(message)


def normalize_prefixes(values: object) -> list[str]:
    """公開CIDRを検証し、許可範囲を広げずに重複と隣接範囲を統合する。

    Returns:
        同じ許可範囲を表す正規化済みのCIDR一覧。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    if not isinstance(values, list) or not values:
        message = "ASNの起点となる公開CIDRが空です。"
        raise ValueError(message)
    networks = []
    for value in values:
        if not isinstance(value, str) or "/" not in value or "%" in value:
            message = "CIDRの形式が不正です。"
            raise ValueError(message)
        network = ipaddress.ip_network(value, strict=True)
        if (
            network.prefixlen == 0
            or not network.is_global
            or network.network_address.is_multicast
            or network.is_reserved
        ):
            message = f"公開経路として許可できないCIDRです: {value}"
            raise ValueError(message)
        networks.append(network)
    # 同じ範囲の重複と隣接経路だけを統合し、許可範囲を広げません。
    return [
        str(network)
        for version in (4, 6)
        for network in ipaddress.collapse_addresses(
            network for network in networks if network.version == version
        )
    ]


def validate_snapshot(
    snapshot: object, asns: list[int], now: datetime | None = None
) -> dict[str, object]:
    """一覧の形式・ASN・鮮度を検証して、正規化したCIDR一覧を返す。

    Returns:
        鮮度とASNを検証した一覧と取得メタデータ。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    now = now or datetime.now(UTC)
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("schema_version") != 1
        or snapshot.get("source") != API_URL
        or snapshot.get("asns") != asns
    ):
        message = "ASN一覧ファイルの形式またはALLOWED_ASNSとの対応が不正です。"
        raise ValueError(message)
    check_fresh(snapshot.get("fetched_at"), now)
    times = snapshot.get("query_times")
    if not isinstance(times, dict) or set(times) != {str(asn) for asn in asns}:
        message = "ASN一覧ファイルの観測日時が不足しています。"
        raise ValueError(message)
    for value in times.values():
        check_fresh(value, now)
    snapshot = dict(snapshot)
    snapshot["cidrs"] = normalize_prefixes(snapshot.get("cidrs"))
    return snapshot


def _parse_prefix_response(
    raw: bytes, asn: int, now: datetime
) -> tuple[list[str], str]:
    """応答サイズ・ASN・観測日時・経路一覧の完全性を検証する。

    Returns:
        公開CIDR一覧とASNの観測日時。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    if len(raw) > MAX_BYTES:
        message = "RIPEstatの応答が大きすぎます。"
        raise ValueError(message)
    result = json.loads(raw)
    data = result["data"]
    if result.get("status") != "ok" or str(data["resource"]) != str(asn):
        message = "RIPEstatの応答が要求したASNと一致しません。"
        raise ValueError(message)
    check_fresh(data["query_time"], now)
    originated = []
    for family, version in (("v4", 4), ("v6", 6)):
        values = data["prefixes"][family].get("originating", [])
        count = data["counts"][family].get("originating", 0)
        if not isinstance(values, list) or count != len(values):
            message = "RIPEstatの経路一覧が欠落しています。"
            raise ValueError(message)
        if any(ipaddress.ip_network(value).version != version for value in values):
            message = "RIPEstatの経路のアドレス種別が不正です。"
            raise ValueError(message)
        originated.extend(values)
    return normalize_prefixes(originated), data["query_time"]


def _request_prefixes(asn: int, now: datetime) -> tuple[list[str], str]:
    """固定のHTTPS APIへASNを照会し、検証した起点経路と観測日時を返す。

    Returns:
        検証済みの起点経路と観測日時。

    """
    query = urlencode({
        "resource": f"AS{asn}",
        "list_prefixes": "true",
        "types": "o",
        "af": "v4,v6",
        "noise": "filter",
    })
    request = Request(f"{API_URL}?{query}", headers={"User-Agent": "ixddns/1.0"})
    with urlopen(request, timeout=20) as response:
        raw = response.read(MAX_BYTES + 1)
    return _parse_prefix_response(raw, asn, now)


def fetch_snapshot(asns: list[int], now: datetime | None = None) -> dict[str, object]:
    """各ASNの最新の起点経路を取得し、デプロイ用の一覧を作る。

    Returns:
        全指定ASNの起点経路と観測・取得日時。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    now = now or datetime.now(UTC)
    prefixes, times = [], {}
    for asn in asns:
        try:
            originated, query_time = _request_prefixes(asn, now)
        except (URLError, OSError, ValueError, KeyError, TypeError) as error:
            message = f"AS{asn}の公開CIDRを取得できません: {error}"
            raise ValueError(message) from error
        times[str(asn)] = query_time
        prefixes.extend(originated)
    return validate_snapshot(
        {
            "schema_version": 1,
            "source": API_URL,
            "fetched_at": now.isoformat(),
            "asns": asns,
            "query_times": times,
            "cidrs": prefixes,
        },
        asns,
        now,
    )


def read_snapshot(path: Path, asns: list[int]) -> dict[str, object]:
    """明示的に指定された一覧ファイルを読み込み、形式と鮮度を検証する。

    Returns:
        読み込みと検証が完了した一覧。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    if path.stat().st_size > MAX_BYTES:
        message = "ASN一覧ファイルが大きすぎます。"
        raise ValueError(message)
    return validate_snapshot(json.loads(path.read_text(encoding="utf-8")), asns)
