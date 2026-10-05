"""RIPE RISの最新の起点経路から、デプロイ用のCIDR一覧を作る。"""

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

API_URL = "https://stat.ripe.net/data/ris-prefixes/data.json"
MAX_BYTES = 10 * 1024 * 1024
MAX_AGE = timedelta(hours=48)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("取得日時が不正です。")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    # RIPEstatのquery_timeはUTCのタイムゾーン表記なしです。
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def check_fresh(value, now):
    age = now - timestamp(value)
    if age > MAX_AGE or age < -timedelta(hours=1):
        raise ValueError(
            "ASN経路情報が48時間より古いか、取得日時が未来です。再取得してください。"
        )


def normalize_prefixes(values):
    if not isinstance(values, list) or not values:
        raise ValueError("ASNの起点となる公開CIDRが空です。")
    networks = []
    for value in values:
        if not isinstance(value, str) or "/" not in value or "%" in value:
            raise ValueError("CIDRの形式が不正です。")
        network = ipaddress.ip_network(value, strict=True)
        if (
            network.prefixlen == 0
            or not network.is_global
            or network.network_address.is_multicast
            or network.is_reserved
        ):
            raise ValueError(f"公開経路として許可できないCIDRです: {value}")
        networks.append(network)
    # 同じ範囲の重複と隣接経路だけを統合し、許可範囲を広げません。
    return [
        str(network)
        for version in (4, 6)
        for network in ipaddress.collapse_addresses(
            network for network in networks if network.version == version
        )
    ]


def validate_snapshot(snapshot, asns, now=None):
    now = now or datetime.now(timezone.utc)
    if (
        not isinstance(snapshot, dict)
        or snapshot.get("schema_version") != 1
        or snapshot.get("source") != API_URL
        or snapshot.get("asns") != asns
    ):
        raise ValueError("ASN一覧ファイルの形式またはALLOWED_ASNSとの対応が不正です。")
    check_fresh(snapshot.get("fetched_at"), now)
    times = snapshot.get("query_times")
    if not isinstance(times, dict) or set(times) != {str(asn) for asn in asns}:
        raise ValueError("ASN一覧ファイルの観測日時が不足しています。")
    for value in times.values():
        check_fresh(value, now)
    snapshot = dict(snapshot)
    snapshot["cidrs"] = normalize_prefixes(snapshot.get("cidrs"))
    return snapshot


def fetch_snapshot(asns, now=None):
    now = now or datetime.now(timezone.utc)
    prefixes, times = [], {}
    for asn in asns:
        query = urlencode(
            {
                "resource": f"AS{asn}",
                "list_prefixes": "true",
                "types": "o",
                "af": "v4,v6",
                "noise": "filter",
            }
        )
        request = Request(f"{API_URL}?{query}", headers={"User-Agent": "ixddns/1.0"})
        try:
            with urlopen(request, timeout=20) as response:
                raw = response.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError("RIPEstatの応答が大きすぎます。")
            result = json.loads(raw)
            data = result["data"]
            if result.get("status") != "ok" or str(data["resource"]) != str(asn):
                raise ValueError("RIPEstatの応答が要求したASNと一致しません。")
            times[str(asn)] = data["query_time"]
            check_fresh(times[str(asn)], now)
            originated = []
            for family in ("v4", "v6"):
                values = data["prefixes"][family].get("originating", [])
                count = data["counts"][family].get("originating", 0)
                if not isinstance(values, list) or count != len(values):
                    raise ValueError("RIPEstatの経路一覧が欠落しています。")
                if any(
                    ipaddress.ip_network(value).version != (4 if family == "v4" else 6)
                    for value in values
                ):
                    raise ValueError("RIPEstatの経路のアドレス種別が不正です。")
                originated.extend(values)
            prefixes.extend(normalize_prefixes(originated))
        except (URLError, OSError, ValueError, KeyError, TypeError) as error:
            raise ValueError(f"AS{asn}の公開CIDRを取得できません: {error}") from error
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


def read_snapshot(path, asns):
    if path.stat().st_size > MAX_BYTES:
        raise ValueError("ASN一覧ファイルが大きすぎます。")
    return validate_snapshot(json.loads(path.read_text(encoding="utf-8")), asns)
