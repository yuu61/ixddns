"""ASN制限の設定を検証し、設定不足による誤ったデプロイを防ぐ。"""

import os
import re
import sys

MAX_ASNS = 100
MAX_ASN_NUMBER = 4294967295


def check_asn_config(enabled: str, allowed: str, method: str = "static") -> list[int]:
    """有効化・方式・許可ASNを検証して、数値で昇順のASN一覧を返す。

    Returns:
        昇順の許可ASN。無効時は空の一覧。

    Raises:
        ValueError: 設定または取得データの検証に失敗した場合。

    """
    if method not in {"static", "waf"}:
        message = "ASN_RESTRICTION_METHODにはstaticまたはwafを設定してください。"
        raise ValueError(message)
    if enabled not in {"true", "false"}:
        message = "ASN_RESTRICTION_ENABLEDにはtrueまたはfalseを設定してください。"
        raise ValueError(message)
    if enabled == "false":
        return []
    values = [value.strip() for value in allowed.split(",")]
    if not 1 <= len(values) <= MAX_ASNS:
        message = "ALLOWED_ASNSには1〜100個のASNを指定してください。"
        raise ValueError(message)
    if any(
        not re.fullmatch(r"[1-9][0-9]{0,9}", value)
        or not 1 <= int(value) <= MAX_ASN_NUMBER
        for value in values
    ):
        message = (
            "ALLOWED_ASNSには1〜4294967295の整数を"
            "カンマ区切りで指定してください。AS接頭辞とASN 0は使えません。"
        )
        raise ValueError(message)
    if len(set(values)) != len(values):
        message = "ALLOWED_ASNSに同じASNが重複しています。"
        raise ValueError(message)
    return sorted(int(value) for value in values)


def main() -> int:
    """環境変数のASN設定を検証し、不正な設定を標準エラーへ表示する。

    Returns:
        成功時は0、失敗時は1。

    """
    try:
        check_asn_config(
            os.environ.get("ASN_RESTRICTION_ENABLED", "false"),
            os.environ.get("ALLOWED_ASNS", ""),
            os.environ.get("ASN_RESTRICTION_METHOD", "static"),
        )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
