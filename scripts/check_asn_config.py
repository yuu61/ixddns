"""ASN制限の設定を検証し、設定不足による誤ったデプロイを防ぐ。"""

import os
import re
import sys


def check_asn_config(enabled, allowed, method="static"):
    if method not in ("static", "waf"):
        raise ValueError(
            "ASN_RESTRICTION_METHODにはstaticまたはwafを設定してください。"
        )
    if enabled not in ("true", "false"):
        raise ValueError(
            "ASN_RESTRICTION_ENABLEDにはtrueまたはfalseを設定してください。"
        )
    if enabled == "false":
        return []
    values = [value.strip() for value in allowed.split(",")]
    if not 1 <= len(values) <= 100:
        raise ValueError("ALLOWED_ASNSには1〜100個のASNを指定してください。")
    if any(
        not re.fullmatch(r"[1-9][0-9]{0,9}", value) or not 1 <= int(value) <= 4294967295
        for value in values
    ):
        raise ValueError(
            "ALLOWED_ASNSには1〜4294967295の整数をカンマ区切りで指定してください。AS接頭辞とASN 0は使えません。"
        )
    if len(set(values)) != len(values):
        raise ValueError("ALLOWED_ASNSに同じASNが重複しています。")
    return sorted(int(value) for value in values)


def main():
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
