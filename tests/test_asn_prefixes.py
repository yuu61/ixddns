"""外部接続せず、ASN経路の取得・欠落・鮮度とテンプレートへの埋め込みを検証する。"""

import ast
import base64
import copy
import io
import json
import os
import random
import tempfile
import unittest
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.error import URLError

from scripts import asn_prefixes, build_template


def snapshot(now: datetime | None = None) -> dict[str, object]:
    """鮮度検証と埋め込みの試験に使う一覧を作る。

    Returns:
        指定した日時で作成した試験用のCIDR一覧。

    """
    now = now or datetime.now(UTC)
    return {
        "schema_version": 1,
        "source": asn_prefixes.API_URL,
        "asns": [3333],
        "fetched_at": now.isoformat(),
        "query_times": {"3333": now.isoformat()},
        "cidrs": ["8.8.8.0/24", "2606:4700::/32"],
    }


def api_response(now: datetime) -> dict[str, object]:
    """起点経路と通過経路を含むRIPEstatの模擬応答を作る。

    Returns:
        起点経路・通過経路・件数を含む模擬応答。

    """
    return {
        "status": "ok",
        "data": {
            "resource": "3333",
            "query_time": now.isoformat(),
            "prefixes": {
                "v4": {"originating": ["8.8.8.0/24"], "transiting": ["1.1.1.0/24"]},
                "v6": {"originating": ["2606:4700::/32"]},
            },
            "counts": {"v4": {"originating": 1}, "v6": {"originating": 1}},
        },
    }


class PrefixTests(unittest.TestCase):
    """起点経路の取得・鮮度・欠落・公開CIDRの正規化を検証する。"""

    def setUp(self) -> None:
        self.now = datetime.now(UTC)
        self.result = api_response(self.now)

    def fetch(
        self, result: dict[str, object] | None = None
    ) -> tuple[dict[str, object], MagicMock]:
        response = io.BytesIO(json.dumps(result or self.result).encode())
        with patch.object(asn_prefixes, "urlopen", return_value=response) as request:
            result = asn_prefixes.fetch_snapshot([3333], self.now)
        return result, request

    def test_fetch_uses_latest_originating_routes_and_never_transiting_routes(
        self,
    ) -> None:
        result, request = self.fetch()
        self.assertEqual(result["cidrs"], ["8.8.8.0/24", "2606:4700::/32"])
        url = request.call_args.args[0].full_url
        for parameter in (
            "resource=AS3333",
            "list_prefixes=true",
            "types=o",
            "noise=filter",
        ):
            self.assertIn(parameter, url)
        self.assertNotIn("starttime", url)
        self.assertEqual(request.call_args.kwargs["timeout"], 20)

    def test_failure_and_partial_response_never_create_a_snapshot(self) -> None:
        variations = []
        for change in (
            "count",
            "empty",
            "private",
            "default",
            "stale",
            "asn",
            "missing",
            "family",
        ):
            result = copy.deepcopy(self.result)
            data = result["data"]
            if change == "count":
                data["counts"]["v4"]["originating"] = 2
            elif change == "empty":
                for family in ("v4", "v6"):
                    data["prefixes"][family]["originating"] = []
                    data["counts"][family]["originating"] = 0
            elif change in {"private", "default", "family"}:
                data["prefixes"]["v4"]["originating"] = [
                    {
                        "private": "10.0.0.0/8",
                        "default": "0.0.0.0/0",
                        "family": "2606:4700::/32",
                    }[change]
                ]
            elif change == "stale":
                data["query_time"] = (self.now - timedelta(hours=49)).isoformat()
            elif change == "asn":
                data["resource"] = "9999"
            elif change == "missing":
                del data["prefixes"]
            variations.append((change, result))
        variations.append(("status", {**self.result, "status": "error"}))
        for change, result in variations:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.fetch(result)
        with (
            patch.object(asn_prefixes, "urlopen", side_effect=URLError("unavailable")),
            self.assertRaises(ValueError),
        ):
            asn_prefixes.fetch_snapshot([3333], self.now)

    def test_every_requested_asn_must_succeed(self) -> None:
        with (
            patch.object(
                asn_prefixes,
                "urlopen",
                side_effect=[
                    io.BytesIO(json.dumps(self.result).encode()),
                    URLError("second ASN failed"),
                ],
            ),
            self.assertRaises(ValueError),
        ):
            asn_prefixes.fetch_snapshot([3333, 9999], self.now)

    def test_single_address_family_is_supported(self) -> None:
        self.result["data"]["prefixes"]["v6"] = {}
        self.result["data"]["counts"]["v6"] = {}
        result, _ = self.fetch()
        self.assertEqual(result["cidrs"], ["8.8.8.0/24"])

    def test_normalization_preserves_exact_ranges(self) -> None:
        values = ["8.8.8.0/25", "8.8.8.128/25", "8.8.8.0/25", "8.8.10.0/24"]
        self.assertEqual(
            asn_prefixes.normalize_prefixes(values), ["8.8.8.0/24", "8.8.10.0/24"]
        )
        for values in (["8.8.8.1/24"], ["8.8.8.8"], ["bad"], ["ff00::/8"], []):
            with self.subTest(values=values), self.assertRaises(ValueError):
                asn_prefixes.normalize_prefixes(values)

    def test_offline_snapshot_requires_matching_asns_and_fresh_times(self) -> None:
        for field in (
            "asns",
            "source",
            "schema_version",
            "fetched_at",
            "query_times",
            "cidrs",
        ):
            data = snapshot(self.now)
            data[field] = {
                "asns": [9999],
                "source": "other",
                "schema_version": 2,
                "fetched_at": (self.now - timedelta(days=3)).isoformat(),
                "query_times": {},
                "cidrs": [],
            }[field]
            with self.subTest(field=field), self.assertRaises(ValueError):
                asn_prefixes.validate_snapshot(data, [3333], self.now)
        data = snapshot(self.now)
        data["query_times"]["3333"] = (self.now + timedelta(hours=2)).isoformat()
        with self.assertRaises(ValueError):
            asn_prefixes.validate_snapshot(data, [3333], self.now)


class BuildTests(unittest.TestCase):
    """一覧の埋め込みと生成失敗時の既存ファイル保持を検証する。"""

    def setUp(self) -> None:
        (build_template.PROJECT / ".build").mkdir(exist_ok=True)
        temporary = tempfile.TemporaryDirectory(dir=build_template.PROJECT / ".build")
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.output = self.directory / "template.json"
        self.environment = patch.dict(
            os.environ,
            {
                "ASN_RESTRICTION_ENABLED": "true",
                "ASN_RESTRICTION_METHOD": "static",
                "ALLOWED_ASNS": "3333",
                "ASN_PREFIXES_FILE": "",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def build(self) -> int:
        with (
            patch("sys.argv", ["build_template", "--output", str(self.output)]),
            patch("sys.stdout", new_callable=io.StringIO),
        ):
            return build_template.main()

    def test_static_build_records_snapshot_and_embeds_compressed_payload(self) -> None:
        data = snapshot()
        with patch.object(build_template, "fetch_snapshot", return_value=data) as fetch:
            self.assertEqual(self.build(), 0)
        fetch.assert_called_once_with([3333])
        content = self.output.read_text(encoding="utf-8")
        code = json.loads(content)["Resources"]["UpdateFunction"]["Properties"]["Code"][
            "ZipFile"
        ]
        self.assertNotIn('ASN_SNAPSHOT_DATA = ""', code)
        self.assertLessEqual(len(content.encode()), 51200)
        self.assertEqual(
            json.loads((self.directory / "asn-prefixes.json").read_text()), data
        )

    def test_failed_fetch_keeps_existing_template_and_snapshot(self) -> None:
        self.output.write_text("old template")
        cached = self.directory / "asn-prefixes.json"
        cached.write_text("old snapshot")
        with (
            patch.object(
                build_template, "fetch_snapshot", side_effect=ValueError("failed")
            ),
            patch("sys.stderr", new_callable=io.StringIO),
        ):
            self.assertEqual(self.build(), 1)
        self.assertEqual(self.output.read_text(), "old template")
        self.assertEqual(cached.read_text(), "old snapshot")

    def test_offline_snapshot_is_validated_without_public_api_call(self) -> None:
        source = self.directory / "input.json"
        source.write_text(json.dumps(snapshot()))
        os.environ["ASN_PREFIXES_FILE"] = str(source)
        with patch.object(build_template, "fetch_snapshot") as fetch:
            self.assertEqual(self.build(), 0)
        fetch.assert_not_called()
        data = snapshot()
        data["asns"] = [9999]
        source.write_text(json.dumps(data))
        original = self.output.read_bytes()
        with patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(self.build(), 1)
        self.assertEqual(self.output.read_bytes(), original)

    def test_disabled_and_waf_builds_never_fetch_prefixes(self) -> None:
        for enabled, method in (("false", "static"), ("false", "waf"), ("true", "waf")):
            with (
                self.subTest(enabled=enabled, method=method),
                patch.dict(
                    os.environ,
                    {
                        "ASN_RESTRICTION_ENABLED": enabled,
                        "ASN_RESTRICTION_METHOD": method,
                    },
                ),
                patch.object(build_template, "fetch_snapshot") as fetch,
            ):
                self.assertEqual(self.build(), 0)
                fetch.assert_not_called()

    def test_large_prefix_lists_are_compressed_without_dropping_entries(self) -> None:
        data = snapshot()
        data["cidrs"] = [
            f"8.{value // 256}.{value % 256}.0/24" for value in range(3000)
        ]
        # 大きな一覧でも、JSONの全CIDRを保持して圧縮します。
        with patch.object(build_template, "fetch_snapshot", return_value=data):
            self.assertEqual(self.build(), 0)
        self.assertLessEqual(self.output.stat().st_size, 51200)
        code = json.loads(self.output.read_text(encoding="utf-8"))["Resources"][
            "UpdateFunction"
        ]["Properties"]["Code"]["ZipFile"]
        assignment = next(
            node
            for node in ast.parse(code).body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "ASN_SNAPSHOT_DATA"
                for target in node.targets
            )
        )
        embedded = json.loads(
            zlib.decompress(base64.b85decode(ast.literal_eval(assignment.value)))
        )
        self.assertEqual(embedded["cidrs"], data["cidrs"])

    def test_oversized_template_stops_without_replacing_existing_artifacts(
        self,
    ) -> None:
        data = snapshot()
        generator = random.Random(0)
        addresses = generator.sample(range(1 << 24), 20000)
        data["cidrs"] = [
            f"8.{value >> 16}.{(value >> 8) & 255}.{value & 255}/32"
            for value in addresses
        ]
        self.output.write_text("old template")
        cached = self.directory / "asn-prefixes.json"
        cached.write_text("old snapshot")
        with (
            patch.object(build_template, "fetch_snapshot", return_value=data),
            patch("sys.stderr", new_callable=io.StringIO) as error,
        ):
            self.assertEqual(self.build(), 1)
        self.assertIn("51,200", error.getvalue())
        self.assertEqual(self.output.read_text(), "old template")
        self.assertEqual(cached.read_text(), "old snapshot")


if __name__ == "__main__":
    unittest.main()
