"""生成されたLambdaコードで、APIが渡す送信元IPとCIDR一覧を照合する。"""

import json
import os
import unittest
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode

import test_handler as support
from test_asn_prefixes import snapshot

from scripts.build_template import build_template


class StaticHandlerTests(unittest.TestCase):
    """埋め込んだCIDR一覧とAPIの送信元IPによる制限を検証する。"""

    @classmethod
    def setUpClass(cls) -> None:
        cls.code = build_template(snapshot())["Resources"]["UpdateFunction"][
            "Properties"
        ]["Code"]["ZipFile"]

    def setUp(self) -> None:
        self.route53, self.secrets = MagicMock(), MagicMock()
        self.route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/test"}
        }
        self.secrets.get_secret_value.return_value = {
            "SecretString": '{"token":"correct-token"}'
        }
        self.module = support.load_handler(self.route53, self.secrets, self.code)
        environment = patch.dict(
            os.environ,
            {
                "ASN_RESTRICTION_ENABLED": "true",
                "ASN_RESTRICTION_METHOD": "static",
                "ALLOWED_ASNS": "3333",
                "HOSTED_ZONE_ID": "ZEXAMPLE",
                "RECORD_NAME": "router.example.com",
                "RECORD_TYPE": "A",
                "RECORD_TTL": "60",
                "TOKEN_SECRET_ARN": "test-secret",
            },
        )
        environment.start()
        self.addCleanup(environment.stop)

    @staticmethod
    def event(
        source: str | None = "8.8.8.8", token: str = "correct-token"
    ) -> dict[str, object]:
        return {
            "rawQueryString": urlencode({"ip": "8.8.8.8", "token": token}),
            "requestContext": {"http": {"method": "GET", "sourceIp": source}},
        }

    def test_allowed_ipv4_and_ipv6_sources_can_update_after_token_authentication(
        self,
    ) -> None:
        for source in ("8.8.8.1", "8.8.8.255", "2606:4700:4700::1111"):
            with self.subTest(source=source):
                self.assertEqual(
                    self.module.handler(self.event(source), None)["statusCode"], 200
                )
        self.assertEqual(self.module.ASN_SNAPSHOT["asns"], [3333])

    def test_outside_missing_invalid_and_scoped_sources_never_read_secret(self) -> None:
        for source in (
            "8.8.9.1",
            "1.1.1.1",
            "2606:4701::1",
            "10.0.0.1",
            "invalid",
            None,
            "8.8.8.8/32",
            "2606:4700::1%eth0",
            "::ffff:8.8.8.8",
        ):
            event = self.event(source)
            event["headers"] = {"X-Forwarded-For": "8.8.8.8"}
            with (
                self.subTest(source=source),
                self.assertLogs("ddns_lambda", level="WARNING") as logs,
            ):
                result = self.module.handler(event, None)
            self.assertEqual(result["statusCode"], 403)
            self.assertEqual(json.loads(result["body"])["status"], "source_not_allowed")
            self.assertNotIn("correct-token", str(logs.output))
        self.secrets.get_secret_value.assert_not_called()
        self.route53.change_resource_record_sets.assert_not_called()

    def test_allowed_source_still_requires_valid_token(self) -> None:
        result = self.module.handler(self.event(token="wrong-token"), None)
        self.assertEqual(result["statusCode"], 401)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_mismatched_asns_or_missing_embedded_snapshot_fail_closed(self) -> None:
        for configured in ("9999", "", "3333,9999"):
            with (
                patch.dict(os.environ, {"ALLOWED_ASNS": configured}),
                self.assertLogs("ddns_lambda", level="ERROR"),
            ):
                self.assertEqual(
                    self.module.handler(self.event(), None)["statusCode"], 503
                )
        module = support.load_handler(self.route53, self.secrets)
        with self.assertLogs("ddns_lambda", level="ERROR"):
            self.assertEqual(module.handler(self.event(), None)["statusCode"], 503)
        self.secrets.get_secret_value.assert_not_called()
        self.route53.change_resource_record_sets.assert_not_called()

    def test_waf_and_disabled_modes_do_not_apply_static_snapshot(self) -> None:
        for enabled, method in (("false", "static"), ("true", "waf")):
            with patch.dict(
                os.environ,
                {"ASN_RESTRICTION_ENABLED": enabled, "ASN_RESTRICTION_METHOD": method},
            ):
                self.assertEqual(
                    self.module.handler(self.event("1.1.1.1"), None)["statusCode"], 200
                )

    def test_rest_event_uses_identity_source_not_headers_or_query(self) -> None:
        event = {
            "httpMethod": "GET",
            "requestContext": {"identity": {"sourceIp": "8.8.8.8"}},
            "multiValueQueryStringParameters": {
                "ip": ["8.8.8.8"],
                "token": ["correct-token"],
            },
        }
        self.assertEqual(self.module.handler(event, None)["statusCode"], 200)
        self.route53.reset_mock()
        event["requestContext"]["identity"]["sourceIp"] = "1.1.1.1"
        with self.assertLogs("ddns_lambda", level="WARNING"):
            self.assertEqual(self.module.handler(event, None)["statusCode"], 403)
        self.route53.change_resource_record_sets.assert_not_called()


if __name__ == "__main__":
    unittest.main()
