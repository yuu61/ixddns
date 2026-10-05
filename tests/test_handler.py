"""追加ライブラリの導入やAWSへの接続を行わず、実際のインラインLambdaを検証する。"""

import json
import os
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
from urllib.parse import urlencode


class ClientError(Exception):
    pass


class BotoCoreError(Exception):
    pass


def load_handler(route53, secrets, code=None):
    code = code or (
        Path(__file__).resolve().parents[1] / "lambda" / "index.py"
    ).read_text(encoding="utf-8")
    if not code.strip():
        raise AssertionError("Lambdaのコードが空です。")

    boto3 = types.ModuleType("boto3")
    boto3.client = lambda service, **kwargs: {
        "route53": route53,
        "secretsmanager": secrets,
    }[service]
    botocore = types.ModuleType("botocore")
    config = types.ModuleType("botocore.config")
    config.Config = lambda **kwargs: kwargs
    exceptions = types.ModuleType("botocore.exceptions")
    exceptions.ClientError = ClientError
    exceptions.BotoCoreError = BotoCoreError
    module = types.ModuleType("ddns_lambda")
    modules = {
        "boto3": boto3,
        "botocore": botocore,
        "botocore.config": config,
        "botocore.exceptions": exceptions,
    }
    with patch.dict(sys.modules, modules):
        exec(compile(code, "lambda/index.py", "exec"), module.__dict__)
    return module


class HandlerTests(unittest.TestCase):
    def setUp(self):
        self.route53 = MagicMock()
        self.route53.change_resource_record_sets.return_value = {
            "ChangeInfo": {"Id": "/change/test"}
        }
        self.secrets = MagicMock()
        self.secrets.get_secret_value.return_value = {
            "SecretString": json.dumps({"token": "correct-token"})
        }
        self.module = load_handler(self.route53, self.secrets)
        self.environment = patch.dict(
            os.environ,
            {
                "HOSTED_ZONE_ID": "ZEXAMPLE",
                "RECORD_NAME": "router.example.com",
                "RECORD_TYPE": "A",
                "RECORD_TTL": "60",
                "TOKEN_SECRET_ARN": "test-secret-arn",
                "ASN_RESTRICTION_ENABLED": "false",
                "ASN_RESTRICTION_METHOD": "static",
            },
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def invoke(self, ip="8.8.8.8", token="correct-token", method="GET", raw=None):
        query = urlencode({"ip": ip, "token": token}) if raw is None else raw
        return self.module.handler(
            {"rawQueryString": query, "requestContext": {"http": {"method": method}}},
            None,
        )

    def test_valid_request_updates_only_the_configured_record(self):
        result = self.invoke()
        self.assertEqual(result["statusCode"], 200)
        self.assertEqual(
            json.loads(result["body"]),
            {"status": "accepted", "change_id": "/change/test"},
        )
        self.route53.change_resource_record_sets.assert_called_once_with(
            HostedZoneId="ZEXAMPLE",
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "UPSERT",
                        "ResourceRecordSet": {
                            "Name": "router.example.com",
                            "Type": "A",
                            "TTL": 60,
                            "ResourceRecords": [{"Value": "8.8.8.8"}],
                        },
                    }
                ]
            },
        )
        self.assertEqual(result["headers"]["Cache-Control"], "no-store")

    def test_missing_or_wrong_or_non_ascii_token_cannot_update_dns(self):
        for token in ("", "wrong-token", "不正なトークン", "x" * 128):
            with self.subTest(token=token):
                self.assertEqual(self.invoke(token=token)["statusCode"], 401)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_token_replacement_takes_effect_on_next_request(self):
        self.assertEqual(self.invoke()["statusCode"], 200)
        self.route53.reset_mock()
        self.secrets.get_secret_value.return_value = {
            "SecretString": '{"token":"replacement-token"}'
        }
        self.assertEqual(self.invoke()["statusCode"], 401)
        self.route53.change_resource_record_sets.assert_not_called()
        self.assertEqual(self.invoke(token="replacement-token")["statusCode"], 200)

    def test_non_public_ipv4_addresses_are_rejected(self):
        for ip in (
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "192.0.2.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
        ):
            with self.subTest(ip=ip):
                self.assertEqual(self.invoke(ip=ip)["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_invalid_or_missing_ip_is_rejected(self):
        for ip in ("", "not-an-ip", "8.8.8.8/32", "8.8.8.8,1.1.1.1"):
            with self.subTest(ip=ip):
                self.assertEqual(self.invoke(ip=ip)["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_duplicate_and_unknown_query_parameters_are_rejected(self):
        for raw in (
            "ip=8.8.8.8&ip=1.1.1.1&token=correct-token",
            "ip=8.8.8.8&token=correct-token&token=correct-token",
            "ip=8.8.8.8&token=correct-token&hostname=other.example.com",
            "ip=8.8.8.8&token=correct-token&broken",
            "ip=8.8.8.8&token=" + "x" * 2048,
        ):
            with self.subTest(raw=raw[:80]):
                self.assertEqual(self.invoke(raw=raw)["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()
        self.secrets.get_secret_value.assert_not_called()

    def test_post_cannot_update_dns(self):
        self.assertEqual(self.invoke(method="POST")["statusCode"], 405)
        self.route53.change_resource_record_sets.assert_not_called()
        self.secrets.get_secret_value.assert_not_called()

    def test_ipv6_and_record_family_are_checked(self):
        self.assertEqual(self.invoke(ip="2606:4700:4700::1111")["statusCode"], 400)
        with patch.dict(os.environ, {"RECORD_TYPE": "AAAA"}):
            self.assertEqual(self.invoke(ip="8.8.8.8")["statusCode"], 400)
            self.assertEqual(
                self.invoke(ip="2606:4700:4700:0:0:0:0:1111")["statusCode"], 200
            )
        record = self.route53.change_resource_record_sets.call_args.kwargs[
            "ChangeBatch"
        ]["Changes"][0]["ResourceRecordSet"]
        self.assertEqual(record["Type"], "AAAA")
        self.assertEqual(record["ResourceRecords"], [{"Value": "2606:4700:4700::1111"}])

    def test_non_routable_or_scoped_ipv6_is_rejected(self):
        with patch.dict(os.environ, {"RECORD_TYPE": "AAAA"}):
            for ip in (
                "::1",
                "::",
                "fe80::1",
                "fd00::1",
                "fec0::1",
                "2001:db8::1",
                "ff02::1",
                "::ffff:8.8.8.8",
                "2606:4700:4700::1111%eth0",
            ):
                with self.subTest(ip=ip):
                    self.assertEqual(self.invoke(ip=ip)["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_aws_error_returns_retryable_failure_without_secret_in_logs(self):
        self.route53.change_resource_record_sets.side_effect = ClientError(
            "sensitive-sdk-message"
        )
        with self.assertLogs("ddns_lambda", level="ERROR") as logs:
            result = self.invoke()
        self.assertEqual(result["statusCode"], 503)
        output = " ".join(logs.output) + result["body"]
        self.assertNotIn("sensitive-sdk-message", output)
        self.assertNotIn("correct-token", output)

    def test_secret_read_failure_never_mutates_dns(self):
        self.secrets.get_secret_value.side_effect = BotoCoreError("read failed")
        with self.assertLogs("ddns_lambda", level="ERROR"):
            self.assertEqual(self.invoke()["statusCode"], 503)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_malformed_secret_never_mutates_dns(self):
        for secret in ({}, {"token": ""}, {"token": 123}, {"token": None}):
            with self.subTest(secret=secret):
                self.secrets.get_secret_value.return_value = {
                    "SecretString": json.dumps(secret)
                }
                with self.assertLogs("ddns_lambda", level="ERROR"):
                    self.assertEqual(self.invoke()["statusCode"], 503)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_rest_api_updates_with_the_same_authentication_and_ip_checks(self):
        event = {
            "httpMethod": "GET",
            "multiValueQueryStringParameters": {
                "ip": ["8.8.8.8"],
                "token": ["correct-token"],
            },
        }
        self.assertEqual(self.module.handler(event, None)["statusCode"], 200)
        self.route53.reset_mock()
        event["multiValueQueryStringParameters"]["token"] = ["wrong-token"]
        self.assertEqual(self.module.handler(event, None)["statusCode"], 401)
        self.route53.change_resource_record_sets.assert_not_called()
        event["multiValueQueryStringParameters"]["token"] = ["correct-token"]
        event["multiValueQueryStringParameters"]["ip"] = ["10.0.0.1"]
        self.assertEqual(self.module.handler(event, None)["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()

    def test_rest_api_duplicate_or_malformed_queries_never_update_dns(self):
        for query in (
            {"ip": ["8.8.8.8", "1.1.1.1"], "token": ["correct-token"]},
            {"ip": ["8.8.8.8"], "token": ["correct-token", "correct-token"]},
            {"ip": "8.8.8.8", "token": ["correct-token"]},
            {"ip": [None], "token": ["correct-token"]},
            {"ip": [], "token": ["correct-token"]},
            {"ip": ["8.8.8.8"], "token": ["correct-token"], "extra": ["value"]},
            {"ip": ["8.8.8.8"], "token": ["x" * 2049]},
            "invalid",
        ):
            with self.subTest(query=query):
                result = self.module.handler(
                    {"httpMethod": "GET", "multiValueQueryStringParameters": query},
                    None,
                )
                self.assertEqual(result["statusCode"], 400)
        self.route53.change_resource_record_sets.assert_not_called()
        self.secrets.get_secret_value.assert_not_called()


if __name__ == "__main__":
    unittest.main()
