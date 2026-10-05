"""結合後の定義でAPIの切り替えと認証・WAFの経路を検証する。"""

import unittest

from scripts.build_template import PROJECT, build_template
from scripts.check_asn_config import check_asn_config


class TemplateTests(unittest.TestCase):
    def setUp(self):
        self.template = build_template()

    def active_resources(self, enabled, method="waf"):
        conditions = self.template["Conditions"]

        def evaluate(expression):
            if not isinstance(expression, dict):
                return expression
            if "Ref" in expression:
                return {
                    "AsnRestrictionEnabled": enabled,
                    "AsnRestrictionMethod": method,
                }[expression["Ref"]]
            if "Condition" in expression:
                return evaluate(conditions[expression["Condition"]])
            if "Fn::Equals" in expression:
                left, right = expression["Fn::Equals"]
                return evaluate(left) == evaluate(right)
            if "Fn::Not" in expression:
                return not evaluate(expression["Fn::Not"][0])
            if "Fn::And" in expression:
                return all(evaluate(item) for item in expression["Fn::And"])
            self.fail(f"未対応の条件式です: {expression}")

        return {
            name: resource
            for name, resource in self.template["Resources"].items()
            if "Condition" not in resource
            or evaluate(conditions[resource["Condition"]])
        }

    def test_disabled_mode_has_http_api_and_no_waf_or_rest_api(self):
        active = self.active_resources("false")
        self.assertIn("HttpApi", active)
        self.assertIn("InvokePermission", active)
        for resource in active.values():
            self.assertNotIn(
                resource["Type"],
                (
                    "AWS::ApiGateway::RestApi",
                    "AWS::WAFv2::WebACL",
                    "AWS::WAFv2::WebACLAssociation",
                    "AWS::WAFv2::LoggingConfiguration",
                ),
            )

    def test_enabled_mode_has_only_the_waf_protected_rest_api(self):
        active = self.active_resources("true")
        for name in (
            "RestApi",
            "RestUpdateMethod",
            "RestStage",
            "RestInvokePermission",
            "DdnsWebAcl",
            "WafAssociation",
            "WafLogging",
        ):
            self.assertIn(name, active)
        self.assertNotIn("HttpApi", active)
        self.assertNotIn("InvokePermission", active)
        for resource in active.values():
            self.assertNotEqual(resource["Type"], "AWS::ApiGatewayV2::Api")
        acl = active["DdnsWebAcl"]["Properties"]
        self.assertEqual(acl["DefaultAction"], {"Block": {}})
        self.assertEqual(acl["Rules"][0]["Action"], {"Block": {}})
        self.assertEqual(
            acl["Rules"][1]["Statement"],
            {"AsnMatchStatement": {"AsnList": {"Ref": "AllowedAsns"}}},
        )
        self.assertIn(
            "${RestApi}/stages/${RestStage}",
            active["WafAssociation"]["Properties"]["ResourceArn"]["Fn::Sub"],
        )

    def test_static_mode_uses_http_api_without_waf(self):
        for enabled in ("true", "false"):
            active = self.active_resources(enabled, "static")
            self.assertIn("HttpApi", active)
            self.assertIn("InvokePermission", active)
            self.assertNotIn("RestApi", active)
            self.assertNotIn("DdnsWebAcl", active)
            self.assertNotIn("WafAssociation", active)

    def test_invalid_method_is_rejected(self):
        with self.assertRaises(ValueError):
            check_asn_config("true", "64496", "statc")

    def test_shared_secret_function_and_logs_survive_mode_switches(self):
        disabled = self.active_resources("false")
        enabled = self.active_resources("true")
        for name in (
            "SharedToken",
            "FunctionRole",
            "UpdateFunction",
            "FunctionLogGroup",
            "ApiAccessLogGroup",
            "WafLogGroup",
        ):
            self.assertEqual(disabled[name], enabled[name])
        code = enabled["UpdateFunction"]["Properties"]["Code"]["ZipFile"]
        self.assertEqual(
            code, (PROJECT / "lambda" / "index.py").read_text(encoding="utf-8")
        )
        self.assertEqual(enabled["SharedToken"]["DeletionPolicy"], "Retain")

    def test_rest_stage_references_the_generated_deployment(self):
        resources = self.template["Resources"]
        deployment = resources["RestStage"]["Properties"]["DeploymentId"]["Ref"]
        self.assertIn(deployment, resources)
        self.assertTrue(deployment.startswith("RestDeployment"))
        self.assertEqual(resources[deployment]["DependsOn"], "RestUpdateMethod")
        self.assertEqual(resources[deployment]["Type"], "AWS::ApiGateway::Deployment")


class AsnConfigTests(unittest.TestCase):
    def test_enabled_mode_requires_a_nonempty_numeric_allow_list(self):
        for allowed in (
            "",
            "0",
            "AS64496",
            "-1",
            "1.5",
            "4294967296",
            "64496,",
            "64496,64496",
            ",".join(str(value) for value in range(1, 102)),
        ):
            with self.subTest(allowed=allowed), self.assertRaises(ValueError):
                check_asn_config("true", allowed)
        check_asn_config("true", "64496, 64500")
        check_asn_config("true", "4294967295")

    def test_disabled_mode_ignores_asns_but_typo_in_switch_is_rejected(self):
        check_asn_config("false", "")
        check_asn_config("false", "AS64496")
        for enabled in ("True", "tru", "1", ""):
            with self.subTest(enabled=enabled), self.assertRaises(ValueError):
                check_asn_config(enabled, "64496")


if __name__ == "__main__":
    unittest.main()
