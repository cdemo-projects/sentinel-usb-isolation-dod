"""Offline contracts and expression fixtures, not an Azure/Logic Apps emulator."""

import copy
import json
import re
import unittest
from pathlib import Path
from urllib.parse import quote, unquote

from jsonschema import Draft4Validator, ValidationError


ROOT = Path(__file__).resolve().parent
TEMPLATE = json.loads((ROOT / "azuredeploy.json").read_text(encoding="utf-8"))
WORKFLOW = next(r for r in TEMPLATE["resources"] if r["type"] == "Microsoft.Logic/workflows")
DEFINITION = WORKFLOW["properties"]["definition"]
WORKSPACE = "/subscriptions/00000000-0000-0000-0000-000000000001/resourceGroups/test/providers/Microsoft.OperationalInsights/workspaces/test"
INCIDENT = WORKSPACE + "/providers/Microsoft.SecurityInsights/incidents/00000000-0000-0000-0000-000000000002"
DEVICE = "a" * 40


def actions_in(actions):
    for name, action in actions.items():
        yield name, action
        yield from actions_in(action.get("actions", {}))
        yield from actions_in(action.get("else", {}).get("actions", {}))


ACTIONS = dict(actions_in(DEFINITION["actions"]))


def strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from strings(value)
    elif isinstance(node, list):
        for value in node:
            yield from strings(value)


class Expression:
    """Parse the expression subset used here and evaluate selected safety guards."""

    token = re.compile(r"\s*('(?:[^']|'')*'|[A-Za-z_$][A-Za-z_0-9$]*|-?\d+|[(),?\[\]])")

    def __init__(self, text):
        self.tokens = []
        pos = 0
        while pos < len(text):
            match = self.token.match(text, pos)
            if not match:
                raise ValueError(f"Invalid expression near: {text[pos:]}")
            self.tokens.append(match.group(1))
            pos = match.end()
        self.pos = 0
        self.tree = self.parse()
        if self.pos != len(self.tokens):
            raise ValueError("Unexpected trailing expression tokens")

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def pop(self, expected=None):
        value = self.peek()
        if value is None or (expected is not None and value != expected):
            raise ValueError(f"Expected {expected}, received {value}")
        self.pos += 1
        return value

    def parse(self):
        value = self.pop()
        if value.startswith("'"):
            node = ("literal", value[1:-1].replace("''", "'"))
        elif re.fullmatch(r"-?\d+", value):
            node = ("literal", int(value))
        else:
            self.pop("(")
            args = []
            if self.peek() != ")":
                args.append(self.parse())
                while self.peek() == ",":
                    self.pop(",")
                    args.append(self.parse())
            self.pop(")")
            node = ("call", value, args)
        while self.peek() in ("?", "["):
            safe = self.peek() == "?"
            if safe:
                self.pop("?")
            self.pop("[")
            key = self.parse()
            self.pop("]")
            node = ("index", node, key, safe)
        return node

    def evaluate(self, context):
        def evaluate(node):
            kind = node[0]
            if kind == "literal":
                return node[1]
            if kind == "index":
                parent, key = evaluate(node[1]), evaluate(node[2])
                if node[3] and (parent is None or (isinstance(parent, dict) and key not in parent)):
                    return None
                return parent[key]
            name, args = node[1], [evaluate(arg) for arg in node[2]]
            functions = {
                "and": lambda *a: all(a),
                "or": lambda *a: any(a),
                "not": lambda a: not a,
                "equals": lambda a, b: a == b,
                "contains": lambda a, b: b in a,
                "startsWith": lambda a, b: a.startswith(b),
                "toLower": lambda a: a.lower(),
                "string": lambda a: "" if a is None else a if isinstance(a, str) else json.dumps(a, separators=(",", ":")),
                "length": len,
                "split": lambda a, b: a.split(b),
                "concat": lambda *a: "".join(a),
                "first": lambda a: a[0],
                "empty": lambda a: a is None or len(a) == 0,
                "coalesce": lambda *a: next((v for v in a if v is not None), None),
                "createArray": lambda *a: list(a),
                "json": json.loads,
                "uriComponent": lambda a: quote(a, safe=""),
                "decodeUriComponent": unquote,
                "triggerBody": lambda: context["trigger"],
                "parameters": lambda name: context["parameters"][name],
                "body": lambda name: context["bodies"].get(name),
                "outputs": lambda name: context["outputs"][name],
                "item": lambda: context["item"],
            }
            return functions[name](*args)
        return evaluate(self.tree)


def evaluate(text, **overrides):
    context = {
        "parameters": {"workspaceResourceId": WORKSPACE},
        "trigger": {"object": {"id": INCIDENT}},
        "bodies": {},
        "outputs": {"Device_id": DEVICE, "Request_comment": "this-incident"},
    }
    context.update(overrides)
    return Expression(text.removeprefix("@")).evaluate(context)


class PackageTests(unittest.TestCase):
    def test_portal_workflow_matches_tested_definition_without_arm_parameters(self):
        portal = json.loads((ROOT / "portal-workflow-definition.json").read_text(encoding="utf-8"))
        expected = copy.deepcopy(DEFINITION)
        expected["parameters"]["$connections"]["defaultValue"] = {}
        expected["parameters"]["workspaceResourceId"]["defaultValue"] = ""
        expected["parameters"]["ruleResourceId"]["defaultValue"] = ""
        expected["parameters"]["alertTitle"]["defaultValue"] = ""
        expected["parameters"]["notificationSenderEmail"]["defaultValue"] = ""
        expected["parameters"]["notificationRecipientEmail"]["defaultValue"] = ""
        self.assertEqual(portal, expected)
        for text in strings(portal):
            self.assertFalse(text.startswith("["), text)
        guide = (ROOT / "CUSTOMER-PORTAL-SETUP.md").read_text(encoding="utf-8")
        query = re.search(r"```kusto\n(.*?)\n```", guide, re.DOTALL).group(1)
        self.assertEqual(query, TEMPLATE["variables"]["query"])
        self.assertIn("portal-code-view.json", guide)

    def test_parameter_contract_and_activation(self):
        params = json.loads((ROOT / "azuredeploy.parameters.json").read_text())
        self.assertFalse(TEMPLATE["parameters"]["enableDetectionAndAutomation"]["defaultValue"])
        self.assertFalse(params["parameters"]["enableDetectionAndAutomation"]["value"])
        self.assertLessEqual(set(params["parameters"]), set(TEMPLATE["parameters"]))
        for resource in TEMPLATE["resources"]:
            if resource["type"].endswith("/alertRules"):
                self.assertEqual(resource["properties"]["enabled"], "[parameters('enableDetectionAndAutomation')]")
            if resource["type"].endswith("/automationRules"):
                logic = resource["properties"]["triggeringLogic"]
                self.assertEqual(logic["isEnabled"], "[parameters('enableDetectionAndAutomation')]")
                self.assertEqual((logic["triggersOn"], logic["triggersWhen"]), ("Incidents", "Created"))
                self.assertEqual(logic["conditions"][0]["conditionProperties"]["propertyName"], "IncidentRelatedAnalyticRuleIds")

    def test_query_parity_and_endpoint_identity(self):
        query = (ROOT / "detection.kql").read_text().strip()
        self.assertEqual(query, TEMPLATE["variables"]["query"])
        self.assertIn('ActionType == "PnpDeviceConnected"', query)
        self.assertIn('USBDeviceId startswith @"USB\\VID_03EB"', query)
        self.assertIn("MDEDeviceId = DeviceId", query)
        self.assertIn("summarize arg_max(TimeGenerated, *) by DeviceId", query)
        self.assertIn("coalesce(ingestion_time(), TimeGenerated) > ago(5m)", query)
        rule = next(r["properties"] for r in TEMPLATE["resources"] if r["type"].endswith("/alertRules"))
        self.assertEqual(rule["customDetails"]["MDEDeviceId"], "MDEDeviceId")
        self.assertEqual(rule["queryFrequency"], "PT5M")
        self.assertEqual(rule["eventGroupingSettings"]["aggregationKind"], "AlertPerResult")
        self.assertFalse(rule["incidentConfiguration"]["groupingConfiguration"]["enabled"])

    def test_all_runtime_expression_syntax_and_action_references(self):
        for text in strings(DEFINITION):
            if text.startswith("@"):
                with self.subTest(expression=text):
                    Expression(text[1:])
                    for name in re.findall(r"(?:body|outputs)\('([^']+)'\)", text):
                        self.assertIn(name, ACTIONS)

    def test_run_after_references_are_siblings(self):
        def check(actions):
            for action in actions.values():
                self.assertLessEqual(set(action.get("runAfter", {})), set(actions))
                check(action.get("actions", {}))
                check(action.get("else", {}).get("actions", {}))
        check(DEFINITION["actions"])

    def test_workspace_scope(self):
        expression = ACTIONS["Validate_incident_scope"]["expression"]
        self.assertTrue(evaluate(expression))
        for value in (None, "", INCIDENT + "/comments/x", INCIDENT.replace("/test/", "/other/"), "https://attacker.invalid" + INCIDENT):
            with self.subTest(value=value):
                self.assertFalse(evaluate(expression, trigger={"object": {"id": value}}))

    def test_target_details_schema_rejects_bad_or_ambiguous_ids(self):
        schema = ACTIONS["Parse_custom_details"]["inputs"]["schema"]
        validator = Draft4Validator(schema)
        valid = {"MDEDeviceId": [DEVICE], "DetectionSignature": ["USB-VID-03EB-v1"]}
        validator.validate(valid)
        for value in ([], [DEVICE, "b" * 40], ["USB\\VID_03EB"], ["../other"], ["a" * 39], ["a" * 41], DEVICE):
            invalid = copy.deepcopy(valid)
            invalid["MDEDeviceId"] = value
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validator.validate(invalid)
        for invalid in ({}, {"MDEDeviceId": [DEVICE]}, {"MDEDeviceId": [DEVICE], "DetectionSignature": ["wrong"]}):
            with self.assertRaises(ValidationError):
                validator.validate(invalid)

    def test_no_parse_json_uses_unsupported_pattern_keywords(self):
        for name, action in ACTIONS.items():
            if action["type"] == "ParseJson":
                schema_text = json.dumps(action["inputs"]["schema"])
                self.assertNotIn('"pattern"', schema_text, name)
                self.assertNotIn('"patternProperties"', schema_text, name)

    def test_submitted_action_allows_initial_null_scope(self):
        schema = ACTIONS["Validate_submitted_action"]["inputs"]["schema"]
        validator = Draft4Validator(schema)
        pending_response = {
            "id": "5123349b-21e4-4e08-9356-478a5ac6b548",
            "machineId": DEVICE,
            "scope": None,
            "type": "Isolate",
            "status": "Pending",
        }
        validator.validate(pending_response)

    def test_custom_details_formats_and_no_silent_missing_default(self):
        expression = ACTIONS["Parse_custom_details"]["inputs"]["content"]
        details = {"MDEDeviceId": [DEVICE], "DetectionSignature": ["USB-VID-03EB-v1"]}
        for key in ("Custom Details", "CustomDetails"):
            for value in (details, json.dumps(details)):
                alert = {"properties": {"additionalData": {key: value}}}
                self.assertEqual(evaluate(expression, bodies={"One_alert": [alert]}), details)
                # Also verify fallback to triggerBody() when POST /incidents/{id}/alerts omits Custom Details
                empty_alert = {"properties": {"additionalData": {}}}
                trigger = {"object": {"id": INCIDENT, "properties": {"alerts": [alert]}}}
                self.assertEqual(evaluate(expression, bodies={"One_alert": [empty_alert]}, trigger=trigger), details)
        with self.assertRaises(json.JSONDecodeError):
            evaluate(expression, bodies={"One_alert": [{"properties": {"additionalData": {}}}]})

    def test_only_one_matching_alert(self):
        validator = Draft4Validator(ACTIONS["One_alert"]["inputs"]["schema"])
        validator.validate([{"properties": {}}])
        for value in ([], [{"properties": {}}, {"properties": {}}]):
            with self.assertRaises(ValidationError):
                validator.validate(value)

    def test_machine_validation(self):
        expression = ACTIONS["Validate_machine"]["expression"]
        for status in ("Onboarded", "onboarded"):
            self.assertTrue(evaluate(expression, bodies={"Get_machine": {"id": DEVICE, "onboardingStatus": status}}))
        for machine in ({}, {"id": "b" * 40, "onboardingStatus": "Onboarded"}, {"id": DEVICE, "onboardingStatus": "CanBeOnboarded"}):
            self.assertFalse(evaluate(expression, bodies={"Get_machine": machine}))

    def test_pending_and_duplicate_guard(self):
        expression = ACTIONS["Existing_requests"]["inputs"]["where"]
        for status in ("Pending", "InProgress"):
            self.assertTrue(evaluate(expression, item={"status": status, "requestorComment": "other"}))
        for status in ("Succeeded", "Failed", "Cancelled"):
            self.assertTrue(evaluate(expression, item={"status": status, "requestorComment": "this-incident"}))
        self.assertFalse(evaluate(expression, item={"status": "Succeeded", "requestorComment": "other"}))
        self.assertFalse(evaluate(ACTIONS["Needs_isolation"]["expression"], bodies={"Existing_requests": [{}]}))

    def test_full_isolation_post_is_not_retried(self):
        request = ACTIONS["Submit_full_isolation"]["inputs"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["body"]["IsolationType"], "Full")
        self.assertEqual(request["retryPolicy"], {"type": "none"})
        self.assertIn("outputs('Device_id')", request["uri"])
        self.assertNotIn("/unisolate", "\n".join(strings(DEFINITION)))
        self.assertEqual(DEFINITION["triggers"]["Sentinel_incident"]["runtimeConfiguration"]["concurrency"]["runs"], 1)

    def test_success_is_actual_full_isolation_on_expected_endpoint(self):
        expression = ACTIONS["Verify_completion"]["expression"]
        valid = {"status": "Succeeded", "scope": "Full", "type": "Isolate", "machineId": DEVICE}
        self.assertTrue(evaluate(expression, bodies={"Poll_action": valid}))
        for key, value in (("status", "Pending"), ("status", "Failed"), ("status", "TimeOut"), ("status", "Cancelled"), ("scope", "Selective"), ("type", "Unisolate"), ("machineId", "b" * 40)):
            with self.subTest(key=key, value=value):
                invalid = valid | {key: value}
                self.assertFalse(evaluate(expression, bodies={"Poll_action": invalid}))
        self.assertFalse(evaluate(expression, bodies={"Poll_action": {}}))
        self.assertEqual(ACTIONS["Wait_for_completion"]["limit"], {"count": 15, "timeout": "PT6M"})

    def test_failure_is_not_reported_as_success(self):
        self.assertEqual(ACTIONS["Fail_run"]["inputs"]["runStatus"], "Failed")
        self.assertEqual(ACTIONS["Fail_unconfirmed_action"]["inputs"]["runStatus"], "Failed")
        self.assertEqual(ACTIONS["Record_failure"]["runAfter"], {"Process_incident": ["Failed", "TimedOut"]})
        self.assertEqual(set(ACTIONS["Send_failure_email_if_configured"]["runAfter"]["Record_failure"]), {"Succeeded", "Failed", "TimedOut"})
        self.assertEqual(set(ACTIONS["Fail_run"]["runAfter"]["Send_failure_email_if_configured"]), {"Succeeded", "Failed", "TimedOut"})
        self.assertIn("empty(body('List_isolation_actions')?['@odata.nextLink'])", ACTIONS["Validate_action_list"]["expression"])

    def test_optional_email_notifications_guard(self):
        for action_name in ("Send_success_email_if_configured", "Send_failure_email_if_configured"):
            expr = ACTIONS[action_name]["expression"]
            self.assertFalse(evaluate(expr, parameters={"workspaceResourceId": WORKSPACE, "notificationSenderEmail": "", "notificationRecipientEmail": ""}))
            self.assertFalse(evaluate(expr, parameters={"workspaceResourceId": WORKSPACE, "notificationSenderEmail": "soc@agency.mil", "notificationRecipientEmail": ""}))
            self.assertTrue(evaluate(expr, parameters={"workspaceResourceId": WORKSPACE, "notificationSenderEmail": "soc@agency.mil", "notificationRecipientEmail": "ir@agency.mil"}))

    def test_no_commercial_runtime_endpoints_or_secrets(self):
        for name, action in ACTIONS.items():
            if action["type"] == "Http":
                authentication = action["inputs"]["authentication"]
                self.assertEqual(authentication["type"], "ManagedServiceIdentity", name)
                self.assertIn(authentication["audience"], {
                    "https://management.core.usgovcloudapi.net/",
                    "https://api-gov.securitycenter.microsoft.us",
                    "https://dod-graph.microsoft.us",
                })
                uri = action["inputs"]["uri"]
                self.assertTrue(
                    uri.startswith("@concat('https://management.usgovcloudapi.net")
                    or uri.startswith("@concat('https://api-gov.securitycenter.microsoft.us")
                    or uri.startswith("@concat('https://dod-graph.microsoft.us"),
                    name,
                )
        text = json.dumps(TEMPLATE)
        for forbidden in ("api.security.microsoft.com", "api-dod.", "login.microsoftonline.com", "client_secret", "clientSecret"):
            self.assertNotIn(forbidden, text)

    def test_permissions_helper_guards_and_whatif(self):
        helper = (ROOT / "Grant-PlaybookAccess.ps1").read_text()
        for required in ("SupportsShouldProcess", "ShouldProcess", "AzureUSGovernment", "USGovDoD", "Machine.Isolate", "Machine.ReadWrite.All", "Microsoft Sentinel Responder"):
            self.assertIn(required, helper)
        self.assertNotIn("-Environment Global", helper)
        self.assertIn("$audiences -notcontains 'https://api-gov.securitycenter.microsoft.us'", helper)


if __name__ == "__main__":
    unittest.main()
