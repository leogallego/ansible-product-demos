"""Structure checks for the NetBox Security Inventory source (stage 1 draft).

These are offline YAML structure checks, not live plugin validation: the
inventory source must still be validated with a live NetBox sync (stage 2)
before device plays consume it.
"""

from pathlib import Path
import unittest

import yaml

REPO = Path(__file__).resolve().parents[5]
SOURCE = REPO / "network/netbox_security/inventory/netbox.yml"


class NetboxInventorySourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = yaml.safe_load(SOURCE.read_text())

    def test_uses_the_netbox_inventory_plugin(self):
        self.assertEqual(self.source["plugin"], "netbox.netbox.nb_inventory")

    def test_caching_is_disabled_and_launch_timeout_is_zero(self):
        self.assertFalse(self.source["cache"])
        self.assertEqual(self.source["cache_timeout"], 0)

    def test_certificates_are_never_bypassed(self):
        self.assertTrue(self.source["validate_certs"])

    def test_credentials_live_in_the_aap_credential_not_the_file(self):
        self.assertNotIn("api_endpoint", self.source)
        self.assertNotIn("token", self.source)

    def test_context_and_custom_fields_stay_namespaced(self):
        self.assertTrue(self.source["config_context"])
        self.assertFalse(self.source["flatten_config_context"])
        self.assertFalse(self.source["flatten_custom_fields"])
        self.assertFalse(self.source["plurals"])

    def test_scope_requires_active_cisco_platform_and_demo_tag(self):
        filters = self.source["device_query_filters"]
        for required in (
            {"status": "active"},
            {"platform": "cisco-iosxe"},
            {"tag": "security-demo"},
        ):
            self.assertIn(required, filters)

    def test_eligible_group_includes_deployment_scoping(self):
        condition = self.source["groups"]["security_eligible"]
        for token in (
            "'active'",
            "'cisco-iosxe'",
            "'security-demo'",
            "apd_deployment_id",
        ):
            self.assertIn(token, condition)

    def test_automation_endpoint_comes_only_from_the_custom_field(self):
        compose = self.source["compose"]
        self.assertEqual(
            compose["ansible_host"],
            "custom_fields.apd_automation_endpoint.host",
        )
        self.assertEqual(
            compose["ansible_port"],
            "custom_fields.apd_automation_endpoint.port",
        )

    def test_primary_management_ip_is_never_an_automation_endpoint(self):
        serialized = yaml.safe_dump(self.source)
        self.assertNotIn("ansible_host_dns_name", self.source)
        self.assertNotIn("oob_ip_as_primary_ip", self.source)
        # The primary IP is exported separately, only as an observation.
        self.assertIn("netbox_management_ip", serialized)
        self.assertNotIn("172.20.20.12", serialized)

    def test_cisco_connection_settings_are_explicit(self):
        compose = self.source["compose"]
        self.assertEqual(compose["ansible_network_os"], "cisco.ios.ios")
        self.assertEqual(compose["ansible_connection"], "ansible.netcommon.network_cli")

    def test_expected_deployment_is_explicitly_wired(self):
        self.assertTrue(self.source["use_extra_vars"])


if __name__ == "__main__":
    unittest.main()
