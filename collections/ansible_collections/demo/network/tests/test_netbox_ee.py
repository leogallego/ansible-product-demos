"""Structure checks for the dedicated NetBox Network Security EE definition."""

from pathlib import Path
import unittest

import yaml

REPO = Path(__file__).resolve().parents[5]
EE_DIR = REPO / "execution_environments"


class NetboxEeDefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.definition = yaml.safe_load((EE_DIR / "apd-ee-netbox.yml").read_text())
        cls.requirements = yaml.safe_load(
            (EE_DIR / "requirements-netbox.yml").read_text()
        )
        cls.collection_names = {
            entry["name"] for entry in cls.requirements["collections"]
        }
        cls.python_names = set(cls.definition["dependencies"]["python"])

    def test_galaxy_requirements_are_wired_to_the_definition(self):
        self.assertEqual(
            self.definition["dependencies"]["galaxy"], "requirements-netbox.yml"
        )

    def test_spec_required_content_is_present(self):
        for collection in (
            "netbox.netbox",
            "ansible.netcommon",
            "cisco.ios",
            "amazon.aws",
            "community.aws",
            "containers.podman",
            "ansible.controller",
            "infra.aap_configuration",
            "ansible.eda",
        ):
            self.assertIn(collection, self.collection_names)
        for python in ("pynetbox", "packaging", "pytz", "paramiko"):
            self.assertTrue(
                any(name == python or name.startswith(python + ">") for name in self.python_names),
                python + " missing from EE python dependencies",
            )

    def test_netbox_collection_is_spec_pinned(self):
        netbox = next(
            entry
            for entry in self.requirements["collections"]
            if entry["name"] == "netbox.netbox"
        )
        self.assertEqual(netbox["version"], "==3.23.1")

    def test_base_runtime_matches_the_proven_shared_ee(self):
        self.assertEqual(
            self.definition["images"]["base_image"]["name"],
            "registry.redhat.io/ansible-automation-platform-27/ee-minimal-rhel9:2.16",
        )

    def test_shared_network_ceilings_are_mirrored_not_upgraded(self):
        pinned = {
            entry["name"]: entry.get("version")
            for entry in self.requirements["collections"]
        }
        self.assertEqual(pinned["ansible.netcommon"], "<8.7.0")
        self.assertEqual(pinned["cisco.ios"], "<11.6.0")

    def test_certificate_verification_is_not_disabled(self):
        definition = str(self.definition)
        self.assertNotIn("validate_certs: false", definition)
        self.assertNotIn("ssl_verify", definition.lower())


if __name__ == "__main__":
    unittest.main()
