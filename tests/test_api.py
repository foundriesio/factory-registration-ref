import json
import os
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

from flask_testing import TestCase  # type: ignore


class TestApi(TestCase):
    def create_app(self):
        from registration_ref.app import app

        return app

    def _sign(self, data: dict):
        headers = {"Content-type": "application/json"}
        return self.client.post("/sign", headers=headers, data=json.dumps(data))

    def test_no_data(self):
        """Fail properly when no data is sent"""
        r = self._sign(None)
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Missing request body", r.data)

    def test_no_csr(self):
        """Fail properly if no csr is provided"""
        r = self._sign({"data": 12})
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Missing required field &#39;csr&#39;", r.data)

    def test_no_hardware_id(self):
        """Fail properly when no hardware-id is provided"""
        r = self._sign({"csr": "valid csr"})
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Missing required field &#39;hardware-id&#39;", r.data)

    def test_invalid_csr(self):
        """Fail properly when an invalid csr is provided"""
        r = self._sign({"csr": "not a valid csr", "hardware-id": "foo"})
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Unable to load request", r.data)

    @patch("registration_ref.app.sign_device_csr")
    @patch("registration_ref.settings._env")
    def test_overrides(self, env, sign_device_csr):
        """Ensure we return proper sota toml overrides"""
        env.return_value = "https://example.com:8443"
        fields = Mock()
        fields.root_crt = "root_crt"
        fields.client_crt = "client_crt"
        fields.uuid = "uuid"
        fields.pubkey = "pub"
        sign_device_csr.return_value = fields
        overrides = {
            "pacman": {
                "type": "ostree_foo",
            }
        }
        with TemporaryDirectory() as d:
            with patch("registration_ref.app.Settings") as settings:
                settings.DEVICES_DIR = d
                settings.API_TOKEN_PATH = None
                r = self._sign({"csr": "n/a", "overrides": overrides})
                with open(os.path.join(d, "uuid")) as f:
                    self.assertEqual("pub", f.read())
        self.assertEqual(201, r.status_code, r.data)
        toml = r.json["sota.toml"]
        self.assertIn("[pacman]\ntype = ostree_foo", toml)
        self.assertIn('[provision]\nserver = "https://example.com:8443"', toml)
