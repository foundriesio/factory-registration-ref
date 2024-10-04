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
        r = self.client.post("/sign")
        self.assertEqual(415, r.status_code, r.data)

    def test_no_csr(self):
        """Fail properly if no csr is provided"""
        r = self._sign({"data": 12})
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Missing required field 'csr'", r.data)

    def test_invalid_csr(self):
        r = self._sign({"csr": "not a valid csr", "hardware-id": "atari"})
        self.assertEqual(400, r.status_code, r.data)
        self.assertIn(b"Unable to load PEM file", r.data)

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
                settings.CA_CRT = "cacrt"
                r = self._sign({"csr": "n/a", "hardware-id": "foo", "overrides": overrides})
                with open(os.path.join(d, "uuid")) as f:
                    self.assertEqual("pub", f.read())
        self.assertEqual(201, r.status_code, r.data)
        toml = r.json["sota.toml"]
        self.assertIn("[pacman]\ntype = ostree_foo", toml)
        self.assertIn('[provision]\nserver = "https://example.com:8443"', toml)
