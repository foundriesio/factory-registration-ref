import os
from time import sleep

from flask import Flask, abort, jsonify, request
import requests

from registration_ref.crypto import sign_device_csr
from registration_ref.sota_toml import sota_toml_fmt
from registration_ref.settings import Settings

app = Flask(__name__)


@app.before_request
def _auth_user():
    pass


def log_device(uuid: str, pubkey: str):
    # Keep a log of created devices
    with open(os.path.join(Settings.DEVICES_DIR, uuid), "w") as f:
        f.write(pubkey)


def create_in_foundries(client_cert: str, api_token: str):
    data = {
        "client.pem": client_cert,
    }
    if Settings.DEVICE_GROUP:
        data["group"] = Settings.DEVICE_GROUP

    headers: dict = {
        "OSF-TOKEN": api_token,
    }
    for x in (0.1, 0.2, 1, 0):
        r = requests.put(
            "https://api.foundries.io/ota/devices/", headers=headers, json=data
        )
        if r.ok:
            return
        msg = f"Unable to create device on server: HTTP_{r.status_code} - {r.text}"
        app.logger.error(msg)
        if x:
            app.logger.info("Trying again in %ds", x)
            sleep(x)
        else:
            abort(500, description=msg)


@app.route("/sign", methods=["POST"])
def sign_csr():
    data = request.get_json()
    if not data:
        abort(400, description="Missing request body")

    csr = data.get("csr")
    if not csr:
        abort(400, description="Missing required field 'csr'")
    if not isinstance(csr, str):
        abort(400, description="Invalid data type for 'csr'")

    overrides = data.get("overrides") or {}
    sota_config_dir = data.get("sota-config-dir") or "/var/sota"

    try:
        fields = sign_device_csr(csr)
    except ValueError as e:
        abort(400, description=str(e))

    if Settings.API_TOKEN_PATH:
        with open(Settings.API_TOKEN_PATH) as f:
            tok = f.read().strip()
            if tok:
                create_in_foundries(fields.client_crt, tok)

    log_device(fields.uuid, fields.pubkey)

    return (
        jsonify(
            {
                "root.crt": fields.root_crt,
                "sota.toml": sota_toml_fmt(overrides, sota_config_dir),
                "client.pem": fields.client_crt,
            },
        ),
        201,
    )
