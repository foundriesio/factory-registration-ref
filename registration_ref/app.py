import os
from time import sleep
from typing import Optional

from flask import Flask, abort as fabort, jsonify, make_response, request
import requests

from registration_ref.crypto import sign_device_csr
from registration_ref.sota_toml import sota_toml_fmt
from registration_ref.settings import Settings

import logging

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.DEBUG)
log = logging.getLogger(__name__)

app = Flask(__name__)


def abort(status_code, description):
    response = make_response(description)
    response.status_code = status_code
    fabort(response)


@app.before_request
def _auth_user():
    log.debug("Received request from client IP: %s", request.remote_addr)
    # Add further authentication checks and log if required
    pass

def log_device(uuid: str, pubkey: str):
    # Keep a log of created devices
    log.debug("Logging device with UUID: %s, pubkey: %s", uuid, pubkey)
    with open(os.path.join(Settings.DEVICES_DIR, uuid), "w") as f:
        f.write(pubkey)


def create_in_foundries(client_cert: str, api_token: str, name: Optional[str] = None):
    log.info("Initiating device creation in foundries")

    data = {
        "client.pem": client_cert,
    }
    if Settings.DEVICE_GROUP:
        data["group"] = Settings.DEVICE_GROUP
    if name:
        data["name"] = name

    headers: dict = {
        "OSF-TOKEN": api_token,
    }
    for x in (0.1, 0.2, 1, 0):
        r = requests.put(
            Settings.DEVICE_REGISTRATION_API,
            headers=headers,
            json=data,
            verify=Settings.VERIFY_SSL
        )
        if r.status_code == 409:
            log.error("Device creation conflict detected: %s", r.text)
            abort(409, description=r.text)
        if r.ok:
            log.info("Device successfully created in foundries")
            return
        log.error("Unable to create device on server: HTTP_%s - %s", r.status_code, r.text)
        if x:
            log.info("Retrying device creation in %ds", x)
            sleep(x)
        else:
            log.error("Failed to create device after retries. Aborting!")
            abort(500, description=r.text)


@app.route("/sign", methods=["POST"])
def sign_csr():
    log.info("Received CSR signing request")

    data = request.get_json()
    if not data:
        log.error("Request body missing in CSR signing request")
        abort(400, description="Missing request body")

    csr = data.get("csr")
    if not csr:
        log.error("Field 'csr' missing in CSR signing request")
        abort(400, description="Missing required field 'csr'")
    if not isinstance(csr, str):
        log.error("Invalid data type for 'csr'")
        abort(400, description="Invalid data type for 'csr'")

    hwid = data.get("hardware-id")
    if not hwid:
        log.error("Field 'hardware-id' missing in CSR signing request")
        abort(400, description="Missing required field 'hardware-id'")

    overrides = data.get("overrides") or {}
    sota_config_dir = data.get("sota-config-dir") or "/var/sota"
    name = data.get("name") or None

    if data.get("group"):
        log.error("Field 'group' not supported in CSR signing request")
        # Since we run w/o any authentication, allowing devices to determine
        # their device group is too dangerous to allow by default. We instead
        # allow a server defined config, Settings.DEVICE_GROUP.
        abort(400, description="Registration-reference does not support 'group' field")

    try:
        fields = sign_device_csr(csr)
        log.info("CSR successfully signed")
    except ValueError as e:
        log.error("Error while signing CSR: %s", str(e))
        abort(400, description=str(e))

    if Settings.API_TOKEN_PATH:
        with open(Settings.API_TOKEN_PATH) as f:
            tok = f.read().strip()
            if tok:
                log.info("Creating in foundries with %s", fields.uuid)
                create_in_foundries(fields.client_crt, tok, name)

    log_device(fields.uuid, fields.pubkey)
    log.info("CSR signing request successfully processed. Responding to client.")
    return (
        jsonify(
            {
                "root.crt": fields.root_crt,
                "sota.toml": sota_toml_fmt(hwid, overrides, sota_config_dir),
                "client.pem": fields.client_crt,
                "client.chained": fields.client_crt + "\n" + Settings.CA_CRT,
            },
        ),
        201,
    )
