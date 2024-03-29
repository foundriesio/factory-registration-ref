from collections import OrderedDict

from registration_ref.settings import Settings


def _mk_config():
    return OrderedDict(
        [
            (
                "tls",
                OrderedDict(
                    [
                        ("server", '"{gateway_server}"'),
                        ("ca_source", '"file"'),
                        ("pkey_source", '"file"'),
                        ("cert_source", '"file"'),
                    ]
                ),
            ),
            (
                "provision",
                OrderedDict(
                    [
                        ("server", '"{gateway_server}"'),
                        ("primary_ecu_hardware_id", '"{hardware_id}"'),
                    ]
                ),
            ),
            (
                "uptane",
                OrderedDict(
                    [
                        ("repo_server", '"{gateway_server}/repo"'),
                        ("key_source", '"file"'),
                    ]
                ),
            ),
            (
                "pacman",
                OrderedDict(
                    [
                        ("type", '"ostree+compose_apps"'),
                        ("ostree_server", '"{ostree_server}/ostree"'),
                    ]
                ),
            ),
            (
                "storage",
                OrderedDict([("type", '"sqlite"'), ("path", '"{sota_config_dir}/"')]),
            ),
            (
                "import",
                OrderedDict(
                    [
                        ("tls_cacert_path", '"{sota_config_dir}/root.crt"'),
                        ("tls_pkey_path", '"{sota_config_dir}/pkey.pem"'),
                        ("tls_clientcert_path", '"{sota_config_dir}/client.pem"'),
                    ]
                ),
            ),
        ]
    )


def sota_toml_fmt(hwid, overrides=None, sota_config_dir="/var/sota"):
    d = _mk_config()
    if overrides:
        for section in overrides:
            if section not in d:
                d[section] = OrderedDict()
            for k, v in overrides[section].items():
                d[section][k] = v

    ret = []
    for section in d:
        ret.append("[{}]".format(section))
        for k, v in d[section].items():
            if v is None or v == "":
                # None or an empty string means unset. (For a literal
                # empty string, use 2 double quote characters, i.e. '""'.)
                ret.append("# {} is not set".format(k))
            else:
                v = v.format(
                    hardware_id=hwid,
                    gateway_server=Settings.DEVICE_GATEWAY_SERVER,
                    ostree_server=Settings.OSTREE_SERVER,
                    sota_config_dir=sota_config_dir,
                )
                ret.append("{} = {}".format(k, v))
        ret.append("")
    return "\n".join(ret).rstrip() + "\n"
