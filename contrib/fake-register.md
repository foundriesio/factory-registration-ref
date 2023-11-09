# Testing/Troubleshooting

This project includes a simple [fake-lmp-device-register](./fake-lmp-device-register) tool.
This tool mimics the behavior of `lmp-device-register`, enabling you to quickly test this project's API
without a real device.

## Running the fake-lmp-device-register

### Dependencies:
- Python 3
- `requests` Python library
- `openssl` command-line tool
- `curl` command-line tool

### Usage:

**To Register the Device:**

You will need define a directory where the fake device config and certificates by using the `--sota-dir` flag:

```shell
pip3 install requests
python3 fake-lmp-device-register --registration-url "http://<IP of docker-compose host>:80/sign" --factory <factory> --sota-dir <path-to-sota-dir>
```

**To Verify Connectivity with the Server**

1. Inspect the server URL configured in the `sota.toml` file:

```shell
cd path/to/sota-dir
$ cat sota.toml 
```

You should see an output similar to:

```shell
[tls]
server = "https://ec056c71-d698-41a6-bea0-1f1ac8c44bde.ota-lite.foundries.io:8443"
ca_source = "file"
pkey_source = "file"
cert_source = "file"
...
```

2. Use curl to verify connectivity with the server:

```shell
$ ./curl https://ec056c71-d698-41a6-bea0-1f1ac8c44bde.ota-lite.foundries.io:8443/repo/root.json                                                                 
```