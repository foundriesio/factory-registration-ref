Foundries.io allows customers to own/manage their own PKI for their factory's
device-gateway. This project provides a reference example of an
lmp-device-register compatible API that can be used with a customer owned
intermediate certificate authority.

This code can be used as-is or forked to accomodate the specific customer
manufacturing needs.

# Requirements:
 * docker-compose
 * git
 * access to your PKI files created/managed via fioctl

# Quick Start

First create/register your PKI with Foundries.io:
~~~
  $ fioctl keys ca create /really-secure-directory
~~~

Next set this project up with:
~~~
 $ git clone https://github.com/foundriesio/factory-registration-ref
 $ cd factory-registration-ref
 $ docker-compose build
~~~

Now copy the required files to this service:
~~~
 $ mkdir -p ./data/certs
 $ cp /really-secure-directory/factory_ca.pem ./data/certs/
 $ cp /really-secure-directory/local-ca.pem ./data/certs/
 $ cp /really-secure-directory/local-ca.key ./data/certs/
 $ cp /really-secure-directory/tls-crt ./data/certs/

 # some of these files are only readable to the file owner. To deal with
 # docker user permissions the easy way:
 chmod +r ./data/certs/*
~~~

You can optionally copy a Foundries.io API token (scope `devices:create`) so
that devices can be defined/configured before the certificate is returned back
to the device. This can be used for setting up device-groups and config so
that a device's first boot will include the proper configuration:
~~~
  # echo <TOKEN> > ./data/fio-api-token
~~~

You can now run this API with:
~~~
 $ docker-compose up
~~~

To register a device, run as root from LmP device:
~~~
 $ DEVICE_API=http://<IP of docker-compose host>/sign lmp-device-register [-T <TOKEN>] [-f <factory>]
~~~

**NOTE** If you're emulating the device with QEMU, by default the gateway (host) IP is `10.0.2.2`.
(i.e. `sudo DEVICE_API=http://10.0.2.2:80/sign lmp-device-register [-T <TOKEN>] [-f <factory>]`)

# Testing/Troubleshooting
This project includes a simple `fake-lmp-device-register` that can be used
to quickly test this project's API. [(More info)](./contrib/fake-register.md)
