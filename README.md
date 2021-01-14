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
 $ cp /really-secure-directory/local_ca.pem ./data/certs/
 $ cp /really-secure-directory/local_ca.key ./data/certs/
 $ cp /really-secure-directory/tls-crt ./data/certs/

 # some of these files are only readable to the file owner. To deal with
 # docker user permissions the easy way:
 chmod +r ./data/certs/*
~~~

You can now run this API with:
~~~
 $ docker-compose up
~~~

From an LmP device:
~~~
 $ DEVICE_API=http://<IP of docker-compose host>/sign lmp-device-register
~~~

# Testing/Troubleshooting
This project includes a simple `fake-lmp-device-register` that can be used
to quickly test this project's API.
