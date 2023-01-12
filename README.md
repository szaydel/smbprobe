[![CodeQL](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml/badge.svg)](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml)
# SMB monitoring probe
## Building the container
The probe is a standalone python program, which has a few dependencies. The program itself is quite simple and for the bulk of the work it relies on the SAMBA package, and specifically the `smbclient` utility. Delivering the probe packaged as a Docker container makes it much easier to provide all the necessary plumbing with the container, eliminating any version incompatibility or missing dependencies on the host type of concerns. Requirements to run the container are minimal, eliminating need for any SMB utilities on the host. The probe depends on a specific version of the `smbclient` utility, which the image built from the provided `Dockerfile` will contain. Use the `Dockerfile` at the root of this repository and build an image with `docker build -t rts/probe:<some-version> .`. This will generate the image that we will need to use with the compose functionality of Docker. See `docker-compose.yml` for details. This file references the name of the image that will be started along with Prometheus.

The contents of `docker-compose.yml` will work seamlessly if we build the container as follows:
```
$ docker build -t rts/probe:latest -t rts/probe:$(git rev-parse --short HEAD).
```

## Running the probe stack
The _stack_ is actually a combination of the probe and Prometheus server. We may add other things in the future to support additional functionality, such as webhooks.
The following is an example of how to run the actual probe once it is built from the `Dockerfile`. While this is good for rapid testing, a `docker-compose.yml` file is provided to make it easier to run this environment as a service. Prometheus container is started along with the SMB probe container and the SMB probe container is automatically scrabed by the Prometheus server.

The container is published via the GHCR and rebuilt when changes are made to master. Download the latest container image with `docker pull ghcr.io/szaydel/smbprobe:latest`.
```
docker run -it --rm -p 8000:8000 \
    -v `pwd`/probe.conf:/monitoring/probe.conf \
    -e SMB_MONITOR_PROBE_PASSWD=abcxyz \
    -e SMB_MONITOR_PROBE_CONFIGFILE=/monitoring/probe.conf \
    ghcr.io/szaydel/smbprobe:latest
```

The config file referenced by the `SMB_MONITOR_PROBE_CONFIGFILE` environment variable needs to have contents that look like the following:
```
--address 1.2.3.4
--domain example.com
--share example_share
--username testuser
--remote-file-prefix probedir/testfile
--interval 5
```
Under the `monitoring` directory locate `probe.conf` and edit it to include correct parameters necessary to connect and interoperate with the share. It is possible to include more than one instance of `--address` in order to probe the same machine via multiple IPs, DNS name, etc. Simply, include more than one instance of `--address <some address>` or include more than one `--address` entry in the config file.

Once done, startup the entire stack with `docker compose up`. To stop the stack it is possible to issue `docker compose stop` and then restart with `docker compose start`.

## Logging from the SMB probe container
To make log-based metrics easier we include an example syslog configuration in the `docker-compose.yml` file. Uncommenting and configuring the `logging` section in the `probe` service block is going to enable automatic log forwarding via syslog to the configured destination. It is easy to test this locally with `netcat`, unless TLS configuration is enabled. Further details are available in Docker documentation about the [Docker Syslog logging driver](https://docs.docker.com/config/containers/logging/syslog).
> If after enabling logging the following error is seen:
> ```
> Error response from daemon: failed to initialize logging driver: dial tcp <address>:<port>: connect: connection refused
> ```
> ...be sure to check that the destination syslog server is correct. It should be possible to verify connectivity to it with `openssl` (if TLS is enabled) or `nc` if plain TCP/UDP.
