[![CodeQL](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml/badge.svg)](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml)
# SMB monitoring probe
What is a SMB monitoring probe? Our customers are perating environments where SMB is a critical protocol and vital operations depend on it. It is therefore important to understand whether the quality and availability of the service is consistent and to detect as soon as possible regressions from the mean. The purpose of the probe is to periodically connect to any number of _targets_ and validate ability to perform basic IO operations as well as to measure the latency associated with these operations. This data is made available via metrics exported using the Prometheus format and when the full stack is deployed, periodically scraped by the Prometheus server. In the environments where Grafana is already leveraged for other monitoring, wiring in this probe becomes a fairly trivial exercise.

We use the term _targets_ to identify destinations being tested or probed. Each **target** is a combination of domain, address (hostname/IP) and share name. We could have many targets, which would make sense in a larger environment where there are a number of storage systems each exporting one or more SMB shares.
## Building the container
The probe is a standalone Python program, which has a few dependencies. The program itself is quite simple and for the bulk of the work it relies on the SAMBA package, and specifically the `smbclient` utility. Delivering the probe packaged as a Docker container makes it much easier to provide all the necessary dependencies with the container, eliminating any version incompatibility or missing dependencies on the host type of concerns. Requirements to run the container are minimal, eliminating need for any SMB utilities on the host. The probe depends on a specific version of the `smbclient` utility, which will all be supplied by the image built from the included `Dockerfile`.

For all development and experimentation, use the `Dockerfile` at the root of this repository and build an image with `make docker-build`. Yes, we assume GNU Make is present on the system. This will generate the image that we will need to use with Docker's Compose functionality. See `docker-compose.yml` for details. This file references the name of the image that will be started along with Prometheus.

## Running the probe stack
The _stack_ is actually a combination of the probe program and Prometheus server. We may add other things in the future to support additional functionality, such as Webhooks.
The following is an example of how to run the actual probe once it is built from the `Dockerfile`. While this is good for rapid testing, a `docker-compose.yml` file is provided to make it easier to run this environment as a service. Prometheus container is started along with the SMB probe container and the SMB probe container is automatically scraped by the Prometheus server. Prometheus server will be accessible at `localhost:9090`, though there is no authentication by default. You have been warned!

The container is published via the GHCR and rebuilt when changes are made to master. Download the latest container image with `docker pull ghcr.io/szaydel/smbprobe:latest`.
```
docker run -it --rm -p 8000:8000 \
    -v `pwd`/probe.conf:/monitoring/probe.conf \
    -e SMB_MONITOR_PROBE_CONFIGFILE=/monitoring/probe.conf \
    ghcr.io/szaydel/smbprobe:latest
```

### Configuration file
**TOML** was chosen as the configuration file format. It has a number of benefits over **JSON** and **YAML**, both of which were considered previously and rejected. The configuration file is assumed to have one or more sections, each having a _descriptive_ title, such as: `[probe-abc-xyz]`, and providing details necessary to monitor this target. The _service_ account used with each such target must have write permissions to the share, because part of the probing process is to write data to the share, read it back and eventually remove the files.

Probe is able to monitor:
- Multiple shares on multiple systems (likely in HA scenarios with pools on both nodes)
- Same share on one system, accessed via multiple addresses, perhaps using one or more DNS names and/or IP addresses
- Multiple shares on the same system, which may or may not be on the same physical storage

While it is permissible to include the password in the configuration file, it is not recommended. It makes the configuration file a serious liability and makes it impossible to commit to a source control (git) repository due to credential leaking. This approach is suitable for testing, demos, etc., but **do not use it in production settings**. Instead, as in **Example 2** it is better to use environment variables. Anything starting with `$ENV_` in the `password` field is interpreted as a name of an environment variable, and its value will be looked-up in the current environment. As long as this variable exists in the container at the time the configuration file is loaded, the password will be taken from this environment variable. This is quite flexible, since each configuration block of which there could be one or multiple, can specify their own environment variable name. If the same account is used for all monitoring then a single environment variable is sufficient, but in those cases where each target is specified with a different account, simply use different variable names, ideally making them as descriptive as possible, without leaking sensitive details.

The following is an example of a minimal configuration file. The probe is capable of monitoring multiple targets. These targets need not be multiple systems.

**Example 1 (not secure; avoid):**
```
[probe1]
address = "system.alpha.example.com"
domain = "example.com"
share = "smb01"
username = "probeuser"
password = "somepassword"
remote_basedir = "."
interval = 5
```
**Example 2 (more secure; preferred):**
```
[probe1]
address = "system.alpha.example.com"
domain = "example.com"
share = "smb01"
username = "probeuser"
password = "$ENV_PASSWORD_PROBE1"
remote_basedir = "."
interval = 5
```

The location of the config file may be referenced by the `SMB_MONITOR_PROBE_CONFIGFILE` environment variable. It is assumed that a bind mount is used to pass the configuration file from the host into the container. It is likewise possible to use the `--config-file` command line argument. Either approach works well in the `docker-compose.yml` file.

Under the `monitoring` directory locate `probe.conf.example`, copy it to `probe.conf` and edit it to include correct parameters necessary to connect and probe all targets in your environment.

Once done, start the entire stack with `docker compose up`. To stop the stack it is possible to issue `docker compose stop` and then restart with `docker compose start`. It is also possible to restart the entire stack with `docker compose restart`.

## Outputs from the Probe
### Logging from the SMB probe container
To make log-based metrics easier we include an example syslog configuration in the `docker-compose.yml` file. Uncommenting and configuring the `logging` section in the `probe` service block is going to enable automatic log forwarding via `syslog` to the configured destination. It is easy to test this locally with `netcat`, unless TLS configuration is enabled. Further details are available in Docker documentation about the [Docker Syslog logging driver](https://docs.docker.com/config/containers/logging/syslog).
> If after enabling logging the following error is seen:
> ```
> Error response from daemon: failed to initialize logging driver: dial tcp <address>:<port>: connect: connection refused
> ```
> ...be sure to check that the destination syslog server is correct. It should be possible to verify connectivity to it with `openssl` (if TLS is enabled) or `nc` if plain TCP/UDP.

### Collected metrics
- `smb_service_state` - State of the service based on the observations performed by the probe. If everything is successful and latency threshold has not been breached status will be 0.
- `smb_operation_latency_seconds` - Latency observations made for each aspect of the testing performed by the probe, by operation.
- `smb_latency_above_threshold_total` - Tracks whether the probe has observed excessive latency in one or more operations, by operation.
- `smb_operation_failed_total` - Counts the number of operations that were not successful, by operation.