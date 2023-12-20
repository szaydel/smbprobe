[![CodeQL](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml/badge.svg)](https://github.com/szaydel/smbprobe/actions/workflows/codeql.yml)
# SMB monitoring probe
This repository is home to a service level monitoring tool specifically focused around monitoring SMB shares with support for gathering metrics notification triggers in the instances where a problem with a share is detected.

What is a SMB monitoring probe? Our customers commonly operate environments where the SMB file sharing protocol is the primary protocol for access to data on remote systems and vital operations depend on it. It is therefore important to understand whether the quality and availability of the service is consistent and to detect as soon as possible regressions in performance as well as loss of service. The purpose of the probe is to periodically connect to one or multiple _targets_ and validate ability to perform basic IO operations as well as to measure the latency associated with these operations. By _targets_ we mean systems with exposed SMB shares with which the probe can interact (i.e. has access to manipulate files in some directory on the share). This health/performance data is made available via metrics exported using the Prometheus format and when the full stack is deployed, periodically scraped by the Prometheus server. In the environments where Grafana is already leveraged for other monitoring, wiring in this probe becomes a fairly trivial exercise.

## Targets
We use the term _targets_ to generically identify destinations being tested or probed. Each **target** is a combination of domain, address (hostname/IP) and share name. We could have many targets, which would make sense in a larger environment where there are a number of storage systems each exporting one or more SMB shares. 

**Target requirements:**
- Must be exposing SMB shares
- Probe must be configured to connect with service account (user account) that has ability to list contents, read, write and remove files
- The target system is expected to be domain joined

## Security
As is true of similar testing and monitoring tools we require use of a _generic_ aka _service_ account. This is not ideal, but it is hard to eliminate this requirement. Ultimately, the key is to protect the probe's configuration, in particular the `.secrets.toml` file from unauthorized eyeballs, because it contains credentials necessary to access the share. Please, take care to make sure that wherever this probe stack is deployed, access controls are adequate to protect from credential theft. In more typical _Enterprise_ settings this probe is most likely to live on some VM, which may have been provisioned for its sole use. Please, guard access to this VM and consider strict permissions on files containing credentials.

## Docker containers
The **probe** is now a small stack consisting of two small services, one of which actually does the probing and collects data and the other posts notifications if there were notification destinations configured. There is a queue between the two services. Redis is used to implement that durable queue. Messages (notifications) are pushed onto a list by the probe service and they are continuously popped off by the notifier service. The probe service serializes a structure and those bytes are pushed onto the queue. That serialized structure is decoded into the same structure after being popped off by the notifier service.

Both services are quite simple in their design. For the bulk of the work the probe relies on the SAMBA package, and specifically the `smbclient` utility. Delivering the probe packaged as a Docker compose stack makes it much easier to provide all the necessary dependencies described in a neat and tidy git-friendly way, eliminating any version incompatibility or missing dependency concerns. Requirements to run the probe stack are minimal, eliminating need for any SMB utilities on the host. The probe depends on a specific version of the `smbclient` utility, which will all be supplied by the image built from the included `Dockerfile`.

### Container registry
#### Published images
Containers are built from the included Dockerfile(s) and pushed to ghcr.io (GitHub Container Registry) for easy and secure deployment. This is done automatically and does not require any manual intervention on each release. To learn more about container signing, have a look at: [Sigstore container signing quickstart](https://docs.sigstore.dev/signing/quickstart/). It is very important to obtain containers from the trusted source. In the case of this project the _only_ trusted source is ghcr.io. Do not obtain the containers from any other location.

We build two images, `smbprobe` and `smbprobe-notifier` from their respective Dockerfile(s). These are the two containers we build as part of the workflow:
- [SMB probe](https://github.com/szaydel/smbprobe/pkgs/container/smbprobe)
- [SMB probe notifier](https://github.com/szaydel/smbprobe/pkgs/container/smbprobe-notifier)

#### Container authenticity
Containers are built from the included Dockerfile(s) and pushed to ghcr.io (GitHub Container Registry) for easy and secure deployment. Containers are signed at the time of building and these signatures can later be verified. Verification of container image integrity is done through the Sigstore container signing and verification tool called `cosign`. Below we provide two example shell scripts used to verify the signature of the two container images using the `cosign` tool against the public key from the GitHub Actions workflow that produced the given images. This verification assures the user that the image was built from the expected source code and has not been tampered with. Validation is specific to a branch on which the workflow originally ran. This ensures that images built from code on the master branch will _only_ pass verification when parameters are specific to the master branch. It is important to note that these scripts use example images. In order to verify a specific image the `TAG` and `DIGEST` values would need to be updated to match the actual image being verified. When retrieving images from the registry it is best practice to always verify signatures to check for any modifications during transit.

Published images in the GHCR are going to be presented with the following syntax for digests: `sha256-{actual SHA256 value}.sig`, for example: `sha256-14b5bf41c0a939e3d3ecd7c08eb41dd2f5797858dfed3aa9967c4ac9240ee6ab.sig`. Take just the actual **SHA256** digest value and use this value prefixed with `sha256:` for the `DIGEST` variable when verifying the images. The `REF` and `TAG` variables will normally be pointing to master. Typical `REF` will be: `"refs/heads/master"` and `TAG` will be `"ghcr.io/szaydel/smbprobe:latest"` The `WORKFLOW` URL stays the same.

The following shell snippet should be copied into a new file called `verify-smbprobe.sh` and run to verify the integrity of the `smbprobe` container image.

```shell
#!/usr/bin/env bash

REF="refs/heads/topic/szaydel/add-notifications"
TAG="ghcr.io/szaydel/smbprobe:topic-szaydel-add-notifications"
DIGEST="sha256:14b5bf41c0a939e3d3ecd7c08eb41dd2f5797858dfed3aa9967c4ac9240ee6ab"
WORKFLOW="https://github.com/szaydel/smbprobe/.github/workflows/docker-publish.yml"

cosign verify \
    --rekor-url="https://rekor.sigstore.dev/" \
    ${TAG}@${DIGEST} \
    --certificate-identity="${WORKFLOW}@${REF}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
    | jq .
```

The following shell snippet should be copied into a new file called `verify-smbprobe-notifier.sh` and run to verify the integrity of the `smbprobe-notifier` container image.

```shell
#!/usr/bin/env bash

REF="refs/heads/topic/szaydel/add-notifications"
TAG="ghcr.io/szaydel/smbprobe-notifier:topic-szaydel-add-notifications"
DIGEST="sha256:b52d1dc4c8cf7337736dd70ea330f8f35d6612b37a95297f2f2ca31bb473881c"
WORKFLOW="https://github.com/szaydel/smbprobe/.github/workflows/docker-publish.yml"

cosign verify \
    --rekor-url "https://rekor.sigstore.dev/" \
    ${TAG}@${DIGEST} \
    --certificate-identity="${WORKFLOW}@${REF}" \
    --certificate-oidc-issuer="https://token.actions.githubusercontent.com" \
    | jq .
```

## Production deployment
### Running the probe stack
Use the provided example `docker-compose.yml.example` file as a starting point. In the typical case no changes to this file will be required. This will start the Redis queue, SMB probe service, notification service (if configured), and the Prometheus server. This stack is expected to run on systems that live on the same networks as the SMB clients whose performance and accessibility to the share we are interested in, so that we can experience similar network conditions with the probe.
The following is an example of how to run the actual probe once it is built from the `Dockerfile`. While this is good for rapid testing, a `docker-compose.yml` file is provided to make it easier to run this environment as a service. Prometheus container is started along with the SMB probe container and the SMB probe container is automatically scraped by the Prometheus server. Prometheus server will be accessible at `localhost:9090`, though there is no authentication by default. You have been warned!

[//]: # (FIXME: Need to improve this language)
The service containers we build (i.e. not Redis, Prometheus, etc.) are published via the GHCR and rebuilt when changes are made to master. Bring up the stack with `docker compose up -d`. If you want to keep Docker in the foreground for debugging, omit the `-d`.

### Probe configuration files
**TOML** was chosen as the configuration file format. It has a number of benefits over **JSON** and **YAML**, both of which were considered previously and rejected. There must be one or more `[[probes]]` sections in the configuration, each describing a target to monitor. This file is assumed to be in the `config` directory, which is at the root of this repository. Should you elect to move the file elsewhere, an update to the `docker-compose.yml` would be required to mount the correct location into the container.

Notifications are configured in the same file using a `[[notifications]]` section. This was chosen to keep all configuration related to probing and notifications together in a single file for simplicity. There are a few downsides to this approach, but the upside is fewer configuration files to keep track of. We designed round the configuration residing in the `config` directory and the actual files in the directory are bind-mounted into the container at runtime. In the example docker-compose file you will note both the `probe` and the `notifier` services configured with two volumes, one for the configuration file and one for the secrets file.

> Volumes block from `docker-compose.yml`
> ```yaml
> volumes:
>    - ./config/probe.toml:/config/probe.toml
>    - ./config/.secrets.toml:/config/.secrets.toml
>```

> Minimal valid configuration with one probe target and no notifications:
> ```toml
> [[probes]]
> name = "" # This is optional and not yet used
> address = "192.168.1.100" # IP address or hostname of the target system
> domain = "target.example.com" # Domain with which our target is joined
> share = "share01" # Name of the share to attach to
> username = "probeuser" # The service username with which to test
> password = "@format {this.secrets.users.probeuser}"
> remote_basedir = "." # Where on the share the test files will be created and removed from
> interval = 60 # Interval in seconds between probing attempts
> ```

#### Multiple configurations for the same share

The probe is able to monitor:
- Multiple shares on multiple systems (likely in HA scenarios with pools on both nodes)
- Same share on one system, accessed via multiple addresses, perhaps using one or more DNS names and/or IP addresses
- Multiple shares on the same system, which may or may not be on the same physical storage

It is not unreasonable to have more than one configuration for one share. A share may be accessible via multiple IP addresses, via DFS, DNS name, i.e. Kerberos, etc. There are circumstances where access via an IP address is fast and via a DNS name slow, due to factors like name resolution, or Kerberos authentication, etc. Each probe is distinguished by a triple of address, domain and share. As long as there are no two entries where these three elements are identical all probes (assuming credentials are correct and shares are reachable) will coexist and will be processed correctly. Multiple entries where this triple is identical are not expected to work correctly. One small caveat is that the `remote_basedir` may have to be different for probes looking at the same share. Files are named randomly, thus there is very small chance of interaction between the probes. However, the probes will each list contents of the directory and if several probes are placing files into the same directory listing time may be affected slightly. This has not been tested, thus is purely speculative.

#### Sensitive credential information
One thing to note is that the password is using a bit of an obscure syntax in the `probe.toml` configuration file. This syntax allows us to keep the passwords in a separate file and reference them without including the plaintext values in the configuration file itself. It is certainly possible to directly reference the password in the configuration file, but separating them means that it is possible to apply different permissions to these files, thus limiting access even further by having more restrictive permissions on the `.secrets.toml` file. The `{this.secrets.users.probeuser}` template will result in the probe looking up the password value from the `config/.secrets.toml` file at the time this template is rendered. Should you elect to move this file elsewhere, an update to the `docker-compose.yml` would be required to mount the correct location into the container. The file must start with `[secrets.users]`. This is necessary so as to create the correct namespace for the probe to lookup the password value. Expect the probe to crash continuously if the format is not valid.

The contents of the file beyond the first line are `key = value` pairs where the key is the **username** and the **password** is the corresponding password for this account. In a typical _Enterprise_ setting this account will be an Active Directory (or similar, LDAP, etc.) account. This project was built with the _Enterprise_ in mind, thus the account is assumed to be a _service_ account which isn't going to have an expiry or require periodic password changes. That being said, it is important to have a password rotation policy for _all_ service accounts. It is trivial to change the value in the `.secrets.toml` file and simply restart the probe stack.

> Minimal valid `.secrets.toml` file:
> ```toml
> [secrets.users]
> probeuser = "probepassword"
> ```

### Notifications
This functionality is still quite young and calling it _beta_ would be rather generous. We are adding support for a few different notification mechanisms. We added support for Better Stack and PagerDuty right away, because they are useful targets for alert generation. Microsoft Teams support was added as well. It is also possible to send notifications to more "generic" destinations. One basic requirement is that the requests are POSTs. We _only_ support **HTTP POST** currently. Because destinations are quite different and some have much richer support for various formatting and _styling_ than others, presentation of the same information will vary pretty significantly. We can always work on improving this styling and its consistency.

#### Generalizations
Because different notification services are fundamentally different we made the decision to generalize things like the _integration key_. Services like PagerDuty have a concept of an _integration key_ which is a unique identifier for an account. PagerDuty happens to call it the _routing key_. This key identifies the service and allows for the notifications to be associated with the correct account. As we add support for more such alerting services in the future we are going to encounter more instances of such identification and/or authorization. We may have other generalizations in the future, but _integration key_ is the one we are likely to see more of.

#### How notifications work
If enabled (i.e. one or more notification destinations are configured), messages are formatted according to what is supported by the configured destination and POST'ed when the number of allowed probe failures exceeds the threshold. The probe is repeatedly connecting to the targets that it is configured to probe and each time there are issues with the target, the probe will push a message onto the queue which the notifier service is going to receive and examine. The notifier service keeps track of each probe by an id that is derived from the unique details of the probe. The notifier service will then examine the queue and if it finds a message for a probe that has not yet been notified, it will POST the message to the configured destination. The notifier service will also keep track of the number of times it has posted a notification for this particular event and will not notify again, at least for this event. The mechanism behind this deduplication is quite straight-forward. If the notifier service is restarted, it will start with a clean slate. It does not have any persistent memory. However, this also means that it can _forget_ about the probe that is detecting an issue and this can result in a duplicate incident to be created. While this is not a serious issue it could be an operational annoyance. The notifier service should normally remain running unless manually restarted. The service will also be restarted by Docker if there is a crash (i.e. encounters a previously undetected bug).

#### Thresholds and resolutions
One of the command line arguments to the notifier service is the `--consecutive-fails-limit` argument, which sets the limit for the number of failures a given probe is allowed to see before a notification is going to be triggered. This argument is present in the `docker-compose.yml.example` file. The default value when not explicitly set is 3. This means that if the probe fails 3 times in a row, a notification will be triggered. The notifier service will also keep track of the number of times it has posted a notification for this particular event and will attempt to avoid notifying again, at least for this event for as long as this event is active. The probe service pushes notifications onto the queue even when the probes are healthy. This makes it easier for the notifier service to detect when the given probe _recovers_ and if it was previously reported as having issues, once it recovers the notifier service is expected to post another message to the configured destinations reporting that a previously detected issue has been resolved and that the probe is healthy again.

#### Better Stack
We support Better Stack and post notifications that should trigger an alert. This is a minimally functional Better Stack configuration. The integration key is actually passed along as the Bearer auth token.

```toml
[[notifications]]
integration_key = "your integration key here"
source_email = "alerting@example.com"
target = "better-stack"
```

#### Generic destinations
We also support generic destinations. POST is still the only allowed HTTP command, but otherwise the configuration is similar and very flexible. In fact, one can pass whatever headers one chooses, which should allow for this to be used in most settings and situations. Because there is not a well known destination URL, one has to be provided. Include any necessary headers as in the example given below.

```toml
[[notifications]]
headers = {"custom-header-1" = "alpha", "custom-header-2" = "beta"}
target = "generic-post"
url = "https://example.com/api/v1/probe-notifications"
```

#### PagerDuty
We support Pager Duty and post notifications that should trigger an alert. This is a minimally functional PagerDuty configuration.

```toml
[[notifications]]
integration_key = "your integration key here"
severity = "error"
target = "pager-duty"
```

#### Microsoft Teams destinations
We also support Microsoft Teams and post notifications via the inbound Webhooks. This is a minimally functional Microsoft Teams configuration. Because there is not a well known destination URL, one has to be provided.

```toml
[[notifications]]
url = "https://example.com/api/v1/probe-notifications"
target = "msft-teams"
```

## Outputs from the Probe
### Logging from the SMB probe container
To make log-based metrics easier we include an example syslog configuration in the `docker-compose.yml.example` file. Uncommenting and configuring the `logging` section in the `probe` service block is going to enable automatic log forwarding via `syslog` to the configured destination. It is easy to test this locally with `netcat`, unless TLS configuration is enabled. Further details are available in Docker documentation about the [Docker Syslog logging driver](https://docs.docker.com/config/containers/logging/syslog).
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

## Development and experimentation
### Requirements
- Python 3
- Docker with docker-compose support
- Make (we assume GNU make)

### Docker images
During development after you make changes to the code it will be necessary to build new containers. Containers are built by executing `make docker-build-test-images`. Yes, we assume GNU Make is present on the system. Replace `make` with `gmake` if on your system `make` isn't an alias for `gmake`. This will generate the images that we will need to use with Docker's compose functionality. See `docker-compose.yml` for details. This file describes the entirety of the stack including Redis and Prometheus containers. It will be necessary to customize the `docker-compose.yml` file and change the image names/tags to reflect the names of the images built locally. Once the images are built and `docker-compose.yml` updated, you can start the stack locally by running `docker-compose up -d` from the root of the repository. This will start all the services in the background. To stop the stack run `docker-compose down`. It is perfectly fine to disable the Prometheus service container by commenting out the lines belonging to it in the `docker-compose.yml` file during development/experimentation. This is really the only truly optional container.

### Getting started
My typical development environment uses the `virtualenv` Python module, which makes it easy to maintain a self-contained, largely host-independent environment. There is a `requirements-dev.txt` file in the root of the repository that lists all the Python dependencies needed to lint, test, etc. If you already enabled `virtualenv` or choose not to use it for any reason, install these requirements with `pip install -r requirements-dev.txt`. Otherwise, to setup a branch new development area, run `make setup`, which will create a new `virtualenv` environment in the `venv` directory and install the necessary dependencies.

### Testing and code formatting
#### Unit tests
There is unit test coverage, somewhat porous but existing and needs more work. Please, be sure to run tests with `make unittest`.

#### Style and linting
We use `black` and `ruff` to format and lint the code. To run them locally run `make lint`.