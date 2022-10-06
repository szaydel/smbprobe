# SMB monitoring probe README

The following is an example of how to run the actual probe once it is built from the `Dockerfile`.
docker run -it --rm -p 8000:8000 \
    -v `pwd`/probe.conf:/monitoring/probe.conf \
    -e SMB_MONITOR_PROBE_PASSWD=abcxyz \
    -e SMB_MONITOR_PROBE_CONFIGFILE=/monitoring/probe.conf \
    rts/probe:test

The config file referenced by the `SMB_MONITOR_PROBE_CONFIGFILE` environment variable needs to have contents that look like the following:
```
--address 1.2.3.4
--domain example.com
--share example_share
--username testuser
--remote-file-prefix probedir/testfile
--interval 5
```

In a more production-like setting build the Docker container with the probe. Use `Dockerfile` at the root of this repository and build an image with `docker build -t rts/probe:<some-version> .`. This will generate the image that we will need to use with the compose functionality of Docker. See `docker-compose.yml` for details. This file references the name of the image that will be started along with Prometheus.

Under the `monitoring` directory locate `probe.conf` and edit it to include correct parameters necessary to connect and interoperate with the share. Once done, startup the entire stack with `docker compose`.