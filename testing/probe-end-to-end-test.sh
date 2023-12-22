#!/usr/bin/env bash

# These are the services which we expect to be running as part of this test
# environment stack. We check later once the stack is running to make sure that
# we see them.
declare -A services
services=(
    [0]=probe
    [1]=samba
)

# This flag, if still zero after the service readiness check loop will result
# in the failing.
ready=0

function cleanup {
    docker compose down --timeout 4
    rm metrics.txt
}

trap cleanup EXIT

# Start the containers.
docker compose up -d --wait-timeout 10

# Wait here to make sure we have all the services in the running state.
count=0
while (( count < 30 )); do
    mapfile -t compose_services <<< "$(docker compose ps --status running --services)"

    (( count++ ))
    count_s=0
    for (( i = 0; i < "${#services[@]}"; i++ )); do
        if [ "${compose_services[$i]}" == "${services[$i]}" ]; then
            (( count_s++ ))
        fi
    done
    if [ "${count_s}" -eq "${#services[@]}" ]; then
        ready=1
        break
    fi
    sleep 0.5
done

if [ "${ready}" -eq 0 ]; then
    echo "ERROR: Not all services were ready after 30 seconds" >&2
    exit 1
fi

# Fetch metrics from the service and confirm that it is operational.
have_ops=0
count=0
while (( count < 60 )); do
    (( count++ ))
    if ! curl -sfS localhost:8000/metrics | grep -E -v '^#' > metrics.txt; then
        sleep 2 # Metrics may not be ready yet, just wait a bit and try again.
        continue
    fi

    if awk 'BEGIN { count=0; }
        /smb_operation_latency_seconds_count/ {
            if ($2 > 0) { count+=int($2); } 
        }
        END { if (count < 5) { exit(1)}; }' < metrics.txt; then
        have_ops=1
        break
    fi
    sleep 2
done

if [ ${have_ops} -eq 0 ]; then
    echo "ERROR: Probe validation failed; check logs from the probe container below" >&2
    docker compose logs probe
    exit 1
fi

# Inspect the metrics collected so far and make sure that what we get is what
# we expect to get. Any failure here should result in the test failing.
if ! awk 'BEGIN { count_failed=0; count_above_thresh=0; count_lat=0; }
    /smb_operation_failed_total/ {
        if ($2 > 0) { count_failed+=int($2); } 
    }
    /smb_latency_above_threshold_total{address="smb",domain="TEST.DOMAIN",operation=".*",share="probe[1-2]"}/ {
        count_above_thresh += 1;
    }
    /smb_operation_latency_seconds_count{address="smb",domain="TEST.DOMAIN",operation=".*",share="probe[1-2]"}/ {
        if ($2 > 0) { count_lat+=int($2); }
    }
    END {
        if (count_lat < 34) {
            printf("ERROR: expected count_lat > 0; got %d\n", count_lat);
            exit(1);
        }
        if (count_failed > 0) {
            printf("ERROR: expected count_failed == 0; got %d\n", count_failed);
            exit(1);
        }
        if (count_above_thresh != 10) {
            printf("ERROR: expected count_above_thresh == 10; got %d\n", count_above_thresh);
            exit(1);
        };
    }' < metrics.txt; then

    docker compose logs probe
    echo "=== Probe Metrics Begin ==="
    cat metrics.txt
    echo "===  Probe Metrics End  ==="
    echo "ERROR: Probe validation failed; check logs and look for 'ERROR:' from the actual assertions" >&2
    exit 1
fi

echo "Probe validated successfully!"