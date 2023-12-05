import pickle
import redis
import redis.exceptions

from typing import Dict, List, Tuple

from classes import ProbeHealth

from common.constants import DEFAULT_NOTIFICATIONS_LIST_NAME

from common.notifications.classes import Data, Notification, Result

from log import LOGGER

from notifications import post_all_notifications


def probe_state_notification_needed(
    key: str,
    probes_health: Dict[tuple[str, str, str], ProbeHealth],
    incident_event_id: Dict[tuple[str, str, str], str],
) -> bool:
    # Given key does not exist in the probes_health tracking dict.
    if probes_health.get(key) is None:
        return False

    is_healthy = not probes_health[key].is_unhealthy

    if probes_health[key].should_notify and incident_event_id.get(key) is None:
        return True

    return is_healthy and incident_event_id.get(key) is not None


def post_and_update_if_necessary(
    key: str,
    probes_health: Dict[tuple[str, str, str], ProbeHealth],
    incident_event_id: Dict[tuple[str, str, str], str],
    notifications: List[Notification],
) -> List[Result] | None:
    if probes_health.get(key) is None:
        return None

    # We skip further notifications if there is still an issue with the
    # probe and we previously generated notifications for this
    # particular issue. If notifications were generated, then the
    # event_id we store in incident_event_id will match the event_id
    # field in given instance of the ProbeHealth class.
    if (
        incident_event_id.get(key) is not None
        and incident_event_id[key] == probes_health[key].event_id
    ):
        return None

    LOGGER.debug(
        "Posting incident: incident_event_id[key]={} probes_health[key].event_id={}".format(
            incident_event_id[key], probes_health[key].event_id
        )
    )

    results = post_all_notifications(probes_health[key].data, notifications)

    # Update incidents tracking dict with the event_id of the current
    # incident so we skip further notifications for this same issue.
    incident_event_id[key] = probes_health[key].event_id

    return results


def rpop_from_list_and_decode(
    db: redis.Redis,
) -> Tuple[Data, None] | Tuple[None, Exception]:
    data = None
    try:
        _, item = db.brpop(DEFAULT_NOTIFICATIONS_LIST_NAME)
        data: Data = pickle.loads(item)
    except redis.exceptions.ConnectionError as err:
        return None, err
    return data, None


def pop_from_queue_and_process_forever(
    db: redis.Redis,
    notifications: List[Notification],
    only_post_failures=False,
    max_failed_intervals=0,
) -> Exception | None:
    probes_health: Dict[tuple[str, str, str], ProbeHealth] = {}
    incident_event_id: Dict[tuple[str, str, str], str] = {}

    # Popping from Redis will block the loop until there is data to pop-off of
    # the list. By default blocking is indefinite, i.e. no timeout is set.
    while True:
        data, err = rpop_from_list_and_decode(db)
        if not data:
            return err

        # If we don't have any notification destinations, just make sure to
        # pop the elements pushed into Redis and do nothing. We don't want to
        # let the list grow unbounded.
        if not notifications:
            continue

        key = data.id

        # If we are not yet aware of this probe, register it in the tracking dicts.
        if key not in probes_health:
            probes_health[key] = ProbeHealth(max_failed_intervals)

        if key not in incident_event_id:
            incident_event_id[key] = None

        probes_health[key].update_health(data)

        # Do not post anything if the following is true:
        # - The probe is currently healthy
        # - There is no existing incident, thus we don't need to resolve
        # - Notifications are only sent when there are failures
        if not probes_health[key].is_unhealthy:  # Probe is healthy
            if not incident_event_id[key] and only_post_failures:
                continue

        # If the probe is unhealthy and threshold has been exceeded, we need to
        # notify. Likewise if things are now healthy, but we did not report
        # remediation, we need to notify.
        if probe_state_notification_needed(key, probes_health, incident_event_id):
            LOGGER.debug("Will post notifications at this point")
            LOGGER.debug("Posting: {}".format(probes_health[key].data))
            LOGGER.debug("Latest event_id: {}".format(probes_health[key].event_id))

            results = post_and_update_if_necessary(
                key, probes_health, incident_event_id, notifications
            )

            if results is None:
                LOGGER.debug(
                    "Skipping previously posted incident with id: {}".format(
                        incident_event_id[key]
                    )
                )
                continue

            for res in results:
                if not res.success:
                    LOGGER.error(
                        "Failed posting notification",
                        extra={
                            "body": res.resp_body,
                            "resp_dict": res.resp_dict,
                            "status_code": res.resp_code,
                        },
                    )

    return None  # Never reached


def resolution_notification_required(
    key: str,
    probes_health: Dict[tuple[str, str, str], ProbeHealth],
    incident_event_id: Dict[tuple[str, str, str], str],
):
    return all(
        [
            not probes_health[key].is_unhealthy,
            incident_event_id[key] is not None,
        ]
    )
