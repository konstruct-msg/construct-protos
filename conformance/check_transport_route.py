#!/usr/bin/env python3
"""The transport-route vectors are the ones this script builds.

`transport_route.json` fixes when a client leaves the direct path for VEIL and when it comes back:
the state machine iOS has in `TransportReducer.swift` (plus the two rules `TransportRouter.swift`
applies around it) and Android in `transport/TransportRoute.kt`. It is not protocol — two clients
deciding differently still read each other's messages — so each platform keeps its own
implementation, and both run these cases so neither drifts without a red test.
Decision: construct-docs decisions/transport-route-per-platform-shared-vectors.md.

Every RPC event names its `lane`: `auth` (the authenticated channel, which also carries the stream)
or `sealed` (the channel with no identity, its own connection). VEIL counts soft failures per lane.

A rotation that blames the front it leaves starts with `demote_relay` naming it: the platform
records a failure for that front, so the next start prefers another. Without it a front that takes
the connection and then carries nothing was picked again by the same restart (the start only
checks that the front answers), and the rotation changed nothing. A rotation for a reason that is
not the front's — a dead local proxy, a background wake, a config change — demotes nothing.
Forgiving the front again is the platform's pool, not this machine: it clears on a start that
comes up on it.

A case either asks for the starting state (`initial`) or runs `events` from `state` under `mode`
and expects the final state and the effects of the last event, in order. Times are Unix
milliseconds; `now_ms` is fixed per case.

`--write` regenerates the file; without it, the file must equal what this builds.
"""

import json
import sys
from pathlib import Path

VECTORS = Path(__file__).resolve().parent / "transport_route.json"

NOW = 1_000_000
RELAY = "relay.example:443"
PORT = 49262
COOLDOWN = 30_000


def direct(fails):
    return {"kind": "direct", "fails": fails}


PROBING = {"kind": "veil_probing"}
OFFLINE = {"kind": "offline"}
SOFT_FAIL_THRESHOLD = 3


def active(auth=0, sealed=0, since_ms=1, port=PORT):
    """VEIL up. `soft_fails`: soft transport failures in a row through it, per channel (lane)."""
    return {"kind": "veil_active", "relay": RELAY, "port": port, "since_ms": since_ms,
            "soft_fails": {"auth": auth, "sealed": sealed}}


ACTIVE = active()


def rpc_failed(failure, via="direct", foreground=True, lane="auth"):
    return {"kind": "rpc_failed", "failure": failure, "via": via, "foreground": foreground, "lane": lane}


def rpc_succeeded(via="direct", lane="auth"):
    return {"kind": "rpc_succeeded", "via": via, "latency_ms": 50, "lane": lane}


def stream_failed(failure, via="direct", method="h2"):
    return {"kind": "stream_failed", "method": method, "failure": failure, "via": via}


def eff(kind, **fields):
    return {"kind": kind, **fields}


STOP, START, INVALIDATE = eff("request_proxy_stop"), eff("request_proxy_start"), eff("invalidate_grpc_client")
UNROUTE = eff("set_veil_port", port=None)
ROTATE = [STOP, UNROUTE, START, INVALIDATE]
DEMOTE = eff("demote_relay", relay=RELAY)
ROTATE_AWAY = [DEMOTE] + ROTATE


def case(name, state, mode, events, expect_state, expect_effects, config=None):
    c = {"name": name, "state": state, "mode": mode, "events": events,
         "expect_state": expect_state, "expect_effects": expect_effects}
    if config:
        c["config"] = config
    return c


def build():
    cases = [
        {"name": "initial_auto_censored_is_direct", "initial": {"mode": "auto", "censored": True, "reachable": True}, "expect_state": direct(0)},
        {"name": "initial_on_probes", "initial": {"mode": "on", "censored": False, "reachable": True}, "expect_state": PROBING},
        {"name": "initial_unreachable_is_offline", "initial": {"mode": "on", "censored": False, "reachable": False}, "expect_state": OFFLINE},

        case("one_direct_failure_counts", direct(0), "auto", [rpc_failed("transport_unknown")], direct(1), []),
        case("two_direct_failures_escalate", direct(0), "auto",
             [rpc_failed("transport_unknown"), rpc_failed("transport_unknown")], PROBING, [START, INVALIDATE]),
        case("off_never_escalates", direct(1), "off", [rpc_failed("transport_unknown")], direct(2), []),
        case("off_never_escalates_on_a_dead_stream", direct(0), "off", [stream_failed("mid_session_timeout")], direct(2), []),
        case("config_can_forbid_escalation", direct(1), "auto", [rpc_failed("transport_unknown")], direct(2), [],
             config={"allow_direct_to_veil_escalation": False}),
    ]
    for failure in ["mid_session_timeout", "mid_session_closed", "mid_session_unknown", "write_failed"]:
        cases.append(case(f"stream_died_{failure}_escalates_at_once", direct(0), "auto",
                          [stream_failed(failure)], PROBING, [START, INVALIDATE]))
    cases += [
        case("open_failure_takes_two", direct(0), "auto",
             [stream_failed("open_timeout"), stream_failed("open_timeout")], PROBING, [START, INVALIDATE]),
        case("quic_stream_failure_counts_too", direct(1), "auto",
             [stream_failed("transport_unknown", method="quic")], PROBING, [START, INVALIDATE]),
        case("a_veil_stream_failure_does_not_count_on_direct", direct(1), "auto",
             [stream_failed("mid_session_timeout", via="veil", method="veil")], direct(1), []),
        case("stream_open_clears_the_streak", direct(1), "auto",
             [{"kind": "stream_opened", "method": "h2", "via": "direct"}], direct(0), []),
        case("rpc_success_clears_the_streak", direct(1), "auto", [rpc_succeeded()], direct(0), []),
        case("background_failure_ignored", direct(1), "auto", [rpc_failed("transport_unknown", foreground=False)], direct(1), []),
        case("application_error_ignored", direct(1), "auto", [rpc_failed("application_error")], direct(1), []),
        case("auth_rejected_ignored", direct(1), "auto", [rpc_failed("auth_rejected")], direct(1), []),

        case("toggling_auto_does_not_force_veil", direct(0), "auto", [{"kind": "veil_mode_changed", "censored": True}], direct(0), []),
        # Turning `on` drops what is open on the direct path before the tunnel exists: a channel or
        # stream opened under `auto` must not carry traffic once the person chose never-direct
        # (2026-10-14: an open QUIC stream and the cached channel kept going direct for 30 s).
        case("turning_on_probes", direct(0), "on", [{"kind": "veil_mode_changed", "censored": False}], PROBING, [INVALIDATE, START]),
        case("turning_off_leaves_veil", ACTIVE, "off", [{"kind": "veil_mode_changed", "censored": False}],
             direct(0), [STOP, UNROUTE, INVALIDATE]),
        case("path_change_in_auto_does_not_start_proxy", ACTIVE, "auto",
             [{"kind": "network_path_changed", "reachable": True, "censored": True}], direct(0), [STOP, UNROUTE, INVALIDATE]),
        case("stale_proxy_start_on_direct_is_torn_down", direct(0), "off",
             [{"kind": "proxy_started", "relay": RELAY, "port": 7, "restarted": False}], direct(0), [STOP, UNROUTE]),

        case("probing_to_active", PROBING, "auto",
             [{"kind": "proxy_started", "relay": RELAY, "port": 7, "restarted": True}],
             active(port=7, since_ms=NOW),
             [eff("set_veil_port", port=7), INVALIDATE]),
        case("probing_failure_cools_down", PROBING, "auto",
             [{"kind": "proxy_start_failed", "relay": None, "reason": "timeout"}],
             {"kind": "veil_cooldown", "until_ms": NOW + COOLDOWN},
             [UNROUTE, eff("schedule_cooldown_end", at_ms=NOW + COOLDOWN)]),
        case("cooldown_ends_on_direct", {"kind": "veil_cooldown", "until_ms": NOW}, "auto",
             [{"kind": "cooldown_elapsed"}], direct(0), [INVALIDATE]),
        case("cooldown_swallows_failures", {"kind": "veil_cooldown", "until_ms": NOW}, "auto",
             [rpc_failed("transport_unknown")], {"kind": "veil_cooldown", "until_ms": NOW}, []),

        # The local proxy died: our process, not the front, so the front keeps its place.
        case("active_rotates_on_a_hard_failure", ACTIVE, "auto", [rpc_failed("stale_local_proxy", via="veil")], PROBING, ROTATE),
    ]
    for failure in ["tls_fingerprint_blocked", "tls_cert_expired", "web_tunnel_blocked"]:
        cases.append(case(f"{failure}_rotates_away_from_the_front", ACTIVE, "auto",
                          [rpc_failed(failure, via="veil")], PROBING, ROTATE_AWAY))
    cases += [
        case("active_reconnects_on_a_soft_failure", ACTIVE, "auto", [rpc_failed("stream_timeout", via="veil")], active(auth=1), [INVALIDATE]),
        # A relay can take a connection and then carry nothing over it. Every failure is then soft
        # (a timeout, a closed connection), and reconnecting goes through the same proxy and the
        # same relay. Until 2026-10-16 that went on for ever: testers in Russia could receive on
        # an old stream and send nothing until they reinstalled. Three soft failures in a row on
        # one channel, with no success between them, replace the proxy. Each channel counts
        # alone: the sealed channel is its own connection, and a success on the authenticated
        # one (a receipt, a token top-up over the live stream's connection) says nothing about it.
        case("three_soft_failures_in_a_row_rotate", active(auth=SOFT_FAIL_THRESHOLD - 1), "auto",
             [rpc_failed("transport_unknown", via="veil")], PROBING, ROTATE_AWAY),
        case("soft_failures_rotate_on_the_sealed_channel_too", ACTIVE, "on",
             [rpc_failed("stream_timeout", via="veil", lane="sealed")] * SOFT_FAIL_THRESHOLD, PROBING, ROTATE_AWAY),
        case("a_success_clears_its_own_channel", active(auth=2, sealed=2), "auto",
             [rpc_succeeded(via="veil", lane="sealed")], active(auth=2), []),
        case("a_success_on_the_other_channel_does_not_clear", active(sealed=SOFT_FAIL_THRESHOLD - 1), "auto",
             [rpc_succeeded(via="veil", lane="auth"), rpc_failed("transport_unknown", via="veil", lane="sealed")],
             PROBING, ROTATE_AWAY),
        case("a_background_soft_failure_does_not_count", active(sealed=SOFT_FAIL_THRESHOLD - 1), "auto",
             [rpc_failed("transport_unknown", via="veil", lane="sealed", foreground=False)],
             active(sealed=SOFT_FAIL_THRESHOLD - 1), []),
        case("an_application_error_does_not_count", active(sealed=SOFT_FAIL_THRESHOLD - 1), "auto",
             [rpc_failed("application_error", via="veil", lane="sealed")], active(sealed=SOFT_FAIL_THRESHOLD - 1), []),
        case("a_veil_stream_death_does_not_count", active(auth=SOFT_FAIL_THRESHOLD - 1), "auto",
             [stream_failed("mid_session_timeout", via="veil", method="veil")], active(auth=SOFT_FAIL_THRESHOLD - 1), [INVALIDATE]),
        case("active_reconnects_on_a_veil_stream_death", ACTIVE, "auto",
             [stream_failed("mid_session_timeout", via="veil", method="veil")], ACTIVE, [INVALIDATE]),
        case("auto_leaves_veil_when_direct_answers", ACTIVE, "auto", [rpc_succeeded()], direct(0), [STOP, UNROUTE]),
        case("on_keeps_veil_when_direct_answers", ACTIVE, "on", [rpc_succeeded()], ACTIVE, []),

        case("background_wake_replaces_the_veil_listener", ACTIVE, "auto", [{"kind": "background_wake"}], PROBING, ROTATE),
        case("background_wake_leaves_direct_alone", direct(0), "auto", [{"kind": "background_wake"}], direct(0), []),
        case("background_stale_proxy_does_not_rotate", ACTIVE, "auto",
             [rpc_failed("stale_local_proxy", via="veil", foreground=False)], ACTIVE, []),
        case("config_change_rotates_active", ACTIVE, "auto", [{"kind": "veil_config_changed"}], PROBING, ROTATE),

        case("offline_ignores_mode", OFFLINE, "on", [{"kind": "veil_mode_changed", "censored": False}], OFFLINE, []),
        case("offline_ignores_failures", OFFLINE, "auto", [rpc_failed("transport_unknown")], OFFLINE, []),
        case("reachable_again_reapplies_on", OFFLINE, "on",
             [{"kind": "network_path_changed", "reachable": True, "censored": False}], PROBING, [STOP, UNROUTE, INVALIDATE, START]),
        case("unreachable_goes_offline", ACTIVE, "auto",
             [{"kind": "network_path_changed", "reachable": False, "censored": False}], OFFLINE, [STOP, UNROUTE, INVALIDATE]),

        case("manual_reset_from_veil", ACTIVE, "auto", [{"kind": "manual_reset"}], direct(0), [STOP, UNROUTE, INVALIDATE]),
        case("manual_reset_on_direct", direct(0), "auto", [{"kind": "manual_reset"}], direct(0), [INVALIDATE]),

        # On never goes direct (construct-docs decisions/veil-on-never-goes-direct.md, 2026-10-13):
        # whatever would land it on the direct path sends it back to the front. With no front up
        # the client is offline, never direct.
        case("on_cooldown_ends_probing_not_direct", {"kind": "veil_cooldown", "until_ms": NOW}, "on",
             [{"kind": "cooldown_elapsed"}], PROBING, [INVALIDATE, START]),
        case("on_manual_reset_probes_again", ACTIVE, "on", [{"kind": "manual_reset"}],
             PROBING, [STOP, UNROUTE, INVALIDATE, START]),
        case("on_manual_reset_from_direct_probes", direct(0), "on", [{"kind": "manual_reset"}],
             PROBING, [INVALIDATE, START]),
    ]
    return {
        "_doc": ("When a client leaves the direct path for VEIL and when it comes back. Not protocol: each platform "
                 "implements it (iOS TransportReducer + TransportRouter, Android TransportRoute) and both run these "
                 "cases. Built by check_transport_route.py; do not edit by hand. Decision: construct-docs "
                 "decisions/transport-route-per-platform-shared-vectors.md."),
        "now_ms": NOW,
        "veil_target": {"port": PORT, "relay": RELAY},
        "default_config": {"direct_fail_threshold": 2, "mid_session_death_weight": 2,
                           "allow_direct_to_veil_escalation": True, "veil_cooldown_ms": COOLDOWN,
                           "veil_soft_fail_threshold": SOFT_FAIL_THRESHOLD},
        "cases": cases,
    }


def main():
    built = json.dumps(build(), indent=2) + "\n"
    names = [c["name"] for c in build()["cases"]]
    if len(names) != len(set(names)):
        sys.exit("duplicate case names")
    if "--write" in sys.argv:
        VECTORS.write_text(built)
        print(f"wrote {VECTORS.name}: {len(names)} cases")
        return
    if not VECTORS.exists() or VECTORS.read_text() != built:
        sys.exit(f"{VECTORS.name} is not what check_transport_route.py builds — run it with --write")
    print(f"✓ {VECTORS.name}: {len(names)} cases")


if __name__ == "__main__":
    main()
