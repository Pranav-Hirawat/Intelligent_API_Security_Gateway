"""
Writes fake attack evidence into the iasg:events stream.

The gateway isn't modified, so nothing else fills that stream yet. This makes
the whole pipeline testable in a second, without an attacker or a gateway.

    python tools/seed_evidence.py --scenario credential-stuffing
"""

from __future__ import annotations

import argparse
import random
from datetime import datetime, timedelta, timezone

from iasg.config import Settings
from iasg.models import (
    DETECTOR_BRUTE_FORCE,
    DETECTOR_ENUMERATION,
    DETECTOR_FLOOD,
    DETECTOR_SQLI,
    DETECTOR_TRAVERSAL,
    SEVERITY_HIGH,
    SEVERITY_LOW,
    SEVERITY_MEDIUM,
    Evidence,
)
from iasg.store import open_store


def credential_stuffing() -> list[Evidence]:
    """Six machines, one subnet, one User-Agent, all on /api/login."""
    base = datetime.now(timezone.utc) - timedelta(minutes=12)
    ips = [f"203.0.113.{n}" for n in (5, 9, 14, 21, 33, 40)]
    users = ["ana@x.com", "ben@x.com", "cara@x.com", "dan@x.com", "eve@x.com"]

    events = []
    for i, ip in enumerate(ips):
        for attempt in range(6):
            events.append(
                Evidence(
                    timestamp=base + timedelta(seconds=i * 7 + attempt * 11),
                    ip=ip,
                    endpoint="/api/login",
                    method="POST",
                    detector=DETECTOR_BRUTE_FORCE,
                    severity=SEVERITY_HIGH if attempt > 3 else SEVERITY_MEDIUM,
                    user_agent="curl/8.4.0",
                    details={
                        "failedLogins": attempt + 5,
                        "distinctUsers": len(users),
                        "attackType": "password_spraying",
                        "window": "60s",
                    },
                )
            )
    return events


def flood() -> list[Evidence]:
    """Three machines hammering the API from different networks."""
    base = datetime.now(timezone.utc) - timedelta(minutes=5)
    ips = ["198.51.100.7", "198.51.100.8", "198.51.100.9"]

    events = []
    for i, ip in enumerate(ips):
        for n in range(8):
            events.append(
                Evidence(
                    timestamp=base + timedelta(seconds=i * 3 + n * 4),
                    ip=ip,
                    endpoint="/api/products",
                    method="GET",
                    detector=DETECTOR_FLOOD,
                    severity=SEVERITY_HIGH if n > 5 else SEVERITY_MEDIUM,
                    user_agent="python-requests/2.32",
                    details={
                        "requestCount": 120 + n * 40,
                        "threshold": 100,
                        "window": "1m0s",
                    },
                )
            )
    return events


def brute_force() -> list[Evidence]:
    """
    One machine grinding away at one account.

    Deliberately a single IP on a single username, which is what makes the
    correlator call this Brute Force rather than Credential Stuffing -- the
    difference is the shape, not the detector. Sustained enough to be worth
    blocking, which a lone attacker could not be before solo confidence
    existed.
    """
    base = datetime.now(timezone.utc) - timedelta(minutes=10)

    return [
        Evidence(
            timestamp=base + timedelta(seconds=n * 10),
            ip="203.0.113.201",
            endpoint="/api/login",
            method="POST",
            detector=DETECTOR_BRUTE_FORCE,
            severity=SEVERITY_HIGH,
            user_agent="Hydra/9.5",
            details={
                "failedLogins": 5 + n,
                "distinctUsers": 1,
                "targetUser": "admin@x.com",
                "attackType": "brute_force",
                "window": "60s",
            },
        )
        for n in range(60)
    ]


def enumeration() -> list[Evidence]:
    """One scanner guessing filenames that should never be reachable."""
    base = datetime.now(timezone.utc) - timedelta(minutes=3)
    paths = [
        "/.env", "/.git/config", "/etc/passwd", "/wp-admin", "/.ssh/id_rsa",
        "/backup.sql", "/config.json", "/.aws/credentials", "/admin", "/phpinfo.php",
        "/.bash_history", "/server-status",
    ]

    return [
        Evidence(
            timestamp=base + timedelta(seconds=n * 6),
            ip="192.0.2.77",
            endpoint=path,
            method="GET",
            detector=DETECTOR_ENUMERATION,
            # Reaching for a credentials file is worse than poking at /admin.
            severity=SEVERITY_HIGH if any(
                s in path for s in (".env", "passwd", "id_rsa", "credentials")
            ) else SEVERITY_MEDIUM,
            user_agent="Nikto/2.5.0",
            details={"matchedPattern": path, "attackType": "enumeration"},
        )
        for n, path in enumerate(paths)
    ]


def path_traversal() -> list[Evidence]:
    """
    One host climbing out of the directory it was given.

    Enumeration guesses names; traversal escapes upward from a path the app
    handed it. Both are reconnaissance, which is why the correlator files them
    under the same campaign type.
    """
    base = datetime.now(timezone.utc) - timedelta(minutes=4)
    # A real scanner works through a long list of encodings and depths rather
    # than trying a handful, so this is sized to look like one.
    payloads = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../etc/shadow",
        "..%2f..%2fetc%2fhosts",
        "%2e%2e%2f%2e%2e%2froot%2f.ssh%2fid_rsa",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//etc/passwd",
        "..%252f..%252fetc%252fpasswd",
        "../../../../var/log/auth.log",
        "..\\..\\windows\\win.ini",
        "..\\..\\..\\boot.ini",
        "../../app/.env",
        "../../../home/app/.ssh/id_rsa",
    ]

    return [
        Evidence(
            timestamp=base + timedelta(seconds=n * 7),
            ip="192.0.2.91",
            endpoint=f"/api/files?path={payload}",
            method="GET",
            detector=DETECTOR_TRAVERSAL,
            severity=SEVERITY_HIGH,
            user_agent="Nikto/2.5.0",
            details={"matchedPattern": payload, "attackType": "path_traversal"},
        )
        for n, payload in enumerate(payloads)
    ]


def recon() -> list[Evidence]:
    """Both halves of reconnaissance together: guessing names and climbing out."""
    return enumeration() + path_traversal()


def sqli() -> list[Evidence]:
    """A couple of hosts probing with SQL payloads."""
    base = datetime.now(timezone.utc) - timedelta(minutes=2)
    payloads = ["' OR 1=1--", "UNION SELECT", "'; DROP TABLE"]

    events = []
    for i, ip in enumerate(["192.0.2.10", "192.0.2.11"]):
        for n, payload in enumerate(payloads):
            events.append(
                Evidence(
                    timestamp=base + timedelta(seconds=i * 5 + n * 8),
                    ip=ip,
                    endpoint="/api/search",
                    method="POST",
                    detector=DETECTOR_SQLI,
                    severity=SEVERITY_HIGH,
                    user_agent="sqlmap/1.8",
                    details={"matchedPattern": payload, "location": "body"},
                )
            )
    return events


def noise() -> list[Evidence]:
    """Unrelated one-off events, so clustering has something to reject."""
    base = datetime.now(timezone.utc) - timedelta(minutes=20)
    return [
        Evidence(
            timestamp=base + timedelta(minutes=random.randint(0, 15)),
            ip=f"10.{random.randint(1, 200)}.{random.randint(1, 200)}.{n}",
            endpoint=random.choice(["/api/cart", "/api/orders"]),
            method="GET",
            detector=DETECTOR_FLOOD,
            severity=SEVERITY_LOW,
            user_agent=f"Mozilla/5.0 (build {n})",
            details={"requestCount": 105, "threshold": 100},
        )
        for n in range(4)
    ]


SCENARIOS = {
    "credential-stuffing": credential_stuffing,
    "brute-force": brute_force,
    "flood": flood,
    "enumeration": enumeration,
    "path-traversal": path_traversal,
    "recon": recon,
    "sqli": sqli,
    "noise": noise,
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed fake attack evidence.")
    parser.add_argument(
        "--scenario",
        default="credential-stuffing",
        choices=[*SCENARIOS, "mixed"],
    )
    parser.add_argument("--clear", action="store_true", help="trim the stream first")
    args = parser.parse_args()

    settings = Settings.from_env()
    store = open_store(settings)

    if args.clear:
        # DEL also destroys consumer groups and leaves a running agent failing
        # with NOGROUP. XTRIM clears history while preserving those cursors.
        store.trim(settings.evidence_stream, 0)
        print(f"cleared {settings.evidence_stream} without deleting consumer groups")

    if args.scenario == "mixed":
        events = (
            credential_stuffing() + brute_force() + flood() + recon() + noise()
        )
    else:
        events = SCENARIOS[args.scenario]()

    events.sort(key=lambda e: e.timestamp)
    for ev in events:
        store.append(settings.evidence_stream, ev.to_telemetry_fields())

    ips = sorted({e.ip for e in events})
    print(f"seeded {len(events)} events from {len(ips)} IPs -> {settings.evidence_stream}")
    store.close()


if __name__ == "__main__":
    main()
