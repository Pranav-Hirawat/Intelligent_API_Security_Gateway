from __future__ import annotations
import json
import uuid
from dataclasses import dataclass,field
from datetime import datetime,timedelta,timezone

DETECTOR_BRUTE_FORCE = "bruteforce"
DETECTOR_FLOOD = "flood"
DETECTOR_SQLI = "sqli"
DETECTOR_TRAVERSAL = "traversal"
DETECTOR_ENUMERATION = "enumeration"
DETECTOR_REPUTATION = "reputation"
DETECTOR_UNKNOWN_ROUTE_SCAN = "unknown_route_scanning"
DETECTOR_OBJECT_ENUMERATION = "object_enumeration"
DETECTOR_OWNERSHIP = "ownership_violation"

# The phase of an intrusion each detector belongs to. Several detectors can
# describe the same phase -- guessing filenames and climbing out of a directory
# are both someone looking around -- so phases are coarser than detectors, and
# a campaign only counts as staged when genuinely different ones appear.
STAGE_RECON = "reconnaissance"
STAGE_CREDENTIAL = "credential attack"
STAGE_INJECTION = "injection"
STAGE_ABUSE = "abuse"

# Reputation is deliberately absent from STAGE_OF below. It is an attribute of
# an address, not a phase of an intrusion -- being on a list is not something
# the attacker *did*. _stages() skips detectors it cannot map, so leaving it out
# keeps len(campaign.stages) honest; including it would hand every listed
# address a free promotion rung in _promote().
STAGE_OF = {
    DETECTOR_ENUMERATION: STAGE_RECON,
    DETECTOR_TRAVERSAL: STAGE_RECON,
    DETECTOR_UNKNOWN_ROUTE_SCAN: STAGE_RECON,
    DETECTOR_BRUTE_FORCE: STAGE_CREDENTIAL,
    DETECTOR_SQLI: STAGE_INJECTION,
    DETECTOR_FLOOD: STAGE_ABUSE,
    # Harvesting other users' records is using the API against its owners, not
    # looking around: it is what reconnaissance was for.
    DETECTOR_OBJECT_ENUMERATION: STAGE_ABUSE,
    # A read the gateway refused because the object belonged to someone else:
    # the same harvesting, caught one object at a time instead of by volume.
    DETECTOR_OWNERSHIP: STAGE_ABUSE,
}

# Go iasg:events signal names -> this agent's detector names.
SIGNAL_TO_DETECTOR = {
    "api_flooding": DETECTOR_FLOOD,
    "sql_injection": DETECTOR_SQLI,
    "brute_force": DETECTOR_BRUTE_FORCE,
    "consecutive_failed_logins": DETECTOR_BRUTE_FORCE,
    "password_spraying": DETECTOR_BRUTE_FORCE,
    "path_traversal": DETECTOR_TRAVERSAL,
    "enumeration": DETECTOR_ENUMERATION,
    "ip_reputation": DETECTOR_REPUTATION,
    "unknown_route_scanning": DETECTOR_UNKNOWN_ROUTE_SCAN,
    "object_enumeration": DETECTOR_OBJECT_ENUMERATION,
    "ownership_violation": DETECTOR_OWNERSHIP,
}

DETECTOR_TO_SIGNAL = {
    DETECTOR_BRUTE_FORCE: "brute_force",
    DETECTOR_FLOOD: "api_flooding",
    DETECTOR_SQLI: "sql_injection",
    DETECTOR_TRAVERSAL: "enumeration_path_traversal",
    DETECTOR_ENUMERATION: "enumeration_path_traversal",
    DETECTOR_REPUTATION: "ip_reputation",
    DETECTOR_UNKNOWN_ROUTE_SCAN: "unknown_route_scanning",
    DETECTOR_OBJECT_ENUMERATION: "object_enumeration",
    DETECTOR_OWNERSHIP: "ownership_violation",
}

# What a campaign is called once it spans more than one phase.
CAMPAIGN_MULTI_STAGE = "Multi-Stage Intrusion"

SEVERITY_LOW = "low"
SEVERITY_MEDIUM = "medium"
SEVERITY_HIGH = "high"

ACTION_MONITOR = "monitor"
ACTION_ALLOW = "allow"
ACTION_THROTTLE = "throttle"
ACTION_TEMP_BLOCK = "temp_block"
ACTION_ESCALATE = "escalate"

# The ladder, weakest first. The order is meaningful: a campaign that survives
# enforcement is promoted one rung along it.
ACTION_LADDER = (ACTION_MONITOR, ACTION_THROTTLE, ACTION_TEMP_BLOCK, ACTION_ESCALATE)

# Actions that actually restrain traffic. Monitor is deliberately excluded --
# a monitored campaign carrying on says nothing about whether enforcement
# works, because nothing was enforced.
ENFORCEMENT_ACTIONS = frozenset({ACTION_THROTTLE, ACTION_TEMP_BLOCK, ACTION_ESCALATE})

def _now() -> datetime:
    return datetime.now(timezone.utc)

def parse_timestamp(raw: str) -> datetime:
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return _now()


@dataclass
class Evidence:
    """
    One detector observation. Delibrately carries NO Verdict.
    """
    timestamp :datetime #when it happend
    ip:str              #who did it
    endpoint:str        #what they hit
    detector:str        #which detector saw it
    severity:str        #"low"/"medium"/"high"

    method : str = ""
    user_agent: str = ""

    details : dict = field(default_factory=dict)

    stream_id : str = ""

    @classmethod
    def from_stream_fields(cls,stream_id: str, fields : dict[str,str]) -> "Evidence":
        """
        Build an Evidence from one Redis entry.

        THIS IS THE IMPORTANT METHOD IN THIS FILE.

        Redis has no types -- everything you read back is text. failedLogins
        comes back as the string "12", not the number 12. All that messy
        conversion lives here, once, instead of being repeated inside every
        agent (where each one would get it slightly wrong).
        """
        raw_details = fields.get("details","")
        try:
            details = json.loads(raw_details) if raw_details else {}
        except json.JSONDecodeError:
            details = {}

        return cls(
            timestamp=parse_timestamp(fields.get("timestamp", "")),
            ip=fields.get("ip", ""),
            endpoint=fields.get("endpoint", ""),
            detector=fields.get("detector", ""),
            severity=fields.get("severity", SEVERITY_LOW),
            method=fields.get("method", ""),
            user_agent=fields.get("userAgent", ""),
            details=details,
            stream_id=stream_id,
        )

    @classmethod
    def from_stream_entry(cls, stream_id: str, fields: dict[str, str]) -> list["Evidence"]:
        """Parse one Redis stream entry into zero or more Evidence records.

        The gateway writes JSON telemetry on iasg:events (field ``event``),
        one request per entry. Fired signals become one Evidence each; clean
        requests are skipped. The seeder and older tests still use the flat
        detector/endpoint fields, which this also accepts.
        """
        raw_event = fields.get("event")
        if raw_event:
            return cls._from_telemetry(stream_id, raw_event)

        if fields.get("detector") and fields.get("ip"):
            return [cls.from_stream_fields(stream_id, fields)]
        return []

    @classmethod
    def _from_telemetry(cls, stream_id: str, raw_event: str | dict) -> list["Evidence"]:
        try:
            event = json.loads(raw_event) if isinstance(raw_event, str) else raw_event
        except json.JSONDecodeError:
            return []
        if not isinstance(event, dict):
            return []

        fired = [name for name in (event.get("fired") or []) if name]
        if not fired:
            return []

        signals = {
            row.get("signal"): row
            for row in (event.get("signals") or [])
            if isinstance(row, dict) and row.get("signal")
        }

        found: list[Evidence] = []
        for name in fired:
            for detector, signal in _detectors_for_signal(name, signals.get(name) or {}):
                details = dict(signal.get("details") or {})
                if signal.get("attackType") and "attackType" not in details:
                    details["attackType"] = signal["attackType"]
                if event.get("riskScore") is not None:
                    details.setdefault("riskScore", event["riskScore"])
                found.append(
                    cls(
                        timestamp=parse_timestamp(str(event.get("ts", ""))),
                        ip=str(event.get("ip") or ""),
                        endpoint=_evidence_endpoint(detector, event, details),
                        detector=detector,
                        severity=_severity_from_score(signal.get("score")),
                        method=str(event.get("method") or ""),
                        user_agent=str(event.get("userAgent") or ""),
                        details=details,
                        stream_id=stream_id,
                    )
                )
        return found

    def to_stream_fields(self) -> dict[str,str]:
        """
        The reverse: turn Evidence into text fields Redis can store.
        Used by the fake-attack generator and by the real gateway log reader.
        """
        return {
            "timestamp" : self.timestamp.astimezone(timezone.utc).isoformat(),
            "ip" : self.ip,
            "endpoint" : self.endpoint,
            "detector" : self.detector,
            "severity" : self.severity,
            "method"   : self.method,
            "userAgent": self.user_agent,
            "details" : json.dumps(self.details),
        }

    def to_telemetry_fields(self) -> dict[str, str]:
        """Shape one Evidence as a gateway iasg:events entry so the seeder
        feeds both the agent and the dashboard."""
        signal = DETECTOR_TO_SIGNAL.get(self.detector, self.detector)
        details = dict(self.details)
        attack_type = str(details.get("attackType") or "")
        if self.detector == DETECTOR_TRAVERSAL:
            details.setdefault("pathTraversalDetected", True)
            details.setdefault("enumerationDetected", False)
            attack_type = attack_type or "path_traversal"
        elif self.detector == DETECTOR_ENUMERATION:
            details.setdefault("pathTraversalDetected", False)
            details.setdefault("enumerationDetected", True)
            attack_type = attack_type or "enumeration"

        score = 80 if self.severity == SEVERITY_HIGH else 50 if self.severity == SEVERITY_MEDIUM else 20
        event = {
            "requestId": self.stream_id or "",
            "ts": self.timestamp.astimezone(timezone.utc).isoformat(),
            "ip": self.ip,
            "method": self.method,
            "path": self.endpoint,
            "status": 401 if self.detector == DETECTOR_BRUTE_FORCE else 200,
            "userAgent": self.user_agent,
            "decision": "allow",
            "riskScore": score,
            "fired": [signal],
            "signals": [
                {
                    "signal": signal,
                    "score": score,
                    "thresholdCross": True,
                    "attackType": attack_type or self.detector,
                    "details": details,
                }
            ],
        }
        return {
            "event": json.dumps(event),
            "ip": self.ip,
            "path": self.endpoint,
            "decision": "allow",
            "riskScore": str(score),
            "fired": signal,
        }


def _evidence_endpoint(detector: str, event: dict, details: dict) -> str:
    """
    The endpoint a piece of evidence is about.

    Normally the raw path. Object enumeration is the exception: its whole
    signature is one template visited with many identifiers, so /api/orders/1
    through /api/orders/40 are one endpoint. Keyed on the raw path they would
    never share a top endpoint, and correlation could not see that several
    addresses were harvesting the same thing.
    """
    template = str(details.get("template") or "")
    if detector in (DETECTOR_OBJECT_ENUMERATION, DETECTOR_OWNERSHIP) and template:
        return template.split(" ", 1)[-1]
    return str(event.get("path") or "")


def _severity_from_score(score) -> str:
    try:
        value = int(score)
    except (TypeError, ValueError):
        return SEVERITY_MEDIUM
    if value >= 70:
        return SEVERITY_HIGH
    if value >= 30:
        return SEVERITY_MEDIUM
    return SEVERITY_LOW


def _detectors_for_signal(name: str, signal: dict) -> list[tuple[str, dict]]:
    if name == "enumeration_path_traversal":
        details = signal.get("details") or {}
        attack = str(signal.get("attackType") or "")
        traversal = bool(details.get("pathTraversalDetected")) or "path_traversal" in attack
        enumeration = bool(details.get("enumerationDetected")) or attack == "enumeration" or attack.endswith("+enumeration")
        rows: list[tuple[str, dict]] = []
        if traversal:
            rows.append((DETECTOR_TRAVERSAL, signal))
        if enumeration:
            rows.append((DETECTOR_ENUMERATION, signal))
        if not rows:
            rows.append((DETECTOR_TRAVERSAL, signal))
        return rows

    detector = SIGNAL_TO_DETECTOR.get(name)
    if not detector:
        return []
    return [(detector, signal)]

@dataclass
class Campaign:
    """
    The Correlation Agent's output. Matches section 13.1 of the proposal.

    This is the whole point of the project: turning six separate "IP X failed
    logins" events into one "these six IPs are running a credential stuffing
    campaign against /api/login".
    """

    campaign_id: str
    type: str
    confidence : float
    ips: list[str]
    reason: str
    severity : str

    first_seen : datetime = field(default_factory=_now)
    last_seen  : datetime = field(default_factory=_now)
    event_count : int = 0

    # How the campaign is going, updated each cycle by the repository's review.
    # "active"    still producing evidence
    # "contained" nothing further since we acted
    status : str = "active"
    quiet_cycles : int = 0
    last_action : str = ""
    outcome : str = ""
    # How many times this campaign was re-identified after the attacker moved
    # to addresses we had never seen. Evidence that tracking survived a rotation.
    rotations : int = 0
    # How many times this campaign came back after we enforced against it, by
    # waiting the policy out or by moving. This is the honest measure of
    # enforcement failing, and it is what pushes the next action up the ladder.
    persistence : int = 0
    # Whether a human has already been told about this one.
    alerted : bool = False

    explanation : str = ""
    assessment : str = ""

    signature : dict = field(default_factory=dict)
    # Intrusion phases seen from this campaign, earliest first. More than one
    # means the actor moved on rather than repeating itself, which is worse
    # than any single phase and is what the policy ladder reacts to.
    stages : list = field(default_factory=list)


@dataclass
class PolicyDecision:
    """
    The Policy Agent's output for a single IP.

    This is the ONLY thing in the whole control plane that can influence the
    gateway. Everything else just produces information.
    """
    ip : str
    action : str
    campaign_id : str
    confidence : float
    ttl_seconds : int
    reason: str = ""
    # Requests per minute this address is allowed while the policy stands.
    # Only meaningful for "throttle": it is what makes the rate limiting
    # adaptive rather than a fixed slowdown applied to everyone alike.
    # Zero means "no rate named", and the gateway falls back to its configured
    # throttle behaviour -- which is also what an older control plane produces,
    # so a policy written before this field existed still enforces.
    requests_per_minute : int = 0
    # "agent" or "human". Decides whose judgement the safety checks defer to:
    # a person outranks the agent's guesses, but not the operator's declared
    # configuration. See policy/simulation.py.
    source : str = "agent"
    issued_at : datetime = field(default_factory=_now)
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    scope: str = "client"
    target_identity: str = ""
    method: str = ""
    route_template: str = ""
    risk_score: float = 0.0
    explanation: dict = field(default_factory=dict)
    mode: str = "automatic"
    issued_by: str = "control-plane"
    baseline_version: str = ""
    config_version: int = 1
    supersedes_policy_id: str = ""

    @property
    def expires_at(self) -> datetime:
        return self.issued_at + timedelta(seconds=max(0, self.ttl_seconds))

    def _canonical_dict(self) -> dict:
        """
        The decision's fields, action spelled the way the rest of the control
        plane and every non-Redis consumer expect -- ACTION_TEMP_BLOCK's own
        value, never the Redis wire spelling.

        This is what a recommendation's Postgres payload is built from. A
        dashboard reading it back (to render a default, or to validate an
        approval that didn't override the action) has to see the same
        spelling its own action vocabulary uses, or a canonical-but-unedited
        approval fails validation for a reason no one asked it to check.
        """
        return {
            "action": self.action,
            "policy_id": self.policy_id,
            "scope": self.scope,
            "target_identity": self.target_identity or self.ip,
            "endpoint_scope": (
                {"method": self.method, "route_template": self.route_template}
                if self.method or self.route_template else None
            ),
            "campaign_id": self.campaign_id,
            "confidence": round(self.confidence, 3),
            "risk_score": round(max(0.0, min(100.0, self.risk_score)), 2),
            "reason": self.reason,
            "explanation": self.explanation,
            "source": self.source,
            "mode": self.mode,
            "issued_by": self.issued_by,
            "issued_at": self.issued_at.astimezone(timezone.utc).isoformat(),
            "expires_at": self.expires_at.astimezone(timezone.utc).isoformat(),
            "expires_in": self.ttl_seconds,
            "requests_per_minute": self.requests_per_minute,
            "baseline_version": self.baseline_version,
            "config_version": self.config_version,
            "supersedes_policy_id": self.supersedes_policy_id or None,
        }

    def to_json(self) -> str:
        """
        Exactly what gets stored at policy:<ip> in Redis.

        The Go gateway will one day read this key and act on it. Keeping the
        shape here means there's a single definition of that contract.

        Wire format only -- do not use this (or to_dict()) for anything that
        gets read back and compared against the canonical action vocabulary,
        such as a recommendation's stored payload or the dashboard's approve
        validation. Use to_dict() for that; it is deliberately not derived
        from this method.
        """
        wire = self._canonical_dict()
        # The adaptive contract uses the unambiguous public spelling while
        # legacy agent/manual records keep their historical value. The Go
        # gateway accepts both during the migration.
        if self.action == ACTION_TEMP_BLOCK and (
            self.source in ("adaptive", "approved") or self.mode == "manual_override"
        ):
            wire["action"] = "temporary_block"
        return json.dumps(wire)

    def to_dict(self) -> dict:
        """The canonical shape -- see _canonical_dict(). Not the Redis wire
        format; use to_json() for that."""
        return self._canonical_dict()

    @classmethod
    def from_dict(cls, value: dict) -> "PolicyDecision":
        endpoint = value.get("endpoint_scope") or {}
        issued = parse_timestamp(str(value.get("issued_at") or ""))
        action = str(value.get("action") or ACTION_MONITOR)
        if action in ("temporary_block", "block"):
            action = ACTION_TEMP_BLOCK
        expires_in = value.get("expires_in")
        if expires_in is None and value.get("expires_at"):
            expires = parse_timestamp(str(value["expires_at"]))
            expires_in = max(0, int((expires - issued).total_seconds()))
        return cls(
            ip=str(value.get("target_identity") or value.get("ip") or ""),
            action=action,
            campaign_id=str(value.get("campaign_id") or ""),
            confidence=float(value.get("confidence") or 0),
            ttl_seconds=int(expires_in or 0),
            reason=str(value.get("reason") or ""),
            requests_per_minute=int(value.get("requests_per_minute") or 0),
            source=str(value.get("source") or "agent"),
            issued_at=issued,
            policy_id=str(value.get("policy_id") or uuid.uuid4()),
            scope=str(value.get("scope") or "client"),
            target_identity=str(value.get("target_identity") or value.get("ip") or ""),
            method=str(endpoint.get("method") or value.get("method") or ""),
            route_template=str(endpoint.get("route_template") or value.get("route_template") or ""),
            risk_score=float(value.get("risk_score") or 0),
            explanation=dict(value.get("explanation") or {}),
            mode=str(value.get("mode") or "automatic"),
            issued_by=str(value.get("issued_by") or "control-plane"),
            baseline_version=str(value.get("baseline_version") or ""),
            config_version=int(value.get("config_version") or 1),
            supersedes_policy_id=str(value.get("supersedes_policy_id") or ""),
        )
