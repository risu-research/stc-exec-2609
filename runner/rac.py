from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Iterable, Sequence

ALLOW = "ALLOW"
DENY = "DENY"
UNRESOLVED = "UNRESOLVED"
STATIC = "STATIC"
SELECTOR = "SELECTOR"
EFFECT = "EFFECT"

PDEL_TOKENS = frozenset({"delete", "remove", "cancel"})


def tokenize(value: str) -> tuple[str, ...]:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return tuple(t for t in re.split(r"[^A-Za-z0-9]+", value.lower()) if t)


def pdel(policy_subject: str) -> str:
    return DENY if PDEL_TOKENS.intersection(tokenize(policy_subject)) else ALLOW


@dataclass(frozen=True)
class Action:
    identity: str
    policy_subject: str


@dataclass(frozen=True)
class DecisionReceipt:
    contract_id: str
    action_identity: str
    decision: str


@dataclass(frozen=True)
class Contract:
    name: str
    form: str
    domain: tuple[str, ...]
    denied: tuple[str, ...]
    static_decision: str | None
    contract_id: str

    def decide(self, action_identity: str | None) -> str:
        if not action_identity or action_identity not in self.domain:
            return UNRESOLVED
        if self.form == STATIC:
            if self.static_decision not in (ALLOW, DENY):
                return UNRESOLVED
            return self.static_decision
        return DENY if action_identity in self.denied else ALLOW

    def authorize(self, action_identity: str | None) -> DecisionReceipt:
        identity = action_identity or ""
        return DecisionReceipt(
            contract_id=self.contract_id,
            action_identity=identity,
            decision=self.decide(action_identity),
        )

    def permits_commit(self, receipt: DecisionReceipt, attempted_identity: str) -> bool:
        return (
            receipt.contract_id == self.contract_id
            and receipt.decision == ALLOW
            and receipt.action_identity == attempted_identity
            and attempted_identity in self.domain
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "form": self.form,
            "domain": list(self.domain),
            "denied": list(self.denied),
            "static_decision": self.static_decision,
            "contract_id": self.contract_id,
        }


def _contract_digest(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def compile_contract(name: str, actions: Iterable[Action], dynamic_form: str) -> Contract:
    if dynamic_form not in (SELECTOR, EFFECT):
        raise ValueError(f"invalid dynamic form: {dynamic_form}")

    by_identity: dict[str, Action] = {}
    decisions: dict[str, str] = {}
    for action in actions:
        if not action.identity:
            raise ValueError("empty action identity")
        prior = by_identity.get(action.identity)
        if prior is not None and prior.policy_subject != action.policy_subject:
            raise ValueError(f"conflicting subjects for identity {action.identity}")
        by_identity[action.identity] = action
        decisions[action.identity] = pdel(action.policy_subject)

    if not by_identity:
        raise ValueError(f"empty contract domain: {name}")

    domain = tuple(sorted(by_identity))
    denied = tuple(sorted(k for k, d in decisions.items() if d == DENY))
    decision_set = set(decisions.values())
    if len(decision_set) == 1:
        form = STATIC
        static_decision = next(iter(decision_set))
    else:
        form = dynamic_form
        static_decision = None

    unsigned = {
        "name": name,
        "form": form,
        "domain": list(domain),
        "denied": list(denied),
        "static_decision": static_decision,
    }
    return Contract(
        name=name,
        form=form,
        domain=domain,
        denied=denied,
        static_decision=static_decision,
        contract_id=_contract_digest(unsigned),
    )


def resolve_unique_identity(candidates: Sequence[str | None]) -> str | None:
    values = [c for c in candidates if c]
    if len(values) != 1:
        return None
    return values[0]


def mediate_trace(contract: Contract, trace: Sequence[str]) -> list[str]:
    return [contract.decide(action) for action in trace]


def baseline_errors(contract: Contract, action_subjects: dict[str, str]) -> dict:
    reference = {a: pdel(subject) for a, subject in action_subjects.items()}
    if contract.form == STATIC:
        return {
            "permissive_false_allows": 0,
            "conservative_false_denies": 0,
        }
    return {
        "permissive_false_allows": sum(d == DENY for d in reference.values()),
        "conservative_false_denies": sum(d == ALLOW for d in reference.values()),
    }
