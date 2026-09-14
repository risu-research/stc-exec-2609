from __future__ import annotations
from dataclasses import dataclass
from typing import Mapping, Sequence
from rac import ALLOW, DENY, UNRESOLVED, Contract, DecisionReceipt

@dataclass(frozen=True)
class IndexedContract:
    name: str
    form: str
    contract_id: str
    domain: frozenset[str]
    denied: frozenset[str]
    static_decision: str | None

    @classmethod
    def build(cls, c: Contract):
        return cls(c.name, c.form, c.contract_id, frozenset(c.domain), frozenset(c.denied), c.static_decision)

    def decide(self, identity: str | None) -> str:
        if not identity or identity not in self.domain:
            return UNRESOLVED
        if self.static_decision is not None:
            return self.static_decision
        return DENY if identity in self.denied else ALLOW

    def authorize(self, identity: str | None) -> DecisionReceipt:
        value = identity or ""
        return DecisionReceipt(self.contract_id, value, self.decide(identity))

    def permits(self, receipt: DecisionReceipt, identity: str) -> bool:
        return receipt.contract_id == self.contract_id and receipt.decision == ALLOW and receipt.action_identity == identity and identity in self.domain

    def mediate(self, identity: str | None) -> str:
        receipt = self.authorize(identity)
        if receipt.decision != ALLOW:
            return receipt.decision
        return ALLOW if self.permits(receipt, identity or "") else UNRESOLVED

@dataclass(frozen=True)
class SelectorCall:
    tool: str
    requested: str | None
    resolved: str | None

@dataclass(frozen=True)
class EffectCall:
    tool: str
    effects: tuple[str, ...]

class SelectorAdapter:
    def __init__(self, contracts: Mapping[str, IndexedContract]):
        self.contracts = contracts
    def mediate(self, call: SelectorCall) -> str:
        c = self.contracts.get(call.tool)
        return UNRESOLVED if c is None else c.mediate(call.resolved)

class EffectAdapter:
    def __init__(self, contract: IndexedContract):
        self.contract = contract
    def mediate(self, call: EffectCall) -> tuple[str, ...]:
        return tuple(self.contract.mediate(x) for x in call.effects)

def compile_index(contracts: Mapping[str, Contract]) -> dict[str, IndexedContract]:
    return {name: IndexedContract.build(c) for name, c in contracts.items()}

def descriptor(c: IndexedContract, policy_digest: str, scope: str) -> dict:
    return {"profile":"org.rac/0.1","contractId":c.contract_id,"policyDigest":policy_digest,"enforcement":{"ordering":"post-resolution-pre-effect","scope":scope,"failClosed":True,"identityBound":True}}

def trace(c: IndexedContract, effects: Sequence[str]) -> tuple[str, ...]:
    return tuple(c.mediate(x) for x in effects)
