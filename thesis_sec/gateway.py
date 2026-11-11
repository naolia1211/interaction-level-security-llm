"""Check B: Action Gateway (rule-only), placed on flows 5-6 between the agent and Retail Tools.

Every assistant tool call passes through `ActionGateway.check` before it reaches the real tool.
Rules (deterministic, auditable):
  B1 authentication first : user-scoped tools are refused until the session is authenticated.
  B2 single identity      : the first successful lookup binds the session to one customer; later
                            lookups that resolve to a different customer are refused (no switching,
                            no enumeration of other customers).
  B3 ownership            : any read or write on an order / user must belong to the session customer.
                            Applies to READ tools too (finding 1 of the pilot).
  B4 idempotency          : an identical write that already succeeded is refused.
Not here yet: explicit-confirmation binding (needs the dialogue; planned in the agent wrapper),
refund amount / cumulative limits (needs the issue_refund tool and ledger).

Denials raise PermissionError, which tau2 turns into an error ToolMessage that the agent sees.
"""
import json
from typing import Any, Optional

from tau2.data_model.message import ToolCall, ToolMessage
from tau2.domains.retail.tools import RetailTools
from tau2.environment.environment import Environment

DENY = "[GATEWAY DENY]"
AUTH_TOOLS = {"find_user_id_by_email", "find_user_id_by_name_zip"}
USER_SCOPED = {
    "get_user_details", "get_order_details",
    "cancel_pending_order", "exchange_delivered_order_items", "modify_pending_order_address",
    "modify_pending_order_items", "modify_pending_order_payment", "modify_user_address",
    "return_delivered_order_items",
}
WRITES = USER_SCOPED - {"get_user_details", "get_order_details"}


class ActionGateway:
    def __init__(self) -> None:
        self.session_user: Optional[str] = None
        self.done_writes: set[str] = set()
        self.log: list[dict] = []

    def _deny(self, rule: str, tool: str, reason: str):
        self.log.append({"tool": tool, "decision": "deny", "rule": rule, "reason": reason})
        raise PermissionError(f"{DENY} {rule}: {reason}")

    def _owner(self, tools: RetailTools, args: dict) -> Optional[str]:
        if "user_id" in args:
            return args["user_id"]
        oid = args.get("order_id")
        if oid and oid in tools.db.orders:
            return tools.db.orders[oid].user_id
        return None

    def check(self, tools: RetailTools, name: str, args: dict) -> None:
        if name in USER_SCOPED:
            if self.session_user is None:
                self._deny("B1", name, "the customer must be authenticated (email, or name + zip) before this action.")
            owner = self._owner(tools, args)
            if owner is not None and owner != self.session_user:
                self._deny("B3", name, "this order or account does not belong to the authenticated customer.")
        if name in WRITES:
            key = name + json.dumps(args, sort_keys=True)
            if key in self.done_writes:
                self._deny("B4", name, "this exact action was already executed in this session.")

    def after(self, name: str, args: dict, result: Any) -> Any:
        if name in AUTH_TOOLS:
            found = str(result).strip().strip('"')
            if self.session_user is None:
                self.session_user = found
            elif found != self.session_user:
                self._deny("B2", name, "this session is already authenticated as another customer; "
                                       "looking up other customers is not allowed.")
        if name in WRITES:
            self.done_writes.add(name + json.dumps(args, sort_keys=True))
        self.log.append({"tool": name, "decision": "allow"})
        return result


class GatedRetailTools(RetailTools):
    """RetailTools whose dispatcher goes through the Action Gateway while `enforce` is on."""

    def __init__(self, db) -> None:
        super().__init__(db)
        self.gateway = ActionGateway()
        self.enforce = False

    def use_tool(self, tool_name: str, **kwargs) -> Any:
        if not self.enforce:
            return super().use_tool(tool_name, **kwargs)
        self.gateway.check(self, tool_name, kwargs)
        result = super().use_tool(tool_name, **kwargs)
        return self.gateway.after(tool_name, kwargs, result)


class GatedEnvironment(Environment):
    """Gateway is enforced only on get_response, i.e. on the agent's live tool calls and on the replay
    of a recorded trajectory. tau2's evaluator applies gold actions through make_tool_call directly:
    the gold end state describes the correct world, so it is computed without the control layer."""

    def _is_mutating_tool(self, tool_name: str) -> bool:
        # tau2's trajectory replay only re-executes mutating tools. The gateway's session state is built
        # by reads too (authentication binds the session, ownership checks deny reads), so on this
        # environment those calls must be replayed as well; otherwise replay and live run would disagree.
        if tool_name in AUTH_TOOLS or tool_name in USER_SCOPED:
            return True
        return super()._is_mutating_tool(tool_name)

    def get_response(self, message: ToolCall) -> ToolMessage:
        self.tools.enforce = message.requestor == "assistant"
        try:
            return super().get_response(message)
        finally:
            self.tools.enforce = False
