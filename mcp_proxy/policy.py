import re
from typing import Dict, Any, List, Optional, Callable, Tuple
from mcp_proxy.inspectors.base import BaseInspector, ParserError


class PolicyRule:
    """Represents a Policy-as-Code rule evaluating input.tool and input.arguments."""
    def __init__(
        self,
        name: str,
        tool: str,
        allow_patterns: Optional[List[Tuple[str, str]]] = None,
        deny_patterns: Optional[List[Tuple[str, str]]] = None,
        custom_check: Optional[Callable[[Dict[str, Any]], Tuple[bool, Optional[str]]]] = None
    ):
        self.name = name
        self.tool = tool
        self.allow_patterns = [
            (field, re.compile(pat, re.IGNORECASE)) for field, pat in (allow_patterns or [])
        ]
        self.deny_patterns = [
            (field, re.compile(pat, re.IGNORECASE)) for field, pat in (deny_patterns or [])
        ]
        self.custom_check = custom_check

    def evaluate(self, tool: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        if self.tool != "*" and self.tool != tool:
            return True, None

        for field, pattern in self.allow_patterns:
            val = str(arguments.get(field, ""))
            if not pattern.search(val):
                return False, f"Policy '{self.name}' violation: Field '{field}' does not match required pattern {pattern.pattern}"

        for field, pattern in self.deny_patterns:
            val = str(arguments.get(field, ""))
            if pattern.search(val):
                return False, f"Policy '{self.name}' violation: Field '{field}' matched forbidden pattern {pattern.pattern}"

        if self.custom_check:
            ok, msg = self.custom_check(arguments)
            if not ok:
                return False, f"Policy '{self.name}' custom check failed: {msg}"

        return True, None


class PolicyEngine(BaseInspector):
    """
    Policy-as-Code engine.
    Applies Rego/OPA-style security policies across tool calls.
    """
    def __init__(self, rules: Optional[List[PolicyRule]] = None, default_allow: bool = True):
        self.rules: List[PolicyRule] = list(rules or [])
        self.default_allow = default_allow

    def add_rule(self, rule: PolicyRule) -> "PolicyEngine":
        self.rules.append(rule)
        return self

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        """Inspects tool and args. Raises ParserError if policy is violated."""
        for rule in self.rules:
            allowed, reason = rule.evaluate(tool, args)
            if not allowed:
                raise ParserError(tool, "policy", reason or f"Rule '{rule.name}' denied access")

    @classmethod
    def create_default_sql_policy(cls) -> "PolicyEngine":
        """
        Creates standard Rego-equivalent policy for SQL execution:
        allow {
            input.tool == "query_sql"
            regex.match("^(?i)\\s*SELECT\\b", input.arguments.query)
            not regex.match("(?i)\\b(DROP|ALTER|TRUNCATE|DELETE|UPDATE)\\b", input.arguments.query)
        }
        """
        sql_rule = PolicyRule(
            name="rego_sql_read_only",
            tool="query_sql",
            allow_patterns=[("query", r"^\s*SELECT\b")],
            deny_patterns=[("query", r"\b(DROP|ALTER|TRUNCATE|DELETE|UPDATE|INSERT|CREATE)\b")]
        )
        engine = cls()
        engine.add_rule(sql_rule)
        return engine
