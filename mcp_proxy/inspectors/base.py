from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional, Callable


class ParserError(Exception):
    """Raised when an inspector detects a policy or contract violation."""
    def __init__(self, tool: str, field: str, reason: str):
        super().__init__(f"[{tool}] Field '{field}' rejected: {reason}")
        self.tool = tool
        self.field = field
        self.reason = reason


class BaseInspector(ABC):
    """Abstract base class for all parameter inspectors."""
    @abstractmethod
    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        """Inspect tool arguments. Raises ParserError if policy is violated."""
        pass


class InspectorDispatcher:
    """Registry and dispatcher for tool inspectors."""
    def __init__(self):
        self._registry: Dict[str, List[BaseInspector]] = {}
        self._global_inspectors: List[BaseInspector] = []

    def register(self, tool_name: str, *inspectors: BaseInspector) -> "InspectorDispatcher":
        """Register one or more inspectors for a specific tool."""
        if tool_name not in self._registry:
            self._registry[tool_name] = []
        self._registry[tool_name].extend(inspectors)
        return self

    def register_global(self, *inspectors: BaseInspector) -> "InspectorDispatcher":
        """Register global inspectors that run on all tools."""
        self._global_inspectors.extend(inspectors)
        return self

    def validate(self, tool_name: str, args: Dict[str, Any]) -> None:
        """Runs all matching inspectors against the tool arguments."""
        # 1. Global inspectors
        for inspector in self._global_inspectors:
            inspector.inspect(tool_name, args)

        # 2. Tool-specific inspectors
        inspectors = self._registry.get(tool_name, [])
        for inspector in inspectors:
            inspector.inspect(tool_name, args)
