from abc import ABC, abstractmethod 
from typing import Dict, Any, List

class ParserError(Exception):
     def __init__(self, tool: str, field: str, reason: str):
         super().__init__(f"[{tool}] Field '{field}' rejected: {reason}")
         self.tool = tool
         self.field = field
         self.reason = reason 

class BaseInspector(ABC):
     @abstractmethod
     def inspect(self, tool: str, args: Dict[str:Any]) -> None:
         pass

class Inspector:
    def __init__(self):
        self._registry: Dict[str, List[BaseInspector]] = {}

    def register(self, tool_name: str, *inspectors: BaseInspector) -> None:
        if tool_name not in self._registry:
            self._registry[tool_name] = []
        self._registry[tool_name].extend(inspectors)

    def validate(self, tool_name: str, args: Dict[str:Any]) -> None:
        inspectors = self._registry.get(tool_name, [])
        for inspector in inspectors:
            inspector.inspect(tool_name, args)
