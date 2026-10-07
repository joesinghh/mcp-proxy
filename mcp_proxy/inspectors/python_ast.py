import ast
from typing import Dict, Any, Set, Optional
from mcp_proxy.inspectors.base import BaseInspector, ParserError


class PythonASTInspector(BaseInspector):
    """
    Inspects Python code payloads via AST parsing and node traversal.
    Blocks forbidden imports, dangerous built-in calls, and sandbox escaping attributes.
    """
    DEFAULT_FORBIDDEN_MODULES: Set[str] = {
        "os", "sys", "subprocess", "socket", "shutil", "ctypes", "pty",
        "posix", "importlib", "builtins", "inspect", "platform", "signal",
        "multiprocessing", "threading"
    }

    DEFAULT_FORBIDDEN_CALLS: Set[str] = {
        "eval", "exec", "compile", "__import__", "open", "input",
        "globals", "locals", "getattr", "setattr", "delattr"
    }

    DEFAULT_FORBIDDEN_ATTRS: Set[str] = {
        "__subclasses__", "__builtins__", "__globals__", "__base__",
        "__bases__", "__mro__", "__class__", "__code__", "__reduce__",
        "__reduce_ex__"
    }

    def __init__(
        self,
        forbidden_modules: Optional[Set[str]] = None,
        forbidden_calls: Optional[Set[str]] = None,
        forbidden_attrs: Optional[Set[str]] = None,
        field_name: str = "code"
    ):
        self.forbidden_modules = forbidden_modules if forbidden_modules is not None else set(self.DEFAULT_FORBIDDEN_MODULES)
        self.forbidden_calls = forbidden_calls if forbidden_calls is not None else set(self.DEFAULT_FORBIDDEN_CALLS)
        self.forbidden_attrs = forbidden_attrs if forbidden_attrs is not None else set(self.DEFAULT_FORBIDDEN_ATTRS)
        self.field_name = field_name

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        code_str = args.get(self.field_name, "")
        if not isinstance(code_str, str) or not code_str.strip():
            raise ParserError(tool, self.field_name, f"Field '{self.field_name}' must be a non-empty string")

        code_str = code_str.strip()

        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            raise ParserError(tool, self.field_name, f"Python syntax error: {e}")

        for node in ast.walk(tree):
            # 1. Block forbidden module imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root_pkg = alias.name.split(".")[0]
                    if root_pkg in self.forbidden_modules or alias.name in self.forbidden_modules:
                        raise ParserError(tool, self.field_name, f"Importing forbidden module: '{alias.name}'")

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    root_pkg = node.module.split(".")[0]
                    if root_pkg in self.forbidden_modules or node.module in self.forbidden_modules:
                        raise ParserError(tool, self.field_name, f"Importing from forbidden module: '{node.module}'")
                for alias in node.names:
                    if alias.name in self.forbidden_modules:
                        raise ParserError(tool, self.field_name, f"Importing forbidden symbol: '{alias.name}'")

            # 2. Block dangerous function calls
            elif isinstance(node, ast.Call):
                func_name = None
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr

                if func_name and func_name in self.forbidden_calls:
                    raise ParserError(tool, self.field_name, f"Calling forbidden function: '{func_name}()'")

            # 3. Block reflection / sandbox escaping attributes
            elif isinstance(node, ast.Attribute):
                if node.attr in self.forbidden_attrs:
                    raise ParserError(tool, self.field_name, f"Accessing forbidden attribute: '{node.attr}'")
