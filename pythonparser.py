from parser import *
import ast

class PythonASTInspector(BaseInspector):
    FORBIDDEN_MODULES = {"os", "sys", "subprocess", "socket", "shutil", "ctypes", "pty"}
    FORBIDDEN_CALLS = {"eval", "exec", "compile", "__import__", "open"}
    FORBIDDEN_ATTRS = {"__subclasses__", "__builtins__", "__globals__", "__base__"}

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        code_str = args.get("code", "").strip()
        if not code_str:
            raise ParserError(tool, "code", "Code field is empty")

        try:
            tree = ast.parse(code_str)
        except SyntaxError as e:
            raise ParserError(tool, "code", f"Python syntax error: {e}")

        for node in ast.walk(tree):
            # Block forbidden imports
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.FORBIDDEN_MODULES:
                        raise ParserError(tool, "code", f"Import '{alias.name}' is forbidden")
            elif isinstance(node, ast.ImportFrom):
                if node.module in self.FORBIDDEN_MODULES:
                    raise ParserError(tool, "code", f"Import from '{node.module}' is forbidden")

            # Block dangerous functions
            elif isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name) and node.func.id in self.FORBIDDEN_CALLS:
                    raise ParserError(tool, "code", f"Calling '{node.func.id}()' is forbidden")

            # Block reflection / sandbox escaping attributes
            elif isinstance(node, ast.Attribute):
                if node.attr in self.FORBIDDEN_ATTRS:
                    raise ParserError(tool, "code", f"Access to '{node.attr}' is forbidden")