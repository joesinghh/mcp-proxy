import bashlex
from typing import Set
from parser import *

class ShellASTInspector(BaseInspector):
    def __init__(self, allowed_binaries: Set[str], allow_pipes: bool = False):
        self.allowed_binaries = allowed_binaries
        self.allow_pipes = allow_pipes

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        cmd_str = args.get("command", "").strip()
        if not cmd_str:
            raise ParserError(tool, "command", "Command field is empty")

        try:
            nodes = bashlex.parse(cmd_str)
        except Exception as e:
            raise ParserError(tool, "command", f"Malformed shell syntax: {e}")

        for node in nodes:
            self._walk_and_check(tool, node)

    def _walk_and_check(self, tool: str, node: Any) -> None:
        node_kind = getattr(node, "kind", None)

        # 1. Block command substitution / subshells: $(...) or `...`
        if node_kind in ("commandsubstitution", "subshell"):
            raise ParserError(tool, "command", "Subshell execution is strictly forbidden")

        # 2. Block file redirections: >, >>, <
        if node_kind == "redirect":
            raise ParserError(tool, "command", "I/O redirection is forbidden")

        # 3. Block pipelines and compound operators (&&, ||)
        if node_kind == "pipeline":
            if not self.allow_pipes:
                raise ParserError(tool, "command", "Piping (|) is disabled by policy")
        if node_kind == "compound":
            raise ParserError(tool, "command", "Compound command chaining is forbidden")

        # 4. Check executable against allowlist
        if node_kind == "command":
            if hasattr(node, "parts") and node.parts:
                first_part = node.parts[0]
                # Extract literal command word
                if getattr(first_part, "kind", None) == "word":
                    binary_name = first_part.word.split("/")[-1]  # Strip path if /bin/ls
                    if binary_name not in self.allowed_binaries:
                        raise ParserError(
                            tool, "command", f"Binary '{binary_name}' is not in allowlist"
                        )

        # Recursively visit children nodes
        for attr in ("parts", "list", "pipe"):
            children = getattr(node, attr, None)
            if isinstance(children, list):
                for child in children:
                    self._walk_and_check(tool, child)