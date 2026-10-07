import bashlex
from typing import Set, Dict, Any, Optional
from mcp_proxy.inspectors.base import BaseInspector, ParserError


class ShellASTInspector(BaseInspector):
    """
    Inspects shell commands using bashlex AST parsing.
    Enforces binary allowlists, blocks command chaining, subshells,
    redirections, and unauthorized pipelines.
    """
    def __init__(
        self,
        allowed_binaries: Set[str],
        allow_pipes: bool = False,
        field_name: str = "command"
    ):
        self.allowed_binaries = set(allowed_binaries)
        self.allow_pipes = allow_pipes
        self.field_name = field_name

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        cmd_str = args.get(self.field_name, "")
        if not isinstance(cmd_str, str) or not cmd_str.strip():
            raise ParserError(tool, self.field_name, f"Field '{self.field_name}' must be a non-empty string")

        cmd_str = cmd_str.strip()

        try:
            nodes = bashlex.parse(cmd_str)
        except Exception as e:
            raise ParserError(tool, self.field_name, f"Malformed shell syntax: {e}")

        # Check for multiple top-level commands (e.g. newline-separated commands)
        if len(nodes) > 1:
            raise ParserError(tool, self.field_name, "Multiple command execution is forbidden")

        for node in nodes:
            self._walk_and_check(tool, node)

    def _walk_and_check(self, tool: str, node: Any) -> None:
        node_kind = getattr(node, "kind", None)

        # 1. Block command substitutions: $(...) or `...`, and subshells
        if node_kind in ("commandsubstitution", "subshell"):
            raise ParserError(tool, self.field_name, "Subshell and command substitution execution is strictly forbidden")

        # 2. Block file redirections: >, >>, <, >&, etc.
        if node_kind == "redirect":
            raise ParserError(tool, self.field_name, "I/O redirection is forbidden by policy")

        # 3. Block command chaining: ;, &&, ||, &
        if node_kind in ("list", "compound"):
            raise ParserError(tool, self.field_name, "Compound command chaining (;, &&, ||) is forbidden")

        # 4. Pipelines (|)
        if node_kind == "pipeline":
            if not self.allow_pipes:
                raise ParserError(tool, self.field_name, "Piping (|) is disabled by policy")

        # 5. Check executable binary against allowlist
        if node_kind == "command":
            parts = getattr(node, "parts", [])
            # Find the command word (executable binary)
            command_word = None
            for part in parts:
                if getattr(part, "kind", None) == "word":
                    command_word = part.word
                    break

            if command_word is not None:
                # Strip directory path (e.g. /bin/ls -> ls)
                binary_name = command_word.split("/")[-1]
                if binary_name not in self.allowed_binaries:
                    raise ParserError(
                        tool,
                        self.field_name,
                        f"Binary '{binary_name}' is not in the allowed command list: {sorted(self.allowed_binaries)}"
                    )

        # Recursively inspect child nodes
        for attr in ("parts", "list", "pipe"):
            children = getattr(node, attr, None)
            if isinstance(children, list):
                for child in children:
                    self._walk_and_check(tool, child)
