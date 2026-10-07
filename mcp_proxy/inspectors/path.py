from pathlib import Path
from typing import Dict, Any, Set, Optional, Union
from mcp_proxy.inspectors.base import BaseInspector, ParserError


class PathTraversalInspector(BaseInspector):
    """
    Guards filesystem tools against path traversal, symlink escapes,
    and unauthorized access to sensitive files.
    """
    SENSITIVE_NAMES: Set[str] = {
        ".env", ".git", ".ssh", "id_rsa", "id_ed25519", "authorized_keys",
        ".aws", ".bash_history", "passwd", "shadow", "credentials"
    }

    def __init__(
        self,
        root_dir: Union[str, Path],
        allow_hidden: bool = False,
        allowed_extensions: Optional[Set[str]] = None,
        field_name: str = "path"
    ):
        self.root_dir = Path(root_dir).resolve()
        self.allow_hidden = allow_hidden
        self.allowed_extensions = {ext.lower() for ext in allowed_extensions} if allowed_extensions is not None else None
        self.field_name = field_name

    def inspect(self, tool: str, args: Dict[str, Any]) -> None:
        raw_path = args.get(self.field_name, "")
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ParserError(tool, self.field_name, f"Field '{self.field_name}' must be a non-empty string path")

        raw_path = raw_path.strip()

        # Handle null bytes in path
        if "\0" in raw_path:
            raise ParserError(tool, self.field_name, "Path contains invalid null byte characters")

        path_obj = Path(raw_path)

        # Canonicalize path (resolving symlinks and '.' or '..')
        if path_obj.is_absolute():
            resolved_path = path_obj.resolve()
        else:
            resolved_path = (self.root_dir / path_obj).resolve()

        # Strict containment check against root directory
        try:
            if not resolved_path.is_relative_to(self.root_dir):
                raise ParserError(
                    tool,
                    self.field_name,
                    f"Path traversal detected: path '{raw_path}' escapes root directory boundary '{self.root_dir}'"
                )
        except AttributeError:
            # Fallback for older python
            if self.root_dir not in resolved_path.parents and resolved_path != self.root_dir:
                raise ParserError(
                    tool,
                    self.field_name,
                    f"Path traversal detected: path '{raw_path}' escapes root directory boundary '{self.root_dir}'"
                )

        rel_parts = resolved_path.relative_to(self.root_dir).parts

        # Check for sensitive files / dotfiles
        if not self.allow_hidden:
            for part in rel_parts:
                if part.startswith(".") and part not in (".", ".."):
                    raise ParserError(tool, self.field_name, f"Access to hidden file or directory '{part}' is forbidden")

        for part in rel_parts:
            if part.lower() in self.SENSITIVE_NAMES:
                raise ParserError(tool, self.field_name, f"Access to sensitive file '{part}' is forbidden")

        # Allowed extensions check
        if self.allowed_extensions is not None and resolved_path.suffix:
            ext = resolved_path.suffix.lower()
            if ext not in self.allowed_extensions:
                raise ParserError(
                    tool,
                    self.field_name,
                    f"File extension '{ext}' is not permitted. Allowed: {sorted(self.allowed_extensions)}"
                )
