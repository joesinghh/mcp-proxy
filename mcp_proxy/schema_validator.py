import jsonschema
from typing import Dict, Any, Optional, Tuple, List


def make_jsonrpc_error(
    req_id: Any,
    code: int = -32602,
    message: str = "Invalid params",
    data: Optional[Any] = None
) -> Dict[str, Any]:
    """Fabricates a native JSON-RPC 2.0 error response frame."""
    error_obj: Dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        error_obj["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": req_id,
        "error": error_obj,
    }


class SchemaValidator:
    """
    Caches tool JSON Schemas and performs strict validation on tools/call payloads.
    Generates synthetic JSON-RPC error frames upon contract violation.
    """
    def __init__(self):
        # tool_name -> inputSchema dict
        self._schemas: Dict[str, Dict[str, Any]] = {}
        # tool_name -> precompiled validator
        self._validators: Dict[str, jsonschema.Draft202012Validator] = {}

    def register_tool_schema(self, tool_name: str, schema: Optional[Dict[str, Any]]) -> None:
        """Stores or updates the schema for a tool."""
        if not schema or not isinstance(schema, dict):
            schema = {"type": "object"}
        self._schemas[tool_name] = schema
        try:
            self._validators[tool_name] = jsonschema.Draft202012Validator(schema)
        except Exception:
            self._validators[tool_name] = jsonschema.Draft7Validator(schema)

    def register_tools_from_list_response(self, tools_list: List[Dict[str, Any]]) -> None:
        """Parses a tools/list response result and updates cached schemas."""
        for tool_def in tools_list:
            name = tool_def.get("name")
            if name:
                schema = tool_def.get("inputSchema")
                self.register_tool_schema(name, schema)

    def get_schema(self, tool_name: str) -> Optional[Dict[str, Any]]:
        return self._schemas.get(tool_name)

    def validate(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """
        Validates arguments against the cached schema for tool_name.
        Returns (is_valid, error_message).
        """
        validator = self._validators.get(tool_name)
        if not validator:
            if not isinstance(arguments, dict):
                return False, f"Gateway Contract Violation: Arguments for '{tool_name}' must be an object"
            return True, None

        errors = sorted(validator.iter_errors(arguments), key=lambda e: e.path)
        if not errors:
            return True, None

        first_error = errors[0]
        field_path = ".".join(str(p) for p in first_error.path)
        if field_path:
            field_desc = f"Field '{field_path}'"
        else:
            field_desc = "Arguments"

        msg = f"Gateway Contract Violation: {field_desc} {first_error.message}."
        return False, msg

    def build_synthetic_error(self, req_id: Any, error_msg: str, code: int = -32602) -> Dict[str, Any]:
        """Creates standard JSON-RPC synthetic error response."""
        return make_jsonrpc_error(req_id=req_id, code=code, message=error_msg)
