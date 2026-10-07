import io
import json
import unittest
import sys
from pathlib import Path

from mcp_proxy.cli import build_default_gateway


class TestE2EIntegration(unittest.TestCase):
    def test_full_pipeline_with_main_server(self):
        project_root = Path(__file__).parent.parent.resolve()
        python_bin = sys.executable
        target_script = str(project_root / "main.py")

        gateway = build_default_gateway(
            target_cmd=[python_bin, target_script],
            root_dir=project_root,
            log_file=str(project_root / "test_audit.jsonl"),
            allowed_binaries=["ls", "git", "echo"],
            allowed_tables=["empl"]
        )

        child = gateway.spawn_child()
        gateway._running = True

        try:
            # 1. Initialize handshake
            init_out = io.StringIO()
            gateway.handle_client_message(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "test-client", "version": "1.0"}}
                }),
                out_stream=init_out
            )

            server_line = child.stdout.readline()
            gateway.handle_server_message(server_line, out_stream=init_out)
            init_res = json.loads(init_out.getvalue().strip())
            self.assertEqual(init_res["id"], 1)
            self.assertIn("serverInfo", init_res["result"])

            # 2. List tools and cache schemas
            tools_out = io.StringIO()
            gateway.handle_client_message(
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
                out_stream=tools_out
            )
            server_line2 = child.stdout.readline()
            gateway.handle_server_message(server_line2, out_stream=tools_out)
            tools_res = json.loads(tools_out.getvalue().strip())
            self.assertEqual(tools_res["id"], 2)
            self.assertTrue(len(tools_res["result"]["tools"]) >= 4)

            self.assertIsNotNone(gateway.schema_validator.get_schema("query_sql"))
            self.assertIsNotNone(gateway.schema_validator.get_schema("execute_command"))

            # 3. Valid SQL query to employe_data.db
            sql_out = io.StringIO()
            gateway.handle_client_message(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "query_sql", "arguments": {"query": "SELECT * FROM empl LIMIT 2"}}
                }),
                out_stream=sql_out
            )
            server_line3 = child.stdout.readline()
            gateway.handle_server_message(server_line3, out_stream=sql_out)
            sql_res = json.loads(sql_out.getvalue().strip())
            self.assertIn("result", sql_res)
            self.assertIn("Rows:", sql_res["result"]["content"][0]["text"])

            # 4. Malicious SQL query (DROP TABLE) - Synthetic error from Gateway!
            drop_out = io.StringIO()
            gateway.handle_client_message(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 4,
                    "method": "tools/call",
                    "params": {"name": "query_sql", "arguments": {"query": "DROP TABLE empl;"}}
                }),
                out_stream=drop_out
            )
            drop_res = json.loads(drop_out.getvalue().strip())
            self.assertIn("error", drop_res)
            self.assertEqual(drop_res["error"]["code"], -32602)
            self.assertIn("violation", drop_res["error"]["message"].lower())

            # 5. DLP secret redaction on tool returning credentials
            dlp_out = io.StringIO()
            gateway.handle_client_message(
                json.dumps({
                    "jsonrpc": "2.0",
                    "id": 5,
                    "method": "tools/call",
                    "params": {"name": "leak_credentials", "arguments": {}}
                }),
                out_stream=dlp_out
            )
            server_line5 = child.stdout.readline()
            gateway.handle_server_message(server_line5, out_stream=dlp_out)
            dlp_res = json.loads(dlp_out.getvalue().strip())
            leaked_text = dlp_res["result"]["content"][0]["text"]
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", leaked_text)
            self.assertNotIn("ghp_123456789012345678901234567890123456", leaked_text)
            self.assertIn("[REDACTED_BY_GATEWAY]", leaked_text)

        finally:
            gateway._running = False
            if child.stdin:
                child.stdin.close()
            if child.stdout:
                child.stdout.close()
            child.terminate()
            child.wait(timeout=2.0)
            audit_file = project_root / "test_audit.jsonl"
            if audit_file.exists():
                audit_file.unlink()


if __name__ == "__main__":
    unittest.main()
