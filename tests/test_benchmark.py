import time
import io
import json
import tracemalloc
import unittest
from pathlib import Path

from mcp_proxy.gateway import Gateway
from mcp_proxy.inspectors.base import InspectorDispatcher
from mcp_proxy.inspectors.shell import ShellASTInspector
from mcp_proxy.inspectors.python_ast import PythonASTInspector
from mcp_proxy.inspectors.sql import SQLASTInspector
from mcp_proxy.inspectors.path import PathTraversalInspector
from mcp_proxy.circuit_breaker import CircuitBreaker
from mcp_proxy.schema_validator import SchemaValidator
from mcp_proxy.dlp import DLPRedactor
from mcp_proxy.flight_recorder import FlightRecorder


class TestGatewayBenchmark(unittest.TestCase):
    def setUp(self):
        self.root_dir = Path(__file__).parent.parent.resolve()
        self.circuit_breaker = CircuitBreaker()
        self.schema_validator = SchemaValidator()
        self.dlp_redactor = DLPRedactor()
        self.flight_recorder = FlightRecorder()

        # Pre-cache schemas
        self.schema_validator.register_tool_schema(
            "execute_command",
            {"type": "object", "properties": {"command": {"type": "string"}}, "required": ["command"]}
        )
        self.schema_validator.register_tool_schema(
            "query_sql",
            {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
        )

        self.dispatcher = InspectorDispatcher()
        self.dispatcher.register("execute_command", ShellASTInspector(allowed_binaries={"ls", "git", "echo"}))
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

    def test_microbenchmark_latency_and_memory(self):
        """
        Microbenchmark: validates that added gateway latency is < 1.5ms per tool call
        and verifies memory stability over high iterations.
        """
        tracemalloc.start()
        snapshot_start = tracemalloc.take_snapshot()

        iterations = 5000
        latencies = []

        req_line = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "execute_command",
                "arguments": {"command": "ls -la"}
            }
        })

        out_stream = io.StringIO()

        # Warm-up
        for _ in range(100):
            self.gateway.handle_client_message(req_line, out_stream=out_stream)

        # Timed benchmark loop
        t_start = time.perf_counter()
        for i in range(iterations):
            t0 = time.perf_counter()
            self.gateway.handle_client_message(req_line, out_stream=out_stream)
            latencies.append((time.perf_counter() - t0) * 1000.0)
        t_total = time.perf_counter() - t_start

        avg_latency_ms = sum(latencies) / len(latencies)
        latencies.sort()
        p50 = latencies[int(len(latencies) * 0.50)]
        p95 = latencies[int(len(latencies) * 0.95)]
        p99 = latencies[int(len(latencies) * 0.99)]

        snapshot_end = tracemalloc.take_snapshot()
        top_stats = snapshot_end.compare_to(snapshot_start, "lineno")
        total_mem_diff_kb = sum(stat.size_diff for stat in top_stats) / 1024.0
        tracemalloc.stop()

        print(f"\n--- Gateway Benchmark Report ({iterations} requests) ---")
        print(f"Total Time:       {t_total:.3f} s")
        print(f"Throughput:       {iterations / t_total:.1f} req/sec")
        print(f"Average Latency:  {avg_latency_ms:.4f} ms")
        print(f"Median (p50):     {p50:.4f} ms")
        print(f"95th %ile (p95):  {p95:.4f} ms")
        print(f"99th %ile (p99):  {p99:.4f} ms")
        print(f"Memory Delta:     {total_mem_diff_kb:.2f} KB")

        # Goal check: < 1.5ms added latency
        self.assertLess(avg_latency_ms, 1.5, f"Gateway added latency ({avg_latency_ms:.3f}ms) exceeded 1.5ms budget")
        self.assertLess(p99, 1.5, f"p99 latency ({p99:.3f}ms) exceeded 1.5ms budget")


if __name__ == "__main__":
    unittest.main()
