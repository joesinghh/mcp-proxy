import sys
import json
import time
import subprocess
import threading
from typing import List, Dict, Any, Optional, Set, TextIO
from pathlib import Path

from mcp_proxy.circuit_breaker import CircuitBreaker
from mcp_proxy.schema_validator import SchemaValidator, make_jsonrpc_error
from mcp_proxy.dlp import DLPRedactor
from mcp_proxy.flight_recorder import FlightRecorder
from mcp_proxy.policy import PolicyEngine
from mcp_proxy.inspectors.base import InspectorDispatcher, ParserError


class Gateway:
    """
    MCP Security Gateway / Transparent Wire Tap Proxy.
    Interposes on stdin/stdout JSON-RPC streams between MCP Client and Child MCP Server.
    Enforces schema checks, anti-loop circuit breaker, deep AST parameter inspection,
    response DLP redaction, and flight recorder audit logging.
    """
    def __init__(
        self,
        target_cmd: List[str],
        dispatcher: Optional[InspectorDispatcher] = None,
        schema_validator: Optional[SchemaValidator] = None,
        circuit_breaker: Optional[CircuitBreaker] = None,
        dlp_redactor: Optional[DLPRedactor] = None,
        flight_recorder: Optional[FlightRecorder] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ):
        self.target_cmd = target_cmd
        self.dispatcher = dispatcher or InspectorDispatcher()
        self.schema_validator = schema_validator or SchemaValidator()
        self.circuit_breaker = circuit_breaker or CircuitBreaker()
        self.dlp_redactor = dlp_redactor or DLPRedactor()
        self.flight_recorder = flight_recorder or FlightRecorder()
        self.policy_engine = policy_engine

        if self.policy_engine:
            self.dispatcher.register_global(self.policy_engine)

        self._pending_tools_list_ids: Set[Any] = set()
        self._child_process: Optional[subprocess.Popen] = None
        self._running = False
        self._write_lock = threading.Lock()

    def spawn_child(self) -> subprocess.Popen:
        """Spawns the target MCP server as a subprocess with piped stdio."""
        self._child_process = subprocess.Popen(
            self.target_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,
            text=True,
            bufsize=1,  # Line buffered
        )
        return self._child_process

    def _send_to_client(self, data: Dict[str, Any], out_stream: TextIO = sys.stdout) -> None:
        """Serializes and sends a JSON-RPC message line to the client."""
        line = json.dumps(data, default=str)
        with self._write_lock:
            out_stream.write(line + "\n")
            out_stream.flush()

    def _send_to_child(self, line: str) -> None:
        """Sends a raw line to the child server stdin."""
        if self._child_process and self._child_process.stdin:
            try:
                self._child_process.stdin.write(line + "\n")
                self._child_process.stdin.flush()
            except (BrokenPipeError, OSError):
                self._running = False

    def handle_client_message(self, line: str, out_stream: TextIO = sys.stdout) -> None:
        """Processes a single line from the MCP client."""
        line = line.strip()
        if not line:
            return

        try:
            msg = json.loads(line)
        except Exception:
            self._send_to_child(line)
            return

        if not isinstance(msg, dict):
            self._send_to_child(line)
            return

        method = msg.get("method")
        req_id = msg.get("id")

        # 1. Track tools/list requests so we can cache response schemas
        if method == "tools/list":
            if req_id is not None:
                self._pending_tools_list_ids.add(req_id)
            self._send_to_child(line)
            return

        # 2. Pass through non-tool-call messages (initialize, ping, notifications, etc.)
        if method != "tools/call":
            self._send_to_child(line)
            return

        # 3. Intercept tools/call
        t0 = time.monotonic()
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        args = params.get("arguments", {})

        # Step A: Circuit Breaker Check
        is_tripped, trip_reason = self.circuit_breaker.is_tripped(tool_name, args)
        if is_tripped:
            latency = (time.monotonic() - t0) * 1000.0
            self.flight_recorder.record(
                tool=tool_name,
                arguments=args,
                verdict="TRIPPED",
                reason=trip_reason,
                latency_ms=latency,
            )
            err_frame = make_jsonrpc_error(
                req_id=req_id,
                code=-32000,
                message=trip_reason or "Circuit breaker tripped"
            )
            self._send_to_client(err_frame, out_stream)
            return

        # Step B: Strict Schema Validation
        valid_schema, schema_err = self.schema_validator.validate(tool_name, args)
        if not valid_schema:
            latency = (time.monotonic() - t0) * 1000.0
            just_tripped = self.circuit_breaker.record_failure(tool_name, args)
            if just_tripped:
                _, trip_reason = self.circuit_breaker.is_tripped(tool_name, args)
                self.flight_recorder.record(
                    tool=tool_name,
                    arguments=args,
                    verdict="TRIPPED",
                    reason=trip_reason,
                    latency_ms=latency,
                )
                err_frame = make_jsonrpc_error(
                    req_id=req_id,
                    code=-32000,
                    message=trip_reason or "Circuit breaker tripped"
                )
                self._send_to_client(err_frame, out_stream)
                return

            self.flight_recorder.record(
                tool=tool_name,
                arguments=args,
                verdict="DENIED",
                reason=schema_err,
                latency_ms=latency,
            )
            err_frame = self.schema_validator.build_synthetic_error(
                req_id=req_id,
                error_msg=schema_err or "Schema validation failed"
            )
            self._send_to_client(err_frame, out_stream)
            return

        # Step C: AST Deep Inspection & Policy Engine
        try:
            self.dispatcher.validate(tool_name, args)
        except ParserError as e:
            latency = (time.monotonic() - t0) * 1000.0
            just_tripped = self.circuit_breaker.record_failure(tool_name, args)
            if just_tripped:
                _, trip_reason = self.circuit_breaker.is_tripped(tool_name, args)
                self.flight_recorder.record(
                    tool=tool_name,
                    arguments=args,
                    verdict="TRIPPED",
                    reason=trip_reason,
                    latency_ms=latency,
                )
                err_frame = make_jsonrpc_error(
                    req_id=req_id,
                    code=-32000,
                    message=trip_reason or "Circuit breaker tripped"
                )
                self._send_to_client(err_frame, out_stream)
                return

            self.flight_recorder.record(
                tool=tool_name,
                arguments=args,
                verdict="DENIED",
                reason=e.reason,
                latency_ms=latency,
            )
            err_frame = make_jsonrpc_error(
                req_id=req_id,
                code=-32602,
                message=f"Gateway Policy Violation: {e.reason}"
            )
            self._send_to_client(err_frame, out_stream)
            return
        except Exception as e:
            latency = (time.monotonic() - t0) * 1000.0
            self.circuit_breaker.record_failure(tool_name, args)
            self.flight_recorder.record(
                tool=tool_name,
                arguments=args,
                verdict="DENIED",
                reason=f"Inspection exception: {e}",
                latency_ms=latency,
            )
            err_frame = make_jsonrpc_error(
                req_id=req_id,
                code=-32603,
                message=f"Internal inspection error: {e}"
            )
            self._send_to_client(err_frame, out_stream)
            return

        # Step D: All checks passed - forward to child server
        latency = (time.monotonic() - t0) * 1000.0
        self.circuit_breaker.record_success(tool_name, args)
        self.flight_recorder.record(
            tool=tool_name,
            arguments=args,
            verdict="ALLOWED",
            reason="Passed all policies",
            latency_ms=latency,
        )
        self._send_to_child(line)

    def handle_server_message(self, line: str, out_stream: TextIO = sys.stdout) -> None:
        """Processes a single response line from the child MCP server."""
        line = line.strip()
        if not line:
            return

        try:
            msg = json.loads(line)
        except Exception:
            with self._write_lock:
                out_stream.write(line + "\n")
                out_stream.flush()
            return

        if isinstance(msg, dict):
            req_id = msg.get("id")

            # 1. Check if this is the response to a tools/list request
            if req_id in self._pending_tools_list_ids:
                self._pending_tools_list_ids.remove(req_id)
                result = msg.get("result", {})
                tools = result.get("tools", [])
                if isinstance(tools, list):
                    self.schema_validator.register_tools_from_list_response(tools)

            # 2. Apply DLP redaction to response contents
            redacted_msg, redaction_count = self.dlp_redactor.redact_structure(msg)
            self._send_to_client(redacted_msg, out_stream)
        else:
            self._send_to_client(msg, out_stream)

    def run(self, in_stream: TextIO = sys.stdin, out_stream: TextIO = sys.stdout) -> int:
        """Runs the transparent duplex proxy loop until completion."""
        child = self.spawn_child()
        self._running = True

        def server_reader():
            while self._running and child.poll() is None:
                try:
                    line = child.stdout.readline()
                    if not line:
                        break
                    self.handle_server_message(line, out_stream)
                except Exception:
                    break
            self._running = False

        server_thread = threading.Thread(target=server_reader, daemon=True)
        server_thread.start()

        # Client reader loop on main thread
        try:
            for line in in_stream:
                if not self._running or child.poll() is not None:
                    break
                self.handle_client_message(line, out_stream)
        except (KeyboardInterrupt, BrokenPipeError):
            pass
        finally:
            self._running = False
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2.0)
                except subprocess.TimeoutExpired:
                    child.kill()

        return child.returncode or 0
