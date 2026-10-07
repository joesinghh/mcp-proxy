import sys
import argparse
from pathlib import Path
from typing import List, Optional

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
from mcp_proxy.policy import PolicyEngine


def build_default_gateway(
    target_cmd: List[str],
    root_dir: Path,
    log_file: Optional[str] = None,
    allow_pipes: bool = False,
    allowed_binaries: Optional[List[str]] = None,
    allowed_tables: Optional[List[str]] = None,
) -> Gateway:
    """Builds and configures the default security gateway with all 5 phases enabled."""
    binaries = set(allowed_binaries or ["git", "ls", "grep", "echo", "pwd", "head", "tail", "wc"])
    tables = set(allowed_tables or ["empl"])

    dispatcher = InspectorDispatcher()

    # 1. Shell AST Inspector for terminal/execute_command tools
    shell_inspector = ShellASTInspector(allowed_binaries=binaries, allow_pipes=allow_pipes, field_name="command")
    dispatcher.register("execute_command", shell_inspector)
    dispatcher.register("bash", shell_inspector)
    dispatcher.register("terminal", shell_inspector)

    # 2. Python AST Inspector for python execution tools
    python_inspector = PythonASTInspector(field_name="code")
    dispatcher.register("run_python", python_inspector)
    dispatcher.register("python", python_inspector)

    # 3. SQL AST Inspector for database query tools
    sql_inspector = SQLASTInspector(allowed_tables=tables, dialect="sqlite", field_name="query")
    dispatcher.register("query_sql", sql_inspector)
    dispatcher.register("execute_sql", sql_inspector)

    # 4. Path Traversal Guard for filesystem tools
    path_inspector = PathTraversalInspector(root_dir=root_dir, field_name="path")
    dispatcher.register("read_file", path_inspector)
    dispatcher.register("write_file", path_inspector)
    dispatcher.register("view_file", path_inspector)

    # 5. Policy Engine (Rego/OPA equivalent SQL read-only rule)
    policy_engine = PolicyEngine.create_default_sql_policy()

    # Components
    circuit_breaker = CircuitBreaker(failure_threshold=3, window_seconds=60.0)
    schema_validator = SchemaValidator()
    dlp_redactor = DLPRedactor()
    flight_recorder = FlightRecorder(log_path=log_file)

    return Gateway(
        target_cmd=target_cmd,
        dispatcher=dispatcher,
        schema_validator=schema_validator,
        circuit_breaker=circuit_breaker,
        dlp_redactor=dlp_redactor,
        flight_recorder=flight_recorder,
        policy_engine=policy_engine,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="mcp-proxy",
        description="MCP Security Gateway & Wire Tap Proxy",
        allow_abbrev=False
    )
    parser.add_argument("--target", required=True, help="Target MCP server executable binary")
    parser.add_argument("--log-file", default="audit.jsonl", help="Append-only flight recorder log file path")
    parser.add_argument("--root-dir", default=str(Path.cwd()), help="Base root directory for path traversal checks")
    parser.add_argument("--allow-pipes", action="store_true", help="Allow shell pipe operators")
    parser.add_argument("--allow-binaries", default="git,ls,grep,echo,pwd,head,tail,wc", help="Comma-separated allowed shell binaries")
    parser.add_argument("--allowed-tables", default="empl", help="Comma-separated allowed SQL tables")

    # Capture remaining args to forward to target binary
    args, forwarded = parser.parse_known_args()

    # If '--' was used, strip it from forwarded args
    if forwarded and forwarded[0] == "--":
        forwarded = forwarded[1:]

    target_cmd = [args.target] + forwarded
    root_path = Path(args.root_dir).resolve()
    allowed_binaries = [b.strip() for b in args.allow_binaries.split(",") if b.strip()]
    allowed_tables = [t.strip() for t in args.allowed_tables.split(",") if t.strip()]

    gateway = build_default_gateway(
        target_cmd=target_cmd,
        root_dir=root_path,
        log_file=args.log_file,
        allow_pipes=args.allow_pipes,
        allowed_binaries=allowed_binaries,
        allowed_tables=allowed_tables,
    )

    exit_code = gateway.run()
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
