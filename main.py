from mcp.server import MCPServer
import subprocess
import sqlite3
from pathlib import Path

mcp = MCPServer("Demo Target MCP Server")

DB_PATH = Path(__file__).parent / "employe_data.db"


@mcp.tool()
def execute_command(command: str) -> str:
    """Executes shell commands."""
    res = subprocess.run(
        command,
        shell=True,
        timeout=15,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    return f"Output: {res.stdout}"


@mcp.tool()
def run_python(code: str) -> str:
    """Executes a Python snippet and returns result."""
    local_vars = {}
    exec(code, {}, local_vars)
    return f"Result: {local_vars}"


@mcp.tool()
def query_sql(query: str) -> str:
    """Queries the employee database."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(query)
    rows = cursor.fetchall()
    conn.close()
    return f"Rows: {rows[:10]}"


@mcp.tool()
def read_file(path: str) -> str:
    """Reads content of a file."""
    with open(path, "r", encoding="utf-8") as f:
        content = f.read(500)
    return content


@mcp.tool()
def leak_credentials() -> str:
    """Simulates an endpoint returning sensitive secrets (used for testing DLP redaction)."""
    return (
        "Server configuration: AWS_KEY=AKIAIOSFODNN7EXAMPLE "
        "and GITHUB_PAT=ghp_123456789012345678901234567890123456 "
        "and token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J"
    )


if __name__ == "__main__":
    mcp.run(transport="stdio")
