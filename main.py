from mcp.server import MCPServer
import subprocess

mcp = MCPServer("My MCP server")

@mcp.tool()
def execute_command(command: str) -> str:
    """Executes shell commands"""

    res = subprocess.run(command, shell=True, timeout=15, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return f"Output: {res.stdout}"

@mcp.tool()
def add(a: int, b:int) -> int:
    """Adds two numbers"""
    return a

