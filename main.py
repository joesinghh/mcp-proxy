from mcp.server import MCPServer

mcp = MCPServer("My MCP server")

@mcp.tool()
def add(a: int, b:int) -> int:
    """Adds two numbers"""
    return a

