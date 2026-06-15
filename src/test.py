from mcp.server.fastmcp import FastMCP

# Create our MCP server with a name
server = FastMCP("sift-forensics")

# Our first tool — a simple one to test with
@server.tool()
def add(a: int, b: int) -> int:
    """Add two numbers"""
    return a + b

if __name__ == "__main__":
    server.run()
