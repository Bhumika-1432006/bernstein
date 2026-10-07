## Pi workers no longer inherit your global MCP servers

Workers spawned by the `pi` adapter now start with `-ne` (`--no-extensions`). Pi's MCP support is a built-in extension, so before this every worker connected to every server in your own Pi configuration: dozens of private background MCP processes across concurrent runs, and tools in each worker's context that the task never asked for. The Claude adapter already passes `--strict-mcp-config` for the same reason (#5965).
