from x402_mock.mcp.server import main as mcp_main


if __name__ == "__main__":
    mcp_main()
    # TODO client and server should be separate with x402-mock, the client role should be the one who use the tools, the server role should be the one who provide the tools, except with in 402 role