"""
Command Line Interface for SENTINEL-NET.
"""

import argparse
import uvicorn

from sentinel_net.config import get_config, setup_logging


def main() -> None:
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(description="EIDOLON // SENTINEL-NET")
    parser.add_argument("--host", type=str, help="API server host")
    parser.add_argument("--port", type=int, help="API server port")
    parser.add_argument("--log-level", type=str, help="Logging level")
    
    args = parser.parse_args()
    
    config = get_config()
    
    host = args.host if args.host else config.api_host
    port = args.port if args.port else config.api_port
    log_level = args.log_level if args.log_level else config.log_level
    
    setup_logging(log_level)
    
    uvicorn.run("sentinel_net.api:app", host=host, port=port, log_level=log_level.lower())


if __name__ == "__main__":
    main()
