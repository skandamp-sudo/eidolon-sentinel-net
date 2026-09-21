"""
Command Line Interface for SENTINEL-NET.
"""

import argparse
import asyncio
import logging
import sys
import threading
from pathlib import Path

import uvicorn

from sentinel_net.config import get_config, setup_logging


def main() -> None:
    """
    Main entry point for the CLI.
    """
    parser = argparse.ArgumentParser(description="EIDOLON // SENTINEL-NET")
    subparsers = parser.add_subparsers(dest="command")

    sensor_parser = subparsers.add_parser('sensor', help='Run a continuous receive-only sensor and API')
    sensor_parser.add_argument('--interface', help='Capture interface (or SENTINEL_CAPTURE_INTERFACE)')
    sensor_parser.add_argument('--model', help='Approved model-name/version (or SENTINEL_SENSOR_MODEL)')
    sensor_parser.add_argument('--host', help='API bind address')
    sensor_parser.add_argument('--port', type=int, help='API port')

    # ── serve (default) ──
    serve_parser = subparsers.add_parser("serve", help="Start the API server")
    serve_parser.add_argument("--host", type=str, help="API server host")
    serve_parser.add_argument("--port", type=int, help="API server port")
    serve_parser.add_argument("--log-level", type=str, help="Logging level")

    # ── replay ──
    replay_parser = subparsers.add_parser(
        "replay",
        help="Replay a PCAP file through the production pipeline into the dashboard",
    )
    replay_parser.add_argument(
        "--pcap", type=str, required=True, help="Path to the PCAP file to replay"
    )
    replay_parser.add_argument('--model', required=True, help='Approved model-name/version')
    replay_parser.add_argument(
        "--host", type=str, default=None, help="API server host"
    )
    replay_parser.add_argument(
        "--port", type=int, default=None, help="API server port"
    )
    replay_parser.add_argument(
        "--realtime",
        action="store_true",
        default=False,
        help="Replay at original PCAP timing (slower, more realistic)",
    )
    replay_parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Speed multiplier for paced replay (default: 1.0)",
    )
    replay_parser.add_argument("--log-level", type=str, help="Logging level")

    model_parser = subparsers.add_parser('model', help='Offline candidate training and local publication')
    model_commands = model_parser.add_subparsers(dest='model_command', required=True)
    train = model_commands.add_parser('train', help='Offline research training; produces an unapproved candidate')
    train.add_argument('--dataset', type=Path, required=True)
    train.add_argument('--output', type=Path, required=True)
    train.add_argument('--name', required=True)
    train.add_argument('--version', required=True)
    train.add_argument('--dataset-hash', help='Known dataset provenance hash; omitted means unavailable')
    train.add_argument('--code-revision', help='Known source revision; omitted means unavailable')
    publish = model_commands.add_parser('publish', help='Explicit operator approval of an evaluated candidate')
    publish.add_argument('--candidate', type=Path, required=True)
    publish.add_argument('--approved-by', required=True)
    publish.add_argument('--evaluation-reference', required=True)

    args = parser.parse_args()

    # Default to "serve" if no subcommand
    if args.command is None or args.command == "serve":
        _run_serve(args)
    elif args.command == "replay":
        _run_replay(args)
    elif args.command == 'model':
        _run_model(args)
    elif args.command == 'sensor':
        _run_sensor(args)
    else:
        parser.print_help()


class SensorServer(uvicorn.Server):
    """Keep delivery consumers alive until the sensor finishes final output."""

    def __init__(self, config, service):
        super().__init__(config)
        self.service = service

    def handle_exit(self, sig, frame):
        # Repeated signals remain graceful: never abandon accepted packets.
        self.service.lifecycle.request_shutdown()
        self.should_exit = True

    async def on_tick(self, counter):
        if self.service.lifecycle.shutdown_requested:
            self.should_exit = True
        return await super().on_tick(counter)

    async def shutdown(self, sockets=None):
        await self.service.quiesce()
        await super().shutdown(sockets)


def _run_sensor(args: argparse.Namespace) -> None:
    from sentinel_net.api.main import create_app
    from sentinel_net.sensor.service import SensorService
    from sentinel_net.sensor.lifecycle import SensorState
    config = get_config().model_copy(update={
        key: value for key, value in {
            'capture_interface': args.interface, 'sensor_model': args.model,
            'api_host': args.host, 'api_port': args.port,
        }.items() if value is not None
    })
    setup_logging(config.log_level)
    service = SensorService(config)
    print(f'LIVE PASSIVE SENSOR | interface={config.capture_interface or "(not set)"}')
    print(f'Database: {config.database_path} | schema: 2.0.0 / 52 features')
    print(f'API: http://{config.api_host}:{config.api_port} | state: starting')
    print('Loading an existing fitted model; no runtime training.')
    server = SensorServer(uvicorn.Config(create_app(sensor_service=service),
        host=config.api_host, port=config.api_port, log_level=config.log_level.lower(),
        timeout_graceful_shutdown=5), service)
    server.run()
    if service.lifecycle.state == SensorState.FAILED or not server.started:
        raise SystemExit(1)


def _run_serve(args: argparse.Namespace) -> None:
    """Start the API server only."""
    config = get_config()
    host = args.host if hasattr(args, "host") and args.host else config.api_host
    port = args.port if hasattr(args, "port") and args.port else config.api_port
    log_level = (
        args.log_level
        if hasattr(args, "log_level") and args.log_level
        else config.log_level
    )
    setup_logging(log_level)
    uvicorn.run(
        "sentinel_net.api:app", host=host, port=port, log_level=log_level.lower()
    )


def _run_replay(args: argparse.Namespace) -> None:
    """Start the API server and replay a PCAP through the production pipeline."""
    config = get_config()
    log_level = args.log_level or config.log_level
    setup_logging(log_level)

    pcap_path = Path(args.pcap)

    if not pcap_path.exists():
        print(f"ERROR: PCAP file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)
    host = args.host or config.api_host
    port = args.port or config.api_port

    # Import here to avoid circular imports at module level
    from sentinel_net.demo_replay import DemoReplayConfig, run_replay
    from sentinel_net.sensor.event_bus import EventBus
    from sentinel_net.sensor.lifecycle import SensorLifecycle
    from sentinel_net.sensor.metrics import SensorMetrics
    from sentinel_net.storage.database import Database

    replay_config = DemoReplayConfig(
        pcap_path=pcap_path,
        model=args.model,
        model_registry=config.model_registry,
        realtime=args.realtime,
        speed=args.speed,
    )

    async def _replay_after_startup(app_state) -> None:
        """Run replay once the server is up, using app-level shared state."""

        db = app_state.db
        event_bus = app_state.event_bus
        metrics = app_state.sensor_metrics
        lifecycle = SensorLifecycle()
        app_state.sensor_lifecycle = lifecycle

        try:
            summary = await run_replay(
                replay_config, db, event_bus, lifecycle, metrics,
                detection=app_state.deployment_detection
            )
            logging.getLogger(__name__).info(
                "Replay finished. Dashboard remains live at http://%s:%d",
                host,
                port,
            )
        except Exception as e:
            logging.getLogger(__name__).error("Replay failed: %s", e)
            raise

    # Use uvicorn with a startup hook
    # We run uvicorn in a thread and the replay in the main asyncio loop
    from sentinel_net.api.main import create_app

    app = create_app()

    # Patch the lifespan to launch replay after init
    original_lifespan = app.router.lifespan_context

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def replay_lifespan(app_instance):
        # Fail before opening storage or advertising a ready API.
        from sentinel_net.sensor.runtime_model import load_runtime_model
        detection = await asyncio.to_thread(load_runtime_model, args.model, registry=config.model_registry)
        app_instance.state.model_identity = detection.deployment_identity
        app_instance.state.deployment_detection = detection
        async with original_lifespan(app_instance):
            # Schedule replay as a background task
            task = asyncio.create_task(_replay_after_startup(app_instance.state))
            try:
                yield
            finally:
                lifecycle = getattr(app_instance.state, 'sensor_lifecycle', None)
                if lifecycle:
                    lifecycle.request_shutdown()
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

    app.router.lifespan_context = replay_lifespan

    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║  EIDOLON // SENTINEL-NET — DEMO REPLAY MODE     ║")
    print("  ║                                                  ║")
    print(f"  ║  PCAP: {str(pcap_path)[:42]:<42} ║")
    print(f"  ║  API:  http://{host}:{port:<24}       ║")
    print("  ║                                                  ║")
    print("  ║  Sensor state will show REPLAYING (not RUNNING)  ║")
    print("  ║  All traffic goes through real ML inference.     ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()

    uvicorn.run(app, host=host, port=port, log_level=log_level.lower())


def _run_model(args):
    from sentinel_net.deployment.bundle import write_candidate, publish_candidate, digest, encoded
    if args.model_command == 'train':
        from sentinel_net.deployment.training import train_detection_pipeline
        pipeline = asyncio.run(train_detection_pipeline(args.dataset))
        path = write_candidate(pipeline, args.output, name=args.name, version=args.version,
                               training_seed=42, dataset_identifier='CICIDS2017', dataset_hash=args.dataset_hash,
                               code_revision=args.code_revision, training_configuration_hash=digest(encoded({
                                   'preprocessing': 'TREE_MODEL_FEATURES', 'seed': 42,
                                   'classifier': {'type': 'XGBoostClassifier', 'n_estimators': 100, 'max_depth': 6},
                                   'anomaly': {'type': 'AnomalyDetector', 'n_estimators': 100, 'fit': 'benign-only'},
                                   'thresholds': pipeline.thresholds.to_dict()})))
        print(f'Candidate written: {path}. Evaluate separately before explicit approval/publication.')
    else:
        identity = publish_candidate(args.candidate, get_config().model_registry,
            approved_by=args.approved_by, evaluation_reference=args.evaluation_reference)
        print(f'Approved immutable model published: {identity}')


if __name__ == "__main__":
    main()
